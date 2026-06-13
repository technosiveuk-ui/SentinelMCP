// Copyright 2024-2026 Technosive Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gateway

import (
	"context"
	"time"
)

// Action is the enforcement action an action-based policy rule dictates. It is
// an alias for Decision (allow / block / redact / interrupt_for_approval) so the
// action-based layer composes with the existing risk-based layer and reuses the
// pipeline's dispatch unchanged — no parallel action vocabulary.
type Action = Decision

// PolicyRule is one action-based policy rule.
//
// A tools/call matches a rule when the tool name matches ANY of Tools (glob),
// AND — if Risk is set — the call's risk level is at least Risk. Within a
// PolicySet, the first matching rule wins.
type PolicyRule struct {
	Name       string        // human-readable id; surfaced in audit
	Tools      []string      // glob patterns; matches if any matches the tool name
	Action     Action        // enforcement decision (ALLOW/BLOCK/REDACT/INTERRUPT)
	Risk       RiskLevel     // optional threshold; empty = match any risk
	Inspection []string      // DLP pattern categories requested on REDACT (Step 3)
	Timeout    time.Duration // INTERRUPT timeout override (Step 5); 0 = default
}

// PolicySet is an action-based policy: an ordered list of rules evaluated
// first-match-wins, with a fallback Policy (typically the risk-based
// DefaultPolicy) for tools no rule matches.
//
// This composes the action-based schema with the existing risk model: explicit
// rules override for the tools they name; unmatched tools fall through to risk
// routing. If no rule matches and no fallback is configured, the call is blocked
// (fail-closed) rather than allowed.
type PolicySet struct {
	rules    []PolicyRule
	fallback Policy
}

// NewPolicySet builds an action-based policy. fallback is consulted when no rule
// matches; pass nil to block unmatched tools (fail-closed).
func NewPolicySet(rules []PolicyRule, fallback Policy) *PolicySet {
	return &PolicySet{rules: rules, fallback: fallback}
}

// Decide implements Policy. Rules are evaluated in order; the first whose Tools
// glob matches the tool (and whose Risk threshold, if any, is met) wins. If no
// rule matches, the fallback decides; a nil fallback blocks (fail-closed).
func (ps *PolicySet) Decide(ctx context.Context, call ToolCallContext) (*DecisionResult, error) {
	for _, rule := range ps.rules {
		if !ruleMatchesTool(rule.Tools, call.ToolName) {
			continue
		}
		if rule.Risk != "" && !riskAtLeast(call.Risk.Level, rule.Risk) {
			continue
		}
		return decideFromRule(rule, call), nil
	}

	if ps.fallback != nil {
		return ps.fallback.Decide(ctx, call)
	}

	// No rule matched and no fallback: fail-closed.
	return &DecisionResult{
		Decision:  DecisionBlock,
		RiskLevel: call.Risk.Level,
		Reason:    "no policy matched and no fallback configured: blocked (fail-closed)",
	}, nil
}

// decideFromRule materializes a DecisionResult from a matched rule, carrying the
// inspection/timeout/policy-name hints the downstream layers (Step 3, Step 5,
// audit) need. The matched findings are attached so a REDACT decision has them.
func decideFromRule(rule PolicyRule, call ToolCallContext) *DecisionResult {
	return &DecisionResult{
		Decision:   rule.Action,
		RiskLevel:  call.Risk.Level,
		Findings:   call.Findings,
		Inspection: rule.Inspection,
		Timeout:    rule.Timeout,
		PolicyName: rule.Name,
		Reason:     ruleReason(rule),
	}
}

// ruleReason builds a human-readable reason for the audit log.
func ruleReason(rule PolicyRule) string {
	base := "policy " + quoteName(rule.Name) + ": " + string(rule.Action)
	if rule.Risk != "" {
		base += " (risk >= " + string(rule.Risk) + ")"
	}
	return base
}

func quoteName(name string) string {
	if name == "" {
		return "<unnamed>"
	}
	return name
}

// ruleMatchesTool reports whether any of the rule's glob patterns match name.
// Reuses matchGlob (shared with YAMLRiskDB) for consistent glob semantics.
func ruleMatchesTool(patterns []string, name string) bool {
	for _, p := range patterns {
		if matchGlob(p, name) {
			return true
		}
	}
	return false
}

// riskAtLeast reports whether level >= threshold, using low < medium < high.
// An unknown level is treated as the lowest (most permissive comparison) so a
// misconfigured risk never accidentally escalates a block threshold.
func riskAtLeast(level, threshold RiskLevel) bool {
	return riskRank(level) >= riskRank(threshold)
}

func riskRank(r RiskLevel) int {
	switch r {
	case RiskLow:
		return 0
	case RiskMedium:
		return 1
	case RiskHigh:
		return 2
	}
	return 0
}
