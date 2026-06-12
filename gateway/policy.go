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
	"sync"
)

// ---------------------------------------------------------------------------
// Policy interface (framework-agnostic)
// ---------------------------------------------------------------------------

// Policy evaluates a tool call and returns a decision.
//
// The default implementation routes by risk level:
//
//	low -> Allow, medium -> Redact, high -> InterruptForApproval
//
// Custom implementations can override this logic per team/agent/session.
//
// OSS extension point: the OSS sidecar ships DefaultPolicy (risk-level routing).
// Enterprise implementations may override with context-aware policies via the
// commercial Control Plane (e.g., per-user, per-session, or ML-based decisions).
type Policy interface {
	// Decide evaluates the tool call context and returns a decision result.
	// On error, the caller must treat the call as blocked (default-deny, NFR-07).
	Decide(ctx context.Context, call ToolCallContext) (*DecisionResult, error)
}

// DefaultPolicy implements the standard risk-level routing.
type DefaultPolicy struct {
	// Mapping from risk level to decision. If nil, uses the built-in defaults:
	//   low -> Allow, medium -> Redact, high -> InterruptForApproval
	RiskMapping map[RiskLevel]Decision
}

// NewDefaultPolicy returns a Policy with the standard risk-to-decision mapping.
func NewDefaultPolicy() *DefaultPolicy {
	return &DefaultPolicy{
		RiskMapping: map[RiskLevel]Decision{
			RiskLow:    DecisionAllow,
			RiskMedium: DecisionRedact,
			RiskHigh:   DecisionInterruptForApproval,
		},
	}
}

// Decide implements Policy using risk-level routing.
func (p *DefaultPolicy) Decide(_ context.Context, call ToolCallContext) (*DecisionResult, error) {
	mapping := p.RiskMapping
	if mapping == nil {
		mapping = map[RiskLevel]Decision{
			RiskLow:    DecisionAllow,
			RiskMedium: DecisionRedact,
			RiskHigh:   DecisionInterruptForApproval,
		}
	}

	decision, ok := mapping[call.Risk.Level]
	if !ok {
		decision = DecisionAllow // unknown risk defaults to allow
	}

	result := &DecisionResult{
		Decision:  decision,
		RiskLevel: call.Risk.Level,
		Findings:  call.Findings,
	}

	switch decision {
	case DecisionAllow:
		result.Reason = "risk level " + string(call.Risk.Level) + ": allowed"
	case DecisionRedact:
		result.Reason = "risk level " + string(call.Risk.Level) + ": redaction required"
		result.RedactedArgs = redactedFields(call.Args, call.Findings)
	case DecisionBlock:
		result.Reason = "risk level " + string(call.Risk.Level) + ": blocked"
	case DecisionInterruptForApproval:
		result.Reason = "risk level " + string(call.Risk.Level) + ": requires human approval"
	}

	return result, nil
}

// redactedFields builds the RedactedArgs map from DLP findings.
// Returns nil if no findings — the caller checks this to skip redaction.
func redactedFields(args map[string]any, findings []DLPFinding) map[string]string {
	if len(findings) == 0 {
		return nil
	}
	redacted := make(map[string]string, len(findings))
	for _, f := range findings {
		if f.Field != "" {
			redacted[f.Field] = "***REDACTED***"
		}
	}
	return redacted
}

// ---------------------------------------------------------------------------
// RiskDB interface (framework-agnostic)
// ---------------------------------------------------------------------------

// RiskDB maps tool names to risk profiles.
//
// OSS extension point: the OSS sidecar ships YAMLRiskDB (static YAML config).
// Enterprise implementations add dynamic risk scoring via the commercial Control Plane.
type RiskDB interface {
	// Lookup returns the ToolRisk for a tool. The returned value is always
	// usable: an explicit (exact or glob) entry when found, or the configured
	// default risk otherwise. The bool indicates an explicit match — callers
	// that only need the level can ignore it and route on the returned ToolRisk.
	Lookup(toolName string) (ToolRisk, bool)
}

// YAMLRiskDB implements RiskDB backed by a static config map.
// Supports exact match and glob patterns (e.g., "db_*").
// Thread-safe via sync.RWMutex for future hot-reload support.
type YAMLRiskDB struct {
	mu       sync.RWMutex
	exact    map[string]ToolRisk // exact tool name -> risk
	patterns []patternEntry      // glob patterns, checked in order
	default_ ToolRisk            // fallback when no match
}

type patternEntry struct {
	glob string
	risk ToolRisk
}

// NewYAMLRiskDB creates a RiskDB from a config map.
// Keys are tool names (exact or glob patterns like "db_*").
// The defaultRisk is returned when no tool matches.
func NewYAMLRiskDB(tools map[string]ToolRisk, defaultRisk ToolRisk) *YAMLRiskDB {
	db := &YAMLRiskDB{
		exact:    make(map[string]ToolRisk, len(tools)),
		default_: defaultRisk,
	}
	for name, risk := range tools {
		if hasGlob(name) {
			db.patterns = append(db.patterns, patternEntry{glob: name, risk: risk})
		} else {
			db.exact[name] = risk
		}
	}
	return db
}

// Lookup implements RiskDB.
func (db *YAMLRiskDB) Lookup(toolName string) (ToolRisk, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Exact match first (O(1)).
	if risk, ok := db.exact[toolName]; ok {
		return risk, true
	}

	// Then glob patterns (OD-03: lookup-time matching; N is small).
	for _, p := range db.patterns {
		if matchGlob(p.glob, toolName) {
			return p.risk, true
		}
	}

	// No explicit or glob match: return the configured default. Returning it
	// here (rather than a zero value) makes default_risk actually take effect —
	// callers route on the returned level, so the default flows through to the
	// policy decision. found stays false to signal "no explicit entry".
	return db.default_, false
}

// hasGlob returns true if the string contains glob metacharacters.
func hasGlob(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '*', '?', '[', '{':
			return true
		}
	}
	return false
}

// matchGlob does simple glob matching (* and ? only).
// Uses path.Match semantics but without the separator restriction.
func matchGlob(pattern, name string) bool {
	pi, ni := 0, 0
	for pi < len(pattern) && ni < len(name) {
		switch pattern[pi] {
		case '*':
			// Try matching rest of pattern after *
			pi++
			for ni <= len(name) {
				if matchGlob(pattern[pi:], name[ni:]) {
					return true
				}
				ni++
			}
			return false
		case '?':
			pi++
			ni++
		default:
			if pattern[pi] != name[ni] {
				return false
			}
			pi++
			ni++
		}
	}
	// Consume trailing *
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern) && ni == len(name)
}
