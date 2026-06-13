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

// Package gateway provides the core types and interfaces for SentinelMCP,
// an Eino-native MCP Security Gateway.
//
// Core types (Decision, RiskLevel, ToolRisk, DLPFinding, etc.) have zero
// Eino imports, satisfying NFR-10 (framework portability). Only the graph
// wiring in graph.go uses Eino types.
package gateway

import (
	"encoding/json"
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// Decision types
// ---------------------------------------------------------------------------

// Decision is the outcome of a policy evaluation for a tool call.
type Decision string

const (
	DecisionAllow                Decision = "allow"
	DecisionRedact               Decision = "redact"
	DecisionBlock                Decision = "block"
	DecisionInterruptForApproval Decision = "interrupt_for_approval"
)

// ---------------------------------------------------------------------------
// Risk classification
// ---------------------------------------------------------------------------

// RiskLevel classifies the danger level of a tool.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// ToolRisk is the risk profile for a specific tool, loaded from config.
type ToolRisk struct {
	Level           RiskLevel `yaml:"risk"             json:"level"`
	RequireApproval bool      `yaml:"require_approval" json:"require_approval"`
	ApprovalReason  string    `yaml:"approval_reason"  json:"approval_reason,omitempty"`
	RedactPatterns  []string  `yaml:"redact_patterns"  json:"redact_patterns,omitempty"`
}

// ---------------------------------------------------------------------------
// DLP findings
// ---------------------------------------------------------------------------

// DLPFindingType categorizes what was detected by the DLP scanner.
type DLPFindingType string

const (
	FindingPII        DLPFindingType = "pii"
	FindingSecret     DLPFindingType = "secret"
	FindingCreditCard DLPFindingType = "credit_card"
	FindingPrivateKey DLPFindingType = "private_key"
	FindingAPIKey     DLPFindingType = "api_key"
	FindingCustom     DLPFindingType = "custom"
)

// DLPSeverity classifies the severity of a DLP finding.
// External DLP vendors (Nightfall, Symantec, etc.) always return severity.
// The policy engine can use this for differentiated decisions (HIGH→block, LOW→redact).
type DLPSeverity string

const (
	SeverityHigh   DLPSeverity = "high"
	SeverityMedium DLPSeverity = "medium"
	SeverityLow    DLPSeverity = "low"
)

// DLPFinding represents one sensitive pattern match found by the DLP scanner.
//
// For the built-in RegexDLPScanner, Value is populated and EndIdx is derived.
// For external DLP scanners (Enterprise), EndIdx is set directly so the scanner
// doesn't need to expose the sensitive Value. The DefaultRedactor prefers EndIdx
// when non-zero, falling back to Position + len(Value).
type DLPFinding struct {
	Type     DLPFindingType `json:"type"`
	Pattern  string         `json:"pattern"`            // pattern name, e.g. "PRIVATE_KEY"
	Value    string         `json:"-"`                  // matched value — NEVER serialized to logs (NFR-06)
	Field    string         `json:"field"`              // argument field name, if applicable
	Position int            `json:"position"`           // byte offset start in content
	EndIdx   int            `json:"end_idx,omitempty"`  // byte offset end; set by external scanners
	Severity DLPSeverity    `json:"severity"`           // high/medium/low — drives policy decisions
	Metadata map[string]any `json:"metadata,omitempty"` // vendor-specific (e.g., nightfall_confidence)
}

// ---------------------------------------------------------------------------
// Policy decision result
// ---------------------------------------------------------------------------

// DecisionResult is the output of Policy.Decide. It carries everything
// the gateway graph needs to route the call — the graph never re-derives info.
type DecisionResult struct {
	Decision  Decision     `json:"decision"`
	Reason    string       `json:"reason"`
	RiskLevel RiskLevel    `json:"risk_level"`
	Findings  []DLPFinding `json:"findings,omitempty"`

	// RedactedArgs is populated when Decision == DecisionRedact.
	// Maps argument field name to redacted value.
	RedactedArgs map[string]string `json:"redacted_args,omitempty"`

	// Inspection carries the pattern categories an action-based REDACT policy
	// asks the DLP layer to scan for (e.g. "pii", "secrets"). Populated by
	// PolicySet; the risk-based DefaultPolicy leaves it empty. Consumed by the
	// inspection layer (Step 3); carried here so the decision is self-describing.
	Inspection []string `json:"inspection,omitempty"`

	// Timeout overrides the global interrupt timeout for an INTERRUPT decision
	// (consumed by Step 5's approval-timeout / auto-block). Zero = use default.
	Timeout time.Duration `json:"timeout,omitempty"`

	// PolicyName names the action-based policy rule that produced this decision,
	// surfaced in the audit log. Empty for risk-based (DefaultPolicy) decisions.
	PolicyName string `json:"policy_name,omitempty"`
}

// ---------------------------------------------------------------------------
// Policy input context
// ---------------------------------------------------------------------------

// ToolCallContext is the full context available to a Policy for decision-making.
// Assembled by the gateway graph's InspectToolCall node before calling Policy.Decide.
//
// Uses a context-struct pattern (not individual parameters) so new fields can
// be added without breaking the Policy interface signature (NFR-09).
type ToolCallContext struct {
	ToolName string         `json:"tool_name"`
	ToolDesc string         `json:"tool_desc"` // from tool.Info().Desc
	Args     map[string]any `json:"args"`
	Risk     ToolRisk       `json:"risk"`     // from RiskDB.Lookup
	Findings []DLPFinding   `json:"findings"` // from DLPScanner.Scan
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

// AuditEvent is a structured security enforcement event emitted by the gateway.
// This is a first-class domain object — the policy engine emits these whenever it
// enforces an action (ALLOW, BLOCK, REDACT, INTERRUPT). The event is handed off
// to the AuditEmitter interface, keeping domain logic decoupled from delivery.
//
// OSS implementations: StdoutAuditEmitter (JSON stdout), FileAuditEmitter (file).
// Enterprise implementations: ControlPlaneEmitter (API push to Control Plane).
type AuditEvent struct {
	Timestamp  time.Time     `json:"ts"`
	Event      string        `json:"event"` // "tool_start" | "tool_end" | "tool_error" | "tool_blocked" | "tool_interrupted"
	ToolName   string        `json:"tool"`
	RiskLevel  RiskLevel     `json:"risk"`
	Decision   Decision      `json:"decision"`
	PolicyName string        `json:"policy,omitempty"` // policy that triggered the decision
	Args       any           `json:"args"`             // REDACTED — never raw values
	Result     string        `json:"result,omitempty"` // REDACTED
	Latency    time.Duration `json:"latency_ms,omitempty"`
	TraceID    string        `json:"trace_id,omitempty"`
	SessionID  string        `json:"session_id,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// MarshalJSON serializes Latency as whole milliseconds rather than the
// nanoseconds a bare time.Duration would emit. The JSON tag is latency_ms and
// the audit stream is consumed by operators and SIEM tooling that read it as
// milliseconds; emitting nanoseconds under an _ms tag was a unit mismatch. All
// other fields keep their default marshalling via the type alias.
func (e AuditEvent) MarshalJSON() ([]byte, error) {
	type alias AuditEvent
	aux := struct {
		alias
		Latency int64 `json:"latency_ms,omitempty"`
	}{
		alias:   alias(e),
		Latency: e.Latency.Milliseconds(),
	}
	return json.Marshal(aux)
}

// ---------------------------------------------------------------------------
// Gateway graph context (internal)
// ---------------------------------------------------------------------------

// GatewayContext flows through all nodes in the gateway graph.
// Each node reads what it needs and enriches the context for downstream nodes.
//
// Boundary conversion:
//   - In:  InvokableRun(ctx, argsJSON) -> parse JSON -> *GatewayContext
//   - Out: *GatewayContext -> serialize to JSON string
type GatewayContext struct {
	// Set at graph entry boundary:
	ToolName string         `json:"tool_name"`
	Args     map[string]any `json:"args"`

	// Set by inspect_tool_call node:
	Risk     *ToolRisk       `json:"risk,omitempty"`
	Findings []DLPFinding    `json:"findings,omitempty"`
	Decision *DecisionResult `json:"decision,omitempty"`

	// Set by run_tool node:
	RawResult string `json:"raw_result,omitempty"`

	// Set by inspect_tool_response node:
	Result   string `json:"result,omitempty"`
	Redacted bool   `json:"redacted,omitempty"`

	// Set on block:
	Blocked bool   `json:"blocked,omitempty"`
	Reason  string `json:"reason,omitempty"`
}

// ---------------------------------------------------------------------------
// Approval / interrupt types
// ---------------------------------------------------------------------------

// InterruptInfo is surfaced when the gateway interrupts for human approval.
type InterruptInfo struct {
	ID           string         `json:"id"`            // Eino interrupt ID
	CheckpointID string         `json:"checkpoint_id"` // Eino checkpoint ID
	ToolName     string         `json:"tool_name"`
	Args         map[string]any `json:"args"`
	RiskLevel    RiskLevel      `json:"risk_level"`
	Reason       string         `json:"reason"`
	SessionID    string         `json:"session_id,omitempty"`
}

// ApprovalAction represents the human's response to an approval request.
type ApprovalAction string

const (
	ApprovalApprove ApprovalAction = "approve"
	ApprovalDeny    ApprovalAction = "deny"
	ApprovalModify  ApprovalAction = "modify"
)

// ApprovalDecision is sent via ResumeWithData when the human responds.
type ApprovalDecision struct {
	Action       ApprovalAction `json:"action"`
	Reason       string         `json:"reason"`
	ModifiedArgs map[string]any `json:"modified_args,omitempty"` // only for "modify"
}

// ---------------------------------------------------------------------------
// Interrupt error — returned by Pipeline.Run when approval is required
// ---------------------------------------------------------------------------

// InterruptError is returned by Pipeline.Run when a tool call requires human
// approval. The caller should present the approval request to a human, collect
// their decision, and call Pipeline.Resume with the InterruptInfo and ApprovalDecision.
//
// Detect with errors.As:
//
//	var ie *gateway.InterruptError
//	if errors.As(err, &ie) { ... }
type InterruptError struct {
	Info InterruptInfo
}

// Error implements the error interface.
func (e *InterruptError) Error() string {
	return fmt.Sprintf("gateway: tool %q interrupted for approval: %s (risk=%s)",
		e.Info.ToolName, e.Info.Reason, e.Info.RiskLevel)
}
