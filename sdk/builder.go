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

// Package sdk is the ergonomic entry point for embedding SentinelMCP directly
// into a Go application (Inline SDK mode). It composes the framework-agnostic
// gateway package with the orchestration adapter behind a small builder API,
// so securing tool calls takes a few lines instead of manual wiring.
//
// The orchestration engine is an implementation detail: this package is the
// only surface most consumers import, and the engine can be swapped without
// changing any security configuration.
package sdk

import (
	"fmt"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// Builder constructs a gateway.Pipeline with sensible defaults. Create one with
// New, tune it with the With* methods, and call Build to materialize the pipeline.
type Builder struct {
	invoker     gateway.ToolInvoker
	riskMap     map[string]gateway.ToolRisk
	defaultRisk gateway.ToolRisk
	policy      gateway.Policy
	dlp         gateway.DLPScanner
	redactor    gateway.Redactor
	audit       gateway.AuditEmitter
	approval    gateway.ApprovalProvider
	metrics     gateway.MetricsRecorder
	mask        string
	boltPath    string // empty = in-memory checkpoints
}

// New starts a Builder around the given tool invoker, which is required.
// Pass a *FuncInvoker (plain Go functions) or any gateway.ToolInvoker.
func New(invoker gateway.ToolInvoker) *Builder {
	return &Builder{
		invoker:     invoker,
		riskMap:     map[string]gateway.ToolRisk{},
		defaultRisk: gateway.ToolRisk{Level: gateway.RiskLow},
		mask:        "***REDACTED***",
	}
}

// WithDefaultRisk sets the risk applied when a tool has no explicit entry.
// The default is low, which routes to Allow under DefaultPolicy.
func (b *Builder) WithDefaultRisk(level gateway.RiskLevel) *Builder {
	b.defaultRisk = gateway.ToolRisk{Level: level}
	return b
}

// StrictDefaults adopts a stricter baseline in one call: the default risk
// becomes medium, so tools with no explicit entry route to Redact instead of
// Allow. Because argument scanning is field-attributed, that means sensitive
// argument fields (a password field, an SSN value, a leaked API key) are masked
// before the tool runs rather than passed through. Recommended for regulated
// environments; equivalent to WithDefaultRisk(gateway.RiskMedium).
//
//	p, err := sdk.New(invoker).StrictDefaults().Build()
func (b *Builder) StrictDefaults() *Builder {
	b.defaultRisk = gateway.ToolRisk{Level: gateway.RiskMedium}
	return b
}

// WithRisk sets the risk level for a named tool. Multiple calls accumulate.
func (b *Builder) WithRisk(tool string, level gateway.RiskLevel) *Builder {
	b.riskMap[tool] = gateway.ToolRisk{Level: level}
	return b
}

// WithPolicy overrides the default DefaultPolicy.
func (b *Builder) WithPolicy(p gateway.Policy) *Builder { b.policy = p; return b }

// WithDLPScanner overrides the default built-in regex DLP scanner.
func (b *Builder) WithDLPScanner(s gateway.DLPScanner) *Builder { b.dlp = s; return b }

// WithRedactor overrides the default mask-based redactor.
func (b *Builder) WithRedactor(r gateway.Redactor) *Builder { b.redactor = r; return b }

// WithAuditEmitter overrides the default stdout audit emitter.
func (b *Builder) WithAuditEmitter(a gateway.AuditEmitter) *Builder { b.audit = a; return b }

// WithApproval overrides the default CLI approval provider, used when a
// high-risk tool interrupts for human approval.
func (b *Builder) WithApproval(a gateway.ApprovalProvider) *Builder { b.approval = a; return b }

// WithMetrics attaches a metrics recorder (for example, the OTel recorder).
// Optional; nil means no-op.
func (b *Builder) WithMetrics(m gateway.MetricsRecorder) *Builder { b.metrics = m; return b }

// WithRedactionMask sets the mask substituted for redacted values.
func (b *Builder) WithRedactionMask(mask string) *Builder { b.mask = mask; return b }

// WithBoltCheckpoints persists interrupt/resume state to a BoltDB file so
// interrupted calls survive process restarts. Without it, checkpoints are
// in-memory and lost on restart.
func (b *Builder) WithBoltCheckpoints(path string) *Builder { b.boltPath = path; return b }

// Build materializes the gateway.Pipeline.
//
// Defaults (each overridable via the With* methods):
//   - Policy:      DefaultPolicy (low→allow, medium→redact, high→interrupt)
//   - RiskDB:      tools from WithRisk over a default risk of low
//   - DLP:         built-in regex patterns (6 patterns)
//   - Redactor:    mask-based ("***REDACTED***")
//   - Audit:       structured JSON to stdout
//   - Approval:    CLI provider (logs interrupts; resume via Pipeline.Resume)
//   - Checkpoints: in-memory (use WithBoltCheckpoints for durability)
func (b *Builder) Build() (gateway.Pipeline, error) {
	if b.invoker == nil {
		return nil, fmt.Errorf("sdk: ToolInvoker is required (pass one to sdk.New)")
	}

	dlp := b.dlp
	if dlp == nil {
		sc, err := gateway.NewRegexDLPScanner(gateway.BuiltinPatterns())
		if err != nil {
			return nil, fmt.Errorf("sdk: build default DLP scanner: %w", err)
		}
		dlp = sc
	}

	policy := b.policy
	if policy == nil {
		policy = gateway.NewDefaultPolicy()
	}

	redactor := b.redactor
	if redactor == nil {
		redactor = gateway.NewDefaultRedactor(b.mask)
	}

	audit := b.audit
	if audit == nil {
		audit = gateway.NewStdoutAuditEmitter(nil)
	}

	approval := b.approval
	if approval == nil {
		approval = gateway.NewCLIApprovalProvider()
	}

	cfg := &gateway.GatewayConfig{
		Policy:           policy,
		RiskDB:           gateway.NewYAMLRiskDB(b.riskMap, b.defaultRisk),
		DLPScanner:       dlp,
		Redactor:         redactor,
		AuditEmitter:     audit,
		ApprovalProvider: approval,
		ToolInvoker:      b.invoker,
		RedactionMask:    b.mask,
		MetricsRecorder:  b.metrics,
	}

	if b.boltPath != "" {
		return eino.BuildGraph(cfg, eino.WithCheckPointStore(eino.NewBoltCheckPointStore(b.boltPath)))
	}
	return eino.BuildGraph(cfg)
}
