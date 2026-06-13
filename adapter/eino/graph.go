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

// Package eino provides the Eino framework adapter for SentinelMCP.
//
// This is the ONLY package in SentinelMCP that imports Eino types.
// All core domain logic lives in the gateway package (zero Eino imports).
// If SentinelMCP ever needs to support a different orchestration framework,
// a new adapter package is created here alongside this one, and the gateway
// package remains untouched.
package eino

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cloudwego/eino/compose"
	"github.com/cloudwego/eino/schema"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Eino type registrations (required for checkpoint serialization)
// ---------------------------------------------------------------------------

func init() {
	schema.RegisterName[*toolCallState]("sentinelmcp/tool_call_state")
	schema.RegisterName[*gateway.ApprovalDecision]("sentinelmcp/approval_decision")
}

// toolCallState is persisted in the checkpoint during interrupt.
// Contains everything needed to restore the gateway context on resume.
type toolCallState struct {
	ToolName string                 `json:"tool_name"`
	Args     map[string]any         `json:"args"`
	Risk     gateway.ToolRisk       `json:"risk"`
	Findings []gateway.DLPFinding   `json:"findings"`
	Decision gateway.DecisionResult `json:"decision"`
}

// ---------------------------------------------------------------------------
// In-memory checkpoint store
// ---------------------------------------------------------------------------

// memCheckpointStore implements compose.CheckPointStore using an in-memory map.
// Sufficient for WP 1.2; production deployments should use a persistent store.
type memCheckpointStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemCheckpointStore() *memCheckpointStore {
	return &memCheckpointStore{data: make(map[string][]byte)}
}

func (s *memCheckpointStore) Get(_ context.Context, id string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.data[id]
	return d, ok, nil
}

func (s *memCheckpointStore) Set(_ context.Context, id string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = data
	return nil
}

// Delete removes a checkpoint, invalidating a paused graph so it can no longer be
// resumed. Used by the approval-timeout registry to expire interrupts (Step 5).
func (s *memCheckpointStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	return nil
}

// ---------------------------------------------------------------------------
// Pipeline implementation
// ---------------------------------------------------------------------------

// graphPipeline implements gateway.Pipeline backed by an Eino compose.Graph.
type graphPipeline struct {
	graph    *compose.Graph[*gateway.GatewayContext, *gateway.GatewayContext]
	compiled compose.Runnable[*gateway.GatewayContext, *gateway.GatewayContext]
	cfg      *gateway.GatewayConfig
	store    compose.CheckPointStore
	registry *interruptRegistry // approval-deadline timers (Step 5)
	mu       sync.Mutex
	cpSeq    int64 // atomic counter for checkpoint IDs
}

// Run implements gateway.Pipeline.
func (p *graphPipeline) Run(ctx context.Context, toolName string, args map[string]any) (string, error) {
	compiled, err := p.getCompiled(ctx)
	if err != nil {
		return "", fmt.Errorf("adapter/eino: compile graph: %w", err)
	}

	if args == nil {
		args = make(map[string]any)
	}

	cpID := p.nextCheckpointID()
	gc := &gateway.GatewayContext{
		ToolName: toolName,
		Args:     args,
	}

	start := time.Now()
	result, err := compiled.Invoke(ctx, gc, compose.WithCheckPointID(cpID))
	if err != nil {
		info, isInterrupt := compose.ExtractInterruptInfo(err)
		if isInterrupt && info != nil && len(info.InterruptContexts) > 0 {
			return p.handleInterrupt(ctx, info, toolName, args, cpID, start)
		}
		return "", fmt.Errorf("adapter/eino: graph invocation failed: %w", err)
	}

	if result.Blocked {
		// Record blocked tool call metric.
		if p.cfg.MetricsRecorder != nil {
			riskLevel := gateway.RiskLow
			if result.Risk != nil {
				riskLevel = result.Risk.Level
			}
			p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
				ToolName:  toolName,
				Decision:  gateway.DecisionBlock,
				RiskLevel: riskLevel,
				Duration:  time.Since(start),
			})
		}
		return "", fmt.Errorf("gateway: tool call blocked: %s", result.Reason)
	}

	// Record successful tool call metric.
	if p.cfg.MetricsRecorder != nil {
		decision := gateway.DecisionAllow
		riskLevel := gateway.RiskLow
		if result.Decision != nil {
			decision = result.Decision.Decision
		}
		if result.Risk != nil {
			riskLevel = result.Risk.Level
		}
		p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
			ToolName:  toolName,
			Decision:  decision,
			RiskLevel: riskLevel,
			Duration:  time.Since(start),
		})
	}

	return result.Result, nil
}

// Resume implements gateway.Pipeline.
func (p *graphPipeline) Resume(ctx context.Context, interruptInfo gateway.InterruptInfo, approval *gateway.ApprovalDecision) (string, error) {
	// Gate the resume against the approval deadline. A late resume (the timer
	// already fired and auto-blocked the call) must not execute the graph.
	if err := p.registry.Claim(interruptInfo.CheckpointID); err != nil {
		// Compliance: the rejection itself is audited so there is a record that a
		// resume was attempted after the call was already resolved (blocked on
		// timeout, or unknown/duplicate) — proving the request stayed blocked,
		// not silently dropped.
		_ = p.cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_blocked",
			ToolName:  interruptInfo.ToolName,
			RiskLevel: interruptInfo.RiskLevel,
			Decision:  gateway.DecisionBlock,
			Error:     fmt.Sprintf("resume_rejected: %v", err),
		})
		return "", fmt.Errorf("adapter/eino: resume rejected: %w", err)
	}

	compiled, err := p.getCompiled(ctx)
	if err != nil {
		return "", fmt.Errorf("adapter/eino: compile graph: %w", err)
	}

	resumeCtx := compose.ResumeWithData(ctx, interruptInfo.ID, approval)

	result, err := compiled.Invoke(resumeCtx, &gateway.GatewayContext{}, compose.WithCheckPointID(interruptInfo.CheckpointID))
	if err != nil {
		info, isInterrupt := compose.ExtractInterruptInfo(err)
		if isInterrupt && info != nil && len(info.InterruptContexts) > 0 {
			return p.handleInterrupt(ctx, info, interruptInfo.ToolName, interruptInfo.Args, interruptInfo.CheckpointID, time.Now())
		}
		return "", fmt.Errorf("adapter/eino: resume invocation failed: %w", err)
	}

	if result.Blocked {
		// Record resumed-but-blocked tool call metric.
		if p.cfg.MetricsRecorder != nil {
			riskLevel := gateway.RiskLow
			if result.Risk != nil {
				riskLevel = result.Risk.Level
			}
			p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
				ToolName:  interruptInfo.ToolName,
				Decision:  gateway.DecisionBlock,
				RiskLevel: riskLevel,
			})
		}
		return "", fmt.Errorf("gateway: tool call blocked: %s", result.Reason)
	}

	// Record approval and successful tool call metrics.
	if p.cfg.MetricsRecorder != nil {
		p.cfg.MetricsRecorder.RecordApproval(ctx, approval.Action, interruptInfo.ToolName)
		decision := gateway.DecisionAllow
		riskLevel := gateway.RiskLow
		if result.Decision != nil {
			decision = result.Decision.Decision
		}
		if result.Risk != nil {
			riskLevel = result.Risk.Level
		}
		p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
			ToolName:  interruptInfo.ToolName,
			Decision:  decision,
			RiskLevel: riskLevel,
		})
	}

	return result.Result, nil
}

// handleInterrupt extracts interrupt info, notifies the approval provider,
// and returns an InterruptError.
func (p *graphPipeline) handleInterrupt(ctx context.Context, info *compose.InterruptInfo, toolName string, args map[string]any, cpID string, start time.Time) (string, error) {
	ic := info.InterruptContexts[0]
	infoMap, _ := ic.Info.(map[string]any)

	reason := ""
	if r, ok := infoMap["reason"].(string); ok {
		reason = r
	}

	var riskLevel gateway.RiskLevel
	if rl, ok := infoMap["risk_level"].(string); ok {
		riskLevel = gateway.RiskLevel(rl)
	}

	// Per-rule approval deadline (action-based INTERRUPT policies may set one).
	// Carried through the interrupt info map; 0 => resolveTimeout falls back to
	// the global default, then the 10m cap — never an unbounded wait.
	var policyTimeout time.Duration
	if t, ok := infoMap["timeout"].(time.Duration); ok {
		policyTimeout = t
	}

	interruptInfo := gateway.InterruptInfo{
		ID:           ic.ID,
		CheckpointID: cpID,
		ToolName:     toolName,
		Args:         args,
		RiskLevel:    riskLevel,
		Reason:       reason,
	}

	// Arm the approval-deadline timer. The timer lives outside the suspended
	// graph (the graph cannot tick its own clock while paused): if it elapses
	// before a resume, the call is auto-blocked and the checkpoint invalidated.
	p.registry.Register(cpID, interruptInfo, resolveTimeout(policyTimeout, p.cfg.ApprovalDefaultTimeout), p.onApprovalTimeout)

	// Notify the approval provider (best-effort — don't block on failure).
	_ = p.cfg.ApprovalProvider.SendApprovalRequest(ctx, interruptInfo)

	// Audit log the interruption.
	_ = p.cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
		Timestamp: time.Now().UTC(),
		Event:     "tool_interrupted",
		ToolName:  toolName,
		RiskLevel: riskLevel,
		Decision:  gateway.DecisionInterruptForApproval,
		Latency:   time.Since(start),
	})

	// Record tool call metric for interrupted calls.
	if p.cfg.MetricsRecorder != nil {
		p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
			ToolName:  toolName,
			Decision:  gateway.DecisionInterruptForApproval,
			RiskLevel: riskLevel,
			Duration:  time.Since(start),
		})
	}

	return "", &gateway.InterruptError{Info: interruptInfo}
}

// onApprovalTimeout is the registry's expiry callback: an interrupt elapsed
// without a resume, so the call is auto-blocked. Emitting the block audit and
// recording the metric here proves the timeout was enforced (compliance),
// rather than the call merely being abandoned.
func (p *graphPipeline) onApprovalTimeout(info gateway.InterruptInfo) {
	ctx := context.Background()
	_ = p.cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
		Timestamp: time.Now().UTC(),
		Event:     "tool_blocked",
		ToolName:  info.ToolName,
		RiskLevel: info.RiskLevel,
		Decision:  gateway.DecisionBlock,
		Error:     "approval_timeout: no approval received within deadline",
	})
	if p.cfg.MetricsRecorder != nil {
		p.cfg.MetricsRecorder.RecordToolCall(ctx, gateway.ToolCallMetric{
			ToolName:  info.ToolName,
			Decision:  gateway.DecisionBlock,
			RiskLevel: info.RiskLevel,
		})
	}
}

// getCompiled lazily compiles the graph (thread-safe, once).
func (p *graphPipeline) getCompiled(ctx context.Context) (compose.Runnable[*gateway.GatewayContext, *gateway.GatewayContext], error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.compiled != nil {
		return p.compiled, nil
	}
	compiled, err := p.graph.Compile(ctx,
		compose.WithCheckPointStore(p.store),
		compose.WithGraphName("sentinelmcp-gateway"),
	)
	if err != nil {
		return nil, err
	}
	p.compiled = compiled
	return p.compiled, nil
}

// nextCheckpointID generates a unique checkpoint ID.
func (p *graphPipeline) nextCheckpointID() string {
	n := atomic.AddInt64(&p.cpSeq, 1)
	return fmt.Sprintf("sentinelmcp-cp-%d", n)
}

// ---------------------------------------------------------------------------
// Graph builder
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Graph builder
// ---------------------------------------------------------------------------

// GraphOption configures the graph builder. Functional options allow
// extensibility without breaking the existing BuildGraph() call signature.
type GraphOption func(*graphOptions)

// graphOptions holds optional graph configuration.
type graphOptions struct {
	checkPointStore compose.CheckPointStore
}

// WithCheckPointStore sets a custom checkpoint store for the graph.
// If not provided, an in-memory store is used (current default behavior).
func WithCheckPointStore(store compose.CheckPointStore) GraphOption {
	return func(o *graphOptions) { o.checkPointStore = store }
}

// BuildGraph constructs an Eino graph that wraps MCP tool calls with
// inspection, policy enforcement, and audit logging.
//
// Graph topology:
//
//	START -> inspect_tool_call --(allow/redact/approved)--> run_tool -> inspect_tool_response -> END
//	              |
//	              +--(blocked)----------------------------------------------> END
//
// Returns a gateway.Pipeline — the caller never sees Eino types.
//
// Backward-compatible: existing callers (cmd/demo) can call BuildGraph(cfg)
// without options to get the default in-memory store.
func BuildGraph(cfg *gateway.GatewayConfig, opts ...GraphOption) (gateway.Pipeline, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	o := &graphOptions{}
	for _, opt := range opts {
		opt(o)
	}

	store := o.checkPointStore
	if store == nil {
		store = newMemCheckpointStore()
	}
	// The approval-timeout registry is gated on the store's Delete capability so
	// expired interrupts can be invalidated at the checkpoint level too.
	registry := newInterruptRegistry(store)

	g := compose.NewGraph[*gateway.GatewayContext, *gateway.GatewayContext]()

	// -----------------------------------------------------------------------
	// Node: inspect_tool_call
	//
	// Deserializes arguments, runs DLP scan, looks up risk, calls Policy.Decide.
	// For high-risk tools, calls StatefulInterrupt for human-in-the-loop approval.
	// On resume, reads the ApprovalDecision and routes accordingly.
	// -----------------------------------------------------------------------
	inspectCallLambda := compose.InvokableLambda(func(ctx context.Context, input *gateway.GatewayContext) (*gateway.GatewayContext, error) {
		start := time.Now()

		// --- Resume path: MUST be checked before nil-input guard ---
		// On resume from interrupt, the graph may supply a nil or empty input.
		// The real context comes from the checkpoint state, not the input.
		wasInterrupted, hasState, state := compose.GetInterruptState[*toolCallState](ctx)
		if wasInterrupted && hasState {
			gc := input
			if gc == nil {
				gc = &gateway.GatewayContext{}
			}
			return inspectResume(ctx, gc, state, cfg, start)
		}

		// --- First run: inspect the tool call ---
		gc := input
		if gc == nil {
			return nil, fmt.Errorf("adapter/eino: inspect_tool_call received nil input")
		}

		// 1. DLP scan the arguments field-by-field. Each finding is attributed
		//    to its argument name so that, on a "redact" decision, RedactArgs
		//    masks exactly the sensitive field instead of an opaque JSON blob.
		findings, err := gateway.ScanArgs(ctx, cfg.DLPScanner, gc.Args)
		if err != nil {
			gc.Blocked = true
			gc.Reason = fmt.Sprintf("DLP scan failed: %v (default-deny NFR-07)", err)
			return gc, nil
		}
		gc.Findings = findings

		// 1b. Record DLP findings to metrics.
		if cfg.MetricsRecorder != nil {
			for _, f := range findings {
				cfg.MetricsRecorder.RecordDLPFinding(ctx, f)
			}
		}

		// 2. Risk lookup from RiskDB. Lookup always returns a usable risk —
		//    the configured default when the tool has no explicit entry — so a
		//    medium default (e.g. StrictDefaults) routes unrecognized tools to
		//    redact rather than silently allowing them.
		risk, _ := cfg.RiskDB.Lookup(gc.ToolName)
		gc.Risk = &risk

		// 3. Call Policy.Decide.
		callCtx := gateway.ToolCallContext{
			ToolName: gc.ToolName,
			Args:     gc.Args,
			Risk:     risk,
			Findings: findings,
		}
		decision, err := cfg.Policy.Decide(ctx, callCtx)
		if err != nil {
			// NFR-07: default-deny on Policy error.
			gc.Blocked = true
			gc.Reason = fmt.Sprintf("policy error: %v (default-deny NFR-07)", err)
			gc.Decision = &gateway.DecisionResult{
				Decision:  gateway.DecisionBlock,
				RiskLevel: risk.Level,
				Reason:    gc.Reason,
			}
			_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
				Timestamp: time.Now().UTC(),
				Event:     "tool_blocked",
				ToolName:  gc.ToolName,
				RiskLevel: risk.Level,
				Decision:  gateway.DecisionBlock,
				Latency:   time.Since(start),
				Error:     gc.Reason,
			})
			return gc, nil
		}
		gc.Decision = decision

		// 4. Route based on decision.
		switch decision.Decision {
		case gateway.DecisionAllow:
			_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
				Timestamp:  time.Now().UTC(),
				Event:      "tool_start",
				ToolName:   gc.ToolName,
				RiskLevel:  risk.Level,
				Decision:   gateway.DecisionAllow,
				PolicyName: decision.PolicyName,
				Latency:    time.Since(start),
			})
			return gc, nil

		case gateway.DecisionRedact:
			// Apply arg redaction before passing to run_tool.
			gc.Args = gateway.RedactArgs(gc.Args, decision, cfg.RedactionMask, cfg.RedactionPreserveLength)
			_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
				Timestamp:  time.Now().UTC(),
				Event:      "tool_start",
				ToolName:   gc.ToolName,
				RiskLevel:  risk.Level,
				Decision:   gateway.DecisionRedact,
				PolicyName: decision.PolicyName,
				Args:       gc.Args,
				Latency:    time.Since(start),
			})
			return gc, nil

		case gateway.DecisionBlock:
			gc.Blocked = true
			gc.Reason = decision.Reason
			_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
				Timestamp:  time.Now().UTC(),
				Event:      "tool_blocked",
				ToolName:   gc.ToolName,
				RiskLevel:  risk.Level,
				Decision:   gateway.DecisionBlock,
				PolicyName: decision.PolicyName,
				Latency:    time.Since(start),
				Error:      decision.Reason,
			})
			return gc, nil

		case gateway.DecisionInterruptForApproval:
			// Build the state to persist across the interrupt.
			interruptState := &toolCallState{
				ToolName: gc.ToolName,
				Args:     gc.Args,
				Risk:     risk,
				Findings: findings,
				Decision: *decision,
			}
			// Interrupt the graph — execution pauses here.
			return nil, compose.StatefulInterrupt(ctx,
				map[string]any{
					"tool_name":  gc.ToolName,
					"args":       gc.Args,
					"risk_level": string(risk.Level),
					"reason":     decision.Reason,
					"timeout":    decision.Timeout,
				},
				interruptState,
			)

		default:
			gc.Blocked = true
			gc.Reason = fmt.Sprintf("unknown decision %q (default-deny)", decision.Decision)
			return gc, nil
		}
	})

	if err := g.AddLambdaNode("inspect_tool_call", inspectCallLambda, compose.WithNodeName("inspect_tool_call")); err != nil {
		return nil, fmt.Errorf("adapter/eino: add inspect_tool_call node: %w", err)
	}

	// -----------------------------------------------------------------------
	// Node: run_tool
	//
	// Executes the actual tool via ToolInvoker with (possibly redacted) args.
	// -----------------------------------------------------------------------
	runToolLambda := compose.InvokableLambda(func(ctx context.Context, input *gateway.GatewayContext) (*gateway.GatewayContext, error) {
		gc := input
		if gc == nil {
			return nil, fmt.Errorf("adapter/eino: run_tool received nil input")
		}

		result, err := cfg.ToolInvoker.Invoke(ctx, gc.ToolName, gc.Args)
		if err != nil {
			return nil, fmt.Errorf("adapter/eino: tool %q invocation failed: %w", gc.ToolName, err)
		}

		gc.RawResult = result
		return gc, nil
	})

	if err := g.AddLambdaNode("run_tool", runToolLambda, compose.WithNodeName("run_tool")); err != nil {
		return nil, fmt.Errorf("adapter/eino: add run_tool node: %w", err)
	}

	// -----------------------------------------------------------------------
	// Node: inspect_tool_response
	//
	// Scans the tool response for sensitive data and redacts if needed.
	// Logs the tool_end audit entry.
	// -----------------------------------------------------------------------
	inspectResponseLambda := compose.InvokableLambda(func(ctx context.Context, input *gateway.GatewayContext) (*gateway.GatewayContext, error) {
		gc := input
		if gc == nil {
			return nil, fmt.Errorf("adapter/eino: inspect_tool_response received nil input")
		}

		// DLP scan the response.
		findings, err := cfg.DLPScanner.Scan(ctx, gc.RawResult)
		if err != nil {
			// Don't block — the tool already ran. Return raw result and log the error.
			gc.Result = gc.RawResult
			_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
				Timestamp: time.Now().UTC(),
				Event:     "tool_end",
				ToolName:  gc.ToolName,
				Error:     fmt.Sprintf("response DLP scan failed: %v", err),
			})
			return gc, nil
		}

		if len(findings) > 0 {
			gc.Result = cfg.Redactor.Redact(gc.RawResult, findings)
			gc.Redacted = true
			// Record response DLP findings to metrics.
			if cfg.MetricsRecorder != nil {
				for _, f := range findings {
					cfg.MetricsRecorder.RecordDLPFinding(ctx, f)
				}
			}
		} else {
			gc.Result = gc.RawResult
		}

		// Audit log: tool_end.
		riskLevel := gateway.RiskLow
		if gc.Risk != nil {
			riskLevel = gc.Risk.Level
		}
		decision := gateway.DecisionAllow
		if gc.Decision != nil {
			decision = gc.Decision.Decision
		}

		_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_end",
			ToolName:  gc.ToolName,
			RiskLevel: riskLevel,
			Decision:  decision,
			Args:      gc.Args,
			Result:    gc.Result,
		})

		return gc, nil
	})

	if err := g.AddLambdaNode("inspect_tool_response", inspectResponseLambda, compose.WithNodeName("inspect_tool_response")); err != nil {
		return nil, fmt.Errorf("adapter/eino: add inspect_tool_response node: %w", err)
	}

	// -----------------------------------------------------------------------
	// Edges
	// -----------------------------------------------------------------------
	if err := g.AddEdge(compose.START, "inspect_tool_call"); err != nil {
		return nil, fmt.Errorf("adapter/eino: add START -> inspect_tool_call edge: %w", err)
	}
	if err := g.AddEdge("run_tool", "inspect_tool_response"); err != nil {
		return nil, fmt.Errorf("adapter/eino: add run_tool -> inspect_tool_response edge: %w", err)
	}
	if err := g.AddEdge("inspect_tool_response", compose.END); err != nil {
		return nil, fmt.Errorf("adapter/eino: add inspect_tool_response -> END edge: %w", err)
	}

	// Branch: blocked calls go directly to END.
	if err := g.AddBranch("inspect_tool_call",
		compose.NewGraphBranch(
			func(_ context.Context, gc *gateway.GatewayContext) (string, error) {
				if gc.Blocked {
					return compose.END, nil
				}
				return "run_tool", nil
			},
			map[string]bool{"run_tool": true, compose.END: true},
		),
	); err != nil {
		return nil, fmt.Errorf("adapter/eino: add inspect_tool_call branch: %w", err)
	}

	return &graphPipeline{
		graph:    g,
		cfg:      cfg,
		store:    store,
		registry: registry,
	}, nil
}

// ---------------------------------------------------------------------------
// Resume helper (package-level function, called from inspect_tool_call lambda)
// ---------------------------------------------------------------------------

// inspectResume handles the resume path when inspect_tool_call was interrupted.
func inspectResume(ctx context.Context, gc *gateway.GatewayContext, state *toolCallState, cfg *gateway.GatewayConfig, start time.Time) (*gateway.GatewayContext, error) {
	// Restore context from saved state.
	gc.ToolName = state.ToolName
	gc.Args = state.Args
	gc.Risk = &state.Risk
	gc.Findings = state.Findings
	gc.Decision = &state.Decision

	// Read the approval decision from the human.
	isResume, hasData, decision := compose.GetResumeContext[*gateway.ApprovalDecision](ctx)
	if !isResume {
		// Not targeted for this interrupt — re-interrupt to preserve state.
		return nil, compose.StatefulInterrupt(ctx,
			map[string]any{
				"tool_name":  state.ToolName,
				"args":       state.Args,
				"risk_level": string(state.Risk.Level),
				"reason":     state.Decision.Reason,
				"timeout":    state.Decision.Timeout,
			},
			state,
		)
	}

	if !hasData || decision == nil {
		// No data — treat as deny (default-deny).
		gc.Blocked = true
		gc.Reason = "no approval data received (default-deny)"
		gc.Decision = &gateway.DecisionResult{
			Decision:  gateway.DecisionBlock,
			RiskLevel: state.Risk.Level,
			Reason:    gc.Reason,
		}
		_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_blocked",
			ToolName:  gc.ToolName,
			RiskLevel: state.Risk.Level,
			Decision:  gateway.DecisionBlock,
			Latency:   time.Since(start),
			Error:     gc.Reason,
		})
		return gc, nil
	}

	switch decision.Action {
	case gateway.ApprovalApprove:
		gc.Decision = &gateway.DecisionResult{
			Decision:  gateway.DecisionAllow,
			RiskLevel: state.Risk.Level,
			Reason:    "approved by human: " + decision.Reason,
		}
		_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_start",
			ToolName:  gc.ToolName,
			RiskLevel: state.Risk.Level,
			Decision:  gateway.DecisionAllow,
			Latency:   time.Since(start),
		})
		return gc, nil

	case gateway.ApprovalDeny:
		gc.Blocked = true
		gc.Reason = "denied by human: " + decision.Reason
		gc.Decision = &gateway.DecisionResult{
			Decision:  gateway.DecisionBlock,
			RiskLevel: state.Risk.Level,
			Reason:    gc.Reason,
		}
		_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_blocked",
			ToolName:  gc.ToolName,
			RiskLevel: state.Risk.Level,
			Decision:  gateway.DecisionBlock,
			Latency:   time.Since(start),
			Error:     gc.Reason,
		})
		return gc, nil

	case gateway.ApprovalModify:
		if len(decision.ModifiedArgs) > 0 {
			gc.Args = decision.ModifiedArgs
		}
		gc.Decision = &gateway.DecisionResult{
			Decision:  gateway.DecisionAllow,
			RiskLevel: state.Risk.Level,
			Reason:    "modified and approved by human: " + decision.Reason,
		}
		_ = cfg.AuditEmitter.Emit(ctx, gateway.AuditEvent{
			Timestamp: time.Now().UTC(),
			Event:     "tool_start",
			ToolName:  gc.ToolName,
			RiskLevel: state.Risk.Level,
			Decision:  gateway.DecisionAllow,
			Args:      gc.Args,
			Latency:   time.Since(start),
		})
		return gc, nil

	default:
		gc.Blocked = true
		gc.Reason = fmt.Sprintf("unknown approval action %q (default-deny)", decision.Action)
		gc.Decision = &gateway.DecisionResult{
			Decision:  gateway.DecisionBlock,
			RiskLevel: state.Risk.Level,
			Reason:    gc.Reason,
		}
		return gc, nil
	}
}
