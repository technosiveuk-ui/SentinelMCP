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

package eino

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// timeoutTestPolicy always returns an INTERRUPT decision, optionally with a
// per-rule deadline. It isolates the approval-timeout wiring from the risk model.
type timeoutTestPolicy struct {
	timeout time.Duration
}

func (p *timeoutTestPolicy) Decide(context.Context, gateway.ToolCallContext) (*gateway.DecisionResult, error) {
	return &gateway.DecisionResult{
		Decision:  gateway.DecisionInterruptForApproval,
		RiskLevel: gateway.RiskHigh,
		Reason:    "test: requires approval",
		Timeout:   p.timeout,
	}, nil
}

// recordingEmitter is a concurrency-safe AuditEmitter. The approval-timeout
// callback runs in the registry's timer goroutine, so a plain bytes.Buffer would
// race with the test reading it; this locks around the slice.
type recordingEmitter struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
}

func (e *recordingEmitter) Emit(_ context.Context, ev gateway.AuditEvent) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.events = append(e.events, ev)
	return nil
}

func (e *recordingEmitter) hasApprovalTimeoutBlock() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.events {
		if ev.Event == "tool_blocked" && strings.Contains(ev.Error, "approval_timeout") {
			return true
		}
	}
	return false
}

func (e *recordingEmitter) snapshot() []gateway.AuditEvent {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]gateway.AuditEvent, len(e.events))
	copy(out, e.events)
	return out
}

func timeoutTestConfig(policy gateway.Policy, defaultTimeout time.Duration) (*gateway.GatewayConfig, *recordingEmitter) {
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"exec_command": {Level: gateway.RiskHigh, RequireApproval: true},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)
	emitter := &recordingEmitter{}
	return &gateway.GatewayConfig{
		Policy:                 policy,
		RiskDB:                 riskDB,
		DLPScanner:             mustNewScanner(),
		Redactor:               gateway.NewDefaultRedactor("***"),
		AuditEmitter:           emitter,
		ApprovalProvider:       gateway.NewCLIApprovalProvider(),
		ToolInvoker:            &recordingInvoker{},
		RedactionMask:          "***",
		ApprovalDefaultTimeout: defaultTimeout,
	}, emitter
}

// waitFor polls pred until it returns true or the deadline elapses.
func waitFor(t *testing.T, timeout time.Duration, desc string, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pred() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

// TestPipeline_ApprovalTimeout_PerRuleAutoBlocks: a policy rule with a short
// timeout drives auto-block through the full wiring (info map -> handleInterrupt
// -> registry -> onTimeout audit), and a subsequent late resume is rejected.
func TestPipeline_ApprovalTimeout_PerRuleAutoBlocks(t *testing.T) {
	cfg, emitter := timeoutTestConfig(&timeoutTestPolicy{timeout: 100 * time.Millisecond}, 0)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "rm -rf /"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got %T: %v", err, err)
	}

	// Do NOT resume — let the per-rule deadline elapse. Asserting it fires well
	// inside the 10m cap proves the per-rule timeout flowed through the info map.
	waitFor(t, 2*time.Second, "approval_timeout auto-block", emitter.hasApprovalTimeoutBlock)

	// Late resume must be rejected, not executed.
	_, err = pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "too late",
	})
	if !errors.Is(err, ErrCheckpointExpired) {
		t.Fatalf("late resume: want ErrCheckpointExpired, got %v", err)
	}
}

// TestPipeline_ApprovalTimeout_GlobalDefault: with no per-rule timeout, the
// global approval.default_timeout drives the auto-block.
func TestPipeline_ApprovalTimeout_GlobalDefault(t *testing.T) {
	cfg, emitter := timeoutTestConfig(&timeoutTestPolicy{timeout: 0}, 120*time.Millisecond)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "ls"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got %T: %v", err, err)
	}

	waitFor(t, 2*time.Second, "global-default auto-block", emitter.hasApprovalTimeoutBlock)

	if _, err := pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{Action: gateway.ApprovalApprove}); !errors.Is(err, ErrCheckpointExpired) {
		t.Fatalf("late resume: want ErrCheckpointExpired, got %v", err)
	}
}

// TestPipeline_ApprovalTimeout_NormalResumeCancelsTimer: a resume before the
// deadline must still succeed, and the timer must be cancelled so no spurious
// auto-block fires afterward (regression guard against the registry breaking the
// happy path or leaking a zombie timer).
func TestPipeline_ApprovalTimeout_NormalResumeCancelsTimer(t *testing.T) {
	cfg, emitter := timeoutTestConfig(&timeoutTestPolicy{timeout: 5 * time.Second}, 0)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "echo hi"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got %T: %v", err, err)
	}

	result, err := pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "ok",
	})
	if err != nil {
		t.Fatalf("resume before deadline should succeed, got %v", err)
	}
	if result != "result[exec_command]" {
		t.Fatalf("resume result: got %q, want result[exec_command]", result)
	}

	// The timer was cancelled on Claim — wait past a reasonable window and confirm
	// no spurious auto-block audit appeared.
	time.Sleep(250 * time.Millisecond)
	if emitter.hasApprovalTimeoutBlock() {
		before := len(emitter.snapshot())
		t.Fatalf("zombie timer: approval_timeout block emitted after a successful resume (events=%d)", before)
	}
}
