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
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Failure injection stubs for NFR-07 graceful degradation tests
// ---------------------------------------------------------------------------

// errorPolicy always returns an error from Decide.
type errorPolicy struct{ err error }

func (p *errorPolicy) Decide(_ context.Context, _ gateway.ToolCallContext) (*gateway.DecisionResult, error) {
	return nil, p.err
}

// errorDLPScanner always returns an error from Scan.
type errorDLPScanner struct{ err error }

func (s *errorDLPScanner) Scan(_ context.Context, _ string) ([]gateway.DLPFinding, error) {
	return nil, s.err
}

// panicPolicy panics inside Decide.
type panicPolicy struct{}

func (p *panicPolicy) Decide(_ context.Context, _ gateway.ToolCallContext) (*gateway.DecisionResult, error) {
	panic("policy panic: simulated unrecoverable error")
}

// panicDLPScanner panics inside Scan.
type panicDLPScanner struct{}

func (s *panicDLPScanner) Scan(_ context.Context, _ string) ([]gateway.DLPFinding, error) {
	panic("DLP scanner panic: simulated unrecoverable error")
}

// errorInvoker always returns an error from Invoke.
type errorInvoker struct{ err error }

func (i *errorInvoker) Invoke(_ context.Context, toolName string, _ map[string]any) (string, error) {
	return "", fmt.Errorf("tool %q invocation failed: %w", toolName, i.err)
}

// degradationConfig builds a GatewayConfig with the given failure injection.
// All other fields are valid defaults from testConfig.
func degradationConfig(
	policy gateway.Policy,
	scanner gateway.DLPScanner,
	invoker gateway.ToolInvoker,
) *gateway.GatewayConfig {
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message": {Level: gateway.RiskLow},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	if policy == nil {
		policy = gateway.NewDefaultPolicy()
	}
	if scanner == nil {
		scanner = mustNewScanner()
	}
	if invoker == nil {
		invoker = &recordingInvoker{}
	}

	return &gateway.GatewayConfig{
		Policy:           policy,
		RiskDB:           riskDB,
		DLPScanner:       scanner,
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(io.Discard),
		ApprovalProvider: gateway.NewCLIApprovalProvider(),
		ToolInvoker:      invoker,
		RedactionMask:    "***",
	}
}

// ---------------------------------------------------------------------------
// Tests: NFR-07 default-deny on failures
// ---------------------------------------------------------------------------

// TestDegradation_PolicyError_DefaultDeny validates that when Policy.Decide
// returns an error, the pipeline blocks the call (default-deny NFR-07).
func TestDegradation_PolicyError_DefaultDeny(t *testing.T) {
	cfg := degradationConfig(
		&errorPolicy{err: fmt.Errorf("policy engine unavailable")},
		nil, // use default scanner
		nil, // use default invoker
	)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
	if err == nil {
		t.Fatal("expected error when policy fails (default-deny), got nil")
	}

	// Error must indicate the call was blocked.
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should mention 'blocked', got: %v", err)
	}

	// Error should mention NFR-07 default-deny.
	if !strings.Contains(err.Error(), "default-deny") {
		t.Errorf("error should mention 'default-deny', got: %v", err)
	}
}

// TestDegradation_DLPScannerError_DefaultDeny validates that when DLPScanner.Scan
// returns an error, the pipeline blocks the call (default-deny NFR-07).
func TestDegradation_DLPScannerError_DefaultDeny(t *testing.T) {
	cfg := degradationConfig(
		nil, // use default policy
		&errorDLPScanner{err: fmt.Errorf("DLP service timeout")},
		nil, // use default invoker
	)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
	if err == nil {
		t.Fatal("expected error when DLP scanner fails (default-deny), got nil")
	}

	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("error should mention 'blocked', got: %v", err)
	}

	if !strings.Contains(err.Error(), "default-deny") {
		t.Errorf("error should mention 'default-deny', got: %v", err)
	}
}

// TestDegradation_PolicyPanic_DefaultDeny validates that when Policy.Decide panics,
// the pipeline does not hang — it recovers and returns an error.
func TestDegradation_PolicyPanic_DefaultDeny(t *testing.T) {
	cfg := degradationConfig(
		&panicPolicy{},
		nil, // use default scanner
		nil, // use default invoker
	)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	// The panic in Policy.Decide will propagate through the Eino graph.
	// The pipeline should NOT hang — it should return an error.
	done := make(chan error, 1)
	go func() {
		_, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
		done <- err
	}()

	select {
	case err := <-done:
		// Pipeline returned (didn't hang). Any error is acceptable here —
		// the key assertion is that we didn't deadlock.
		if err == nil {
			t.Error("expected error when policy panics, got nil — call should not succeed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline hung when policy panicked — NFR-07 violated")
	}
}

// TestDegradation_DLPScannerPanic_DefaultDeny validates that when DLPScanner.Scan
// panics, the pipeline does not hang — it recovers and returns an error.
func TestDegradation_DLPScannerPanic_DefaultDeny(t *testing.T) {
	cfg := degradationConfig(
		nil, // use default policy
		&panicDLPScanner{},
		nil, // use default invoker
	)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("expected error when DLP scanner panics, got nil — call should not succeed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline hung when DLP scanner panicked — NFR-07 violated")
	}
}

// TestDegradation_InvokerError_ReturnsError validates that when ToolInvoker.Invoke
// returns an error, the pipeline propagates it (tool execution failure, not default-deny).
func TestDegradation_InvokerError_ReturnsError(t *testing.T) {
	cfg := degradationConfig(
		nil, // use default policy
		nil, // use default scanner
		&errorInvoker{err: fmt.Errorf("tool crashed")},
	)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	_, err = pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
	if err == nil {
		t.Fatal("expected error when invoker fails, got nil")
	}

	// Invoker error is a tool execution failure, not a block.
	if !strings.Contains(err.Error(), "invocation failed") {
		t.Errorf("error should mention 'invocation failed', got: %v", err)
	}
}
