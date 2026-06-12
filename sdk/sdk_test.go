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

package sdk

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// captureAudit records emitted events for assertions.
type captureAudit struct {
	mu     sync.Mutex
	events []gateway.AuditEvent
}

func (c *captureAudit) Emit(_ context.Context, e gateway.AuditEvent) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, e)
	return nil
}

func (c *captureAudit) snapshot() []gateway.AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]gateway.AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

func (c *captureAudit) hasDecision(d gateway.Decision) bool {
	for _, e := range c.snapshot() {
		if e.Decision == d {
			return true
		}
	}
	return false
}

func TestBuilder_RequiresInvoker(t *testing.T) {
	if _, err := New(nil).Build(); err == nil {
		t.Fatal("expected error when invoker is nil")
	}
}

func TestBuilder_DefaultLow_AllowsAndDoesNotRedact(t *testing.T) {
	var seen map[string]any
	invoker := NewFuncInvoker().Register("lookup", func(_ context.Context, args map[string]any) (string, error) {
		seen = args
		return "done", nil
	})
	audit := &captureAudit{}

	p, err := New(invoker).WithAuditEmitter(audit).WithRedactionMask("[MASK]").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := p.Run(context.Background(), "lookup", map[string]any{"ssn": "123-45-6789"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// 'lookup' is unknown to the risk DB → default low → allow → value untouched.
	if seen["ssn"] != "123-45-6789" {
		t.Errorf("default low should pass args through, got ssn=%v", seen["ssn"])
	}
	if !audit.hasDecision(gateway.DecisionAllow) {
		t.Error("expected an allow decision in the audit trail")
	}
}

func TestBuilder_StrictDefaults_RedactsUnknownToolSecret(t *testing.T) {
	var seen map[string]any
	invoker := NewFuncInvoker().Register("lookup", func(_ context.Context, args map[string]any) (string, error) {
		seen = args
		return "done", nil
	})
	audit := &captureAudit{}

	p, err := New(invoker).StrictDefaults().WithAuditEmitter(audit).WithRedactionMask("[MASK]").Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := p.Run(context.Background(), "lookup", map[string]any{
		"ssn":  "123-45-6789",
		"name": "alice",
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// StrictDefaults → default medium → redact: sensitive field masked, clean
	// field untouched. This is the proof the redact posture is real, not just a
	// label in the audit trail.
	if seen["ssn"] != "[MASK]" {
		t.Errorf("expected ssn masked under StrictDefaults, got %v", seen["ssn"])
	}
	if seen["name"] != "alice" {
		t.Errorf("expected clean 'name' to pass through, got %v", seen["name"])
	}
	if !audit.hasDecision(gateway.DecisionRedact) {
		t.Error("expected a redact decision in the audit trail")
	}
}

func TestBuilder_StrictDefaults_EqualsMediumDefaultRisk(t *testing.T) {
	// StrictDefaults() is documented as shorthand for WithDefaultRisk(RiskMedium).
	b1 := New(nilFuncInvoker()).StrictDefaults()
	b2 := New(nilFuncInvoker()).WithDefaultRisk(gateway.RiskMedium)
	if b1.defaultRisk.Level != b2.defaultRisk.Level {
		t.Errorf("StrictDefaults level=%s, WithDefaultRisk(Medium) level=%s", b1.defaultRisk.Level, b2.defaultRisk.Level)
	}
	if b1.defaultRisk.Level != gateway.RiskMedium {
		t.Errorf("expected medium, got %s", b1.defaultRisk.Level)
	}
}

func TestBuilder_ResponseRedaction(t *testing.T) {
	invoker := NewFuncInvoker().Register("fetch", func(_ context.Context, _ map[string]any) (string, error) {
		return "key=-----BEGIN RSA PRIVATE KEY-----\nleaked\n-----END PRIVATE KEY-----", nil
	})
	p, err := New(invoker).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	res, err := p.Run(context.Background(), "fetch", nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if strings.Contains(res, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("expected private key redacted in response, got: %s", res)
	}
	if !strings.Contains(res, "***REDACTED***") {
		t.Errorf("expected default redaction mask in response, got: %s", res)
	}
}

func TestBuilder_HighRisk_InterruptAndApprove(t *testing.T) {
	var ran bool
	invoker := NewFuncInvoker().Register("exec", func(_ context.Context, args map[string]any) (string, error) {
		ran = true
		return "ran " + args["cmd"].(string), nil
	})
	p, err := New(invoker).WithRisk("exec", gateway.RiskHigh).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	_, err = p.Run(context.Background(), "exec", map[string]any{"cmd": "rm -rf /tmp"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got: %v", err)
	}
	if ran {
		t.Error("tool must not run before approval")
	}

	res, err := p.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "approved in test",
	})
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if !ran {
		t.Error("tool should have run after approval")
	}
	if !strings.Contains(res, "ran ") {
		t.Errorf("expected tool output after approval, got: %s", res)
	}
}

func TestFuncInvoker_UnknownTool(t *testing.T) {
	p, err := New(NewFuncInvoker()).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, err = p.Run(context.Background(), "nope", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("expected unknown-tool error, got: %v", err)
	}
}

func TestDefaults_ConstructorsDoNotPanic(t *testing.T) {
	if _, err := BuiltinDLP(); err != nil {
		t.Errorf("BuiltinDLP: %v", err)
	}
	if StdoutAudit() == nil {
		t.Error("StdoutAudit returned nil")
	}
	if CLIApproval() == nil {
		t.Error("CLIApproval returned nil")
	}
	if WebhookApproval("https://example.com/hook", "https://example.com/resume") == nil {
		t.Error("WebhookApproval returned nil")
	}
}

// nilFuncInvoker returns a no-op invoker for builder-state assertions that never
// actually run the pipeline.
func nilFuncInvoker() *FuncInvoker {
	return NewFuncInvoker().Register("_", func(context.Context, map[string]any) (string, error) {
		return "", nil
	})
}
