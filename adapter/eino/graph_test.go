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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// recordingInvoker captures tool calls for test assertions.
// Thread-safe: safe for concurrent use in load tests.
type recordingInvoker struct {
	mu    sync.Mutex
	calls []invokerCall
}

type invokerCall struct {
	toolName string
	args     map[string]any
}

func (r *recordingInvoker) Invoke(_ context.Context, toolName string, args map[string]any) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, invokerCall{toolName: toolName, args: args})
	return fmt.Sprintf("result[%s]", toolName), nil
}

// testConfig builds a fully-wired GatewayConfig for tests.
func testConfig(invoker gateway.ToolInvoker) (*gateway.GatewayConfig, *bytes.Buffer) {
	var auditBuf bytes.Buffer

	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true, ApprovalReason: "dangerous"},
			"db_*":            {Level: gateway.RiskHigh, RequireApproval: true},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	if invoker == nil {
		invoker = &recordingInvoker{}
	}

	cfg := &gateway.GatewayConfig{
		Policy:           gateway.NewDefaultPolicy(),
		RiskDB:           riskDB,
		DLPScanner:       mustNewScanner(),
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(&auditBuf),
		ApprovalProvider: gateway.NewCLIApprovalProvider(),
		ToolInvoker:      invoker,
		RedactionMask:    "***",
	}
	return cfg, &auditBuf
}

func mustNewScanner() *gateway.RegexDLPScanner {
	s, err := gateway.NewRegexDLPScanner(gateway.BuiltinPatterns())
	if err != nil {
		panic(err)
	}
	return s
}

// auditEvents parses audit log lines from the buffer.
func auditEvents(buf *bytes.Buffer) []gateway.AuditEvent {
	var entries []gateway.AuditEvent
	for _, line := range strings.Split(buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var entry gateway.AuditEvent
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		entries = append(entries, entry)
	}
	return entries
}

// ---------------------------------------------------------------------------
// Tests: Pipeline lifecycle
// ---------------------------------------------------------------------------

func TestBuildGraph_ValidatesConfig(t *testing.T) {
	_, err := BuildGraph(&gateway.GatewayConfig{}) // missing everything
	if err == nil {
		t.Fatal("expected validation error for empty config")
	}
}

func TestPipeline_LowRisk_Allow(t *testing.T) {
	cfg, auditBuf := testConfig(nil)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if !strings.Contains(result, "echo_message") {
		t.Errorf("expected result to contain tool name, got: %s", result)
	}

	// Verify audit trail: tool_start + tool_end
	events := auditEvents(auditBuf)
	if len(events) < 2 {
		t.Fatalf("expected at least 2 audit events, got %d", len(events))
	}
	if events[0].Event != "tool_start" {
		t.Errorf("first event should be tool_start, got %s", events[0].Event)
	}
	if events[1].Event != "tool_end" {
		t.Errorf("second event should be tool_end, got %s", events[1].Event)
	}
}

func TestPipeline_MediumRisk_Redact(t *testing.T) {
	invoker := &recordingInvoker{}
	cfg, auditBuf := testConfig(invoker)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "filesystem_read", map[string]any{
		"path": "/etc/hosts",
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if !strings.Contains(result, "filesystem_read") {
		t.Errorf("expected result to contain tool name, got: %s", result)
	}

	// Verify audit trail shows redact decision
	events := auditEvents(auditBuf)
	if len(events) == 0 {
		t.Fatal("expected audit events")
	}
	if events[0].Decision != gateway.DecisionRedact {
		t.Errorf("expected decision redact, got %s", events[0].Decision)
	}
}

func TestPipeline_HighRisk_InterruptAndApprove(t *testing.T) {
	invoker := &recordingInvoker{}
	cfg, _ := testConfig(invoker)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	// Run should interrupt for high-risk tool.
	result, err := pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "rm -rf /tmp"})
	if err == nil {
		t.Fatal("expected InterruptError for high-risk tool")
	}

	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got: %T: %v", err, err)
	}

	if ie.Info.ToolName != "exec_command" {
		t.Errorf("expected tool name exec_command, got %s", ie.Info.ToolName)
	}
	if ie.Info.RiskLevel != gateway.RiskHigh {
		t.Errorf("expected RiskHigh, got %s", ie.Info.RiskLevel)
	}
	if ie.Info.CheckpointID == "" {
		t.Error("expected non-empty checkpoint ID")
	}
	if ie.Info.ID == "" {
		t.Error("expected non-empty interrupt ID")
	}

	// The tool should NOT have been invoked (interrupt happened first).
	if len(invoker.calls) != 0 {
		t.Errorf("expected 0 tool invocations before approval, got %d", len(invoker.calls))
	}

	// Resume with approval.
	result, err = pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "test approval",
	})
	if err != nil {
		t.Fatalf("Resume error: %v", err)
	}

	if !strings.Contains(result, "exec_command") {
		t.Errorf("expected result to contain tool name after approval, got: %s", result)
	}

	// Now the tool should have been invoked exactly once.
	if len(invoker.calls) != 1 {
		t.Fatalf("expected 1 tool invocation after approval, got %d", len(invoker.calls))
	}
	if invoker.calls[0].toolName != "exec_command" {
		t.Errorf("expected invocation of exec_command, got %s", invoker.calls[0].toolName)
	}
}

func TestPipeline_HighRisk_InterruptAndDeny(t *testing.T) {
	invoker := &recordingInvoker{}
	cfg, _ := testConfig(invoker)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	// Run — expect interrupt.
	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "rm -rf /"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got: %v", err)
	}

	// Resume with denial.
	_, err = pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalDeny,
		Reason: "too dangerous",
	})
	if err == nil {
		t.Fatal("expected error for denied approval")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected blocked error, got: %v", err)
	}

	// Tool should NOT have been invoked.
	if len(invoker.calls) != 0 {
		t.Errorf("expected 0 tool invocations after deny, got %d", len(invoker.calls))
	}
}

func TestPipeline_HighRisk_InterruptAndModify(t *testing.T) {
	invoker := &recordingInvoker{}
	cfg, _ := testConfig(invoker)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	// Run — expect interrupt.
	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "rm -rf /data"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got: %v", err)
	}

	// Resume with modified args (safer command).
	result, err := pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action:       gateway.ApprovalModify,
		Reason:       "use safer command",
		ModifiedArgs: map[string]any{"cmd": "ls /data"},
	})
	if err != nil {
		t.Fatalf("Resume error: %v", err)
	}

	if !strings.Contains(result, "exec_command") {
		t.Errorf("expected result to contain tool name, got: %s", result)
	}

	// Tool should have been invoked with modified args.
	if len(invoker.calls) != 1 {
		t.Fatalf("expected 1 invocation, got %d", len(invoker.calls))
	}
	if invoker.calls[0].args["cmd"] != "ls /data" {
		t.Errorf("expected modified args, got: %v", invoker.calls[0].args)
	}
}

func TestPipeline_UnknownTool_DefaultsToLow(t *testing.T) {
	cfg, _ := testConfig(nil)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "unknown_tool", map[string]any{"x": 1})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	if !strings.Contains(result, "unknown_tool") {
		t.Errorf("expected result to contain tool name, got: %s", result)
	}
}

func TestPipeline_NilArgs_DefaultsToEmpty(t *testing.T) {
	cfg, _ := testConfig(nil)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "echo_message", nil)
	if err != nil {
		t.Fatalf("Run error for nil args: %v", err)
	}

	if !strings.Contains(result, "echo_message") {
		t.Errorf("expected result to contain tool name, got: %s", result)
	}
}

func TestPipeline_GlobRiskMatch(t *testing.T) {
	invoker := &recordingInvoker{}
	cfg, _ := testConfig(invoker)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	// db_query matches "db_*" glob → high risk → interrupt.
	_, err = pipeline.Run(context.Background(), "db_query", map[string]any{"sql": "SELECT 1"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError for db_query (glob match), got: %v", err)
	}

	if ie.Info.RiskLevel != gateway.RiskHigh {
		t.Errorf("expected RiskHigh for db_* glob match, got %s", ie.Info.RiskLevel)
	}
}

func TestPipeline_ResponseDLPRedaction(t *testing.T) {
	// Tool returns a response containing a private key pattern.
	sensitiveInvoker := &recordingInvoker{}
	cfg, _ := testConfig(sensitiveInvoker)

	// Override invoker to return sensitive content.
	cfg.ToolInvoker = &sensitiveResultInvoker{result: "key=-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----"}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "get-key"})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// The result should have the BEGIN PRIVATE KEY line redacted.
	// Note: the DLP regex only matches "-----BEGIN...PRIVATE KEY-----",
	// not the END line, so we check for that specific redaction.
	if strings.Contains(result, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("expected BEGIN PRIVATE KEY to be redacted in response, got: %s", result)
	}
	if !strings.Contains(result, "***") {
		t.Errorf("expected redaction mask in response, got: %s", result)
	}
}

// ---------------------------------------------------------------------------
// Additional test helpers
// ---------------------------------------------------------------------------

// sensitiveResultInvoker returns a fixed result (for testing response DLP).
type sensitiveResultInvoker struct {
	result string
}

func (s *sensitiveResultInvoker) Invoke(_ context.Context, toolName string, _ map[string]any) (string, error) {
	return s.result, nil
}

func TestPipeline_MultipleRunsAreIsolated(t *testing.T) {
	cfg, _ := testConfig(nil)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph error: %v", err)
	}

	// Run three different tools sequentially — each should be independent.
	_, err1 := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "a"})
	_, err2 := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "b"})
	_, err3 := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "c"})

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("expected all runs to succeed: %v %v %v", err1, err2, err3)
	}
}
