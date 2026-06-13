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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	"github.com/technosiveuk-ui/sentinelmcp/adapter/sidecar"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Sidecar E2E test infrastructure
// ---------------------------------------------------------------------------

// testUpstreamTools creates tool metadata for testing without a real server.
func testUpstreamTools() []sidecar.ToolMeta {
	return []sidecar.ToolMeta{
		{
			Name:        "echo_message",
			Description: "Echo back a message",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{"msg": map[string]any{"type": "string"}},
			},
		},
		{
			Name:        "filesystem_read",
			Description: "Read a file (may contain secrets)",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{"path": map[string]any{"type": "string"}},
			},
		},
		{
			Name:        "exec_command",
			Description: "Execute a command",
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{"cmd": map[string]any{"type": "string"}},
			},
		},
	}
}

// echoInvoker returns results that echo back the tool name.
type echoInvoker struct{}

func (e *echoInvoker) Invoke(_ context.Context, toolName string, args map[string]any) (string, error) {
	return fmt.Sprintf("result-from-%s", toolName), nil
}

// sensitiveInvoker returns a result containing DLP-triggering content.
type sensitiveInvoker struct{}

func (s *sensitiveInvoker) Invoke(_ context.Context, _ string, _ map[string]any) (string, error) {
	return "config: password=supersecret123 host=db.local", nil
}

// testPipeline creates a fully-wired pipeline (risk-based DefaultPolicy) for
// sidecar E2E tests.
func testPipeline(invoker gateway.ToolInvoker) (gateway.Pipeline, *bytes.Buffer) {
	return testPipelineWithPolicy(invoker, gateway.NewDefaultPolicy())
}

// testPipelineWithPolicy builds a fully-wired pipeline with a custom Policy,
// used to exercise action-based PolicySet enforcement. Returns the pipeline and
// the buffer capturing its JSON audit stream.
func testPipelineWithPolicy(invoker gateway.ToolInvoker, policy gateway.Policy) (gateway.Pipeline, *bytes.Buffer) {
	var auditBuf bytes.Buffer

	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true, ApprovalReason: "dangerous command"},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	scanner, err := gateway.NewRegexDLPScanner(gateway.BuiltinPatterns())
	if err != nil {
		panic(err)
	}

	cfg := &gateway.GatewayConfig{
		Policy:           policy,
		RiskDB:           riskDB,
		DLPScanner:       scanner,
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(&auditBuf),
		ApprovalProvider: gateway.NewCLIApprovalProvider(),
		ToolInvoker:      invoker,
		RedactionMask:    "***",
	}

	pipeline, err := eino.BuildGraph(cfg)
	if err != nil {
		panic(err)
	}
	return pipeline, &auditBuf
}

// ---------------------------------------------------------------------------
// Tests: Sidecar E2E
// ---------------------------------------------------------------------------

// TestSidecar_LowRisk_Allow tests the full MCP proxy path for a low-risk tool.
func TestSidecar_LowRisk_Allow(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)

	// Simulate an MCP call through the proxy handler.
	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "echo_message",
			Arguments: map[string]any{"msg": "hello sidecar"},
		},
	}

	result, err := proxy.handleToolCall(context.Background(), "echo_message", req)
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}

	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	text := contentText(result)
	if !strings.Contains(text, "echo_message") {
		t.Errorf("expected result to contain 'echo_message', got: %s", text)
	}
}

// TestSidecar_ActionPolicy_BlocksAndAudits: an action-based PolicySet overrides
// the risk model — a normally low-risk tool is blocked by an explicit BLOCK rule,
// and the firing policy name is surfaced in the audit stream.
func TestSidecar_ActionPolicy_BlocksAndAudits(t *testing.T) {
	policy := gateway.NewPolicySet([]gateway.PolicyRule{
		{Name: "block-echo", Tools: []string{"echo_*"}, Action: gateway.DecisionBlock},
	}, gateway.NewDefaultPolicy()) // fallback for non-echo tools

	pipeline, auditBuf := testPipelineWithPolicy(&echoInvoker{}, policy)
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "echo_message",
			Arguments: map[string]any{"msg": "hello"},
		},
	}
	result, err := proxy.handleToolCall(context.Background(), "echo_message", req)
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}
	if !result.IsError {
		t.Fatal("action-based block-echo policy should block the (low-risk) echo_message call")
	}
	audit := auditBuf.String()
	if !strings.Contains(audit, "block-echo") {
		t.Fatalf("audit should record the firing action policy name, got: %s", audit)
	}
}

// TestSidecar_MediumRisk_RedactsResponse tests that medium-risk tool responses
// are DLP-scanned and redacted in the proxy path.
func TestSidecar_MediumRisk_RedactsResponse(t *testing.T) {
	pipeline, _ := testPipeline(&sensitiveInvoker{})
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "filesystem_read",
			Arguments: map[string]any{"path": "/etc/shadow"},
		},
	}

	result, err := proxy.handleToolCall(context.Background(), "filesystem_read", req)
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}

	text := contentText(result)
	// The password should be redacted by DLP scanning on the response.
	if strings.Contains(text, "supersecret123") {
		t.Errorf("expected DLP redaction of password, got: %s", text)
	}
	if !strings.Contains(text, "***") {
		t.Errorf("expected redaction mask in response, got: %s", text)
	}
}

// TestSidecar_HighRisk_InterruptAndResume tests the full interrupt→resume cycle
// through the proxy and admin server.
func TestSidecar_HighRisk_InterruptAndResume(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)

	// Step 1: Call high-risk tool → should return interrupt message.
	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "exec_command",
			Arguments: map[string]any{"cmd": "rm -rf /tmp"},
		},
	}

	result, err := proxy.handleToolCall(context.Background(), "exec_command", req)
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}

	if !result.IsError {
		t.Fatal("expected error result for high-risk interrupt")
	}

	text := contentText(result)
	if !strings.Contains(text, "human approval") {
		t.Errorf("expected interrupt message, got: %s", text)
	}

	// Extract interrupt ID and checkpoint ID from the message.
	// Message format: "...Interrupt ID: <id>, Checkpoint: <cp>"
	interruptID, checkpointID := extractInterruptIDs(text)
	if interruptID == "" || checkpointID == "" {
		t.Fatalf("could not extract interrupt IDs from: %s", text)
	}

	// Step 2: Resume via admin server.
	admin := NewAdminServer("127.0.0.1:0", pipeline, WithAdminToken("test-token"))
	admin.SetReady(true)

	resumeBody := fmt.Sprintf(`{"interrupt_id":"%s","checkpoint_id":"%s","action":"approve","reason":"test approval"}`,
		interruptID, checkpointID)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/approval/resume", strings.NewReader(resumeBody))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()

	admin.handleResume(w, httpReq)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("resume returned %d: %s", resp.StatusCode, body)
	}

	var resumeResp map[string]string
	if err := json.Unmarshal(body, &resumeResp); err != nil {
		t.Fatalf("unmarshal resume response: %v", err)
	}

	if resumeResp["status"] != "completed" {
		t.Errorf("expected status=completed, got: %s", resumeResp["status"])
	}
}

// TestSidecar_Blocked_HighRiskDeny tests that denying an interrupt blocks the tool call.
func TestSidecar_Blocked_HighRiskDeny(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "exec_command",
			Arguments: map[string]any{"cmd": "rm -rf /"},
		},
	}

	result, _ := proxy.handleToolCall(context.Background(), "exec_command", req)
	if !result.IsError {
		t.Fatal("expected error for high-risk tool")
	}

	text := contentText(result)
	interruptID, checkpointID := extractInterruptIDs(text)
	if interruptID == "" {
		t.Fatal("could not extract interrupt ID")
	}

	// Resume with deny.
	admin := NewAdminServer("127.0.0.1:0", pipeline, WithAdminToken("test-token"))
	admin.SetReady(true)

	resumeBody := fmt.Sprintf(`{"interrupt_id":"%s","checkpoint_id":"%s","action":"deny","reason":"too dangerous"}`,
		interruptID, checkpointID)

	httpReq := httptest.NewRequest(http.MethodPost, "/api/v1/approval/resume", strings.NewReader(resumeBody))
	httpReq.Header.Set("Authorization", "Bearer test-token")
	w := httptest.NewRecorder()
	admin.handleResume(w, httpReq)

	resp := w.Result()
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-200 for denied approval")
	}
}

// TestSidecar_HealthEndpoints tests /healthz and /readyz.
func TestSidecar_HealthEndpoints(t *testing.T) {
	admin := NewAdminServer("127.0.0.1:0", nil)

	// Not ready initially.
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()
	admin.handleReadyz(w, req)
	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Error("expected 503 when not ready")
	}

	// Set ready.
	admin.SetReady(true)
	w = httptest.NewRecorder()
	admin.handleReadyz(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected 200 when ready")
	}

	// Healthz always returns 200.
	w = httptest.NewRecorder()
	admin.handleHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Result().StatusCode != http.StatusOK {
		t.Error("expected 200 for healthz")
	}
}

// TestSidecar_ResumeAPI_Validation tests the resume API input validation.
func TestSidecar_ResumeAPI_Validation(t *testing.T) {
	// Need a real pipeline so handleResume gets past the nil check.
	pipeline, _ := testPipeline(&echoInvoker{})
	admin := NewAdminServer("127.0.0.1:0", pipeline, WithAdminToken("test-token"))
	admin.SetReady(true)

	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
	}{
		{"wrong method", http.MethodGet, "", http.StatusMethodNotAllowed},
		{"invalid JSON", http.MethodPost, "{bad", http.StatusBadRequest},
		{"invalid action", http.MethodPost, `{"interrupt_id":"x","checkpoint_id":"y","action":"explode"}`, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}
			req := httptest.NewRequest(tt.method, "/api/v1/approval/resume", body)
			req.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()
			admin.handleResume(w, req)

			if w.Result().StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, w.Result().StatusCode)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tests: Admin server security (transport-security hardening, Step 1)
// ---------------------------------------------------------------------------

// TestAdmin_Resume_RequiresToken verifies the resume endpoint is gated by the admin token.
func TestAdmin_Resume_RequiresToken(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})
	admin := NewAdminServer("127.0.0.1:0", pipeline, WithAdminToken("secret"))

	// Create a real interrupt to resume, so a valid token reaches a real decision.
	proxy := NewProxy(pipeline, sidecar.Catalog{Tools: testUpstreamTools()}, nil)
	res, err := proxy.handleToolCall(context.Background(), "exec_command",
		mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "exec_command", Arguments: map[string]any{"cmd": "rm -rf /tmp"}}})
	if err != nil {
		t.Fatalf("handleToolCall: %v", err)
	}
	interruptID, checkpointID := extractInterruptIDs(contentText(res))

	cases := []struct {
		name       string
		authHeader string
		want       int
	}{
		{"no token", "", http.StatusUnauthorized},
		{"wrong token", "Bearer nope", http.StatusUnauthorized},
		{"correct token", "Bearer secret", http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Use "approve" so a valid token reaches the authorized success path
			// (200). The deny path (non-200) is covered by TestSidecar_Blocked_HighRiskDeny.
			body := fmt.Sprintf(`{"interrupt_id":"%s","checkpoint_id":"%s","action":"approve","reason":"x"}`,
				interruptID, checkpointID)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/approval/resume", strings.NewReader(body))
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			w := httptest.NewRecorder()
			admin.handleResume(w, req)
			if w.Result().StatusCode != tc.want {
				t.Errorf("got %d, want %d", w.Result().StatusCode, tc.want)
			}
		})
	}
}

// TestAdmin_Resume_DisabledWithoutToken verifies resume is disabled (401) when no token is configured.
func TestAdmin_Resume_DisabledWithoutToken(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})
	admin := NewAdminServer("127.0.0.1:0", pipeline) // no token configured

	req := httptest.NewRequest(http.MethodPost, "/api/v1/approval/resume", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	admin.handleResume(w, req)

	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 (resume disabled without configured token), got %d", w.Result().StatusCode)
	}
}

// TestAdmin_ValidateBind verifies the admin bind policy.
func TestAdmin_ValidateBind(t *testing.T) {
	pipeline, _ := testPipeline(&echoInvoker{})

	cases := []struct {
		addr         string
		token        string
		allowNonLoop bool
		wantErr      bool
	}{
		{"127.0.0.1:9090", "", false, false}, // IPv4 loopback: token optional
		{"localhost:9090", "", false, false}, // localhost: token optional
		{"[::1]:9090", "", false, false},     // IPv6 loopback: token optional
		{"0.0.0.0:9090", "", false, true},    // non-loopback, no flag: refuse
		{"0.0.0.0:9090", "", true, true},     // non-loopback, flag, no token: refuse
		{"0.0.0.0:9090", "tok", true, false}, // non-loopback, flag, token: ok
		{":9090", "", false, true},           // wildcard: non-loopback, no flag: refuse
		{":9090", "tok", true, false},        // wildcard, flag, token: ok
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			admin := NewAdminServer(tc.addr, pipeline, WithAdminToken(tc.token))
			err := admin.ValidateBind(tc.allowNonLoop)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// contentText extracts the text content from an MCP result.
func contentText(result *mcp.CallToolResult) string {
	var parts []string
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

// extractInterruptIDs parses interrupt ID and checkpoint ID from the proxy message.
func extractInterruptIDs(text string) (string, string) {
	// Format: "...Interrupt ID: <uuid>, Checkpoint: <cp>. Use the resume API..."
	var interruptID, checkpointID string

	// Extract Interrupt ID.
	if idx := strings.Index(text, "Interrupt ID:"); idx >= 0 {
		rest := text[idx+len("Interrupt ID:"):]
		rest = strings.TrimSpace(rest)
		if comma := strings.Index(rest, ","); comma >= 0 {
			interruptID = strings.TrimSpace(rest[:comma])
		}
	}

	// Extract Checkpoint.
	if idx := strings.Index(text, "Checkpoint:"); idx >= 0 {
		rest := text[idx+len("Checkpoint:"):]
		rest = strings.TrimSpace(rest)
		// Take everything up to period or comma.
		for i, ch := range rest {
			if ch == '.' || ch == ',' {
				checkpointID = strings.TrimSpace(rest[:i])
				break
			}
		}
		if checkpointID == "" {
			checkpointID = rest
		}
	}

	return interruptID, checkpointID
}
