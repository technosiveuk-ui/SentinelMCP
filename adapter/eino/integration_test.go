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
	"testing"

	einomcp "github.com/cloudwego/eino-ext/components/tool/mcp"
	"github.com/cloudwego/eino/components/tool"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Integration test helpers: real MCP servers + in-process transport
// ---------------------------------------------------------------------------

// newTestEchoServer creates a minimal MCP server with one "echo_message" tool.
func newTestEchoServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("test-echo", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(mcp.NewTool("echo_message",
		mcp.WithDescription("Echo back a message"),
		mcp.WithString("msg", mcp.Required(), mcp.Description("Message")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		msg, _ := args["msg"].(string)
		return mcp.NewToolResultText(msg), nil
	})
	return srv
}

// newTestSensitiveServer returns a server whose tool response contains DLP-triggering content.
func newTestSensitiveServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("test-sensitive", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(mcp.NewTool("filesystem_read",
		mcp.WithDescription("Read a file (may contain secrets)"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return mcp.NewToolResultText("config: password=supersecret123 host=db.local"), nil
	})
	return srv
}

// newTestShellServer returns a server whose tool simulates command execution.
func newTestShellServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("test-shell", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(mcp.NewTool("exec_command",
		mcp.WithDescription("Execute a shell command"),
		mcp.WithString("cmd", mcp.Required(), mcp.Description("Command")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		cmd, _ := args["cmd"].(string)
		return mcp.NewToolResultText(fmt.Sprintf("executed: %s", cmd)), nil
	})
	return srv
}

// connectAndDiscover creates an in-process MCP client, initializes it,
// and discovers all tools from the given server.
func connectAndDiscover(ctx context.Context, srv *mcpserver.MCPServer) ([]tool.BaseTool, error) {
	cli, err := client.NewInProcessClient(srv)
	if err != nil {
		return nil, fmt.Errorf("in-process client: %w", err)
	}
	if err := cli.Start(ctx); err != nil {
		return nil, fmt.Errorf("start client: %w", err)
	}
	if _, err := cli.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "sentinelmcp-test",
				Version: "0.0.1",
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("initialize client: %w", err)
	}
	return einomcp.GetTools(ctx, &einomcp.Config{Cli: cli})
}

// integrationConfig builds a fully-wired GatewayConfig for integration tests.
// It uses real MCP tool discovery from the provided server.
func integrationConfig(srv *mcpserver.MCPServer) (*gateway.GatewayConfig, *bytes.Buffer, error) {
	ctx := context.Background()
	tools, err := connectAndDiscover(ctx, srv)
	if err != nil {
		return nil, nil, err
	}

	invoker, err := NewMCPToolInvoker(tools)
	if err != nil {
		return nil, nil, fmt.Errorf("create MCP tool invoker: %w", err)
	}

	var auditBuf bytes.Buffer
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true, ApprovalReason: "dangerous"},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

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
	return cfg, &auditBuf, nil
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

func TestIntegration_EchoServer_LowRisk_Allow(t *testing.T) {
	cfg, auditBuf, err := integrationConfig(newTestEchoServer())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello MCP"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The MCP tool result is JSON-wrapped: {"content":[{"type":"text","text":"hello MCP"}]}
	if !strings.Contains(result, "hello MCP") {
		t.Errorf("expected result to contain 'hello MCP', got: %s", result)
	}

	// Verify audit trail.
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

func TestIntegration_SensitiveServer_MediumRisk_RedactsResponse(t *testing.T) {
	cfg, _, err := integrationConfig(newTestSensitiveServer())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	result, err := pipeline.Run(context.Background(), "filesystem_read", map[string]any{"path": "/etc/hosts"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// The server returns "password=supersecret123" — DLP should redact the password.
	if strings.Contains(result, "supersecret123") {
		t.Errorf("expected password to be redacted in response, got: %s", result)
	}
	if !strings.Contains(result, "***") {
		t.Errorf("expected redaction mask in response, got: %s", result)
	}
}

func TestIntegration_ShellServer_HighRisk_InterruptAndApprove(t *testing.T) {
	cfg, _, err := integrationConfig(newTestShellServer())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	// Run should interrupt for the high-risk exec_command tool.
	_, err = pipeline.Run(context.Background(), "exec_command", map[string]any{"cmd": "rm -rf /tmp"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("expected InterruptError, got: %T: %v", err, err)
	}

	if ie.Info.ToolName != "exec_command" {
		t.Errorf("expected tool name exec_command, got %s", ie.Info.ToolName)
	}
	if ie.Info.CheckpointID == "" {
		t.Error("expected non-empty checkpoint ID")
	}

	// Resume with approval.
	result, err := pipeline.Resume(context.Background(), ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "integration test approve",
	})
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}

	// The shell server returns "executed: rm -rf /tmp".
	if !strings.Contains(result, "executed: rm -rf /tmp") {
		t.Errorf("expected tool result after approval, got: %s", result)
	}
}

func TestIntegration_ShellServer_HighRisk_InterruptAndDeny(t *testing.T) {
	cfg, _, err := integrationConfig(newTestShellServer())
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
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
}

func TestIntegration_MultiServer_AllFlows(t *testing.T) {
	// Create all 3 servers and combine their tools into one invoker.
	ctx := context.Background()

	echoTools, err := connectAndDiscover(ctx, newTestEchoServer())
	if err != nil {
		t.Fatalf("echo discover: %v", err)
	}
	shellTools, err := connectAndDiscover(ctx, newTestShellServer())
	if err != nil {
		t.Fatalf("shell discover: %v", err)
	}
	sensitiveTools, err := connectAndDiscover(ctx, newTestSensitiveServer())
	if err != nil {
		t.Fatalf("sensitive discover: %v", err)
	}

	allTools := append(echoTools, shellTools...)
	allTools = append(allTools, sensitiveTools...)

	invoker, err := NewMCPToolInvoker(allTools)
	if err != nil {
		t.Fatalf("create invoker: %v", err)
	}

	// Verify all 3 tools are registered.
	names := invoker.ToolNames()
	if len(names) != 3 {
		t.Errorf("expected 3 tools, got %d: %v", len(names), names)
	}

	// Build gateway with multi-server invoker.
	var auditBuf bytes.Buffer
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	gwCfg := &gateway.GatewayConfig{
		Policy:           gateway.NewDefaultPolicy(),
		RiskDB:           riskDB,
		DLPScanner:       mustNewScanner(),
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(&auditBuf),
		ApprovalProvider: gateway.NewCLIApprovalProvider(),
		ToolInvoker:      invoker,
		RedactionMask:    "***",
	}

	pipeline, err := BuildGraph(gwCfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	// Flow 1: Low risk — echo.
	r1, err := pipeline.Run(ctx, "echo_message", map[string]any{"msg": "multi"})
	if err != nil {
		t.Errorf("echo run: %v", err)
	}
	if !strings.Contains(r1, "multi") {
		t.Errorf("echo result missing 'multi': %s", r1)
	}

	// Flow 2: Medium risk — filesystem (DLP redaction).
	r2, err := pipeline.Run(ctx, "filesystem_read", map[string]any{"path": "/x"})
	if err != nil {
		t.Errorf("fs run: %v", err)
	}
	if strings.Contains(r2, "supersecret123") {
		t.Errorf("fs result should have redacted password: %s", r2)
	}

	// Flow 3: High risk — exec (interrupt + approve).
	_, err = pipeline.Run(ctx, "exec_command", map[string]any{"cmd": "ls"})
	var ie *gateway.InterruptError
	if !errors.As(err, &ie) {
		t.Fatalf("exec should interrupt, got: %v", err)
	}
	r3, err := pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
		Action: gateway.ApprovalApprove,
		Reason: "ok",
	})
	if err != nil {
		t.Errorf("exec resume: %v", err)
	}
	if !strings.Contains(r3, "executed: ls") {
		t.Errorf("exec result unexpected: %s", r3)
	}

	// Verify comprehensive audit trail.
	events := auditEvents(&auditBuf)
	// Expected: tool_start+tool_end (echo) + tool_start+tool_end (fs) + tool_interrupted + tool_start+tool_end (exec)
	if len(events) < 6 {
		t.Errorf("expected at least 6 audit events, got %d", len(events))
	}

	// Parse all events to verify structured JSON is valid.
	for i, e := range events {
		data, err := json.Marshal(e)
		if err != nil {
			t.Errorf("event %d marshal error: %v", i, err)
		}
		if !strings.Contains(string(data), `"ts"`) {
			t.Errorf("event %d missing timestamp: %s", i, string(data))
		}
	}
}
