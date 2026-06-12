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

// cmd/demo/servers.go defines three in-process MCP servers for the SentinelMCP demo.
//
// Each server exposes tools at a different risk tier:
//   - echo_server  → "echo_message" tool (low risk, pass-through)
//   - calc_server  → "calculator" tool  (medium risk, demonstrates DLP redaction)
//   - shell_server → "exec_command" tool (high risk, requires human approval)
package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// newEchoServer creates an MCP server with an "echo_message" tool.
// Risk: low — simply echoes back the provided message.
func newEchoServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("sentinelmcp-echo", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	srv.AddTool(mcp.NewTool("echo_message",
		mcp.WithDescription("Echo back the provided message"),
		mcp.WithString("msg",
			mcp.Required(),
			mcp.Description("The message to echo back"),
		),
	), handleEcho)

	return srv
}

func handleEcho(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	msg, _ := args["msg"].(string)
	return mcp.NewToolResultText(msg), nil
}

// newCalcServer creates an MCP server with a "calculator" tool.
// Risk: medium — the result could contain sensitive data, triggers DLP redaction.
func newCalcServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("sentinelmcp-calculator", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	srv.AddTool(mcp.NewTool("calculator",
		mcp.WithDescription("Perform arithmetic calculations"),
		mcp.WithString("operation",
			mcp.Required(),
			mcp.Description("Arithmetic expression to evaluate (e.g. '2 + 3')"),
		),
	), handleCalc)

	return srv
}

func handleCalc(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	expr, _ := args["operation"].(string)
	// Simple eval: support "X op Y" format only (no math/big for demo safety).
	parts := strings.Fields(expr)
	if len(parts) != 3 {
		return mcp.NewToolResultError(fmt.Sprintf("unsupported expression: %q (use 'X op Y' format)", expr)), nil
	}
	var a, b float64
	fmt.Sscanf(parts[0], "%f", &a)
	fmt.Sscanf(parts[2], "%f", &b)

	var result float64
	switch parts[1] {
	case "+":
		result = a + b
	case "-":
		result = a - b
	case "*":
		result = a * b
	case "/":
		if b == 0 {
			return mcp.NewToolResultError("division by zero"), nil
		}
		result = a / b
	default:
		return mcp.NewToolResultError(fmt.Sprintf("unsupported operator: %s", parts[1])), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("%.6g", result)), nil
}

// newShellServer creates an MCP server with an "exec_command" tool.
// Risk: high — executes commands, requires human approval.
func newShellServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("sentinelmcp-shell", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	srv.AddTool(mcp.NewTool("exec_command",
		mcp.WithDescription("Execute a shell command (HIGH RISK: requires approval)"),
		mcp.WithString("cmd",
			mcp.Required(),
			mcp.Description("The shell command to execute"),
		),
	), handleShell)

	return srv
}

func handleShell(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	cmd, _ := args["cmd"].(string)
	// In a real server this would run the command.
	// For the demo we simulate execution with a safe response.
	return mcp.NewToolResultText(fmt.Sprintf("[demo] would execute: %s", cmd)), nil
}

// newFilesystemServer creates an MCP server with a "filesystem_read" tool.
// Risk: medium — reads files, could expose secrets in content.
func newFilesystemServer() *mcpserver.MCPServer {
	srv := mcpserver.NewMCPServer("sentinelmcp-filesystem", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	srv.AddTool(mcp.NewTool("filesystem_read",
		mcp.WithDescription("Read file contents from the filesystem"),
		mcp.WithString("path",
			mcp.Required(),
			mcp.Description("Path to the file to read"),
		),
	), handleFilesystemRead)

	return srv
}

func handleFilesystemRead(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := req.GetArguments()
	path, _ := args["path"].(string)
	// Simulate reading a file that might contain secrets.
	return mcp.NewToolResultText(fmt.Sprintf("[demo] contents of %s: host=db.example.com password=supersecret123", path)), nil
}
