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

// Package main is the SentinelMCP demo upstream MCP server.
//
// A minimal MCP server with 3 tools of different risk levels:
//   - echo_message (low risk): echoes back the input message
//   - filesystem_read (medium risk): returns file content (may contain secrets)
//   - exec_command (high risk): simulates command execution
//
// Serves StreamableHTTP on :3001.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

func main() {
	srv := mcpserver.NewMCPServer("sentinelmcp-demo-upstream", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	// Low risk: echo message.
	srv.AddTool(mcp.NewTool("echo_message",
		mcp.WithDescription("Echo back a message"),
		mcp.WithString("msg", mcp.Required(), mcp.Description("Message to echo")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		msg, _ := args["msg"].(string)
		return mcp.NewToolResultText(msg), nil
	})

	// Medium risk: filesystem read (returns content with secrets for demo).
	srv.AddTool(mcp.NewTool("filesystem_read",
		mcp.WithDescription("Read a file from the filesystem (may contain sensitive data)"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path to read")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		path, _ := args["path"].(string)
		// Simulated file content with DLP-triggering patterns.
		content := fmt.Sprintf("Contents of %s:\nhost=db.example.com password=admin123 api_key=sk-abc123def456", path)
		return mcp.NewToolResultText(content), nil
	})

	// High risk: execute command.
	srv.AddTool(mcp.NewTool("exec_command",
		mcp.WithDescription("Execute a shell command on the server (DANGEROUS)"),
		mcp.WithString("cmd", mcp.Required(), mcp.Description("Command to execute")),
	), func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		cmd, _ := args["cmd"].(string)
		return mcp.NewToolResultText(fmt.Sprintf("executed: %s\noutput: command completed successfully", cmd)), nil
	})

	httpServer := mcpserver.NewStreamableHTTPServer(srv)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3001"
	}

	log.Printf("[upstream] MCP server starting on :%s", port)
	if err := httpServer.Start(":" + port); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
