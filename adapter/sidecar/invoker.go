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

// Package sidecar provides adapters for the SentinelMCP sidecar proxy mode.
//
// SidecarInvoker routes tool calls to upstream MCP servers via mcp-go/client.
// This is used by the sidecar binary (cmd/sentinelmcp/) to proxy tool calls
// through the gateway pipeline.
package sidecar

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// SidecarInvoker — routes tool calls to upstream MCP servers
// ---------------------------------------------------------------------------

// SidecarInvoker implements gateway.ToolInvoker by routing each tool call
// to the correct upstream MCP server via mcp-go/client.
type SidecarInvoker struct {
	// toolClient maps tool name → MCP client that serves that tool.
	toolClient map[string]*client.Client

	// serverClients maps server name → MCP client (for health checks).
	serverClients map[string]*client.Client
}

// Compile-time interface check.
var _ gateway.ToolInvoker = (*SidecarInvoker)(nil)

// Invoke implements gateway.ToolInvoker.
// Routes the tool call to the correct upstream MCP server.
func (inv *SidecarInvoker) Invoke(ctx context.Context, toolName string, args map[string]any) (string, error) {
	c, ok := inv.toolClient[toolName]
	if !ok {
		return "", fmt.Errorf("sidecar: no upstream MCP server for tool %q", toolName)
	}

	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      toolName,
			Arguments: args,
		},
	})
	if err != nil {
		return "", fmt.Errorf("sidecar: call tool %q on upstream: %w", toolName, err)
	}

	if result.IsError {
		return "", fmt.Errorf("sidecar: tool %q returned error: %s", toolName, extractContentText(result.Content))
	}

	return extractContentText(result.Content), nil
}

// extractContentText extracts text from MCP content blocks.
func extractContentText(contents []mcp.Content) string {
	var parts []string
	for _, c := range contents {
		if tc, ok := c.(mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		} else {
			// Non-text content: serialize to JSON.
			b, _ := json.Marshal(c)
			parts = append(parts, string(b))
		}
	}
	return strings.Join(parts, "\n")
}
