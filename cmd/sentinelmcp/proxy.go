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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/sidecar"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Proxy — MCP server wrapping the gateway pipeline
// ---------------------------------------------------------------------------

// Proxy is an MCP server that proxies tool calls through the SentinelMCP pipeline.
// Each discovered upstream tool is registered on the proxy server. When a client
// calls a tool, the proxy routes it through policy enforcement, DLP scanning,
// and human-in-the-loop approval before forwarding to the upstream MCP server.
type Proxy struct {
	server   *mcpserver.MCPServer
	pipeline gateway.Pipeline
	tools    []sidecar.ToolMeta
}

// NewProxy creates a proxy MCP server wrapping the gateway pipeline.
func NewProxy(pipeline gateway.Pipeline, tools []sidecar.ToolMeta) *Proxy {
	srv := mcpserver.NewMCPServer(
		"sentinelmcp-proxy",
		"1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	p := &Proxy{
		server:   srv,
		pipeline: pipeline,
		tools:    tools,
	}

	// Register each discovered tool on the proxy server.
	for _, t := range tools {
		p.registerTool(t)
	}

	return p
}

// registerTool registers a single tool on the proxy MCP server.
func (p *Proxy) registerTool(meta sidecar.ToolMeta) {
	tool := mcpserver.ServerTool{
		Tool: convertToolMeta(meta),
		Handler: func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return p.handleToolCall(ctx, meta.Name, req)
		},
	}
	p.server.AddTools(tool)
	log.Printf("[proxy] registered tool: %s", meta.Name)
}

// handleToolCall routes a single tool call through the gateway pipeline.
func (p *Proxy) handleToolCall(ctx context.Context, toolName string, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Extract arguments from the request.
	args := make(map[string]any)
	if req.Params.Arguments != nil {
		if m, ok := req.Params.Arguments.(map[string]any); ok {
			args = m
		}
	}

	// Run through the gateway pipeline.
	result, err := p.pipeline.Run(ctx, toolName, args)
	if err != nil {
		// Check if it's an interrupt (needs human approval).
		var ie *gateway.InterruptError
		if errors.As(err, &ie) {
			return &mcp.CallToolResult{
				Content: []mcp.Content{
					mcp.TextContent{
						Type: "text",
						Text: fmt.Sprintf("Tool %q requires human approval. Interrupt ID: %s, Checkpoint: %s. Use the resume API to approve/deny.",
							toolName, ie.Info.ID, ie.Info.CheckpointID),
					},
				},
				IsError: true,
			}, nil
		}

		// Other errors (blocked, pipeline failure).
		return &mcp.CallToolResult{
			Content: []mcp.Content{
				mcp.TextContent{
					Type: "text",
					Text: fmt.Sprintf("SentinelMCP blocked tool %q: %v", toolName, err),
				},
			},
			IsError: true,
		}, nil
	}

	// Success — return the (possibly redacted) result.
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: result,
			},
		},
	}, nil
}

// Server returns the underlying MCP server for transport binding.
func (p *Proxy) Server() *mcpserver.MCPServer {
	return p.server
}

// ToolNames returns the names of all registered proxy tools.
func (p *Proxy) ToolNames() []string {
	names := make([]string, 0, len(p.tools))
	for _, t := range p.tools {
		names = append(names, t.Name)
	}
	return names
}

// convertToolMeta converts adapter sidecar ToolMeta to mcp.Tool.
func convertToolMeta(meta sidecar.ToolMeta) mcp.Tool {
	// Marshal the InputSchema to JSON, then use it via RawInputSchema.
	schemaJSON, err := json.Marshal(meta.InputSchema)
	if err != nil {
		schemaJSON = []byte(`{"type":"object"}`)
	}

	return mcp.Tool{
		Name:           meta.Name,
		Description:    meta.Description,
		RawInputSchema: schemaJSON,
	}
}
