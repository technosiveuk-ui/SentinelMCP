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

// upstreamForwarder forwards resource and prompt reads to upstream MCP servers.
// Raw pass-through — no policy/DLP — the gateway pipeline owns tools/call only.
// *sidecar.SidecarInvoker satisfies this; tests may substitute a stub.
type upstreamForwarder interface {
	ReadResource(ctx context.Context, uri string) ([]mcp.ResourceContents, error)
	GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error)
}

// Proxy is an MCP server that proxies tool calls through the SentinelMCP pipeline.
// Each discovered upstream tool is registered on the proxy server. When a client
// calls a tool, the proxy routes it through policy enforcement, DLP scanning,
// and human-in-the-loop approval before forwarding to the upstream MCP server.
// Discovered resources, resource templates, and prompts are registered as
// transparent pass-through handlers (no pipeline) so the proxy faithfully
// mirrors the upstream catalog beyond tools/call.
type Proxy struct {
	server    *mcpserver.MCPServer
	pipeline  gateway.Pipeline
	catalog   sidecar.Catalog
	forwarder upstreamForwarder
}

// NewProxy creates a proxy MCP server wrapping the gateway pipeline.
// Tools are pipeline-wrapped; resources, resource templates, and prompts are
// forwarded as raw pass-through. Registering a family auto-enables its MCP
// capability, so a server that discovered none advertises none (the client sees
// METHOD_NOT_FOUND, the correct response for an unsupported capability).
func NewProxy(pipeline gateway.Pipeline, catalog sidecar.Catalog, forwarder upstreamForwarder) *Proxy {
	srv := mcpserver.NewMCPServer(
		"sentinelmcp-proxy",
		"1.0.0",
		mcpserver.WithToolCapabilities(true),
	)

	p := &Proxy{
		server:    srv,
		pipeline:  pipeline,
		catalog:   catalog,
		forwarder: forwarder,
	}

	// Register each discovered item. Tool handlers run the pipeline; the rest
	// forward straight through to the owning upstream.
	for _, t := range catalog.Tools {
		p.registerTool(t)
	}
	for _, r := range catalog.Resources {
		p.registerResource(r)
	}
	for _, t := range catalog.ResourceTemplates {
		p.registerResourceTemplate(t)
	}
	for _, pr := range catalog.Prompts {
		p.registerPrompt(pr)
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

// registerResource registers a static upstream resource as a transparent
// pass-through. The handler forwards resources/read to the upstream that owns
// the URI. No pipeline, no DLP — raw forwarding.
func (p *Proxy) registerResource(res mcp.Resource) {
	p.server.AddResources(mcpserver.ServerResource{
		Resource: res,
		Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return p.forwarder.ReadResource(ctx, req.Params.URI)
		},
	})
	log.Printf("[proxy] registered resource: %s", res.URI)
}

// registerResourceTemplate registers an upstream resource template as a
// transparent pass-through. mcp-go matches a concrete read URI against the
// template and invokes this handler, which forwards the concrete URI upstream.
func (p *Proxy) registerResourceTemplate(tmpl mcp.ResourceTemplate) {
	p.server.AddResourceTemplates(mcpserver.ServerResourceTemplate{
		Template: tmpl,
		Handler: func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return p.forwarder.ReadResource(ctx, req.Params.URI)
		},
	})
	log.Printf("[proxy] registered resource template: %s", tmpl.Name)
}

// registerPrompt registers an upstream prompt as a transparent pass-through. The
// handler forwards prompts/get (name + arguments) to the owning upstream.
func (p *Proxy) registerPrompt(pr mcp.Prompt) {
	p.server.AddPrompt(pr, func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return p.forwarder.GetPrompt(ctx, req.Params.Name, req.Params.Arguments)
	})
	log.Printf("[proxy] registered prompt: %s", pr.Name)
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
	names := make([]string, 0, len(p.catalog.Tools))
	for _, t := range p.catalog.Tools {
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
