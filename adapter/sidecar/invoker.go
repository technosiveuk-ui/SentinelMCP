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
// to the correct upstream MCP server via mcp-go/client. It also routes raw
// resource/prompt reads (transparent proxying); those paths are pass-through —
// the gateway pipeline owns tools/call only.
type SidecarInvoker struct {
	// toolClient maps tool name → MCP client that serves that tool.
	toolClient map[string]*client.Client

	// serverClients maps server name → MCP client (for health checks).
	serverClients map[string]*client.Client

	// resourceClient maps a static resource URI → the upstream serving it.
	resourceClient map[string]*client.Client
	// resourceTemplates binds each discovered resource template to its upstream
	// client, so a concrete read URI can be routed to the owning upstream after
	// mcp-go matches the URI to the template. First match wins.
	resourceTemplates []resourceTemplateRoute
	// promptClient maps a prompt name → the upstream serving it.
	promptClient map[string]*client.Client
}

// resourceTemplateRoute binds a discovered resource template to the upstream
// client that serves it.
type resourceTemplateRoute struct {
	uriTemplate *mcp.URITemplate
	client      *client.Client
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

// ReadResource forwards a resources/read for the given URI to the upstream that
// owns it. Static resources route by exact URI; resource templates route by
// matching the concrete URI against each discovered template. Raw pass-through —
// no policy/DLP (the pipeline owns tools/call only; inspection of resource
// contents is a later concern).
func (inv *SidecarInvoker) ReadResource(ctx context.Context, uri string) ([]mcp.ResourceContents, error) {
	if cli, ok := inv.resourceClient[uri]; ok {
		return inv.readResourceWith(ctx, cli, uri)
	}
	for _, route := range inv.resourceTemplates {
		if route.uriTemplate == nil {
			continue
		}
		if route.uriTemplate.Regexp().MatchString(uri) {
			return inv.readResourceWith(ctx, route.client, uri)
		}
	}
	return nil, fmt.Errorf("sidecar: no upstream MCP server for resource %q", uri)
}

// readResourceWith calls resources/read on the given upstream client and returns
// the raw contents. The concrete URI is forwarded unchanged.
func (inv *SidecarInvoker) readResourceWith(ctx context.Context, cli *client.Client, uri string) ([]mcp.ResourceContents, error) {
	result, err := cli.ReadResource(ctx, mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{URI: uri},
	})
	if err != nil {
		return nil, fmt.Errorf("sidecar: read resource %q on upstream: %w", uri, err)
	}
	return result.Contents, nil
}

// GetPrompt forwards a prompts/get for the named prompt to the upstream that
// owns it. Raw pass-through — no policy/DLP.
func (inv *SidecarInvoker) GetPrompt(ctx context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	cli, ok := inv.promptClient[name]
	if !ok {
		return nil, fmt.Errorf("sidecar: no upstream MCP server for prompt %q", name)
	}
	result, err := cli.GetPrompt(ctx, mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{Name: name, Arguments: args},
	})
	if err != nil {
		return nil, fmt.Errorf("sidecar: get prompt %q on upstream: %w", name, err)
	}
	return result, nil
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
