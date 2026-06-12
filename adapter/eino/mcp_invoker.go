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

// Package eino provides the Eino framework adapter for SentinelMCP.
//
// MCPToolInvoker bridges the framework-agnostic gateway.ToolInvoker interface
// to real MCP servers via Eino's tool.InvokableTool wrappers. The gateway core
// never sees Eino or MCP types — only the adapter does.
package eino

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cloudwego/eino/components/tool"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// MCPToolInvoker implements gateway.ToolInvoker by routing tool calls to
// MCP servers via Eino tool wrappers (typically obtained from eino-ext/mcp.GetTools).
//
// Create one using NewMCPToolInvoker after discovering tools from MCP clients.
type MCPToolInvoker struct {
	tools map[string]tool.InvokableTool // tool name → Eino invokable tool
}

// NewMCPToolInvoker creates a ToolInvoker from a slice of Eino BaseTool instances.
// Each tool must implement tool.InvokableTool (which eino-ext/mcp tools do).
// Tool names are taken from their Info() metadata.
func NewMCPToolInvoker(baseTools []tool.BaseTool) (*MCPToolInvoker, error) {
	invoker := &MCPToolInvoker{
		tools: make(map[string]tool.InvokableTool, len(baseTools)),
	}
	for _, bt := range baseTools {
		it, ok := bt.(tool.InvokableTool)
		if !ok {
			info, _ := bt.Info(context.Background())
			name := "unknown"
			if info != nil {
				name = info.Name
			}
			return nil, fmt.Errorf("adapter/eino: tool %q does not implement InvokableTool", name)
		}
		info, err := it.Info(context.Background())
		if err != nil {
			return nil, fmt.Errorf("adapter/eino: get tool info: %w", err)
		}
		if info.Name == "" {
			return nil, fmt.Errorf("adapter/eino: tool with empty name registered")
		}
		invoker.tools[info.Name] = it
	}
	return invoker, nil
}

// Invoke implements gateway.ToolInvoker.
// It looks up the tool by name, serializes args to JSON, and calls InvokableRun.
func (m *MCPToolInvoker) Invoke(ctx context.Context, toolName string, args map[string]any) (string, error) {
	t, ok := m.tools[toolName]
	if !ok {
		return "", fmt.Errorf("adapter/eino: no MCP tool registered for %q", toolName)
	}

	argsJSON, err := json.Marshal(args)
	if err != nil {
		return "", fmt.Errorf("adapter/eino: marshal args for tool %q: %w", toolName, err)
	}

	result, err := t.InvokableRun(ctx, string(argsJSON))
	if err != nil {
		return "", fmt.Errorf("adapter/eino: invoke MCP tool %q: %w", toolName, err)
	}

	return result, nil
}

// Compile-time interface check.
var _ gateway.ToolInvoker = (*MCPToolInvoker)(nil)

// ToolNames returns the names of all registered MCP tools.
func (m *MCPToolInvoker) ToolNames() []string {
	names := make([]string, 0, len(m.tools))
	for name := range m.tools {
		names = append(names, name)
	}
	return names
}
