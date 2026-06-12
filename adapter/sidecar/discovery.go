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

package sidecar

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

// ---------------------------------------------------------------------------
// UpstreamConfig — configuration for one upstream MCP server
// ---------------------------------------------------------------------------

// UpstreamConfig describes a single upstream MCP server to connect to.
type UpstreamConfig struct {
	Name string // display name
	URL  string // e.g. "http://localhost:3001/mcp", "stdio:///path/to/binary"
}

// ToolMeta holds discovered tool metadata for registering on the proxy server.
type ToolMeta struct {
	Name        string
	Description string
	InputSchema mcp.ToolInputSchema
}

// ---------------------------------------------------------------------------
// DiscoverTools — connects to upstream MCP servers, discovers tools
// ---------------------------------------------------------------------------

// DiscoverTools connects to all configured upstream MCP servers, discovers
// their tools, and returns the tool metadata along with a populated SidecarInvoker.
func DiscoverTools(ctx context.Context, servers []UpstreamConfig) ([]ToolMeta, *SidecarInvoker, error) {
	invoker := &SidecarInvoker{
		toolClient:    make(map[string]*client.Client),
		serverClients: make(map[string]*client.Client),
	}

	var allTools []ToolMeta

	for _, srv := range servers {
		cli, err := connectUpstream(ctx, srv)
		if err != nil {
			return nil, nil, fmt.Errorf("sidecar: connect to upstream %q (%s): %w", srv.Name, srv.URL, err)
		}

		tools, err := listTools(ctx, cli)
		if err != nil {
			return nil, nil, fmt.Errorf("sidecar: discover tools from %q: %w", srv.Name, err)
		}

		for _, t := range tools {
			invoker.toolClient[t.Name] = cli
			allTools = append(allTools, t)
		}

		invoker.serverClients[srv.Name] = cli
		log.Printf("[sidecar] discovered %d tools from %q (%s)", len(tools), srv.Name, srv.URL)
	}

	log.Printf("[sidecar] total tools discovered: %d", len(allTools))
	return allTools, invoker, nil
}

// connectUpstream creates an MCP client for the given upstream server URL.
func connectUpstream(ctx context.Context, srv UpstreamConfig) (*client.Client, error) {
	var cli *client.Client
	var err error

	switch {
	case strings.HasPrefix(srv.URL, "http://"), strings.HasPrefix(srv.URL, "https://"):
		cli, err = client.NewStreamableHttpClient(srv.URL)
		if err != nil {
			return nil, fmt.Errorf("create HTTP client: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported upstream URL scheme: %s (supported: http://, https://)", srv.URL)
	}

	// MCP protocol handshake.
	if _, err := cli.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo: mcp.Implementation{
				Name:    "sentinelmcp-sidecar",
				Version: "1.0.0",
			},
		},
	}); err != nil {
		return nil, fmt.Errorf("initialize: %w", err)
	}

	return cli, nil
}

// listTools discovers all tools from an MCP server.
func listTools(ctx context.Context, cli *client.Client) ([]ToolMeta, error) {
	result, err := cli.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, fmt.Errorf("list tools: %w", err)
	}

	tools := make([]ToolMeta, 0, len(result.Tools))
	for _, t := range result.Tools {
		tools = append(tools, ToolMeta{
			Name:        t.Name,
			Description: t.Description,
			InputSchema: t.InputSchema,
		})
	}
	return tools, nil
}
