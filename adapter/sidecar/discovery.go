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
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/technosiveuk-ui/sentinelmcp/gateway/secrets"
)

// ---------------------------------------------------------------------------
// UpstreamConfig — configuration for one upstream MCP server
// ---------------------------------------------------------------------------

// UpstreamConfig describes a single upstream MCP server to connect to.
type UpstreamConfig struct {
	Name         string // display name
	URL          string // e.g. "https://fs.local/mcp"
	CABundle     string // PEM CA bundle: inline PEM or file path; empty = system roots
	ServerName   string // TLS SNI / verification hostname override
	PinnedSHA256 string // hex SHA-256 of leaf cert SPKI; additional pin on top of chain validation
	CredentialsRef string // key into the secrets provider; empty = no credentials injected
}

// ToolMeta holds discovered tool metadata for registering on the proxy server.
type ToolMeta struct {
	Name        string
	Description string
	InputSchema mcp.ToolInputSchema
}

// Catalog holds the full set of MCP items discovered from upstream servers.
// The proxy registers every item: tools are pipeline-wrapped; resources,
// resource templates, and prompts are transparently forwarded (raw pass-through).
type Catalog struct {
	Tools             []ToolMeta
	Resources         []mcp.Resource
	ResourceTemplates []mcp.ResourceTemplate
	Prompts           []mcp.Prompt
}

// ---------------------------------------------------------------------------
// Discover — connects to upstream MCP servers, discovers tools + resources + prompts
// ---------------------------------------------------------------------------

// Discover connects to all configured upstream MCP servers, discovers their
// tools, resources, resource templates, and prompts, and returns the catalog
// along with a populated SidecarInvoker that routes each item to its upstream.
// provider resolves outbound credentials for upstreams that declare a
// credentials_ref (may be nil when no upstream needs credentials).
//
// Per upstream, resources/resource-templates are gathered only when the server
// advertises the resources capability, and prompts only when it advertises the
// prompts capability. A failure within an optional family is logged and skipped
// — the upstream may still serve tools. (cache-at-discovery: items added
// upstream after startup are not seen until re-discovery.)
func Discover(ctx context.Context, servers []UpstreamConfig, provider secrets.Provider) (*Catalog, *SidecarInvoker, error) {
	invoker := &SidecarInvoker{
		toolClient:     make(map[string]*client.Client),
		serverClients:  make(map[string]*client.Client),
		resourceClient: make(map[string]*client.Client),
		promptClient:   make(map[string]*client.Client),
	}

	catalog := &Catalog{}

	for _, srv := range servers {
		cli, err := connectUpstream(ctx, srv, provider)
		if err != nil {
			return nil, nil, fmt.Errorf("sidecar: connect to upstream %q (%s): %w", srv.Name, srv.URL, err)
		}

		tools, err := listTools(ctx, cli)
		if err != nil {
			return nil, nil, fmt.Errorf("sidecar: discover tools from %q: %w", srv.Name, err)
		}
		for _, t := range tools {
			invoker.toolClient[t.Name] = cli
			catalog.Tools = append(catalog.Tools, t)
		}

		caps := cli.GetServerCapabilities()
		if caps.Resources != nil {
			discoverResources(ctx, srv.Name, cli, invoker, catalog)
		}
		if caps.Prompts != nil {
			discoverPrompts(ctx, srv.Name, cli, invoker, catalog)
		}

		invoker.serverClients[srv.Name] = cli
		log.Printf("[sidecar] discovered %d tools from %q (%s)", len(tools), srv.Name, srv.URL)
	}

	log.Printf("[sidecar] total discovered: %d tools, %d resources, %d resource templates, %d prompts",
		len(catalog.Tools), len(catalog.Resources), len(catalog.ResourceTemplates), len(catalog.Prompts))
	return catalog, invoker, nil
}

// discoverResources lists static resources and resource templates from an
// upstream and binds them to the invoker (for read routing) and the catalog
// (for proxy registration). Each family is independent and best-effort: a list
// error is logged and skipped, never fatal.
func discoverResources(ctx context.Context, serverName string, cli *client.Client, invoker *SidecarInvoker, catalog *Catalog) {
	if res, err := cli.ListResources(ctx, mcp.ListResourcesRequest{}); err != nil {
		log.Printf("[sidecar] skip resources from %q: list resources: %v", serverName, err)
	} else {
		for _, r := range res.Resources {
			invoker.resourceClient[r.URI] = cli
			catalog.Resources = append(catalog.Resources, r)
		}
	}

	if tmpls, err := cli.ListResourceTemplates(ctx, mcp.ListResourceTemplatesRequest{}); err != nil {
		log.Printf("[sidecar] skip resource templates from %q: list templates: %v", serverName, err)
	} else {
		for _, t := range tmpls.ResourceTemplates {
			invoker.resourceTemplates = append(invoker.resourceTemplates, resourceTemplateRoute{
				uriTemplate: t.URITemplate,
				client:      cli,
			})
			catalog.ResourceTemplates = append(catalog.ResourceTemplates, t)
		}
	}
}

// discoverPrompts lists prompts from an upstream and binds them to the invoker
// (for get routing) and the catalog (for proxy registration). Best-effort: a
// list error is logged and skipped.
func discoverPrompts(ctx context.Context, serverName string, cli *client.Client, invoker *SidecarInvoker, catalog *Catalog) {
	prompts, err := cli.ListPrompts(ctx, mcp.ListPromptsRequest{})
	if err != nil {
		log.Printf("[sidecar] skip prompts from %q: list prompts: %v", serverName, err)
		return
	}
	for _, p := range prompts.Prompts {
		invoker.promptClient[p.Name] = cli
		catalog.Prompts = append(catalog.Prompts, p)
	}
}

// connectUpstream creates an MCP client for the given upstream server URL.
func connectUpstream(ctx context.Context, srv UpstreamConfig, provider secrets.Provider) (*client.Client, error) {
	var cli *client.Client

	switch {
	case strings.HasPrefix(srv.URL, "http://"), strings.HasPrefix(srv.URL, "https://"):
		httpClient, err := buildUpstreamHTTPClient(srv)
		if err != nil {
			return nil, fmt.Errorf("build HTTP client: %w", err)
		}
		opts := []transport.StreamableHTTPCOption{transport.WithHTTPBasicClient(httpClient)}

		// Outbound credentials (Step 4). Fail-closed: a declared credentials_ref
		// that cannot be resolved blocks the upstream entirely (NFR-07).
		headers, err := resolveUpstreamHeaders(ctx, srv, provider)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: %w", srv.Name, err)
		}
		if len(headers) > 0 {
			opts = append(opts, transport.WithHTTPHeaders(headers))
		}

		cli, err = client.NewStreamableHttpClient(srv.URL, opts...)
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

// resolveUpstreamHeaders returns the outbound credential headers for an
// upstream, or an error if a declared credentials_ref cannot be resolved
// (fail-closed). An empty credentials_ref means no credentials are needed.
func resolveUpstreamHeaders(ctx context.Context, srv UpstreamConfig, provider secrets.Provider) (map[string]string, error) {
	if srv.CredentialsRef == "" {
		return nil, nil
	}
	if provider == nil {
		return nil, fmt.Errorf("declares credentials_ref %q but no secrets provider is configured", srv.CredentialsRef)
	}
	cred, err := provider.Fetch(ctx, srv.CredentialsRef)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}
	return cred.Headers, nil
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
