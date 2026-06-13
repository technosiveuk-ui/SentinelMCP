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
	"net/http/httptest"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// newCatalogUpstream stands up a real in-process MCP server that advertises a
// tool, a static resource, a resource template, and a prompt — then serves it
// over Streamable HTTP so Discover() can connect to it like any network upstream.
func newCatalogUpstream(t *testing.T) string {
	t.Helper()

	srv := mcpserver.NewMCPServer("catalog-upstream", "1.0.0",
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithResourceCapabilities(false, false),
		mcpserver.WithPromptCapabilities(false),
	)

	// Static resource: config://app -> a fixed text body.
	srv.AddResources(mcpserver.ServerResource{
		Resource: mcp.NewResource("config://app", "app-config",
			mcp.WithResourceDescription("application configuration")),
		Handler: func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: "config://app", MIMEType: "text/plain", Text: "the-secret-value"},
			}, nil
		},
	})

	// Resource template: file:///files{/path*} -> echoes the concrete URI back.
	// The {/path*} explosion operator is what matches multi-segment paths under
	// RFC 6570 (a bare {path} var excludes "/"), mirroring real filesystem servers.
	srv.AddResourceTemplate(
		mcp.NewResourceTemplate("file:///files{/path*}", "files",
			mcp.WithTemplateDescription("filesystem entries")),
		func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, MIMEType: "text/plain", Text: "body-of-" + req.Params.URI},
			}, nil
		},
	)

	// Prompt: greet -> a single user message.
	srv.AddPrompt(
		mcp.NewPrompt("greet", mcp.WithPromptDescription("greet a user")),
		func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Description: "a greeting",
				Messages: []mcp.PromptMessage{{
					Role:    mcp.RoleUser,
					Content: mcp.TextContent{Type: "text", Text: "hello from upstream"},
				}},
			}, nil
		},
	)

	ts := httptest.NewServer(mcpserver.NewStreamableHTTPServer(srv))
	t.Cleanup(ts.Close)
	return ts.URL
}

// TestDiscover_CatalogAndRouting: Discover gathers resources, resource templates,
// and prompts from an upstream that advertises them, and the SidecarInvoker
// routes static reads, template reads, and prompt gets to the owning upstream.
func TestDiscover_CatalogAndRouting(t *testing.T) {
	url := newCatalogUpstream(t)

	ctx := context.Background()
	catalog, invoker, err := Discover(ctx, []UpstreamConfig{{Name: "u", URL: url}}, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	if len(catalog.Resources) != 1 || catalog.Resources[0].URI != "config://app" {
		t.Fatalf("expected 1 resource config://app, got %+v", catalog.Resources)
	}
	if len(catalog.ResourceTemplates) != 1 || catalog.ResourceTemplates[0].Name != "files" {
		t.Fatalf("expected 1 resource template 'files', got %+v", catalog.ResourceTemplates)
	}
	if len(catalog.Prompts) != 1 || catalog.Prompts[0].Name != "greet" {
		t.Fatalf("expected 1 prompt 'greet', got %+v", catalog.Prompts)
	}

	// Static resource: exact-URI route.
	contents, err := invoker.ReadResource(ctx, "config://app")
	if err != nil {
		t.Fatalf("ReadResource static: %v", err)
	}
	if len(contents) != 1 {
		t.Fatalf("expected 1 content block, got %d", len(contents))
	}
	tc, ok := contents[0].(mcp.TextResourceContents)
	if !ok || tc.Text != "the-secret-value" {
		t.Fatalf("static resource body mismatch: %#v", contents[0])
	}

	// Resource template: concrete URI matched against file:///files{/path*}.
	contents, err = invoker.ReadResource(ctx, "file:///files/etc/hosts")
	if err != nil {
		t.Fatalf("ReadResource template: %v", err)
	}
	tc, ok = contents[0].(mcp.TextResourceContents)
	if !ok || tc.Text != "body-of-file:///files/etc/hosts" {
		t.Fatalf("template resource body mismatch: %#v", contents[0])
	}

	// Prompt: name-keyed route.
	res, err := invoker.GetPrompt(ctx, "greet", nil)
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}
	if len(res.Messages) != 1 {
		t.Fatalf("expected 1 prompt message, got %d", len(res.Messages))
	}
	if gtxt, _ := res.Messages[0].Content.(mcp.TextContent); gtxt.Text != "hello from upstream" {
		t.Fatalf("prompt body mismatch: %#v", res.Messages[0].Content)
	}

	// Routing miss on an unknown resource URI is an error (no upstream owns it).
	if _, err := invoker.ReadResource(ctx, "unknown://nope"); err == nil {
		t.Fatal("expected error routing an unknown resource URI")
	}
	if _, err := invoker.GetPrompt(ctx, "missing", nil); err == nil {
		t.Fatal("expected error routing an unknown prompt name")
	}
}

// TestDiscover_ToolsOnly_NoResourcesPrompts: an upstream that advertises only
// tools yields an empty resource/prompt catalog and an invoker that errors on
// resource/prompt reads (no METHOD_NOT_FOUND leak — routing simply misses).
func TestDiscover_ToolsOnly_NoResourcesPrompts(t *testing.T) {
	srv := mcpserver.NewMCPServer("tools-only-upstream", "1.0.0",
		mcpserver.WithToolCapabilities(true),
	)
	srv.AddTool(mcp.NewTool("ping"), func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "pong"}}}, nil
	})
	ts := httptest.NewServer(mcpserver.NewStreamableHTTPServer(srv))
	t.Cleanup(ts.Close)

	catalog, invoker, err := Discover(context.Background(), []UpstreamConfig{{Name: "u", URL: ts.URL}}, nil)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(catalog.Tools) != 1 || len(catalog.Resources) != 0 || len(catalog.Prompts) != 0 {
		t.Fatalf("expected tools-only catalog, got tools=%d resources=%d prompts=%d",
			len(catalog.Tools), len(catalog.Resources), len(catalog.Prompts))
	}
	if _, err := invoker.ReadResource(context.Background(), "config://app"); err == nil {
		t.Fatal("tools-only upstream must not route resources")
	}
}
