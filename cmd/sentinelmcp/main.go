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
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	"github.com/technosiveuk-ui/sentinelmcp/adapter/sidecar"
	shieldconfig "github.com/technosiveuk-ui/sentinelmcp/config"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to SentinelMCP config YAML")
	insecureAdminBind := flag.Bool("insecure-admin-bind", false, "allow the admin server to bind a non-loopback address (requires admin_token)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ---------------------------------------------------------------
	// Step 1: Load configuration.
	// ---------------------------------------------------------------
	cfg, err := shieldconfig.LoadOrDefault(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	log.Printf("Config loaded (schema=%s, default_risk=%s)", cfg.SchemaVersion, cfg.Global.DefaultRisk)

	// ---------------------------------------------------------------
	// Step 2: Discover upstream MCP tools.
	// ---------------------------------------------------------------
	upstreams := make([]sidecar.UpstreamConfig, 0, len(cfg.Sidecar.UpstreamServers))
	for _, us := range cfg.Sidecar.UpstreamServers {
		upstreams = append(upstreams, sidecar.UpstreamConfig{
			Name: us.Name,
			URL:  us.URL,
		})
	}

	if len(upstreams) == 0 {
		log.Println("[warn] no upstream MCP servers configured — sidecar will have no tools to proxy")
	}

	tools, invoker, err := sidecar.DiscoverTools(ctx, upstreams)
	if err != nil {
		log.Fatalf("Failed to discover upstream tools: %v", err)
	}

	log.Printf("Discovered %d tools from %d upstream servers", len(tools), len(upstreams))
	for _, t := range tools {
		log.Printf("  - %s", t.Name)
	}

	// ---------------------------------------------------------------
	// Step 3: Build gateway config and pipeline.
	// ---------------------------------------------------------------
	gwCfg, err := buildGatewayConfig(cfg, invoker)
	if err != nil {
		log.Fatalf("Failed to build gateway config: %v", err)
	}

	// Build pipeline with optional BoltDB checkpoint store.
	// Sprint 1: BoltCheckPointStore delegates to in-memory.
	var opts []eino.GraphOption
	if cfg.Sidecar.CheckpointPath != "" {
		cpStore := eino.NewBoltCheckPointStore(cfg.Sidecar.CheckpointPath)
		opts = append(opts, eino.WithCheckPointStore(cpStore))
	}

	pipeline, err := eino.BuildGraph(gwCfg, opts...)
	if err != nil {
		log.Fatalf("Failed to build gateway pipeline: %v", err)
	}
	log.Println("Gateway pipeline constructed.")

	// ---------------------------------------------------------------
	// Step 4: Create proxy MCP server.
	// ---------------------------------------------------------------
	proxy := NewProxy(pipeline, tools)
	log.Printf("Proxy MCP server created with %d tools", len(proxy.ToolNames()))

	// ---------------------------------------------------------------
	// Step 5: Start admin HTTP server (health + resume API).
	// ---------------------------------------------------------------
	// Resolve the admin token: the SENTINELMCP_ADMIN_TOKEN env var takes
	// precedence over the config file, so a world-readable config need not carry
	// the secret. The config loader already fail-closes if the token is present
	// in a group/world-readable config file.
	adminToken := cfg.Sidecar.AdminToken
	if v := os.Getenv("SENTINELMCP_ADMIN_TOKEN"); v != "" {
		adminToken = v
	}

	admin := NewAdminServer(cfg.Sidecar.HealthAddr, pipeline, WithAdminToken(adminToken))
	if err := admin.ValidateBind(*insecureAdminBind); err != nil {
		log.Fatalf("Admin server: %v", err)
	}
	if err := admin.Start(); err != nil {
		log.Fatalf("Failed to start admin server: %v", err)
	}
	admin.SetReady(true)
	log.Printf("Admin server started on %s", cfg.Sidecar.HealthAddr)

	// ---------------------------------------------------------------
	// Step 6: Start MCP proxy server.
	// ---------------------------------------------------------------
	transport := cfg.Sidecar.Transport
	if transport == "" {
		transport = "streamable_http"
	}

	switch transport {
	case "streamable_http":
		startStreamableHTTP(ctx, proxy, cfg.Sidecar.ListenAddr)
	default:
		log.Fatalf("Unsupported transport: %s (supported: streamable_http)", transport)
	}
}

// startStreamableHTTP starts the MCP proxy server using StreamableHTTP transport.
func startStreamableHTTP(ctx context.Context, proxy *Proxy, addr string) {
	httpServer := mcpserver.NewStreamableHTTPServer(proxy.Server())

	// Start server in goroutine.
	go func() {
		log.Printf("[mcp] StreamableHTTP proxy listening on %s", addr)
		if err := httpServer.Start(addr); err != nil {
			log.Fatalf("MCP server error: %v", err)
		}
	}()

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(ctx, 5)
	defer cancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
