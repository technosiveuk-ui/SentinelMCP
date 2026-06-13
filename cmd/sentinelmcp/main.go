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

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	"github.com/technosiveuk-ui/sentinelmcp/adapter/sidecar"
	shieldconfig "github.com/technosiveuk-ui/sentinelmcp/config"
	"github.com/technosiveuk-ui/sentinelmcp/gateway/auth"
	"github.com/technosiveuk-ui/sentinelmcp/gateway/secrets"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to SentinelMCP config YAML")
	insecureAdminBind := flag.Bool("insecure-admin-bind", false, "allow the admin server to bind a non-loopback address (requires admin_token)")
	insecureDevMode := flag.Bool("insecure-dev-mode", false, "disable non-loopback inbound TLS/auth requirements for local dev/demo (NOT for production)")
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

	// Loud warning when strict mode is disabled. Per the loopback-plaintext
	// principle, plaintext upstreams are acceptable only for trusted
	// private-network/local upstreams — never production.
	if !cfg.Sidecar.Strict {
		log.Println("[warn] sidecar.strict is DISABLED: plaintext (http://) and IP-literal upstreams are permitted. " +
			"Intended for local/private-network demos only — set sidecar.strict: true in production.")
	}

	// Build the inbound authenticator from configured API keys. nil means
	// anonymous — permitted only on loopback or in dev mode; the bind policy
	// below fail-closes any non-loopback anonymous exposure.
	var authenticator auth.Authenticator
	if len(cfg.Auth.APIKeys) > 0 {
		authenticator = auth.NewAPIKeyAuthenticator(cfg.Auth.APIKeys)
	}
	if *insecureDevMode {
		fmt.Fprintln(os.Stderr, "[warn] --insecure-dev-mode: inbound MCP non-loopback TLS/auth requirements are DISABLED. For local dev/demo ONLY.")
	}
	if err := validateInboundBind(cfg.Sidecar.ListenAddr, cfg.Sidecar.TLS.CertFile, cfg.Sidecar.TLS.KeyFile, authenticator, *insecureDevMode); err != nil {
		log.Fatalf("MCP inbound: %v", err)
	}

	// ---------------------------------------------------------------
	// Step 2: Discover upstream MCP tools.
	// ---------------------------------------------------------------
	// Build the outbound secrets provider (file map with env fallback). Even
	// without a secrets file this is env-capable, so a credentials_ref can still
	// resolve via SENTINELMCP_UPSTREAM_<KEY>_TOKEN.
	secretsMap, err := secrets.LoadSecretsFile(cfg.Secrets.File)
	if err != nil {
		log.Fatalf("secrets: %v", err)
	}
	secretsProvider := secrets.NewFileEnvProvider(secretsMap)

	upstreams := make([]sidecar.UpstreamConfig, 0, len(cfg.Sidecar.UpstreamServers))
	for _, us := range cfg.Sidecar.UpstreamServers {
		upstreams = append(upstreams, sidecar.UpstreamConfig{
			Name:           us.Name,
			URL:            us.URL,
			CABundle:       us.CABundle,
			ServerName:     us.ServerName,
			PinnedSHA256:   us.PinnedSHA256,
			CredentialsRef: us.CredentialsRef,
		})
	}

	if len(upstreams) == 0 {
		log.Println("[warn] no upstream MCP servers configured — sidecar will have no tools to proxy")
	}

	tools, invoker, err := sidecar.DiscoverTools(ctx, upstreams, secretsProvider)
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
		startStreamableHTTP(ctx, proxy, cfg.Sidecar.ListenAddr, cfg.Sidecar.TLS.CertFile, cfg.Sidecar.TLS.KeyFile, authenticator)
	default:
		log.Fatalf("Unsupported transport: %s (supported: streamable_http)", transport)
	}
}
