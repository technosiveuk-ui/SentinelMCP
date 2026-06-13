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
	"log/slog"
	"os"
	"strings"

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

	// Bootstrap a fallback structured logger immediately so even pre-config
	// messages — including a config-load failure — are structured rather than
	// raw log output. Reconfigured from the loaded config below.
	configureLogging(shieldconfig.LogConfig{})

	// ---------------------------------------------------------------
	// Step 1: Load configuration.
	// ---------------------------------------------------------------
	cfg, err := shieldconfig.LoadOrDefault(*configPath)
	if err != nil {
		fatalf("config load failed", "error", err)
	}
	// Reconfigure logging from the now-loaded config (format/level).
	configureLogging(cfg.Log)
	slog.Info("config loaded", "schema", cfg.SchemaVersion, "default_risk", cfg.Global.DefaultRisk)

	// Loud warning when strict mode is disabled. Per the loopback-plaintext
	// principle, plaintext upstreams are acceptable only for trusted
	// private-network/local upstreams — never production.
	if !cfg.Sidecar.Strict {
		slog.Warn("sidecar.strict is disabled: plaintext (http://) and IP-literal upstreams are permitted — local/private-network demos only, set sidecar.strict: true in production")
	}
	if cfg.Sidecar.Strict && len(cfg.Sidecar.EgressAllowlist) == 0 && len(cfg.Sidecar.UpstreamServers) > 0 {
		slog.Warn("sidecar.strict is enabled but sidecar.egress_allowlist is empty — upstream egress is unrestricted; set sidecar.egress_allowlist in production to bound upstream hosts")
	}

	// Build the inbound authenticator from configured API keys. nil means
	// anonymous — permitted only on loopback or in dev mode; the bind policy
	// below fail-closes any non-loopback anonymous exposure.
	var authenticator auth.Authenticator
	if len(cfg.Auth.APIKeys) > 0 {
		authenticator = auth.NewAPIKeyAuthenticator(cfg.Auth.APIKeys)
	}
	if *insecureDevMode {
		slog.Warn("--insecure-dev-mode: inbound MCP non-loopback TLS/auth requirements are disabled — for local dev/demo only")
	}
	if err := validateInboundBind(cfg.Sidecar.ListenAddr, cfg.Sidecar.TLS.CertFile, cfg.Sidecar.TLS.KeyFile, authenticator, *insecureDevMode); err != nil {
		fatalf("inbound bind policy", "error", err)
	}

	// ---------------------------------------------------------------
	// Step 2: Discover upstream MCP tools.
	// ---------------------------------------------------------------
	// Build the outbound secrets provider (file map with env fallback). Even
	// without a secrets file this is env-capable, so a credentials_ref can still
	// resolve via SENTINELMCP_UPSTREAM_<KEY>_TOKEN.
	secretsMap, err := secrets.LoadSecretsFile(cfg.Secrets.File)
	if err != nil {
		fatalf("secrets load", "error", err)
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
		slog.Warn("no upstream MCP servers configured — sidecar will have no tools to proxy")
	}

	tools, invoker, err := sidecar.Discover(ctx, upstreams, secretsProvider)
	if err != nil {
		fatalf("upstream discovery", "error", err)
	}

	slog.Info("discovered upstream catalog",
		"tools", len(tools.Tools), "resources", len(tools.Resources),
		"prompts", len(tools.Prompts), "upstreams", len(upstreams))
	for _, t := range tools.Tools {
		slog.Debug("proxy tool", "tool", t.Name)
	}

	// ---------------------------------------------------------------
	// Step 3: Build gateway config and pipeline.
	// ---------------------------------------------------------------
	gwCfg, reloadable, err := buildGatewayConfig(cfg, invoker)
	if err != nil {
		fatalf("gateway config", "error", err)
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
		fatalf("gateway pipeline", "error", err)
	}
	slog.Info("gateway pipeline constructed")

	// ---------------------------------------------------------------
	// Hot-reload: policies update without a restart. The ConfigWatcher
	// reloads the whole config on file change; we rebuild the policy from it
	// and swap it atomically into the ReloadablePolicy the pipeline holds.
	// Fail-closed on both legs: a malformed file is rejected by Load (the
	// watcher keeps the previous config and never calls back), and a policy
	// build error is logged with the previous policy retained — the sidecar
	// never degrades to allow-all because of a config typo.
	// ---------------------------------------------------------------
	if *configPath != "" {
		watcher, err := shieldconfig.NewWatcher(*configPath, func(reloaded *shieldconfig.Config) {
			next, err := buildPolicy(reloaded)
			if err != nil {
				slog.Error("policy reload skipped, keeping previous policy", "error", err)
				return
			}
			reloadable.Set(next)
			if reloaded.HasPolicies() {
				slog.Info("policy reloaded", "rules", len(reloaded.Policies), "mode", "action-based")
			} else {
				slog.Info("policy reloaded", "mode", "risk-based")
			}
		})
		if err != nil {
			fatalf("config watcher", "error", err)
		}
		go func() {
			watcher.Start(ctx)
			watcher.Close()
		}()
		slog.Info("watching config for policy changes", "path", *configPath)
	}

	// ---------------------------------------------------------------
	// Step 4: Create proxy MCP server.
	// ---------------------------------------------------------------
	proxy := NewProxy(pipeline, *tools, invoker)
	slog.Info("proxy MCP server created", "tools", len(proxy.ToolNames()))

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
		fatalf("admin server bind policy", "error", err)
	}
	if err := admin.Start(); err != nil {
		fatalf("admin server start", "error", err)
	}
	admin.SetReady(true)
	slog.Info("admin server started", "addr", cfg.Sidecar.HealthAddr)

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
		fatalf("unsupported transport", "transport", transport, "supported", "streamable_http")
	}
}

// configureLogging builds the slog default logger from config and installs it
// globally. All packages log via the package-level slog functions, which honor
// this handler — slog.Default() is resolved per call, so the configured handler
// is always in effect regardless of package init order. Output always goes to
// stderr so it never collides with the JSON audit stream on stdout. Format
// defaults to text (human-readable, greppable); operators shipping to a log
// aggregator set log.format: json.
func configureLogging(lc shieldconfig.LogConfig) {
	level, err := shieldconfig.ParseLogLevel(lc.Level)
	if err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(strings.TrimSpace(lc.Format)) {
	case "json":
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// fatalf logs a fatal startup error via slog and exits 1. Startup failures are
// fatal by design (fail-closed): the gateway must not run half-initialized.
func fatalf(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
