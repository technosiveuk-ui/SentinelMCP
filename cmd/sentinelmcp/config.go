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

// Package main is the SentinelMCP sidecar proxy binary.
//
// The sidecar acts as an MCP server that proxies tool calls through the
// SentinelMCP gateway pipeline (policy enforcement, DLP scanning, HITL approval).
//
// Usage:
//
//	./sentinelmcp -config config/config.yaml
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	"github.com/technosiveuk-ui/sentinelmcp/adapter/sidecar"
	shieldconfig "github.com/technosiveuk-ui/sentinelmcp/config"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// buildGatewayConfig constructs the gateway configuration from the loaded config.
// This is the wire-up layer — it creates all gateway interfaces and their
// implementations based on the YAML config. It returns the ReloadablePolicy
// wrapping the active policy so the caller can hot-swap it via the config watcher.
func buildGatewayConfig(cfg *shieldconfig.Config, invoker *sidecar.SidecarInvoker) (*gateway.GatewayConfig, *gateway.ReloadablePolicy, error) {
	// Policy engine: action-based PolicySet when policies are configured,
	// otherwise the risk-based DefaultPolicy. Always wrapped in a ReloadablePolicy
	// so the watcher can hot-swap it without restarting.
	policy, err := buildPolicy(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build policy: %w", err)
	}
	reloadable := gateway.NewReloadablePolicy(policy)

	// Risk database from YAML tool config.
	riskDB := cfg.ToRiskDB()

	// DLP scanner from YAML pattern config.
	dlpScanner, err := gateway.NewRegexDLPScanner(cfg.ToDLPPatterns())
	if err != nil {
		return nil, nil, fmt.Errorf("compile DLP patterns: %w", err)
	}

	// Redactor with configured mask.
	redactor := gateway.NewDefaultRedactor(cfg.Global.RedactionMask)

	// Audit emitter: use CompositeAuditEmitter composing configured sinks.
	auditEmitter, err := buildAuditEmitter(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build audit emitter: %w", err)
	}

	// Approval provider based on config.
	approvalProvider, err := buildApprovalProvider(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("build approval provider: %w", err)
	}

	return &gateway.GatewayConfig{
		Policy:           reloadable, // pipeline holds the reloadable wrapper
		RiskDB:           riskDB,
		DLPScanner:       dlpScanner,
		Redactor:         redactor,
		AuditEmitter:     auditEmitter,
		ApprovalProvider: approvalProvider,
		ToolInvoker:      invoker,
		RedactionMask:    cfg.Global.RedactionMask,
		MetricsRecorder:  buildMetricsRecorder(cfg),
	}, reloadable, nil
}

// buildPolicy resolves the active gateway.Policy from config: the action-based
// PolicySet when policies are configured (falling back to the risk-based
// DefaultPolicy for unmatched tools), otherwise the DefaultPolicy alone. Shared
// by startup and the config watcher's hot-reload path.
func buildPolicy(cfg *shieldconfig.Config) (gateway.Policy, error) {
	fallback := gateway.NewDefaultPolicy()
	if !cfg.HasPolicies() {
		return fallback, nil
	}
	return cfg.ToPolicySet(fallback)
}

// buildAuditEmitter creates the audit emitter based on config.
func buildAuditEmitter(cfg *shieldconfig.Config) (gateway.AuditEmitter, error) {
	var sinks []gateway.AuditSink

	// Default: always log to stdout.
	sinks = append(sinks, gateway.StdoutAuditSink())

	// Configured SIEM sinks.
	for _, sc := range cfg.SIEM.Sinks {
		switch sc.Type {
		case "file":
			sink, err := createFileSink(sc)
			if err != nil {
				return nil, err
			}
			sinks = append(sinks, sink)
		case "splunk_hec":
			sink := createSplunkSink(sc)
			sinks = append(sinks, sink)
		default:
			fmt.Fprintf(os.Stderr, "[warn] unknown SIEM sink type %q, skipping\n", sc.Type)
		}
	}

	return gateway.NewCompositeAuditEmitter(sinks...), nil
}

// buildApprovalProvider creates the approval provider based on config.
func buildApprovalProvider(cfg *shieldconfig.Config) (gateway.ApprovalProvider, error) {
	switch cfg.Approval.Provider {
	case "webhook":
		if cfg.Approval.Webhook.URL == "" {
			return nil, fmt.Errorf("approval provider is 'webhook' but approval.webhook.url is empty")
		}
		resumeURL := cfg.Approval.Webhook.ResumeBaseURL + "/api/v1/approval/resume"
		return gateway.NewWebhookApprovalProvider(cfg.Approval.Webhook.URL, resumeURL), nil
	case "cli", "":
		return gateway.NewCLIApprovalProvider(), nil
	default:
		fmt.Fprintf(os.Stderr, "[warn] unknown approval provider %q, falling back to CLI\n", cfg.Approval.Provider)
		return gateway.NewCLIApprovalProvider(), nil
	}
}

// buildMetricsRecorder creates the metrics recorder based on config.
// Returns nil (no-op) if OTel is disabled, which the pipeline handles gracefully.
func buildMetricsRecorder(cfg *shieldconfig.Config) gateway.MetricsRecorder {
	if !cfg.OTel.Enabled {
		return nil // nil = no-op, pipeline guards all calls
	}

	exportInterval, err := time.ParseDuration(cfg.OTel.ExportInterval)
	if err != nil || exportInterval <= 0 {
		exportInterval = 15 * time.Second
	}

	recorder, err := eino.NewOTelMetricsRecorder(eino.OTelConfig{
		Endpoint:       cfg.OTel.Endpoint,
		ServiceName:    cfg.OTel.ServiceName,
		ExportInterval: exportInterval,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[warn] OTel metrics initialization failed, metrics disabled: %v\n", err)
		return nil
	}
	return recorder
}
