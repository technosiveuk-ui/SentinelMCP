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

// Package config provides YAML configuration loading and validation for SentinelMCP.
package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Config structs (mirrors the YAML DSL from the design doc)
// ---------------------------------------------------------------------------

// Config is the top-level SentinelMCP configuration.
type Config struct {
	SchemaVersion string                `yaml:"schema_version"`
	Global        GlobalConfig          `yaml:"global"`
	Tools         map[string]ToolConfig `yaml:"tools"`
	DLPPatterns   map[string]PatternDef `yaml:"dlp_patterns"`
	Sidecar       SidecarConfig         `yaml:"sidecar"`
	SIEM          SIEMConfig            `yaml:"siem"`
	OTel          OTelConfig            `yaml:"otel"`
	Approval      ApprovalConfig        `yaml:"approval"`
}

// GlobalConfig contains settings that apply to all tools unless overridden.
type GlobalConfig struct {
	DefaultRisk        string            `yaml:"default_risk"`
	AuditOutput        string            `yaml:"audit_output"`
	AuditFile          string            `yaml:"audit_file"`
	RedactionMask      string            `yaml:"redaction_mask"`
	DefaultDLPPatterns []string          `yaml:"default_dlp_patterns"`
	PolicyDefaults     map[string]string `yaml:"policy_defaults"`
}

// ToolConfig is the risk configuration for a single tool (or glob pattern).
type ToolConfig struct {
	Risk            string   `yaml:"risk"`
	RequireApproval bool     `yaml:"require_approval"`
	ApprovalReason  string   `yaml:"approval_reason"`
	RedactPatterns  []string `yaml:"redact_patterns"`
}

// PatternDef defines a single DLP pattern.
type PatternDef struct {
	Regex string `yaml:"regex"`
	Type  string `yaml:"type"` // "secret" | "pii" | "custom"
}

// ---------------------------------------------------------------------------
// Sidecar proxy configuration
// ---------------------------------------------------------------------------

// SidecarConfig configures the sidecar proxy binary.
type SidecarConfig struct {
	ListenAddr      string           `yaml:"listen_addr"`     // e.g. "localhost:8080"
	Transport       string           `yaml:"transport"`       // "stdio" | "streamable_http"
	HealthAddr      string           `yaml:"health_addr"`     // e.g. "localhost:9090"
	CheckpointPath  string           `yaml:"checkpoint_path"` // BoltDB path, e.g. "./sentinelmcp-checkpoints.db"
	UpstreamServers []UpstreamConfig `yaml:"upstream_servers"`
}

// UpstreamConfig describes a single upstream MCP server.
type UpstreamConfig struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"` // e.g. "http://localhost:3001/mcp"
}

// ---------------------------------------------------------------------------
// SIEM configuration
// ---------------------------------------------------------------------------

// SIEMConfig configures audit sink destinations.
type SIEMConfig struct {
	Sinks []SinkConfig `yaml:"sinks"`
}

// SinkConfig describes a single audit sink.
type SinkConfig struct {
	Type       string `yaml:"type"`        // "splunk_hec" | "file"
	Endpoint   string `yaml:"endpoint"`    // for splunk_hec
	Token      string `yaml:"token"`       // for splunk_hec
	Path       string `yaml:"path"`        // for file
	MaxSizeMB  int    `yaml:"max_size_mb"` // for file (Sprint 2)
	MaxBackups int    `yaml:"max_backups"` // for file (Sprint 2)
	Compress   bool   `yaml:"compress"`    // for file (Sprint 2)
}

// ---------------------------------------------------------------------------
// OpenTelemetry configuration
// ---------------------------------------------------------------------------

// OTelConfig configures OpenTelemetry metrics export.
type OTelConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Endpoint       string `yaml:"endpoint"`        // e.g. "localhost:4317"
	ServiceName    string `yaml:"service_name"`    // e.g. "sentinelmcp"
	ExportInterval string `yaml:"export_interval"` // e.g. "15s"
}

// ---------------------------------------------------------------------------
// Approval provider configuration
// ---------------------------------------------------------------------------

// ApprovalConfig configures the human-in-the-loop approval provider.
type ApprovalConfig struct {
	Provider string        `yaml:"provider"` // "cli" | "webhook"
	Webhook  WebhookConfig `yaml:"webhook"`
}

// WebhookConfig configures the generic webhook approval provider.
type WebhookConfig struct {
	URL           string `yaml:"url"`             // webhook endpoint URL
	ResumeBaseURL string `yaml:"resume_base_url"` // e.g. "http://localhost:9090"
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

// DefaultConfig returns a Config with sensible defaults (zero configuration).
// All tools are treated as low risk, audit goes to stdout.
func DefaultConfig() *Config {
	return &Config{
		SchemaVersion: "1.0",
		Global: GlobalConfig{
			DefaultRisk:        "low",
			AuditOutput:        "stdout",
			RedactionMask:      "***REDACTED***",
			DefaultDLPPatterns: []string{"PRIVATE_KEY", "PASSWORD"},
			PolicyDefaults: map[string]string{
				"low":    "allow",
				"medium": "redact",
				"high":   "interrupt_for_approval",
			},
		},
		Tools:       map[string]ToolConfig{},
		DLPPatterns: map[string]PatternDef{},
		Sidecar: SidecarConfig{
			ListenAddr:     "localhost:8080",
			Transport:      "streamable_http",
			HealthAddr:     "localhost:9090",
			CheckpointPath: "./sentinelmcp-checkpoints.db",
		},
		OTel: OTelConfig{
			Enabled:        false,
			Endpoint:       "localhost:4317",
			ServiceName:    "sentinelmcp",
			ExportInterval: "15s",
		},
		Approval: ApprovalConfig{
			Provider: "cli",
			Webhook: WebhookConfig{
				ResumeBaseURL: "http://localhost:9090",
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parse YAML: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadOrDefault returns the config from path, or defaults if path is empty.
func LoadOrDefault(path string) (*Config, error) {
	if path == "" {
		return DefaultConfig(), nil
	}
	return Load(path)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// Validate checks the config for errors. Returns actionable error messages (NFR-12).
func (c *Config) Validate() error {
	// 1. schema_version is required and must be "1.0".
	if c.SchemaVersion == "" {
		return fmt.Errorf("config: schema_version is required (must be \"1.0\")")
	}
	if c.SchemaVersion != "1.0" {
		return fmt.Errorf("config: unsupported schema_version %q (supported: [\"1.0\"])", c.SchemaVersion)
	}

	// 2. global.default_risk must be valid.
	validRisks := map[string]bool{"low": true, "medium": true, "high": true}
	if c.Global.DefaultRisk != "" && !validRisks[c.Global.DefaultRisk] {
		return fmt.Errorf("config: global.default_risk: must be one of [low, medium, high], got %q", c.Global.DefaultRisk)
	}

	// 3. global.audit_output must be valid.
	validOutputs := map[string]bool{"stdout": true, "stderr": true, "file": true}
	if c.Global.AuditOutput != "" && !validOutputs[c.Global.AuditOutput] {
		return fmt.Errorf("config: global.audit_output: must be one of [stdout, stderr, file], got %q", c.Global.AuditOutput)
	}

	// 4. file output requires audit_file path.
	if c.Global.AuditOutput == "file" && c.Global.AuditFile == "" {
		return fmt.Errorf("config: global.audit_file is required when global.audit_output is \"file\"")
	}

	// 5. Each tool's risk must be valid.
	for name, tc := range c.Tools {
		if !validRisks[tc.Risk] {
			return fmt.Errorf("config: tools.%s.risk: must be one of [low, medium, high], got %q", name, tc.Risk)
		}
	}

	// 6. Validate DLP patterns compile.
	for name, def := range c.DLPPatterns {
		if _, err := regexp.Compile(def.Regex); err != nil {
			return fmt.Errorf("config: dlp_patterns.%s.regex: invalid regexp: %w", name, err)
		}
	}

	// 7. Tool redact_patterns must reference built-in or defined patterns.
	builtins := gateway.BuiltinPatterns()
	for toolName, tc := range c.Tools {
		for i, patName := range tc.RedactPatterns {
			if _, isBuiltin := builtins[patName]; !isBuiltin {
				if _, isDefined := c.DLPPatterns[patName]; !isDefined {
					return fmt.Errorf("config: tools.%s.redact_patterns[%d]: undefined pattern %q (not in dlp_patterns or built-ins)",
						toolName, i, patName)
				}
			}
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Conversion to gateway types
// ---------------------------------------------------------------------------

// ToRiskDB converts the tools config into a gateway.RiskDB.
func (c *Config) ToRiskDB() gateway.RiskDB {
	tools := make(map[string]gateway.ToolRisk, len(c.Tools))
	for name, tc := range c.Tools {
		tools[name] = gateway.ToolRisk{
			Level:           gateway.RiskLevel(tc.Risk),
			RequireApproval: tc.RequireApproval,
			ApprovalReason:  tc.ApprovalReason,
			RedactPatterns:  tc.RedactPatterns,
		}
	}

	defaultRisk := gateway.ToolRisk{
		Level: gateway.RiskLevel(c.Global.DefaultRisk),
	}
	if defaultRisk.Level == "" {
		defaultRisk.Level = gateway.RiskLow
	}

	return gateway.NewYAMLRiskDB(tools, defaultRisk)
}

// ToDLPPatterns merges built-in patterns with user-defined patterns,
// including only those referenced in global.default_dlp_patterns and tool configs.
func (c *Config) ToDLPPatterns() map[string]gateway.PatternDef {
	patterns := gateway.BuiltinPatterns()

	// Add/override with user-defined patterns.
	for name, def := range c.DLPPatterns {
		patterns[name] = gateway.PatternDef{
			Regex: def.Regex,
			Type:  def.Type,
		}
	}

	return patterns
}
