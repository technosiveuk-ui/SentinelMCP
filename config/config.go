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
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

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
	Policies      []PolicyDef           `yaml:"policies"`
	Sidecar       SidecarConfig         `yaml:"sidecar"`
	Auth          AuthConfig            `yaml:"auth"`
	Secrets       SecretsConfig         `yaml:"secrets"`
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

// PolicyDef defines one action-based policy rule. The action-based layer
// composes with the existing risk model: a rule matches a tools/call when the
// tool name matches any Tools glob and, if Risk is set, the call's risk is at
// least Risk. The first matching rule (in order) wins.
type PolicyDef struct {
	Name       string   `yaml:"name"`       // required; surfaced in audit
	Tools      []string `yaml:"tools"`      // required; glob patterns
	Action     string   `yaml:"action"`     // required; ALLOW | BLOCK | REDACT | INTERRUPT
	Risk       string   `yaml:"risk"`       // optional threshold; low | medium | high
	Inspection []string `yaml:"inspection"` // DLP categories on REDACT (Step 3); e.g. pii, secrets
	Timeout    string   `yaml:"timeout"`    // INTERRUPT timeout override (Step 5); e.g. 300s
}

// ---------------------------------------------------------------------------
// Sidecar proxy configuration
// ---------------------------------------------------------------------------

// SidecarConfig configures the sidecar proxy binary.
type SidecarConfig struct {
	ListenAddr      string           `yaml:"listen_addr"`     // e.g. "localhost:8080"
	Transport       string           `yaml:"transport"`       // "stdio" | "streamable_http"
	HealthAddr      string           `yaml:"health_addr"`     // e.g. "localhost:9090"
	AdminToken      string           `yaml:"admin_token"`      // gates /api/v1/approval/resume; override via SENTINELMCP_ADMIN_TOKEN
	Strict          bool             `yaml:"strict"`           // default true: reject http:// + IP-literal upstreams at load (fail-closed)
	EgressAllowlist []string         `yaml:"egress_allowlist"` // host suffixes; when set, upstream hosts must match (IPs must match exactly)
	CheckpointPath  string           `yaml:"checkpoint_path"`  // BoltDB path, e.g. "./sentinelmcp-checkpoints.db"
	TLS             TLSConfig        `yaml:"tls"`             // opt-in inbound TLS; required when listen_addr is non-loopback
	UpstreamServers []UpstreamConfig `yaml:"upstream_servers"`
}

// TLSConfig configures inbound TLS for the MCP proxy listener.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"` // PEM cert file path
	KeyFile  string `yaml:"key_file"`  // PEM key file path
}

// ---------------------------------------------------------------------------
// Inbound authentication configuration
// ---------------------------------------------------------------------------

// AuthConfig configures inbound caller authentication for the MCP proxy.
// OSS ships the static API-key authenticator; Enterprise plugs in mTLS/OAuth2
// behind the same gateway/auth.Authenticator seam.
type AuthConfig struct {
	APIKeys map[string]string `yaml:"api_keys"` // key -> principal; enforced on every inbound call when non-empty
}

// SecretsConfig configures outbound credential resolution for upstream MCP
// servers. OSS ships the file/env provider; Enterprise plugs in Vault / ASM /
// GCP SM behind the same gateway/secrets.Provider seam.
type SecretsConfig struct {
	Provider string `yaml:"provider"` // "file" (OSS); Enterprise overrides in SentinelENT
	File     string `yaml:"file"`     // path to secrets.yaml (mode 0600 enforced); empty = env-only
}

// UpstreamConfig describes a single upstream MCP server.
type UpstreamConfig struct {
	Name         string `yaml:"name"`
	URL          string `yaml:"url"`          // e.g. "https://fs.local/mcp"
	CABundle     string `yaml:"ca_bundle"`    // PEM CA bundle: inline PEM or a file path; empty = system roots
	ServerName   string `yaml:"server_name"`  // TLS SNI / verification hostname override
	PinnedSHA256 string `yaml:"pinned_sha256"` // hex SHA-256 of the leaf cert SPKI; additional pin on top of chain validation
	CredentialsRef string `yaml:"credentials_ref"` // key into the secrets provider; empty = no credentials injected
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
			Strict:         true, // reject http:// + IP-literal upstreams at config load
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

	// Fail-closed (NFR-06 family): a config file holding a secret must not be
	// readable by group or other users.
	if err := cfg.guardSecretFilePerms(path); err != nil {
		return nil, err
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

// guardSecretFilePerms enforces the secrets-at-rest discipline (NFR-06 family).
// A config file that contains a secret (sidecar.admin_token now; auth.api_keys
// lands in a later step) must not be readable by group or other users. Fail-closed.
func (c *Config) guardSecretFilePerms(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0077 != 0 { // any group/other access bits set
		if c.Sidecar.AdminToken != "" || len(c.Auth.APIKeys) > 0 {
			return fmt.Errorf(
				"config: %s is group/world-readable (mode %o) but contains secrets "+
					"(sidecar.admin_token and/or auth.api_keys): tighten the file to mode 0600, "+
					"or supply secrets via the SENTINELMCP_ADMIN_TOKEN env var / a separate 0600 secrets file",
				path, info.Mode().Perm(),
			)
		}
	}
	return nil
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

	// 8. Action-based policies (compose with the risk model). Validated at load
	// so a malformed initial policies section is fatal (fail-loud at startup),
	// and a malformed hot-reload is rejected before the swap (fail-closed).
	seenPolicyNames := make(map[string]bool, len(c.Policies))
	for i, p := range c.Policies {
		if p.Name == "" {
			return fmt.Errorf("config: policies[%d].name is required", i)
		}
		if seenPolicyNames[p.Name] {
			return fmt.Errorf("config: policies[%d].name %q is duplicate (policy names must be unique)", i, p.Name)
		}
		seenPolicyNames[p.Name] = true

		if len(p.Tools) == 0 {
			return fmt.Errorf("config: policies[%d] (%q): tools is required (at least one glob)", i, p.Name)
		}
		if _, err := parseAction(p.Action); err != nil {
			return fmt.Errorf("config: policies[%d] (%q): %w", i, p.Name, err)
		}
		if p.Risk != "" && !validRisks[p.Risk] {
			return fmt.Errorf("config: policies[%d] (%q): risk must be one of [low, medium, high], got %q", i, p.Name, p.Risk)
		}
		if p.Timeout != "" {
			if d, err := time.ParseDuration(p.Timeout); err != nil || d <= 0 {
				return fmt.Errorf("config: policies[%d] (%q): timeout must be a positive duration (e.g. 300s), got %q", i, p.Name, p.Timeout)
			}
		}
	}

	// 9. Upstream transport + egress policy (fail-closed, NFR-07 family). In
	// strict mode, reject plaintext (http://) schemes and IP-literal hosts
	// (unless the IP is an exact egress_allowlist entry). When an egress
	// allowlist is set, require every upstream host to match it. Forces TLS +
	// bounded, hostname-based egress in production.
	for _, us := range c.Sidecar.UpstreamServers {
		if err := validateUpstream(us, c.Sidecar.Strict, c.Sidecar.EgressAllowlist); err != nil {
			return err
		}
	}

	return nil
}

// validateUpstream enforces the strict-mode scheme/IP policy and the egress
// allowlist for a single upstream. Returns an actionable error (NFR-12).
func validateUpstream(us UpstreamConfig, strict bool, allowlist []string) error {
	u, err := url.Parse(us.URL)
	if err != nil {
		return fmt.Errorf("config: upstream %q has invalid URL %q: %w", us.Name, us.URL, err)
	}
	host := u.Hostname()

	if strict {
		if u.Scheme != "https" {
			return fmt.Errorf("config: upstream %q URL %q uses plaintext scheme %q, but sidecar.strict is enabled: "+
				"use https://, or set sidecar.strict: false only for a trusted private-network upstream",
				us.Name, us.URL, u.Scheme)
		}
		// IP literals are rejected in strict mode unless they are an exact
		// egress_allowlist entry (IPs defeat SNI, cert SAN matching, and
		// hostname-based allowlisting, so they must be opt-in explicit).
		if host != "" && net.ParseIP(host) != nil && !hostAllowed(host, allowlist) {
			return fmt.Errorf("config: upstream %q URL %q uses an IP-literal host %q, but sidecar.strict is enabled: "+
				"use a hostname, or add the exact IP to sidecar.egress_allowlist",
				us.Name, us.URL, host)
		}
	}

	if len(allowlist) > 0 && !hostAllowed(host, allowlist) {
		return fmt.Errorf("config: upstream %q host %q is not permitted by sidecar.egress_allowlist %q",
			us.Name, host, allowlist)
	}

	return nil
}

// hostAllowed reports whether host matches the egress allowlist. Hostnames match
// by exact or suffix (subdomain) entry — ".local" matches "fs.local"; IP
// literals match by exact entry only (suffix matching on IPs is unsafe).
func hostAllowed(host string, allowlist []string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	isIP := net.ParseIP(host) != nil
	for _, raw := range allowlist {
		entry := strings.ToLower(strings.TrimSpace(raw))
		entry = strings.TrimPrefix(entry, ".")
		if entry == "" {
			continue
		}
		if isIP {
			if host == entry {
				return true
			}
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
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

// parseAction parses a YAML action string into a gateway.Decision. Accepts the
// short INTERRUPT form as well as the canonical interrupt_for_approval value,
// case-insensitively. Returns an actionable error (NFR-12).
func parseAction(s string) (gateway.Decision, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "allow":
		return gateway.DecisionAllow, nil
	case "block":
		return gateway.DecisionBlock, nil
	case "redact":
		return gateway.DecisionRedact, nil
	case "interrupt", "interrupt_for_approval":
		return gateway.DecisionInterruptForApproval, nil
	case "":
		return "", fmt.Errorf("action is required (ALLOW | BLOCK | REDACT | INTERRUPT)")
	default:
		return "", fmt.Errorf("invalid action %q (want ALLOW | BLOCK | REDACT | INTERRUPT)", s)
	}
}

// ToPolicySet builds an action-based gateway.PolicySet from the configured
// policies. fallback is consulted for tools no rule matches (typically the
// risk-based DefaultPolicy); pass nil to block unmatched tools (fail-closed).
// Validate() should already have caught malformed entries; this is defensive.
func (c *Config) ToPolicySet(fallback gateway.Policy) (*gateway.PolicySet, error) {
	rules := make([]gateway.PolicyRule, 0, len(c.Policies))
	for _, pd := range c.Policies {
		action, err := parseAction(pd.Action)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", pd.Name, err)
		}
		var timeout time.Duration
		if pd.Timeout != "" {
			timeout, err = time.ParseDuration(pd.Timeout)
			if err != nil {
				return nil, fmt.Errorf("policy %q: invalid timeout %q: %w", pd.Name, pd.Timeout, err)
			}
		}
		rules = append(rules, gateway.PolicyRule{
			Name:       pd.Name,
			Tools:      pd.Tools,
			Action:     action,
			Risk:       gateway.RiskLevel(pd.Risk),
			Inspection: pd.Inspection,
			Timeout:    timeout,
		})
	}
	return gateway.NewPolicySet(rules, fallback), nil
}

// HasPolicies reports whether action-based policies are configured. When false,
// the sidecar uses the risk-based DefaultPolicy (fully backward-compatible).
func (c *Config) HasPolicies() bool { return len(c.Policies) > 0 }
