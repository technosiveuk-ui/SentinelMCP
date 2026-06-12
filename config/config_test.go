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

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// findConfigYAML resolves the path to config/config.yaml relative to the repo root.
func findConfigYAML(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file path")
	}
	// thisFile: .../config/config_test.go → repo root is one dir up
	repoRoot := filepath.Dir(thisFile)
	return filepath.Join(repoRoot, "config.yaml")
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.SchemaVersion != "1.0" {
		t.Errorf("expected schema_version 1.0, got %s", cfg.SchemaVersion)
	}
	if cfg.Global.DefaultRisk != "low" {
		t.Errorf("expected default_risk low, got %s", cfg.Global.DefaultRisk)
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should validate: %v", err)
	}
}

func TestLoadOrDefault_EmptyPath(t *testing.T) {
	cfg, err := LoadOrDefault("")
	if err != nil {
		t.Fatalf("LoadOrDefault error: %v", err)
	}
	if cfg.SchemaVersion != "1.0" {
		t.Errorf("expected schema 1.0, got %s", cfg.SchemaVersion)
	}
}

func TestLoad_ActualConfig(t *testing.T) {
	cfg, err := Load(findConfigYAML(t))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.SchemaVersion != "1.0" {
		t.Errorf("expected schema 1.0, got %s", cfg.SchemaVersion)
	}
	if len(cfg.Tools) == 0 {
		t.Error("expected tools in config")
	}

	// Verify specific tool configs.
	echo, ok := cfg.Tools["echo_message"]
	if !ok {
		t.Fatal("expected echo_message tool")
	}
	if echo.Risk != "low" {
		t.Errorf("expected echo_message risk low, got %s", echo.Risk)
	}

	exec, ok := cfg.Tools["exec_command"]
	if !ok {
		t.Fatal("expected exec_command tool")
	}
	if exec.Risk != "high" {
		t.Errorf("expected exec_command risk high, got %s", exec.Risk)
	}
	if !exec.RequireApproval {
		t.Error("expected exec_command to require approval")
	}
}

func TestValidate_InvalidSchemaVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SchemaVersion = "2.0"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid schema version")
	}
}

func TestValidate_EmptySchemaVersion(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SchemaVersion = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty schema version")
	}
}

func TestValidate_InvalidRisk(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tools["bad_tool"] = ToolConfig{Risk: "critical"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid risk level")
	}
}

func TestValidate_InvalidAuditOutput(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Global.AuditOutput = "syslog"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid audit output")
	}
}

func TestValidate_FileOutputWithoutPath(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Global.AuditOutput = "file"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for file output without audit_file")
	}
}

func TestValidate_InvalidRegex(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DLPPatterns["broken"] = PatternDef{Regex: "[invalid", Type: "custom"}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid regex")
	}
}

func TestValidate_UndefinedPattern(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tools["my_tool"] = ToolConfig{
		Risk:           "medium",
		RedactPatterns: []string{"NONEXISTENT_PATTERN"},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for undefined redact pattern")
	}
}

func TestToRiskDB(t *testing.T) {
	cfg, err := Load(findConfigYAML(t))
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	db := cfg.ToRiskDB()

	// Exact match.
	risk, found := db.Lookup("echo_message")
	if !found {
		t.Fatal("expected to find echo_message")
	}
	if risk.Level != gateway.RiskLow {
		t.Errorf("expected RiskLow, got %s", risk.Level)
	}

	// Glob match.
	risk, found = db.Lookup("db_query")
	if !found {
		t.Fatal("expected glob match for db_query")
	}
	if risk.Level != gateway.RiskHigh {
		t.Errorf("expected RiskHigh for db_query, got %s", risk.Level)
	}

	// Unknown tool.
	_, found = db.Lookup("nonexistent_tool")
	if found {
		t.Error("expected no match for nonexistent tool")
	}
}

func TestToDLPPatterns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DLPPatterns["CUSTOM"] = PatternDef{
		Regex: `\bCUSTOM-\d+\b`,
		Type:  "custom",
	}

	patterns := cfg.ToDLPPatterns()

	// Built-in patterns should be present.
	if _, ok := patterns["PRIVATE_KEY"]; !ok {
		t.Error("expected PRIVATE_KEY in DLP patterns")
	}
	if _, ok := patterns["PASSWORD"]; !ok {
		t.Error("expected PASSWORD in DLP patterns")
	}

	// Custom pattern should be present.
	if _, ok := patterns["CUSTOM"]; !ok {
		t.Error("expected CUSTOM in DLP patterns")
	}
}

func TestLoad_NonexistentFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestRoundTrip(t *testing.T) {
	// Create a temp config file, load it, verify it matches.
	dir := t.TempDir()
	content := `
schema_version: "1.0"
global:
  default_risk: medium
  audit_output: stdout
  redaction_mask: "[HIDDEN]"

tools:
  my_tool:
    risk: high
    require_approval: true
    approval_reason: "test reason"

dlp_patterns:
  MY_PATTERN:
    regex: '\bSECRET-\d+\b'
    type: secret
`
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write error: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	if cfg.Global.DefaultRisk != "medium" {
		t.Errorf("expected default_risk medium, got %s", cfg.Global.DefaultRisk)
	}
	if cfg.Global.RedactionMask != "[HIDDEN]" {
		t.Errorf("expected redaction mask [HIDDEN], got %s", cfg.Global.RedactionMask)
	}
	if cfg.Tools["my_tool"].Risk != "high" {
		t.Errorf("expected my_tool risk high, got %s", cfg.Tools["my_tool"].Risk)
	}
	if cfg.DLPPatterns["MY_PATTERN"].Regex != `\bSECRET-\d+\b` {
		t.Errorf("unexpected custom pattern: %v", cfg.DLPPatterns["MY_PATTERN"])
	}
}
