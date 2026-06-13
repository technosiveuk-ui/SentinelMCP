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

package config_test

import (
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/config"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

const validPoliciesYAML = `schema_version: "1.0"
policies:
  - name: "block-file-ops"
    tools: ["fs_*"]
    action: BLOCK
  - name: "approve-destructive"
    tools: ["db_drop*", "db_delete*"]
    action: INTERRUPT
    timeout: 300s
  - name: "high-only-block"
    tools: ["exec_*"]
    action: BLOCK
    risk: high
  - name: "redact-pii"
    tools: ["*"]
    action: REDACT
    inspection: [pii, secrets]
`

func TestValidate_Policies_Valid(t *testing.T) {
	p := writeConfigAt(t, 0o600, validPoliciesYAML)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("valid policies should load: %v", err)
	}
	if !cfg.HasPolicies() {
		t.Fatal("HasPolicies should be true")
	}
}

func TestToPolicySet_BuildsRules(t *testing.T) {
	p := writeConfigAt(t, 0o600, validPoliciesYAML)
	cfg, _ := config.Load(p)

	ps, err := cfg.ToPolicySet(gateway.NewDefaultPolicy())
	if err != nil {
		t.Fatalf("ToPolicySet: %v", err)
	}

	// "interrupt" -> DecisionInterruptForApproval with the 300s timeout carried.
	res, _ := ps.Decide(t.Context(), gateway.ToolCallContext{ToolName: "db_drop_users"})
	if res.Decision != gateway.DecisionInterruptForApproval {
		t.Fatalf("db_drop* should interrupt, got %s", res.Decision)
	}
	if res.Timeout != 300*time.Second || res.PolicyName != "approve-destructive" {
		t.Fatalf("interrupt policy not carried: timeout=%v name=%q", res.Timeout, res.PolicyName)
	}

	// glob + inspection carried for redact-pii.
	res, _ = ps.Decide(t.Context(), gateway.ToolCallContext{ToolName: "anything"})
	if res.Decision != gateway.DecisionRedact || len(res.Inspection) != 2 {
		t.Fatalf("redact-pii mismatch: %s / %v", res.Decision, res.Inspection)
	}
}

func TestValidate_Policies_RejectBadAction(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - name: "x"
    tools: ["a"]
    action: NUKE
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestValidate_Policies_RejectMissingName(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - tools: ["a"]
    action: BLOCK
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for missing policy name")
	}
}

func TestValidate_Policies_RejectDuplicateName(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - name: "dup"
    tools: ["a"]
    action: BLOCK
  - name: "dup"
    tools: ["b"]
    action: ALLOW
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for duplicate policy name")
	}
}

func TestValidate_Policies_RejectMissingTools(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - name: "x"
    action: BLOCK
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for missing tools")
	}
}

func TestValidate_Policies_RejectBadRisk(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - name: "x"
    tools: ["a"]
    action: BLOCK
    risk: critical
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for invalid risk threshold")
	}
}

func TestValidate_Policies_RejectBadTimeout(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
policies:
  - name: "x"
    tools: ["a"]
    action: INTERRUPT
    timeout: not-a-duration
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestValidate_RedactionStyle(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
global:
  redaction_style: preserve_length
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("preserve_length should be valid: %v", err)
	}

	p = writeConfigAt(t, 0o600, `schema_version: "1.0"
global:
  redaction_style: scramble
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for invalid redaction_style")
	}
}
