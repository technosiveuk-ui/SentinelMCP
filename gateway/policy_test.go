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

package gateway

import (
	"context"
	"testing"
)

func TestDefaultPolicy_Decide_Allow(t *testing.T) {
	policy := NewDefaultPolicy()
	call := ToolCallContext{
		ToolName: "echo",
		Args:     map[string]any{"msg": "hello"},
		Risk:     ToolRisk{Level: RiskLow},
		Findings: nil,
	}

	result, err := policy.Decide(context.Background(), call)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("expected DecisionAllow, got %s", result.Decision)
	}
	if result.RiskLevel != RiskLow {
		t.Errorf("expected RiskLow, got %s", result.RiskLevel)
	}
}

func TestDefaultPolicy_Decide_Redact(t *testing.T) {
	policy := NewDefaultPolicy()
	call := ToolCallContext{
		ToolName: "db_query",
		Args:     map[string]any{"query": "SELECT * FROM users WHERE ssn='123-45-6789'"},
		Risk:     ToolRisk{Level: RiskMedium},
		Findings: []DLPFinding{
			{Type: FindingPII, Pattern: "SSN", Field: "query", Position: 30},
		},
	}

	result, err := policy.Decide(context.Background(), call)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	if result.Decision != DecisionRedact {
		t.Errorf("expected DecisionRedact, got %s", result.Decision)
	}
	if result.RedactedArgs == nil {
		t.Fatal("expected RedactedArgs to be populated")
	}
	if _, ok := result.RedactedArgs["query"]; !ok {
		t.Error("expected 'query' field to be in RedactedArgs")
	}
}

func TestDefaultPolicy_Decide_InterruptForApproval(t *testing.T) {
	policy := NewDefaultPolicy()
	call := ToolCallContext{
		ToolName: "exec_command",
		Args:     map[string]any{"cmd": "rm -rf /"},
		Risk:     ToolRisk{Level: RiskHigh, RequireApproval: true},
	}

	result, err := policy.Decide(context.Background(), call)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	if result.Decision != DecisionInterruptForApproval {
		t.Errorf("expected DecisionInterruptForApproval, got %s", result.Decision)
	}
}

func TestDefaultPolicy_Decide_Block(t *testing.T) {
	policy := &DefaultPolicy{
		RiskMapping: map[RiskLevel]Decision{
			RiskHigh: DecisionBlock,
		},
	}
	call := ToolCallContext{
		ToolName: "dangerous_tool",
		Risk:     ToolRisk{Level: RiskHigh},
	}

	result, err := policy.Decide(context.Background(), call)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	if result.Decision != DecisionBlock {
		t.Errorf("expected DecisionBlock, got %s", result.Decision)
	}
}

func TestDefaultPolicy_Decide_UnknownRisk_DefaultsToAllow(t *testing.T) {
	policy := NewDefaultPolicy()
	call := ToolCallContext{
		ToolName: "unknown_tool",
		Risk:     ToolRisk{Level: RiskLevel("critical")}, // not in mapping
	}

	result, err := policy.Decide(context.Background(), call)
	if err != nil {
		t.Fatalf("Decide returned error: %v", err)
	}

	if result.Decision != DecisionAllow {
		t.Errorf("expected DecisionAllow for unknown risk, got %s", result.Decision)
	}
}

func TestRedactedFields_NoFindings(t *testing.T) {
	result := redactedFields(map[string]any{"key": "val"}, nil)
	if result != nil {
		t.Errorf("expected nil for no findings, got %v", result)
	}
}

func TestRedactedFields_EmptyField(t *testing.T) {
	findings := []DLPFinding{
		{Type: FindingSecret, Pattern: "PASSWORD", Value: "secret123", Field: "", Position: 0},
	}
	result := redactedFields(map[string]any{"key": "val"}, findings)
	// Empty field means we can't map to an arg key — map is created but empty.
	if len(result) != 0 {
		t.Errorf("expected empty map when no findings have Field set, got %v", result)
	}
}

func TestRedactedFields_WithField(t *testing.T) {
	findings := []DLPFinding{
		{Type: FindingSecret, Pattern: "PASSWORD", Value: "secret123", Field: "password", Position: 0},
	}
	result := redactedFields(map[string]any{"password": "secret123"}, findings)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result["password"] != "***REDACTED***" {
		t.Errorf("expected redacted value, got %s", result["password"])
	}
}
