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
	"testing"
)

func TestYAMLRiskDB_ExactMatch(t *testing.T) {
	db := NewYAMLRiskDB(
		map[string]ToolRisk{
			"echo_message": {Level: RiskLow},
			"exec_command": {Level: RiskHigh, RequireApproval: true, ApprovalReason: "dangerous"},
		},
		ToolRisk{Level: RiskLow},
	)

	risk, found := db.Lookup("echo_message")
	if !found {
		t.Fatal("expected to find echo_message")
	}
	if risk.Level != RiskLow {
		t.Errorf("expected RiskLow, got %s", risk.Level)
	}

	risk, found = db.Lookup("exec_command")
	if !found {
		t.Fatal("expected to find exec_command")
	}
	if risk.Level != RiskHigh {
		t.Errorf("expected RiskHigh, got %s", risk.Level)
	}
	if !risk.RequireApproval {
		t.Error("expected RequireApproval")
	}
}

func TestYAMLRiskDB_GlobMatch(t *testing.T) {
	db := NewYAMLRiskDB(
		map[string]ToolRisk{
			"db_*": {Level: RiskHigh, RequireApproval: true},
		},
		ToolRisk{Level: RiskLow},
	)

	risk, found := db.Lookup("db_query")
	if !found {
		t.Fatal("expected glob to match db_query")
	}
	if risk.Level != RiskHigh {
		t.Errorf("expected RiskHigh, got %s", risk.Level)
	}

	risk, found = db.Lookup("db_insert")
	if !found {
		t.Fatal("expected glob to match db_insert")
	}
	if risk.Level != RiskHigh {
		t.Errorf("expected RiskHigh, got %s", risk.Level)
	}
}

func TestYAMLRiskDB_NoMatch_ReturnsDefault(t *testing.T) {
	db := NewYAMLRiskDB(
		map[string]ToolRisk{
			"known_tool": {Level: RiskMedium},
		},
		ToolRisk{Level: RiskLow},
	)

	_, found := db.Lookup("unknown_tool")
	if found {
		t.Error("expected no match for unknown_tool")
	}
}

func TestYAMLRiskDB_ExactMatchPreferred(t *testing.T) {
	db := NewYAMLRiskDB(
		map[string]ToolRisk{
			"db_admin": {Level: RiskHigh},
			"db_*":     {Level: RiskMedium},
		},
		ToolRisk{Level: RiskLow},
	)

	risk, found := db.Lookup("db_admin")
	if !found {
		t.Fatal("expected to find db_admin")
	}
	if risk.Level != RiskHigh {
		t.Errorf("exact match should take priority, expected RiskHigh got %s", risk.Level)
	}

	risk, found = db.Lookup("db_other")
	if !found {
		t.Fatal("expected glob to match db_other")
	}
	if risk.Level != RiskMedium {
		t.Errorf("expected glob match to return RiskMedium, got %s", risk.Level)
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, name string
		want          bool
	}{
		{"db_*", "db_query", true},
		{"db_*", "db_", true},
		{"db_*", "db", false},
		{"*", "anything", true},
		{"*_test", "unit_test", true},
		{"*_test", "integration_test", true},
		{"*_test", "production", false},
		{"file?read", "file_read", true},
		{"file?read", "fileread", false},
		{"exact", "exact", true},
		{"exact", "other", false},
	}

	for _, tt := range tests {
		got := matchGlob(tt.pattern, tt.name)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}
