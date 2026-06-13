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
	"time"
)

func TestPolicySet_FirstMatchWins(t *testing.T) {
	ps := NewPolicySet([]PolicyRule{
		{Name: "allow-echo", Tools: []string{"echo_*"}, Action: DecisionAllow},
		{Name: "block-all-echo", Tools: []string{"echo_*"}, Action: DecisionBlock}, // shadowed
	}, nil)

	// echo_message matches the first rule (allow); the second is never reached.
	res, err := ps.Decide(context.Background(), ToolCallContext{ToolName: "echo_message"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Decision != DecisionAllow || res.PolicyName != "allow-echo" {
		t.Fatalf("expected allow from allow-echo, got %s/%q", res.Decision, res.PolicyName)
	}
}

func TestPolicySet_RiskThresholdComposes(t *testing.T) {
	ps := NewPolicySet([]PolicyRule{
		// Only block fs_* when risk is high.
		{Name: "block-fs-high", Tools: []string{"fs_*"}, Action: DecisionBlock, Risk: RiskHigh},
	}, NewDefaultPolicy()) // fallback so unmatched/low-risk is not fail-closed

	// Low risk: threshold not met -> rule skipped -> fallback decides (allow).
	res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: "fs_read", Risk: ToolRisk{Level: RiskLow}})
	if res.Decision != DecisionAllow {
		t.Fatalf("low-risk fs_read should fall through to allow, got %s", res.Decision)
	}

	// High risk: threshold met -> rule blocks.
	res, _ = ps.Decide(context.Background(), ToolCallContext{ToolName: "fs_read", Risk: ToolRisk{Level: RiskHigh}})
	if res.Decision != DecisionBlock || res.PolicyName != "block-fs-high" {
		t.Fatalf("high-risk fs_read should block via block-fs-high, got %s/%q", res.Decision, res.PolicyName)
	}
}

func TestPolicySet_GlobMultiplePatterns(t *testing.T) {
	ps := NewPolicySet([]PolicyRule{
		{Name: "destructive", Tools: []string{"db_drop*", "db_delete*"}, Action: DecisionInterruptForApproval},
	}, nil)

	for _, tool := range []string{"db_drop_table", "db_delete_rows"} {
		res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: tool})
		if res.Decision != DecisionInterruptForApproval {
			t.Fatalf("%s should interrupt, got %s", tool, res.Decision)
		}
	}
	res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: "db_select"})
	if res.Decision != DecisionBlock {
		t.Fatalf("db_select should not match -> fail-closed block, got %s", res.Decision)
	}
}

func TestPolicySet_Fallback(t *testing.T) {
	// fallback = risk-based DefaultPolicy. Unmatched tool falls through to risk routing.
	ps := NewPolicySet([]PolicyRule{
		{Name: "only-echo", Tools: []string{"echo"}, Action: DecisionAllow},
	}, NewDefaultPolicy())

	res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: "other", Risk: ToolRisk{Level: RiskHigh}})
	if res.Decision != DecisionInterruptForApproval {
		t.Fatalf("unmatched high-risk tool should fall through to interrupt, got %s", res.Decision)
	}
	if res.PolicyName != "" {
		t.Fatalf("fallback decision should have empty PolicyName, got %q", res.PolicyName)
	}
}

func TestPolicySet_NoFallback_BlocksUnmatched(t *testing.T) {
	ps := NewPolicySet([]PolicyRule{
		{Name: "echo", Tools: []string{"echo"}, Action: DecisionAllow},
	}, nil) // no fallback

	res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: "other"})
	if res.Decision != DecisionBlock {
		t.Fatalf("unmatched tool with no fallback must block (fail-closed), got %s", res.Decision)
	}
}

func TestPolicySet_InspectionAndTimeoutCarried(t *testing.T) {
	ps := NewPolicySet([]PolicyRule{
		{
			Name: "redact-pii", Tools: []string{"*"}, Action: DecisionRedact,
			Inspection: []string{"pii", "secrets"}, Timeout: 300 * time.Second,
		},
	}, nil)

	res, _ := ps.Decide(context.Background(), ToolCallContext{ToolName: "anything"})
	if res.Decision != DecisionRedact {
		t.Fatalf("got %s", res.Decision)
	}
	if len(res.Inspection) != 2 || res.Inspection[0] != "pii" {
		t.Fatalf("inspection not carried: %v", res.Inspection)
	}
	if res.Timeout != 300*time.Second {
		t.Fatalf("timeout not carried: %v", res.Timeout)
	}
}

func TestRiskAtLeast(t *testing.T) {
	cases := []struct {
		level, threshold RiskLevel
		want             bool
	}{
		{RiskHigh, RiskMedium, true},
		{RiskMedium, RiskHigh, false},
		{RiskMedium, RiskMedium, true},
		{RiskLow, RiskMedium, false},
	}
	for _, c := range cases {
		if got := riskAtLeast(c.level, c.threshold); got != c.want {
			t.Errorf("riskAtLeast(%s,%s)=%v want %v", c.level, c.threshold, got, c.want)
		}
	}
}
