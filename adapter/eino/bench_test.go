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

package eino

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Benchmarks: measure gateway overhead per decision path
// ---------------------------------------------------------------------------
// NFR-01 target: ≤500μs p99 for Allow decisions on the critical path.
// ---------------------------------------------------------------------------

// benchPipeline creates a pipeline wired with a lightweight echo invoker
// (no real MCP server, to isolate gateway overhead).
// Uses a silent approval provider to avoid log noise during benchmarks.
func benchPipeline(b *testing.B) (gateway.Pipeline, *bytes.Buffer) {
	b.Helper()

	invoker := &recordingInvoker{}
	var auditBuf bytes.Buffer

	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	cfg := &gateway.GatewayConfig{
		Policy:           gateway.NewDefaultPolicy(),
		RiskDB:           riskDB,
		DLPScanner:       mustNewScanner(),
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(&auditBuf),
		ApprovalProvider: &silentApprovalProvider{},
		ToolInvoker:      invoker,
		RedactionMask:    "***",
	}

	pipeline, err := BuildGraph(cfg)
	if err != nil {
		b.Fatalf("BuildGraph: %v", err)
	}
	return pipeline, &auditBuf
}

// silentApprovalProvider does nothing — used in benchmarks to suppress log noise.
type silentApprovalProvider struct{}

func (s *silentApprovalProvider) SendApprovalRequest(_ context.Context, _ gateway.InterruptInfo) error {
	return nil
}

func (s *silentApprovalProvider) WaitForApproval(_ context.Context, _ gateway.InterruptInfo) (*gateway.ApprovalDecision, error) {
	return &gateway.ApprovalDecision{Action: gateway.ApprovalApprove}, nil
}

// BenchmarkPipeline_Allow measures the critical-path overhead for low-risk tools.
// This is the hot path — every non-sensitive tool call goes through here.
func BenchmarkPipeline_Allow(b *testing.B) {
	pipeline, _ := benchPipeline(b)
	ctx := context.Background()
	args := map[string]any{"msg": "benchmark test payload"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := pipeline.Run(ctx, "echo_message", args)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}

// BenchmarkPipeline_Redact measures the overhead for medium-risk tools
// that require DLP scanning + arg redaction.
func BenchmarkPipeline_Redact(b *testing.B) {
	pipeline, _ := benchPipeline(b)
	ctx := context.Background()
	args := map[string]any{"path": "/etc/hosts"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := pipeline.Run(ctx, "filesystem_read", args)
		if err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}

// BenchmarkPipeline_Interrupt measures the overhead for high-risk tools
// up to the point of interrupt (no resume).
func BenchmarkPipeline_Interrupt(b *testing.B) {
	pipeline, _ := benchPipeline(b)
	ctx := context.Background()
	args := map[string]any{"cmd": "rm -rf /tmp"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = pipeline.Run(ctx, "exec_command", args)
		// Error is expected (InterruptError); we measure up to that point.
	}
}

// BenchmarkPipeline_Resume measures the full interrupt → approve → resume cycle.
func BenchmarkPipeline_Resume(b *testing.B) {
	ctx := context.Background()
	args := map[string]any{"cmd": "rm -rf /tmp"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pipeline, _ := benchPipeline(b)
		b.StartTimer()

		_, err := pipeline.Run(ctx, "exec_command", args)
		if err == nil {
			b.Fatal("expected interrupt error")
		}

		var ie *gateway.InterruptError
		if !errors.As(err, &ie) {
			b.Fatalf("expected InterruptError, got: %T", err)
		}

		_, err = pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
			Action: gateway.ApprovalApprove,
			Reason: "bench",
		})
		if err != nil {
			b.Fatalf("Resume: %v", err)
		}
	}
}

// BenchmarkDLPScanner measures raw DLP scanning overhead.
func BenchmarkDLPScanner(b *testing.B) {
	scanner := mustNewScanner()
	ctx := context.Background()

	// Simulate a typical tool call argument payload.
	content := `{"msg": "hello world", "password": "supersecret123", "host": "db.example.com"}`

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := scanner.Scan(ctx, content)
		if err != nil {
			b.Fatalf("Scan: %v", err)
		}
	}
}

// BenchmarkRiskDB measures risk lookup overhead (includes glob matching).
func BenchmarkRiskDB(b *testing.B) {
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message": {Level: gateway.RiskLow},
			"filesystem_*": {Level: gateway.RiskMedium},
			"exec_command": {Level: gateway.RiskHigh, RequireApproval: true},
			"db_*":         {Level: gateway.RiskHigh, RequireApproval: true},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, _ = riskDB.Lookup("echo_message")
		_, _ = riskDB.Lookup("db_query")
		_, _ = riskDB.Lookup("unknown_tool")
	}
}

// BenchmarkPolicyDecide measures policy decision overhead.
func BenchmarkPolicyDecide(b *testing.B) {
	policy := gateway.NewDefaultPolicy()
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := policy.Decide(ctx, gateway.ToolCallContext{
			ToolName: "echo_message",
			Args:     map[string]any{"msg": "test"},
			Risk:     gateway.ToolRisk{Level: gateway.RiskLow},
		})
		if err != nil {
			b.Fatalf("Decide: %v", err)
		}
	}
}
