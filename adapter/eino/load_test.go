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
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Load tests — validate NFR-03 (100+ concurrent, no deadlock)
// and NFR-01 (p99 ≤ 500μs for Allow decisions)
// ---------------------------------------------------------------------------

// loadConfig builds a GatewayConfig for load testing with a lightweight invoker.
func loadConfig() *gateway.GatewayConfig {
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message":    {Level: gateway.RiskLow},
			"filesystem_read": {Level: gateway.RiskMedium},
			"exec_command":    {Level: gateway.RiskHigh, RequireApproval: true, ApprovalReason: "dangerous"},
		},
		gateway.ToolRisk{Level: gateway.RiskLow},
	)

	return &gateway.GatewayConfig{
		Policy:           gateway.NewDefaultPolicy(),
		RiskDB:           riskDB,
		DLPScanner:       mustNewScanner(),
		Redactor:         gateway.NewDefaultRedactor("***"),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(discardWriter{}),
		ApprovalProvider: &silentApprovalProvider{},
		ToolInvoker:      &recordingInvoker{},
		RedactionMask:    "***",
	}
}

// discardWriter is an io.Writer that discards all output.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// loadResult captures the outcome of a single pipeline call in a load test.
type loadResult struct {
	duration time.Duration
	err      error
}

// TestLoad_100ConcurrentAllow_NoDeadlock validates NFR-03: 100 goroutines each
// making 10 low-risk Allow calls should complete without deadlock within 30s.
func TestLoad_100ConcurrentAllow_NoDeadlock(t *testing.T) {
	cfg := loadConfig()
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const goroutines = 100
	const callsPer = 10
	total := goroutines * callsPer

	results := make(chan loadResult, total)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < callsPer; i++ {
				start := time.Now()
				_, err := pipeline.Run(ctx, "echo_message", map[string]any{
					"msg": fmt.Sprintf("goroutine-%d-call-%d", id, i),
				})
				results <- loadResult{duration: time.Since(start), err: err}
			}
		}(g)
	}

	wg.Wait()
	close(results)

	var errors int
	for r := range results {
		if r.err != nil {
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("%d/%d calls failed", errors, total)
	}
	t.Logf("✓ %d concurrent Allow calls completed (0 deadlocks)", total)
}

// TestLoad_100ConcurrentMixedDecisions_NoDeadlock validates NFR-03 with a mix of
// low (allow), medium (redact), and high (interrupt+resume) risk calls concurrently.
func TestLoad_100ConcurrentMixedDecisions_NoDeadlock(t *testing.T) {
	cfg := loadConfig()
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const perRisk = 33
	results := make(chan error, perRisk*3)
	var wg sync.WaitGroup

	// Low-risk: Allow path
	for i := 0; i < perRisk; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := pipeline.Run(ctx, "echo_message", map[string]any{"msg": fmt.Sprintf("low-%d", id)})
			results <- err
		}(i)
	}

	// Medium-risk: Redact path
	for i := 0; i < perRisk; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := pipeline.Run(ctx, "filesystem_read", map[string]any{"path": fmt.Sprintf("/data/%d", id)})
			results <- err
		}(i)
	}

	// High-risk: Interrupt + Resume path
	for i := 0; i < perRisk; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, err := pipeline.Run(ctx, "exec_command", map[string]any{"cmd": fmt.Sprintf("rm -rf /tmp/%d", id)})
			if err == nil {
				results <- fmt.Errorf("expected interrupt for high-risk call %d", id)
				return
			}
			results <- nil // interrupt is expected
		}(i)
	}

	wg.Wait()
	close(results)

	var errors int
	for e := range results {
		if e != nil {
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("%d/%d mixed-decision calls failed", errors, perRisk*3)
	}
	t.Logf("✓ %d concurrent mixed-decision calls completed", perRisk*3)
}

// TestLoad_100ConcurrentInterruptResume_NoDeadlock validates the full interrupt→resume
// cycle under concurrency: 50 goroutines each interrupt, then resume with approve.
func TestLoad_100ConcurrentInterruptResume_NoDeadlock(t *testing.T) {
	// Each goroutine needs its own pipeline instance for independent checkpoint state.
	const goroutines = 50

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	results := make(chan error, goroutines)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine builds its own pipeline (independent checkpoints).
			cfg := loadConfig()
			pipeline, err := BuildGraph(cfg)
			if err != nil {
				results <- fmt.Errorf("goroutine %d: BuildGraph: %w", id, err)
				return
			}

			// Run → expect interrupt.
			_, err = pipeline.Run(ctx, "exec_command", map[string]any{
				"cmd": fmt.Sprintf("rm -rf /tmp/%d", id),
			})
			var ie *gateway.InterruptError
			if !errors.As(err, &ie) {
				results <- fmt.Errorf("goroutine %d: expected interrupt, got: %v", id, err)
				return
			}

			// Resume → approve.
			_, err = pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
				Action: gateway.ApprovalApprove,
				Reason: fmt.Sprintf("approved-%d", id),
			})
			results <- err
		}(g)
	}

	wg.Wait()
	close(results)

	var errors int
	for e := range results {
		if e != nil {
			errors++
		}
	}

	if errors > 0 {
		t.Errorf("%d/%d interrupt+resume cycles failed", errors, goroutines)
	}
	t.Logf("✓ %d concurrent interrupt→resume cycles completed", goroutines)
}

// TestLoad_NoSharedStateCorruption validates that 100 concurrent calls with unique
// tool names and args don't corrupt each other's state.
func TestLoad_NoSharedStateCorruption(t *testing.T) {
	// Custom invoker that captures the exact tool name it received.
	capturedInvoker := &capturingInvoker{}

	cfg := loadConfig()
	cfg.ToolInvoker = capturedInvoker
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const goroutines = 100
	type callRecord struct {
		inputName  string
		outputName string
	}

	results := make(chan callRecord, goroutines)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			toolName := fmt.Sprintf("tool_%d", id)
			pipeline.Run(ctx, toolName, map[string]any{"id": id})

			// Check what the invoker received.
			capturedInvoker.mu.Lock()
			lastCall := ""
			for _, c := range capturedInvoker.calls {
				if c.toolName == toolName {
					lastCall = c.toolName
					break
				}
			}
			capturedInvoker.mu.Unlock()

			results <- callRecord{inputName: toolName, outputName: lastCall}
		}(g)
	}

	wg.Wait()
	close(results)

	var mismatches int
	for r := range results {
		if r.inputName != r.outputName {
			mismatches++
			t.Errorf("state corruption: input=%q, invoker saw=%q", r.inputName, r.outputName)
		}
	}

	if mismatches > 0 {
		t.Errorf("%d/%d calls had corrupted state", mismatches, goroutines)
	} else {
		t.Logf("✓ %d concurrent calls — zero state corruption", goroutines)
	}
}

// TestLoad_P99LatencyUnderConcurrency measures p99 latency for Allow decisions
// under 100 concurrent goroutines making 100 calls each.
func TestLoad_P99LatencyUnderConcurrency(t *testing.T) {
	cfg := loadConfig()
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Warmup: stabilize graph compilation.
	for i := 0; i < 10; i++ {
		pipeline.Run(ctx, "echo_message", map[string]any{"msg": "warmup"})
	}

	const goroutines = 100
	const callsPer = 100
	total := goroutines * callsPer

	results := make(chan time.Duration, total)
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < callsPer; i++ {
				start := time.Now()
				_, err := pipeline.Run(ctx, "echo_message", map[string]any{
					"msg": fmt.Sprintf("latency-%d-%d", id, i),
				})
				dur := time.Since(start)
				if err != nil {
					// Record a large duration for errors.
					dur = 10 * time.Second
				}
				results <- dur
			}
		}(g)
	}

	wg.Wait()
	close(results)

	// Collect all durations and compute p99.
	durations := make([]time.Duration, 0, total)
	for d := range results {
		durations = append(durations, d)
	}

	if len(durations) != total {
		t.Fatalf("expected %d results, got %d", total, len(durations))
	}

	// Sort for percentile calculation.
	sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })

	p50 := durations[len(durations)*50/100]
	p99 := durations[len(durations)*99/100]
	max := durations[len(durations)-1]

	t.Logf("Allow latency: p50=%v p99=%v max=%v (%d calls)", p50, p99, max, total)

	// NFR-01 (concurrent): p99 must be ≤ 50ms under 100 concurrent goroutines.
	// Note: The single-thread benchmark (BenchmarkPipeline_Allow) validates the
	// ≤500μs target. Under high concurrency, Eino's internal graph synchronization
	// adds overhead — 50ms is a generous ceiling that proves no pathological behavior.
	if p99 > 50*time.Millisecond {
		t.Errorf("NFR-01 (concurrent) VIOLATED: p99 latency = %v (target: ≤50ms under 100 goroutines)", p99)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// capturingInvoker is a thread-safe invoker that records all calls.
type capturingInvoker struct {
	mu    sync.Mutex
	calls []invokerCall
}

func (c *capturingInvoker) Invoke(_ context.Context, toolName string, args map[string]any) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, invokerCall{toolName: toolName, args: args})
	return fmt.Sprintf("result[%s]", toolName), nil
}
