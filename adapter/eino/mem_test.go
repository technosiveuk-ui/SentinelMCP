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
	"fmt"
	"runtime"
	"sync"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Memory tests — validate NFR-02 (<10MB heap per 1k calls)
// ---------------------------------------------------------------------------

// heapDelta measures heap allocation delta between before and after fn runs.
func heapDelta(fn func()) uint64 {
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	fn()

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if after.HeapAlloc > before.HeapAlloc {
		return after.HeapAlloc - before.HeapAlloc
	}
	return 0
}

// memConfig builds a GatewayConfig for memory tests (discards audit output).
func memConfig() *gateway.GatewayConfig {
	riskDB := gateway.NewYAMLRiskDB(
		map[string]gateway.ToolRisk{
			"echo_message": {Level: gateway.RiskLow},
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

// TestMemory_1000ConcurrentCalls_Under10MB validates NFR-02: 1000 concurrent
// calls should not cause heap growth beyond 10MB.
func TestMemory_1000ConcurrentCalls_Under10MB(t *testing.T) {
	cfg := memConfig()
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx := context.Background()

	// Warmup: stabilize graph compilation.
	for i := 0; i < 10; i++ {
		pipeline.Run(ctx, "echo_message", map[string]any{"msg": "warmup"})
	}

	const calls = 1000
	delta := heapDelta(func() {
		var wg sync.WaitGroup
		for i := 0; i < calls; i++ {
			wg.Add(1)
			go func(id int) {
				defer wg.Done()
				pipeline.Run(ctx, "echo_message", map[string]any{
					"msg": fmt.Sprintf("mem-test-%d", id),
				})
			}(i)
		}
		wg.Wait()
	})

	mb := float64(delta) / 1024 / 1024
	t.Logf("Heap growth after %d concurrent calls: %.2f MB", calls, mb)

	// NFR-02: <10MB heap growth per 1k calls.
	if mb > 10.0 {
		t.Errorf("NFR-02 VIOLATED: %.2f MB heap growth (target: <10MB for %d calls)", mb, calls)
	}
}

// TestMemory_1000SequentialCalls_HeapGrowth validates that 1000 sequential calls
// don't accumulate heap (no goroutine or buffer leaks).
func TestMemory_1000SequentialCalls_HeapGrowth(t *testing.T) {
	cfg := memConfig()
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	ctx := context.Background()

	// Warmup: stabilize graph compilation.
	for i := 0; i < 10; i++ {
		pipeline.Run(ctx, "echo_message", map[string]any{"msg": "warmup"})
	}

	const calls = 1000
	delta := heapDelta(func() {
		for i := 0; i < calls; i++ {
			pipeline.Run(ctx, "echo_message", map[string]any{
				"msg": fmt.Sprintf("seq-mem-%d", i),
			})
		}
	})

	mb := float64(delta) / 1024 / 1024
	perCallKB := float64(delta) / float64(calls) / 1024
	t.Logf("Heap growth after %d sequential calls: %.2f MB (%.1f KB/call)", calls, mb, perCallKB)

	// NFR-02: <10MB heap growth per 1k calls.
	if mb > 10.0 {
		t.Errorf("NFR-02 VIOLATED: %.2f MB heap growth (target: <10MB for %d calls)", mb, calls)
	}
}
