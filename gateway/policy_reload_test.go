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
	"sync"
	"testing"
)

func TestReloadablePolicy_Swap(t *testing.T) {
	block := &DefaultPolicy{RiskMapping: map[RiskLevel]Decision{RiskLow: DecisionBlock}}
	allow := &DefaultPolicy{RiskMapping: map[RiskLevel]Decision{RiskLow: DecisionAllow}}

	r := NewReloadablePolicy(block)
	res, _ := r.Decide(context.Background(), ToolCallContext{Risk: ToolRisk{Level: RiskLow}})
	if res.Decision != DecisionBlock {
		t.Fatalf("initial policy should block, got %s", res.Decision)
	}

	r.Set(allow) // hot-swap
	res, _ = r.Decide(context.Background(), ToolCallContext{Risk: ToolRisk{Level: RiskLow}})
	if res.Decision != DecisionAllow {
		t.Fatalf("after swap should allow, got %s", res.Decision)
	}
}

func TestReloadablePolicy_NilInitial_Blocks(t *testing.T) {
	r := NewReloadablePolicy(nil)
	res, _ := r.Decide(context.Background(), ToolCallContext{})
	if res.Decision != DecisionBlock {
		t.Fatalf("nil policy must fail-closed (block), got %s", res.Decision)
	}
}

func TestReloadablePolicy_SetNil_Ignored(t *testing.T) {
	allow := &DefaultPolicy{RiskMapping: map[RiskLevel]Decision{RiskLow: DecisionAllow}}
	r := NewReloadablePolicy(allow)
	r.Set(nil) // a reload error must never install nil/allow-all
	res, _ := r.Decide(context.Background(), ToolCallContext{Risk: ToolRisk{Level: RiskLow}})
	if res.Decision != DecisionAllow {
		t.Fatalf("Set(nil) must not replace the policy, got %s", res.Decision)
	}
}

// TestReloadablePolicy_Concurrent exercises Decide-under-swap under the race
// detector: many readers overlapping a writer must not race or panic.
func TestReloadablePolicy_Concurrent(t *testing.T) {
	r := NewReloadablePolicy(NewDefaultPolicy())
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = r.Decide(context.Background(), ToolCallContext{Risk: ToolRisk{Level: RiskLow}})
		}()
		go func() {
			defer wg.Done()
			r.Set(NewDefaultPolicy())
		}()
	}
	wg.Wait()
}
