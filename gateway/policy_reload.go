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
)

// ReloadablePolicy is a Policy whose underlying implementation can be swapped
// atomically at runtime, without restarting the process. It is the seam the
// config watcher uses for policy hot-reload: the pipeline always holds the same
// ReloadablePolicy, and a config change calls Set with a freshly parsed policy.
//
// Concurrency follows the existing model (sync.RWMutex, like YAMLRiskDB): Decide
// takes a read lock on the hot path, Set takes a write lock. Fail-closed by
// construction — Decide blocks when no policy is set, and Set ignores nil so a
// reload error can never install an empty/allow-all policy.
type ReloadablePolicy struct {
	mu      sync.RWMutex
	current Policy
}

// NewReloadablePolicy wraps an initial Policy for atomic hot-swap. initial may
// be nil — Decide will fail-closed (block) until a real policy is Set.
func NewReloadablePolicy(initial Policy) *ReloadablePolicy {
	return &ReloadablePolicy{current: initial}
}

// Decide delegates to the current policy. If no policy is set, the call is
// blocked (fail-closed, NFR-07) rather than allowed.
func (r *ReloadablePolicy) Decide(ctx context.Context, call ToolCallContext) (*DecisionResult, error) {
	r.mu.RLock()
	p := r.current
	r.mu.RUnlock()
	if p == nil {
		return &DecisionResult{
			Decision: DecisionBlock,
			Reason:   "policy not initialized: blocked (fail-closed)",
		}, nil
	}
	return p.Decide(ctx, call)
}

// Set atomically replaces the active policy. A nil argument is ignored so a
// reload that fails to build a policy keeps the previous valid one — the sidecar
// never degrades to allow-all because of a typo in the config.
func (r *ReloadablePolicy) Set(p Policy) {
	if p == nil {
		return
	}
	r.mu.Lock()
	r.current = p
	r.mu.Unlock()
}
