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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// fakeStore is a checkpointDeleter that records Delete calls.
type fakeStore struct {
	mu      sync.Mutex
	deleted []string
}

func (s *fakeStore) Get(context.Context, string) ([]byte, bool, error) { return nil, false, nil }
func (s *fakeStore) Set(context.Context, string, []byte) error         { return nil }
func (s *fakeStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = append(s.deleted, id)
	return nil
}
func (s *fakeStore) deletedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.deleted))
	copy(out, s.deleted)
	return out
}

func sampleInfo() gateway.InterruptInfo {
	return gateway.InterruptInfo{
		ID:           "interrupt-1",
		CheckpointID: "cp-1",
		ToolName:     "db_drop_table",
		RiskLevel:    gateway.RiskHigh,
		Reason:       "destructive",
	}
}

// TestRegistry_ClaimPending_ThenRemoved: a resume before the deadline wins, and
// the entry is gone (no state leak).
func TestRegistry_ClaimPending_ThenRemoved(t *testing.T) {
	r := newInterruptRegistry(nil)
	defer r.Close()
	r.Register("cp-1", sampleInfo(), time.Minute, nil)

	if err := r.Claim("cp-1"); err != nil {
		t.Fatalf("Claim pending: want nil, got %v", err)
	}
	if _, ok := r.entries["cp-1"]; ok {
		t.Fatal("entry not removed after claim (state leak)")
	}
}

func TestRegistry_ClaimUnknown(t *testing.T) {
	r := newInterruptRegistry(nil)
	defer r.Close()
	if !errors.Is(r.Claim("nope"), ErrUnknownInterrupt) {
		t.Fatalf("Claim unknown: want ErrUnknownInterrupt, got %v", r.Claim("nope"))
	}
}

// TestRegistry_Timeout_AutoBlocksAndInvalidates: when the timer fires, the
// onTimeout callback runs (audit/metric), the checkpoint is deleted from the
// store, and a later Claim returns ErrCheckpointExpired.
func TestRegistry_Timeout_AutoBlocksAndInvalidates(t *testing.T) {
	store := &fakeStore{}
	r := newInterruptRegistry(store)
	defer r.Close()
	r.grace = time.Hour // keep the entry around so we can observe ErrCheckpointExpired

	var fired atomic.Int32
	info := sampleInfo()
	var seen gateway.InterruptInfo
	var seenMu sync.Mutex
	cb := func(gi gateway.InterruptInfo) {
		seenMu.Lock()
		seen = gi
		seenMu.Unlock()
		fired.Add(1)
	}
	r.Register("cp-1", info, 20*time.Millisecond, cb)

	// Wait for the timer to fire.
	deadline := time.After(2 * time.Second)
	for fired.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("onTimeout callback never fired")
		case <-time.After(5 * time.Millisecond):
		}
	}

	seenMu.Lock()
	if seen.ToolName != info.ToolName || seen.CheckpointID != info.CheckpointID {
		t.Fatalf("onTimeout got wrong info: %+v", seen)
	}
	seenMu.Unlock()

	if got := store.deletedIDs(); len(got) != 1 || got[0] != "cp-1" {
		t.Fatalf("checkpoint not invalidated on timeout; deleted=%v", got)
	}

	if !errors.Is(r.Claim("cp-1"), ErrCheckpointExpired) {
		t.Fatalf("late Claim: want ErrCheckpointExpired, got %v", r.Claim("cp-1"))
	}
}

// TestRegistry_ClaimWinsRace_OverTimeout: a resume arriving just before the
// deadline wins; the timer callback that fires afterward is a no-op (no zombie,
// no double-callback).
func TestRegistry_ClaimWinsRace_OverTimeout(t *testing.T) {
	r := newInterruptRegistry(&fakeStore{})
	defer r.Close()

	var fired atomic.Int32
	r.Register("cp-1", sampleInfo(), 30*time.Millisecond, func(gateway.InterruptInfo) {
		fired.Add(1)
	})

	if err := r.Claim("cp-1"); err != nil {
		t.Fatalf("Claim: want nil, got %v", err)
	}

	// Wait past the original deadline; the timer must not fire (it was stopped).
	time.Sleep(80 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatal("onTimeout fired after a successful claim (zombie timer)")
	}
}

// TestRegistry_ExpiredEntry_ReapedAfterGrace: after the grace window, an expired
// entry is garbage-collected so the registry cannot grow unbounded; a Claim then
// returns ErrUnknownInterrupt rather than ErrCheckpointExpired.
func TestRegistry_ExpiredEntry_ReapedAfterGrace(t *testing.T) {
	r := newInterruptRegistry(&fakeStore{})
	defer r.Close()
	r.grace = 40 * time.Millisecond

	var fired atomic.Int32
	r.Register("cp-1", sampleInfo(), 15*time.Millisecond, func(gateway.InterruptInfo) { fired.Add(1) })

	// Wait for expiry + grace + reap.
	time.Sleep(150 * time.Millisecond)
	if fired.Load() != 1 {
		t.Fatalf("onTimeout should have fired once, got %d", fired.Load())
	}

	r.mu.Lock()
	_, present := r.entries["cp-1"]
	r.mu.Unlock()
	if present {
		t.Fatal("expired entry not reaped after grace window (state leak)")
	}
	if !errors.Is(r.Claim("cp-1"), ErrUnknownInterrupt) {
		t.Fatalf("post-grace Claim: want ErrUnknownInterrupt, got %v", r.Claim("cp-1"))
	}
}

// TestRegistry_Register_ReplacesExisting: a re-interrupt on the same checkpoint
// replaces the prior entry and stops its timers (never two live timers per cpID).
func TestRegistry_Register_ReplacesExisting(t *testing.T) {
	r := newInterruptRegistry(nil)
	defer r.Close()

	var fired atomic.Int32
	r.Register("cp-1", sampleInfo(), 20*time.Millisecond, func(gateway.InterruptInfo) { fired.Add(1) })
	// Immediately re-register with a longer timeout (simulates re-interrupt).
	r.Register("cp-1", sampleInfo(), time.Hour, func(gateway.InterruptInfo) { fired.Add(1) })

	time.Sleep(60 * time.Millisecond)
	if fired.Load() != 0 {
		t.Fatalf("replaced entry's timer fired (old timer not stopped): %d", fired.Load())
	}
	if err := r.Claim("cp-1"); err != nil {
		t.Fatalf("Claim after re-register: want nil, got %v", err)
	}
}

func TestResolveTimeout(t *testing.T) {
	cases := []struct {
		name         string
		policy, glob time.Duration
		want         time.Duration
	}{
		{"policy wins", 5 * time.Second, time.Minute, 5 * time.Second},
		{"global fallback", 0, 2 * time.Minute, 2 * time.Minute},
		{"cap when both zero", 0, 0, defaultApprovalTimeout},
		{"negative ignored", -1, -1, defaultApprovalTimeout},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTimeout(c.policy, c.glob); got != c.want {
				t.Fatalf("resolveTimeout(%v,%v) = %v, want %v", c.policy, c.glob, got, c.want)
			}
		})
	}
}
