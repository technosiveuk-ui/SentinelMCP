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
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Approval timeout / auto-block registry
// ---------------------------------------------------------------------------

// defaultApprovalTimeout is the last-resort finite cap applied when neither the
// policy rule nor the global approval.default_timeout supplies one. Every
// interrupt gets a finite timeout — an unbounded wait is a denial-of-service
// vector against the gateway's checkpoint state (Step 5).
const defaultApprovalTimeout = 10 * time.Minute

// expiredEntryGrace is how long an expired entry lingers before garbage
// collection. A late resume arriving within this window still gets
// ErrCheckpointExpired (a clear, audit-distinct error) rather than the generic
// ErrUnknownInterrupt; after the window the entry is reaped so the registry
// cannot grow unbounded.
const expiredEntryGrace = 5 * time.Minute

// checkpointDeleter is an optional capability of a compose.CheckPointStore: the
// ability to remove a checkpoint. compose.CheckPointStore only mandates Get/Set;
// both the in-memory and BoltDB stores add Delete so an expired interrupt can be
// invalidated at the store level too (defense in depth on top of the registry
// gate — the paused graph state is destroyed, not just hidden).
type checkpointDeleter interface {
	Delete(ctx context.Context, id string) error
}

// deleterFor returns the store's Delete capability, or nil if the store doesn't
// implement it (expiry then degrades to registry-gating only).
func deleterFor(store any) checkpointDeleter {
	if d, ok := store.(checkpointDeleter); ok {
		return d
	}
	return nil
}

// interruptState tracks the lifecycle of one pending approval.
type interruptState int

const (
	interruptPending   interruptState = iota // waiting for a resume
	interruptExpired                         // timer fired -> auto-blocked
	interruptCancelled                       // resumed before the timer fired
)

// pendingInterrupt is one registry entry.
type pendingInterrupt struct {
	info      gateway.InterruptInfo
	timeout   time.Duration
	timer     *time.Timer // fires -> expire
	gcTimer   *time.Timer // reaps an expired entry after the grace window
	state     interruptState
	onTimeout func(gateway.InterruptInfo) // audit + metric on expiry
}

// ErrCheckpointExpired is returned by Claim when the approval timer has already
// fired and the call was auto-blocked. A late resume must surface this and must
// NOT invoke the graph — the operator never approved the call.
var ErrCheckpointExpired = errors.New("approval checkpoint expired (auto-blocked on timeout)")

// ErrUnknownInterrupt is returned by Claim for a checkpoint the registry has no
// record of (never registered, or already resumed/reaped).
var ErrUnknownInterrupt = errors.New("unknown or already-resumed approval checkpoint")

// interruptRegistry tracks every pending approval interrupt and arms a timer per
// entry. It is the single source of truth for "is this interrupt still live":
// the Eino checkpoint store holds the paused graph state, but the registry gates
// whether a Resume may proceed at all.
//
// This closes two gaps:
//   - An interrupt that never gets a resume would otherwise wait forever,
//     accumulating checkpoint state (a denial-of-service sink). The timer
//     auto-blocks it and frees the state.
//   - A late resume arriving after the deadline would otherwise execute a call
//     the operator never approved. Claim rejects it with ErrCheckpointExpired.
//
// A single mutex serializes the timeout-fire vs. resume-claim race: exactly one
// wins, so there is no zombie timer and no double-execution.
type interruptRegistry struct {
	mu      sync.Mutex
	store   checkpointDeleter // nil => best-effort skip on stores that can't delete
	grace   time.Duration     // how long expired entries linger before reaping
	entries map[string]*pendingInterrupt
}

// newInterruptRegistry builds a registry gated on the given checkpoint store's
// Delete capability. Expired entries linger for expiredEntryGrace before GC.
func newInterruptRegistry(store any) *interruptRegistry {
	return &interruptRegistry{
		store:   deleterFor(store),
		grace:   expiredEntryGrace,
		entries: make(map[string]*pendingInterrupt),
	}
}

// resolveTimeout picks the effective timeout: the policy's per-rule timeout if
// positive, else the global default if positive, else the hard-coded cap. The
// result is always positive — an interrupt never waits forever.
func resolveTimeout(policyTimeout, globalDefault time.Duration) time.Duration {
	switch {
	case policyTimeout > 0:
		return policyTimeout
	case globalDefault > 0:
		return globalDefault
	default:
		return defaultApprovalTimeout
	}
}

// Register arms a timer for an interrupt that has just paused the graph. If an
// entry already exists for this checkpoint ID (a re-interrupt on resume), it is
// replaced and its old timers stopped — there is never more than one live timer
// per checkpoint.
func (r *interruptRegistry) Register(cpID string, info gateway.InterruptInfo, timeout time.Duration, onTimeout func(gateway.InterruptInfo)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.entries[cpID]; ok {
		existing.timer.Stop()
		if existing.gcTimer != nil {
			existing.gcTimer.Stop()
		}
	}

	e := &pendingInterrupt{
		info:      info,
		timeout:   timeout,
		state:     interruptPending,
		onTimeout: onTimeout,
	}
	e.timer = time.AfterFunc(timeout, func() { r.expire(cpID) })
	r.entries[cpID] = e
}

// Claim is called by Resume before the graph is invoked. It atomically resolves
// the race with the timeout:
//   - pending  -> the caller wins (timer stopped, entry removed); resume proceeds.
//   - expired  -> ErrCheckpointExpired; the caller MUST NOT invoke the graph.
//   - missing  -> ErrUnknownInterrupt; the caller MUST NOT invoke the graph.
//
// On a successful claim the entry is removed immediately (no state leak).
func (r *interruptRegistry) Claim(cpID string) error {
	r.mu.Lock()
	e, ok := r.entries[cpID]
	if !ok {
		r.mu.Unlock()
		return ErrUnknownInterrupt
	}
	switch e.state {
	case interruptPending:
		e.state = interruptCancelled
		e.timer.Stop()
		if e.gcTimer != nil {
			e.gcTimer.Stop()
		}
		delete(r.entries, cpID)
		r.mu.Unlock()
		return nil
	case interruptExpired:
		// Lazy reap: a late resume is the natural cleanup trigger for an
		// expired entry still inside the grace window.
		if e.gcTimer != nil {
			e.gcTimer.Stop()
		}
		delete(r.entries, cpID)
		r.mu.Unlock()
		return ErrCheckpointExpired
	default: // interruptCancelled (concurrent double-claim)
		r.mu.Unlock()
		return ErrUnknownInterrupt
	}
}

// expire fires when an approval timer elapses. It atomically marks the interrupt
// expired, invalidates the paused checkpoint in the store (so a late resume finds
// no graph state to execute), invokes the onTimeout callback (audit + metric),
// and arms a grace-window GC so the entry is reaped without losing the clear
// ErrCheckpointExpired signal for a shortly-late resume. If the interrupt was
// already resumed (cancelled) this is a no-op.
func (r *interruptRegistry) expire(cpID string) {
	r.mu.Lock()
	e, ok := r.entries[cpID]
	if !ok || e.state != interruptPending {
		r.mu.Unlock()
		return // resumed first, or already gone
	}
	e.state = interruptExpired
	info := e.info
	cb := e.onTimeout
	store := r.store
	grace := r.grace
	if grace > 0 {
		e.gcTimer = time.AfterFunc(grace, func() {
			r.mu.Lock()
			if cur, ok := r.entries[cpID]; ok && cur.state == interruptExpired {
				delete(r.entries, cpID)
			}
			r.mu.Unlock()
		})
	}
	r.mu.Unlock()

	// Invalidate the checkpoint outside the lock (store I/O). The registry is
	// the primary gate, but removing the paused state is defense in depth.
	if store != nil {
		_ = store.Delete(context.Background(), cpID)
	}
	if cb != nil {
		cb(info)
	}
}

// Close stops every pending timer and clears the registry. It does NOT
// auto-block remaining interrupts — on shutdown the process is going away and
// in-flight calls are abandoned, not silently resolved. Intended for clean
// teardown (primarily tests).
func (r *interruptRegistry) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		e.timer.Stop()
		if e.gcTimer != nil {
			e.gcTimer.Stop()
		}
	}
	r.entries = make(map[string]*pendingInterrupt)
}
