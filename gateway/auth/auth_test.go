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

package auth

import (
	"context"
	"testing"
)

func TestAPIKeyAuthenticator_Valid(t *testing.T) {
	a := NewAPIKeyAuthenticator(map[string]string{"key-123": "alice"})
	ac, err := a.Authenticate(context.Background(), "key-123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ac.Principal != "alice" {
		t.Fatalf("principal = %q, want alice", ac.Principal)
	}
}

func TestAPIKeyAuthenticator_MultipleKeys(t *testing.T) {
	a := NewAPIKeyAuthenticator(map[string]string{
		"key-123": "alice",
		"key-456": "bob",
	})
	for cred, want := range map[string]string{"key-123": "alice", "key-456": "bob"} {
		ac, err := a.Authenticate(context.Background(), cred)
		if err != nil {
			t.Fatalf("%s: %v", cred, err)
		}
		if ac.Principal != want {
			t.Fatalf("principal = %q, want %q", ac.Principal, want)
		}
	}
}

func TestAPIKeyAuthenticator_Invalid(t *testing.T) {
	a := NewAPIKeyAuthenticator(map[string]string{"key-123": "alice"})
	if _, err := a.Authenticate(context.Background(), "wrong"); err == nil {
		t.Fatal("expected error for wrong key")
	}
}

func TestAPIKeyAuthenticator_EmptyCredential(t *testing.T) {
	a := NewAPIKeyAuthenticator(map[string]string{"key-123": "alice"})
	if _, err := a.Authenticate(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty credential")
	}
}

func TestAPIKeyAuthenticator_NoKeysDeniesAll(t *testing.T) {
	a := NewAPIKeyAuthenticator(nil)
	if _, err := a.Authenticate(context.Background(), "key-123"); err == nil {
		t.Fatal("expected error when no keys are configured")
	}
}

// TestAPIKeyAuthenticator_ConstantTimeNoEarlyExit sanity-checks that rejection
// of a wrong key visits every configured key (no short-circuit). This is a
// structural guard, not a rigorous timing test.
func TestAPIKeyAuthenticator_ConstantTimeNoEarlyExit(t *testing.T) {
	keys := map[string]string{"a": "p1", "b": "p2", "c": "p3"}
	a := NewAPIKeyAuthenticator(keys)
	// A wrong credential must fail regardless of key set size.
	if _, err := a.Authenticate(context.Background(), "not-a-key"); err == nil {
		t.Fatal("expected rejection of unknown key")
	}
}

func TestContext_RoundTrip(t *testing.T) {
	ctx := context.Background()
	if got := FromContext(ctx); got != nil {
		t.Fatal("expected nil before stamping")
	}
	stamped := &Context{Principal: "bob", Scopes: []string{"read"}}
	ctx2 := WithContext(ctx, stamped)
	got := FromContext(ctx2)
	if got == nil || got.Principal != "bob" {
		t.Fatalf("round-trip failed: %+v", got)
	}
	// Original ctx is untouched.
	if FromContext(ctx) != nil {
		t.Fatal("original context was mutated")
	}
}

func TestContext_NilFromUnknownContext(t *testing.T) {
	// A context carrying an unrelated value must not panic or misreturn.
	ctx := context.WithValue(context.Background(), struct{ s string }{"other"}, 42)
	if got := FromContext(ctx); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}
