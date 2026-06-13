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

// Package auth provides framework-agnostic authentication primitives for
// SentinelMCP. It is deliberately pure: no net/http, no transport types. The
// adapter layer (cmd/sentinelmcp) extracts credentials from requests and calls
// these interfaces. This is the open-core seam — OSS ships APIKeyAuthenticator;
// Enterprise implementations (mTLS, OAuth2/OIDC) plug in behind Authenticator.
package auth

import (
	"context"
	"crypto/subtle"
	"fmt"
)

// Context is the authenticated identity of a caller, resolved by an
// Authenticator. It is the load-bearing input to per-principal policy.
type Context struct {
	// Principal identifies the caller (e.g. an API-key label or OAuth subject).
	Principal string
	// Scopes are the caller's permissions, when the Authenticator provides them.
	Scopes []string
	// Metadata carries arbitrary claims (issuer, token id, ...) for audit/log.
	// It MUST NOT carry raw secrets; callers must not log it verbatim (NFR-06).
	Metadata map[string]any
}

// Authenticator resolves a presented credential into a Context.
// Implementations must be safe for concurrent use.
//
// OSS extension point: APIKeyAuthenticator. Enterprise adds mTLS/OAuth2/OIDC
// client authenticators behind this interface in the private SentinelENT repo.
type Authenticator interface {
	// Authenticate validates the credential and returns the caller's Context.
	// An empty or invalid credential MUST return a non-nil error (never a nil
	// Context); callers treat any error as deny (fail-closed, NFR-07).
	Authenticate(ctx context.Context, credential string) (*Context, error)
}

// APIKeyAuthenticator validates a static API key against a configured map of
// key -> principal. OSS implementation.
//
// Lookup is constant-time across all configured keys (no early exit), so the
// time to reject an unknown key does not leak which keys exist.
type APIKeyAuthenticator struct {
	keys map[string]string // key -> principal
}

// NewAPIKeyAuthenticator builds an Authenticator from a key->principal map.
// A nil or empty map authenticates nobody (every Authenticate call fails) —
// callers use a nil Authenticator (not an empty one) to mean "anonymous allowed".
func NewAPIKeyAuthenticator(keys map[string]string) *APIKeyAuthenticator {
	copied := make(map[string]string, len(keys))
	for k, v := range keys {
		copied[k] = v
	}
	return &APIKeyAuthenticator{keys: copied}
}

// Authenticate implements Authenticator. Constant-time comparison against every
// configured key; returns the matching principal on success.
func (a *APIKeyAuthenticator) Authenticate(_ context.Context, credential string) (*Context, error) {
	if credential == "" {
		return nil, fmt.Errorf("auth: empty credential")
	}
	// Compare against every configured key (no early exit) so rejection timing
	// is uniform regardless of how many keys exist or which one matches.
	var matched bool
	var principal string
	for key, p := range a.keys {
		if subtle.ConstantTimeCompare([]byte(credential), []byte(key)) == 1 {
			matched = true
			principal = p
		}
	}
	if !matched {
		return nil, fmt.Errorf("auth: invalid API key")
	}
	return &Context{Principal: principal}, nil
}

// ---------------------------------------------------------------------------
// Context propagation (the auth -> policy seam)
// ---------------------------------------------------------------------------

type ctxKey struct{}

// WithContext stamps the auth Context onto ctx so downstream policy and audit
// can read it via FromContext.
func WithContext(ctx context.Context, ac *Context) context.Context {
	return context.WithValue(ctx, ctxKey{}, ac)
}

// FromContext retrieves the auth Context stamped by WithContext. Returns nil
// when absent (e.g. loopback or dev-mode anonymous calls) — callers must treat
// nil as "unauthenticated" and apply their own default (loopback trusts the
// host boundary; non-loopback must have been gated by the bind policy).
func FromContext(ctx context.Context) *Context {
	v, _ := ctx.Value(ctxKey{}).(*Context)
	return v
}
