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

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway/auth"
)

// ---------------------------------------------------------------------------
// authMiddleware
// ---------------------------------------------------------------------------

func TestAuthMiddleware_NoToken_401(t *testing.T) {
	a := auth.NewAPIKeyAuthenticator(map[string]string{"k": "alice"})
	reached := false
	h := authMiddleware(a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if reached {
		t.Fatal("handler must not be reached without a credential")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_BadToken_401(t *testing.T) {
	a := auth.NewAPIKeyAuthenticator(map[string]string{"k": "alice"})
	h := authMiddleware(a, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", w.Code)
	}
}

func TestAuthMiddleware_GoodToken_ReachesHandler_WithAuthContext(t *testing.T) {
	a := auth.NewAPIKeyAuthenticator(map[string]string{"key-1": "alice"})
	var gotPrincipal string
	h := authMiddleware(a, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if ac := auth.FromContext(r.Context()); ac != nil {
			gotPrincipal = ac.Principal
		}
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer key-1")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
	if gotPrincipal != "alice" {
		t.Fatalf("principal = %q, want alice", gotPrincipal)
	}
}

func TestAuthMiddleware_XAPIKey_Header(t *testing.T) {
	a := auth.NewAPIKeyAuthenticator(map[string]string{"key-1": "alice"})
	var got string
	h := authMiddleware(a, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if ac := auth.FromContext(r.Context()); ac != nil {
			got = ac.Principal
		}
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("X-API-Key", "key-1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "alice" {
		t.Fatalf("X-API-Key not honored; principal = %q", got)
	}
}

func TestAuthMiddleware_NilAuthenticator_PassThrough(t *testing.T) {
	reached := false
	h := authMiddleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil) // no credential
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !reached {
		t.Fatal("nil authenticator must pass through (loopback/dev mode)")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", w.Code)
	}
}

// ---------------------------------------------------------------------------
// extractCredential
// ---------------------------------------------------------------------------

func TestExtractCredential(t *testing.T) {
	cases := []struct {
		name   string
		apiKey string
		authz  string
		want   string
	}{
		{"x-api-key", "kkk", "", "kkk"},
		{"bearer", "", "Bearer bbb", "bbb"},
		{"raw authz", "", "rawtoken", "rawtoken"},
		{"none", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			if got := extractCredential(req); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// validateInboundBind
// ---------------------------------------------------------------------------

func TestValidateInboundBind(t *testing.T) {
	authn := auth.NewAPIKeyAuthenticator(map[string]string{"k": "alice"})
	cases := []struct {
		name    string
		addr    string
		cert    string
		key     string
		authn   auth.Authenticator
		devMode bool
		wantErr bool
	}{
		{"loopback ipv4 no tls no auth", "127.0.0.1:8080", "", "", nil, false, false},
		{"loopback localhost", "localhost:8080", "", "", nil, false, false},
		{"loopback ipv6", "[::1]:8080", "", "", nil, false, false},
		{"non-loopback no tls", "0.0.0.0:8080", "", "", authn, false, true},
		{"non-loopback tls no auth", "0.0.0.0:8080", "c", "k", nil, false, true},
		{"non-loopback tls+auth", "0.0.0.0:8080", "c", "k", authn, false, false},
		{"non-loopback dev-mode no tls", "0.0.0.0:8080", "", "", nil, true, false},
		{"wildcard no tls no auth", ":8080", "", "", nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateInboundBind(tc.addr, tc.cert, tc.key, tc.authn, tc.devMode)
			if tc.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// authContextFunc (the WithHTTPContextFunc seam)
// ---------------------------------------------------------------------------

func TestAuthContextFunc_Propagates(t *testing.T) {
	stamped := &auth.Context{Principal: "alice"}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req = req.WithContext(auth.WithContext(req.Context(), stamped))
	out := authContextFunc(context.Background(), req)
	if ac := auth.FromContext(out); ac == nil || ac.Principal != "alice" {
		t.Fatalf("authContextFunc did not propagate: %+v", ac)
	}
}

func TestAuthContextFunc_NoAuth_Unchanged(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	out := authContextFunc(context.Background(), req)
	if auth.FromContext(out) != nil {
		t.Fatal("expected nil auth context when none stamped on request")
	}
}
