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

package sidecar

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/gateway/secrets"
)

// stubProvider is a test secrets.Provider returning canned headers or an error.
type stubProvider struct {
	headers map[string]string
	err     error
}

func (s *stubProvider) Fetch(_ context.Context, _ string) (*secrets.Credential, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.headers == nil {
		return nil, nil
	}
	return &secrets.Credential{Headers: s.headers}, nil
}

// ---------------------------------------------------------------------------
// resolveUpstreamHeaders
// ---------------------------------------------------------------------------

func TestResolveUpstreamHeaders_NoRef(t *testing.T) {
	srv := UpstreamConfig{Name: "x"} // no CredentialsRef
	h, err := resolveUpstreamHeaders(context.Background(), srv, nil)
	if err != nil || h != nil {
		t.Fatalf("expected (nil,nil), got (%v,%v)", h, err)
	}
}

func TestResolveUpstreamHeaders_NilProvider(t *testing.T) {
	srv := UpstreamConfig{Name: "x", CredentialsRef: "fs"}
	if _, err := resolveUpstreamHeaders(context.Background(), srv, nil); err == nil {
		t.Fatal("expected error when credentials_ref is set but provider is nil")
	}
}

func TestResolveUpstreamHeaders_Resolved(t *testing.T) {
	srv := UpstreamConfig{Name: "x", CredentialsRef: "fs"}
	p := &stubProvider{headers: map[string]string{"Authorization": "Bearer t"}}
	h, err := resolveUpstreamHeaders(context.Background(), srv, p)
	if err != nil {
		t.Fatal(err)
	}
	if h["Authorization"] != "Bearer t" {
		t.Fatalf("got %v", h)
	}
}

func TestResolveUpstreamHeaders_ProviderError(t *testing.T) {
	srv := UpstreamConfig{Name: "x", CredentialsRef: "fs"}
	p := &stubProvider{err: fmt.Errorf("vault down")}
	if _, err := resolveUpstreamHeaders(context.Background(), srv, p); err == nil {
		t.Fatal("expected provider error to propagate (fail-closed)")
	}
}

// ---------------------------------------------------------------------------
// connectUpstream — credential injection on the wire + fail-closed
// ---------------------------------------------------------------------------

// TestConnectUpstream_InjectsCredentialHeader: a declared credentials_ref's
// headers reach the upstream wire. The httptest server need not speak MCP — the
// Initialize POST carries the header before its (expected) response-parse error.
func TestConnectUpstream_InjectsCredentialHeader(t *testing.T) {
	var gotAuth string
	var sawRequest bool
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		sawRequest = true
		gotAuth = r.Header.Get("Authorization")
	}))
	defer ts.Close()

	provider := secrets.NewFileEnvProvider(map[string]map[string]string{
		"fs": {"Authorization": "Bearer secret-token"},
	})
	srv := UpstreamConfig{Name: "fs", URL: ts.URL, CredentialsRef: "fs"}

	_, _ = connectUpstream(context.Background(), srv, provider) // Initialize errors; only the header matters

	if !sawRequest {
		t.Fatal("expected an outbound request to the upstream")
	}
	if gotAuth != "Bearer secret-token" {
		t.Fatalf("injected Authorization header not on the wire: got %q", gotAuth)
	}
}

// TestConnectUpstream_MissingCredential_FailClosed: an unresolved credentials_ref
// fails BEFORE any request is made — the upstream is never dialed.
func TestConnectUpstream_MissingCredential_FailClosed(t *testing.T) {
	sawRequest := false
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		sawRequest = true
	}))
	defer ts.Close()

	provider := secrets.NewFileEnvProvider(nil) // nothing for "fs", no env var
	srv := UpstreamConfig{Name: "fs", URL: ts.URL, CredentialsRef: "fs"}

	_, err := connectUpstream(context.Background(), srv, provider)
	if err == nil {
		t.Fatal("expected error when credentials_ref cannot be resolved")
	}
	if sawRequest {
		t.Fatal("must NOT dial the upstream when credentials are unresolved (fail-closed)")
	}
}

// TestConnectUpstream_NoRef_NoAuthHeader: an upstream without a credentials_ref
// sends no injected Authorization header.
func TestConnectUpstream_NoRef_NoAuthHeader(t *testing.T) {
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer ts.Close()

	srv := UpstreamConfig{Name: "fs", URL: ts.URL} // no credentials_ref
	_, _ = connectUpstream(context.Background(), srv, secrets.NewFileEnvProvider(nil))
	if gotAuth != "" {
		t.Fatalf("expected no injected Authorization header, got %q", gotAuth)
	}
}
