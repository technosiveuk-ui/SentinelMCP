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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

// newTestTLSServer starts a minimal TLS server with a self-signed cert.
func newTestTLSServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
}

// TestBuildUpstreamHTTPClient_NoCustomization: with no TLS fields the builder
// returns a usable default client (system roots).
func TestBuildUpstreamHTTPClient_NoCustomization(t *testing.T) {
	c, err := buildUpstreamHTTPClient(UpstreamConfig{Name: "x", URL: "https://x.local/mcp"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("nil client")
	}
}

// TestBuildUpstreamHTTPClient_TrustedCAAndPin_Succeeds: trusting the server's
// self-signed cert as a CA AND pinning its SPKI allows the TLS connection.
func TestBuildUpstreamHTTPClient_TrustedCAAndPin_Succeeds(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	leaf := ts.Certificate()
	u, _ := url.Parse(ts.URL)

	cli, err := buildUpstreamHTTPClient(UpstreamConfig{
		Name:         "t",
		URL:          ts.URL,
		CABundle:     string(encodePEMCert(leaf.Raw)),
		ServerName:   u.Hostname(),
		PinnedSHA256: encodeLeafPin(leaf),
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	resp, err := cli.Get(ts.URL)
	if err != nil {
		t.Fatalf("expected TLS connection with trusted CA + pin to succeed: %v", err)
	}
	resp.Body.Close()
}

// TestBuildUpstreamHTTPClient_WrongPin_Rejects: a valid chain but a non-matching
// pin must abort the handshake (pinning is enforced on top of chain validation).
func TestBuildUpstreamHTTPClient_WrongPin_Rejects(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	leaf := ts.Certificate()
	u, _ := url.Parse(ts.URL)

	cli, err := buildUpstreamHTTPClient(UpstreamConfig{
		Name:         "t",
		URL:          ts.URL,
		CABundle:     string(encodePEMCert(leaf.Raw)), // CA trusted so chain validates
		ServerName:   u.Hostname(),
		PinnedSHA256: strings.Repeat("00", 32),        // valid 32-byte pin that won't match
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	if _, err := cli.Get(ts.URL); err == nil {
		t.Fatal("expected TLS handshake to fail when the pin does not match")
	}
}

// TestBuildUpstreamHTTPClient_UntrustedCA_Rejects: without a matching CA the
// normal chain validation fails (never InsecureSkipVerify).
func TestBuildUpstreamHTTPClient_UntrustedCA_Rejects(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	u, _ := url.Parse(ts.URL)
	cli, err := buildUpstreamHTTPClient(UpstreamConfig{
		Name:       "t",
		URL:        ts.URL,
		ServerName: u.Hostname(), // no CABundle → system roots don't trust the self-signed cert
	})
	if err != nil {
		t.Fatalf("build client: %v", err)
	}

	if _, err := cli.Get(ts.URL); err == nil {
		t.Fatal("expected TLS handshake to fail when the CA is untrusted")
	}
}

// TestBuildUpstreamHTTPClient_InvalidCABundle: garbage PEM is rejected.
func TestBuildUpstreamHTTPClient_InvalidCABundle(t *testing.T) {
	_, err := buildUpstreamHTTPClient(UpstreamConfig{
		Name:     "t",
		URL:      "https://t.local/mcp",
		CABundle: "-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----",
	})
	if err == nil {
		t.Fatal("expected error for invalid CA bundle PEM")
	}
}

// TestBuildUpstreamHTTPClient_BadPinHex: malformed pins (non-hex, wrong length)
// are rejected by the builder before any connection.
func TestBuildUpstreamHTTPClient_BadPinHex(t *testing.T) {
	cases := []string{
		"nothex",                 // non-hex
		"ab",                     // too short
		strings.Repeat("ab", 31), // 31 bytes, not 32
	}
	for _, pin := range cases {
		_, err := buildUpstreamHTTPClient(UpstreamConfig{
			Name: "t", URL: "https://t.local/mcp", PinnedSHA256: pin,
		})
		if err == nil {
			t.Errorf("expected error for invalid pin %q", pin)
		}
	}
}

// TestLoadCABundle_FilePath: a CA bundle can be loaded from a file path (not
// just inline PEM).
func TestLoadCABundle_FilePath(t *testing.T) {
	ts := newTestTLSServer(t)
	defer ts.Close()

	p := t.TempDir() + "/ca.pem"
	if err := os.WriteFile(p, encodePEMCert(ts.Certificate().Raw), 0o600); err != nil {
		t.Fatal(err)
	}
	pool, err := loadCABundle(p)
	if err != nil {
		t.Fatalf("loadCABundle from path: %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool")
	}
}

// TestLoadCABundle_Garbage: non-PEM input is rejected with a clear error.
func TestLoadCABundle_Garbage(t *testing.T) {
	if _, err := loadCABundle("definitely not a certificate"); err == nil {
		t.Fatal("expected error for non-PEM input")
	}
}
