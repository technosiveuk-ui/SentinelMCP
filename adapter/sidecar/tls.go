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
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// buildUpstreamHTTPClient builds the *http.Client used to dial an upstream MCP
// server. With no TLS customization it returns a client using the default
// transport (system roots, normal verification). With ca_bundle / server_name /
// pinned_sha256 it returns a client carrying a custom TLSClientConfig passed to
// the MCP client via transport.WithHTTPBasicClient (native mcp-go — no wrapper).
//
// Security: InsecureSkipVerify is NEVER enabled. Certificate pinning is applied
// as an ADDITIONAL check via VerifyPeerCertificate, on top of normal chain
// validation — never instead of it. A TLS verification failure blocks all calls
// to the upstream (fail-closed, NFR-07 family).
func buildUpstreamHTTPClient(srv UpstreamConfig) (*http.Client, error) {
	if srv.CABundle == "" && srv.ServerName == "" && srv.PinnedSHA256 == "" {
		// No customization: standard verification against system roots.
		return &http.Client{}, nil
	}

	// InsecureSkipVerify stays at its zero value (false). Pinning is enforced via
	// VerifyPeerCertificate, which runs AFTER normal chain validation succeeds.
	tlsCfg := &tls.Config{}

	if srv.ServerName != "" {
		tlsCfg.ServerName = srv.ServerName
	}

	if srv.CABundle != "" {
		pool, err := loadCABundle(srv.CABundle)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: load ca_bundle: %w", srv.Name, err)
		}
		tlsCfg.RootCAs = pool
	}

	if srv.PinnedSHA256 != "" {
		pin, err := normalizePin(srv.PinnedSHA256)
		if err != nil {
			return nil, fmt.Errorf("upstream %q: invalid pinned_sha256: %w", srv.Name, err)
		}
		tlsCfg.VerifyPeerCertificate = makePinVerifier(pin)
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
	}, nil
}

// isInlinePEM reports whether spec looks like inline PEM rather than a file path.
func isInlinePEM(spec string) bool {
	return strings.Contains(spec, "-----BEGIN")
}

// loadCABundle loads a PEM-encoded CA bundle from an inline string or a file
// path into an x509 CertPool used as RootCAs for upstream verification.
func loadCABundle(spec string) (*x509.CertPool, error) {
	var pemBytes []byte
	if isInlinePEM(spec) {
		pemBytes = []byte(spec)
	} else {
		b, err := os.ReadFile(spec)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", spec, err)
		}
		pemBytes = b
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("no certificates parsed from PEM (verify the ca_bundle is valid PEM)")
	}
	return pool, nil
}

// normalizePin decodes a hex-encoded SHA-256 SPKI pin to its 32 raw bytes.
func normalizePin(hexPin string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(hexPin))
	if err != nil {
		return nil, fmt.Errorf("decode hex: %w", err)
	}
	if len(b) != sha256.Size {
		return nil, fmt.Errorf("expected %d bytes (SHA-256), got %d", sha256.Size, len(b))
	}
	return b, nil
}

// makePinVerifier returns a VerifyPeerCertificate callback that asserts the
// leaf certificate's SubjectPublicKeyInfo matches pin. The callback runs after
// normal chain validation, so pinning is an additional requirement, not a
// replacement for it. Comparison is constant-time to avoid pin disclosure via
// timing (mirrors the NFR-06 secret-discipline posture).
func makePinVerifier(pin []byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("pin check: server presented no certificate")
		}
		leaf, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("pin check: parse leaf certificate: %w", err)
		}
		got := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
		if !hmac.Equal(got[:], pin) {
			return fmt.Errorf("pin check: certificate SPKI does not match pinned_sha256 (got %x)", got)
		}
		return nil
	}
}

// encodeLeafPin returns the hex SHA-256 SPKI pin for a parsed leaf certificate.
// Exposed for tests and tooling that need to compute a pin from a known cert.
func encodeLeafPin(leaf *x509.Certificate) string {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// encodePEMCert is a small helper for tests/tooling to PEM-encode a DER cert.
func encodePEMCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
