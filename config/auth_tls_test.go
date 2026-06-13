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

package config_test

import (
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/config"
)

// TestLoad_APIKeysFilePerms_FailClosed: a group/world-readable config containing
// auth.api_keys must be rejected at load (secrets-at-rest, NFR-06 family).
func TestLoad_APIKeysFilePerms_FailClosed(t *testing.T) {
	body := `schema_version: "1.0"
auth:
  api_keys:
    "key-123": "alice"
`
	p := writeConfigAt(t, 0o644, body)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: group/world-readable config with auth.api_keys must be rejected")
	}
}

// TestLoad_APIKeysFilePerms_TightModeOK: the same config at 0600 loads and parses.
func TestLoad_APIKeysFilePerms_TightModeOK(t *testing.T) {
	body := `schema_version: "1.0"
auth:
  api_keys:
    "key-123": "alice"
`
	p := writeConfigAt(t, 0o600, body)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("expected success at 0600: %v", err)
	}
	if cfg.Auth.APIKeys["key-123"] != "alice" {
		t.Fatalf("api_keys not parsed: %v", cfg.Auth.APIKeys)
	}
}

// TestLoad_TLSConfig: inbound TLS cert/key paths parse cleanly.
func TestLoad_TLSConfig(t *testing.T) {
	body := `schema_version: "1.0"
sidecar:
  tls:
    cert_file: "/etc/ssl/sentinelmcp.crt"
    key_file: "/etc/ssl/sentinelmcp.key"
`
	p := writeConfigAt(t, 0o600, body)
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sidecar.TLS.CertFile != "/etc/ssl/sentinelmcp.crt" ||
		cfg.Sidecar.TLS.KeyFile != "/etc/ssl/sentinelmcp.key" {
		t.Fatalf("TLS config not parsed: %+v", cfg.Sidecar.TLS)
	}
}
