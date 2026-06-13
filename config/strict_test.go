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

// TestStrict_DefaultTrue verifies strict is on by default and stays on when the
// field is omitted from the config file (YAML leaves unset fields untouched when
// unmarshaling into a pre-populated struct — the secure default must survive).
func TestStrict_DefaultTrue(t *testing.T) {
	if !config.DefaultConfig().Sidecar.Strict {
		t.Fatal("DefaultConfig().Sidecar.Strict must be true (secure by default)")
	}

	p := writeConfigAt(t, 0o600, "schema_version: \"1.0\"\nsidecar:\n  upstream_servers: []\n")
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Sidecar.Strict {
		t.Fatal("strict must default to true when omitted from the config file")
	}
}

// TestValidate_Strict_RejectsHTTPUpstream: plaintext upstreams are rejected at
// load time when strict is enabled (fail-closed).
func TestValidate_Strict_RejectsHTTPUpstream(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  upstream_servers:
    - name: "fs"
      url: "http://fs.local/mcp"
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: http:// upstream must be rejected under strict")
	}
}

// TestValidate_Strict_AllowsHTTPSUpstream: https upstreams load cleanly.
func TestValidate_Strict_AllowsHTTPSUpstream(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  upstream_servers:
    - name: "fs"
      url: "https://fs.local/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("https upstream should be allowed under strict: %v", err)
	}
}

// TestValidate_Strict_RejectsIPLiteral: IP-literal hosts are rejected under
// strict (they defeat SNI, cert SAN matching, and DNS allowlisting).
func TestValidate_Strict_RejectsIPLiteral(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  upstream_servers:
    - name: "fs"
      url: "https://10.0.0.5/mcp"
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: IP-literal upstream must be rejected under strict")
	}
}

// TestValidate_StrictFalse_AllowsHTTP: opting out (strict: false) permits the
// plaintext upstream — the trusted private-network escape hatch.
func TestValidate_StrictFalse_AllowsHTTP(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: false
  upstream_servers:
    - name: "fs"
      url: "http://fs.local/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("http upstream should be allowed when strict=false: %v", err)
	}
}
