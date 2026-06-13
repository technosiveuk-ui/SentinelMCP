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

// TestValidate_EgressAllowlist_NonAllowlisted_Rejects: a host outside the
// allowlist is rejected at load (fail-closed).
func TestValidate_EgressAllowlist_NonAllowlisted_Rejects(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: false
  egress_allowlist:
    - example.com
  upstream_servers:
    - name: "fs"
      url: "https://evil.com/mcp"
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: upstream host not in egress_allowlist")
	}
}

// TestValidate_EgressAllowlist_SuffixMatch_OK: a subdomain of an allowlisted
// suffix is permitted.
func TestValidate_EgressAllowlist_SuffixMatch_OK(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: false
  egress_allowlist:
    - local
  upstream_servers:
    - name: "fs"
      url: "https://fs.local/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("suffix match should be allowed: %v", err)
	}
}

// TestValidate_EgressAllowlist_ExactMatch_OK: an exact hostname match is permitted.
func TestValidate_EgressAllowlist_ExactMatch_OK(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: false
  egress_allowlist:
    - fs.local
  upstream_servers:
    - name: "fs"
      url: "https://fs.local/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("exact match should be allowed: %v", err)
	}
}

// TestValidate_EgressAllowlist_IPLiteral_ExactOK: strict mode normally rejects
// IP literals, but an exact egress_allowlist entry permits one.
func TestValidate_EgressAllowlist_IPLiteral_ExactOK(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: true
  egress_allowlist:
    - 10.0.0.5
  upstream_servers:
    - name: "fs"
      url: "https://10.0.0.5/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("exact-allowlisted IP literal should be allowed in strict: %v", err)
	}
}

// TestValidate_EgressAllowlist_IPNotExact_Rejects: an IP literal that is not an
// exact allowlist entry is rejected (IPs never suffix-match).
func TestValidate_EgressAllowlist_IPNotExact_Rejects(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: true
  egress_allowlist:
    - 10.0.0.5
  upstream_servers:
    - name: "fs"
      url: "https://10.0.0.6/mcp"
`)
	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error: IP literal not exact-allowlisted")
	}
}

// TestValidate_EgressAllowlist_Empty_AllowsAll: an empty allowlist imposes no
// egress restriction (warned at runtime, not denied at load).
func TestValidate_EgressAllowlist_Empty_AllowsAll(t *testing.T) {
	p := writeConfigAt(t, 0o600, `schema_version: "1.0"
sidecar:
  strict: true
  upstream_servers:
    - name: "fs"
      url: "https://fs.local/mcp"
`)
	if _, err := config.Load(p); err != nil {
		t.Fatalf("empty allowlist should allow hostname upstreams: %v", err)
	}
}
