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

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileEnvProvider_FromMap(t *testing.T) {
	p := NewFileEnvProvider(map[string]map[string]string{
		"fs": {"Authorization": "Bearer x", "X-Tenant": "acme"},
	})
	c, err := p.Fetch(context.Background(), "fs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Headers["Authorization"] != "Bearer x" {
		t.Errorf("Authorization = %q", c.Headers["Authorization"])
	}
	if c.Headers["X-Tenant"] != "acme" {
		t.Errorf("custom header not preserved: %v", c.Headers)
	}
}

func TestFileEnvProvider_EnvFallback(t *testing.T) {
	t.Setenv("SENTINELMCP_UPSTREAM_FS_TOKEN", "env-tok")
	p := NewFileEnvProvider(nil)
	c, err := p.Fetch(context.Background(), "fs")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Headers["Authorization"] != "Bearer env-tok" {
		t.Fatalf("env token not used: %v", c.Headers)
	}
}

func TestFileEnvProvider_MapPrecedenceOverEnv(t *testing.T) {
	t.Setenv("SENTINELMCP_UPSTREAM_FS_TOKEN", "env-tok")
	p := NewFileEnvProvider(map[string]map[string]string{
		"fs": {"Authorization": "Bearer file-tok"},
	})
	c, err := p.Fetch(context.Background(), "fs")
	if err != nil {
		t.Fatal(err)
	}
	if c.Headers["Authorization"] != "Bearer file-tok" {
		t.Fatalf("file map should take precedence: %v", c.Headers)
	}
}

func TestFileEnvProvider_NotFound_Error(t *testing.T) {
	p := NewFileEnvProvider(nil)
	if _, err := p.Fetch(context.Background(), "missing"); err == nil {
		t.Fatal("expected error when no credentials resolve")
	}
}

func TestEnvUpstreamToken_Sanitize(t *testing.T) {
	cases := map[string]string{
		"fs":          "SENTINELMCP_UPSTREAM_FS_TOKEN",
		"my-upstream": "SENTINELMCP_UPSTREAM_MY_UPSTREAM_TOKEN",
		"db_2":        "SENTINELMCP_UPSTREAM_DB_2_TOKEN",
		"a.b/c":       "SENTINELMCP_UPSTREAM_A_B_C_TOKEN",
	}
	for in, want := range cases {
		if got := EnvUpstreamToken(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}

func writeSecretsAt(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secrets.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSecretsFile_PermFailClosed(t *testing.T) {
	p := writeSecretsAt(t, 0o644, "upstreams:\n  fs:\n    headers:\n      Authorization: Bearer x\n")
	if _, err := LoadSecretsFile(p); err == nil {
		t.Fatal("expected error: group/world-readable secrets file must be rejected")
	}
}

func TestLoadSecretsFile_TightModeOK(t *testing.T) {
	p := writeSecretsAt(t, 0o600, "upstreams:\n  fs:\n    headers:\n      Authorization: Bearer x\n")
	m, err := LoadSecretsFile(p)
	if err != nil {
		t.Fatalf("expected success at 0600: %v", err)
	}
	if m["fs"]["Authorization"] != "Bearer x" {
		t.Fatalf("parsed wrong: %v", m)
	}
}

func TestLoadSecretsFile_EmptyPath(t *testing.T) {
	m, err := LoadSecretsFile("")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) != 0 {
		t.Fatalf("expected empty map, got %v", m)
	}
}

func TestLoadSecretsFile_MissingFile(t *testing.T) {
	if _, err := LoadSecretsFile(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
