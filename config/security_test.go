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
	"os"
	"path/filepath"
	"testing"

	"github.com/technosiveuk-ui/sentinelmcp/config"
)

// writeConfigAt writes body to a temp file and forces the given mode (umask-proof).
func writeConfigAt(t *testing.T, mode os.FileMode, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	return p
}

// TestLoad_AdminTokenFilePerms_FailClosed: a group/world-readable config that
// contains sidecar.admin_token must be rejected at load time (NFR-06 family).
func TestLoad_AdminTokenFilePerms_FailClosed(t *testing.T) {
	body := "schema_version: \"1.0\"\nsidecar:\n  admin_token: \"supersecret\"\n"
	p := writeConfigAt(t, 0o644, body)

	if _, err := config.Load(p); err == nil {
		t.Fatal("expected error for group/world-readable config containing admin_token, got nil")
	}
}

// TestLoad_AdminTokenFilePerms_TightModeOK: the same config at 0600 loads fine.
func TestLoad_AdminTokenFilePerms_TightModeOK(t *testing.T) {
	body := "schema_version: \"1.0\"\nsidecar:\n  admin_token: \"supersecret\"\n"
	p := writeConfigAt(t, 0o600, body)

	if _, err := config.Load(p); err != nil {
		t.Fatalf("expected success for 0600 config containing admin_token, got: %v", err)
	}
}

// TestLoad_NoSecrets_OpenModeOK: a group/world-readable config WITHOUT secrets
// is not blocked by the secrets-at-rest guard.
func TestLoad_NoSecrets_OpenModeOK(t *testing.T) {
	body := "schema_version: \"1.0\"\n"
	p := writeConfigAt(t, 0o644, body)

	if _, err := config.Load(p); err != nil {
		t.Fatalf("expected success for world-readable config without secrets, got: %v", err)
	}
}
