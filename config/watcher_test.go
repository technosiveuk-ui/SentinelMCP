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

package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfigWatcher_ReloadOnWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-config.yaml")

	// Write initial config.
	initialYAML := `
schema_version: "1.0"
global:
  default_risk: "low"
  audit_output: "stdout"
  redaction_mask: "***REDACTED***"
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var reloadCount atomic.Int32
	onChange := func(cfg *Config) {
		reloadCount.Add(1)
	}

	watcher, err := NewWatcher(path, onChange)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watcher.Start(ctx)

	// Give the watcher time to initialize.
	time.Sleep(100 * time.Millisecond)

	// Modify the config file.
	updatedYAML := `
schema_version: "1.0"
global:
  default_risk: "medium"
  audit_output: "stdout"
  redaction_mask: "***REDACTED***"
`
	if err := os.WriteFile(path, []byte(updatedYAML), 0644); err != nil {
		t.Fatalf("WriteFile update: %v", err)
	}

	// Wait for debounce + reload.
	time.Sleep(1 * time.Second)

	count := reloadCount.Load()
	if count == 0 {
		t.Error("expected at least one reload after config file change")
	}
}

func TestConfigWatcher_InvalidYAMLNoCrash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-config.yaml")

	// Write valid initial config.
	initialYAML := `
schema_version: "1.0"
global:
  default_risk: "low"
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	var reloadCount atomic.Int32
	onChange := func(cfg *Config) {
		reloadCount.Add(1)
	}

	watcher, err := NewWatcher(path, onChange)
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	defer watcher.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watcher.Start(ctx)
	time.Sleep(100 * time.Millisecond)

	// Write invalid YAML — should log error but not crash.
	badYAML := `this is not: valid: yaml: [[[`
	if err := os.WriteFile(path, []byte(badYAML), 0644); err != nil {
		t.Fatalf("WriteFile bad: %v", err)
	}

	// Wait for debounce + reload attempt.
	time.Sleep(1 * time.Second)

	// Reload count should still be 0 (invalid YAML doesn't trigger callback).
	if reloadCount.Load() != 0 {
		t.Error("expected no reload for invalid YAML")
	}

	// Write valid YAML again — should reload successfully.
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("WriteFile restore: %v", err)
	}

	time.Sleep(1 * time.Second)

	if reloadCount.Load() == 0 {
		t.Error("expected reload after restoring valid config")
	}
}

func TestConfigWatcher_Close(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "close-test.yaml")

	initialYAML := `
schema_version: "1.0"
global:
  default_risk: "low"
`
	if err := os.WriteFile(path, []byte(initialYAML), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	watcher, err := NewWatcher(path, func(*Config) {})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go watcher.Start(ctx)
	time.Sleep(50 * time.Millisecond)

	// Close should not panic.
	if err := watcher.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
