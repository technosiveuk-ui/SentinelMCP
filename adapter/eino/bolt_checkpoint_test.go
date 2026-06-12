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

package eino

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBoltCheckPointStore_GetSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-checkpoints.db")

	store := NewBoltCheckPointStore(path)
	defer store.Close()

	ctx := context.Background()

	// Get non-existent key.
	data, found, err := store.Get(ctx, "nonexistent")
	if err != nil {
		t.Fatalf("Get nonexistent: %v", err)
	}
	if found {
		t.Error("expected found=false for nonexistent key")
	}
	if data != nil {
		t.Errorf("expected nil data for nonexistent key, got %v", data)
	}

	// Set and Get.
	if err := store.Set(ctx, "test-1", []byte("hello world")); err != nil {
		t.Fatalf("Set: %v", err)
	}

	data, found, err = store.Get(ctx, "test-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if string(data) != "hello world" {
		t.Errorf("data = %q, want %q", data, "hello world")
	}
}

func TestBoltCheckPointStore_Overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-overwrite.db")

	store := NewBoltCheckPointStore(path)
	defer store.Close()

	ctx := context.Background()

	if err := store.Set(ctx, "key-1", []byte("first")); err != nil {
		t.Fatalf("Set first: %v", err)
	}
	if err := store.Set(ctx, "key-1", []byte("second")); err != nil {
		t.Fatalf("Set second: %v", err)
	}

	data, found, err := store.Get(ctx, "key-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !found {
		t.Fatal("expected found=true")
	}
	if string(data) != "second" {
		t.Errorf("data = %q, want %q", data, "second")
	}
}

func TestBoltCheckPointStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-persist.db")
	ctx := context.Background()

	// Write with first store instance.
	store1 := NewBoltCheckPointStore(path)
	if err := store1.Set(ctx, "persist-key", []byte("persisted-value")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	store1.Close()

	// Verify file exists.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("BoltDB file not created")
	}

	// Reopen and verify data survived.
	store2 := NewBoltCheckPointStore(path)
	defer store2.Close()

	data, found, err := store2.Get(ctx, "persist-key")
	if err != nil {
		t.Fatalf("Get after reopen: %v", err)
	}
	if !found {
		t.Fatal("data not found after reopen")
	}
	if string(data) != "persisted-value" {
		t.Errorf("data = %q, want %q", data, "persisted-value")
	}
}

func TestBoltCheckPointStore_MultipleKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-multi.db")

	store := NewBoltCheckPointStore(path)
	defer store.Close()

	ctx := context.Background()

	keys := []string{"a", "b", "c", "d", "e"}
	for i, k := range keys {
		if err := store.Set(ctx, k, []byte{byte(i)}); err != nil {
			t.Fatalf("Set %s: %v", k, err)
		}
	}

	for i, k := range keys {
		data, found, err := store.Get(ctx, k)
		if err != nil {
			t.Fatalf("Get %s: %v", k, err)
		}
		if !found {
			t.Fatalf("key %s not found", k)
		}
		if len(data) != 1 || data[0] != byte(i) {
			t.Errorf("key %s: data = %v, want [%d]", k, data, i)
		}
	}
}
