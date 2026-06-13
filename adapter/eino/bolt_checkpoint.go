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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"

	"github.com/cloudwego/eino/compose"
)

// ---------------------------------------------------------------------------
// BoltCheckPointStore — BoltDB-backed checkpoint store
// ---------------------------------------------------------------------------

const (
	checkpointBucket = "checkpoints"
)

// BoltCheckPointStore implements compose.CheckPointStore backed by a BoltDB file.
//
// BoltDB provides ACID transactions, crash recovery, and zero-config operation —
// ideal for the sidecar's interrupt/resume state persistence. The store uses a
// single bucket with checkpoint ID as key and serialized state as value.
//
// If the database file doesn't exist, it is created automatically. The parent
// directory must be writable.
type BoltCheckPointStore struct {
	db   *bbolt.DB
	path string
}

// NewBoltCheckPointStore opens (or creates) a BoltDB checkpoint store at path.
// The file and parent directories are created if they don't exist.
func NewBoltCheckPointStore(path string) *BoltCheckPointStore {
	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		// Fatal-by-design: the gateway cannot operate without a working
		// checkpoint store (interrupt/resume state would be lost).
		slog.Error("checkpoint: failed to create directory", "component", "checkpoint", "dir", dir, "error", err)
		os.Exit(1)
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		slog.Error("checkpoint: failed to open BoltDB", "component", "checkpoint", "path", path, "error", err)
		os.Exit(1)
	}

	// Ensure the bucket exists.
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(checkpointBucket))
		return err
	}); err != nil {
		slog.Error("checkpoint: failed to create bucket", "component", "checkpoint", "error", err)
		os.Exit(1)
	}

	slog.Info("checkpoint store opened", "component", "checkpoint", "path", path)
	return &BoltCheckPointStore{db: db, path: path}
}

// Get retrieves a checkpoint by ID. Returns the data, whether it existed, and any error.
func (s *BoltCheckPointStore) Get(_ context.Context, id string) ([]byte, bool, error) {
	var data []byte
	var found bool

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(checkpointBucket))
		if b == nil {
			return nil // bucket doesn't exist yet
		}
		v := b.Get([]byte(id))
		if v != nil {
			found = true
			// Copy the value — BoltDB bytes are only valid within the transaction.
			data = make([]byte, len(v))
			copy(data, v)
		}
		return nil
	})
	if err != nil {
		return nil, false, fmt.Errorf("checkpoint: get %q: %w", id, err)
	}

	return data, found, nil
}

// Set stores a checkpoint. Overwrites any existing checkpoint with the same ID.
func (s *BoltCheckPointStore) Set(_ context.Context, id string, data []byte) error {
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(checkpointBucket))
		if err != nil {
			return fmt.Errorf("create bucket: %w", err)
		}
		return b.Put([]byte(id), data)
	})
	if err != nil {
		return fmt.Errorf("checkpoint: set %q: %w", id, err)
	}
	return nil
}

// Delete removes a checkpoint, invalidating a paused graph so it can no longer
// be resumed. Used by the approval-timeout registry to expire interrupts so a
// late resume finds no graph state to execute (Step 5).
func (s *BoltCheckPointStore) Delete(_ context.Context, id string) error {
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(checkpointBucket))
		if b == nil {
			return nil // nothing to delete; bucket never created
		}
		return b.Delete([]byte(id))
	})
	if err != nil {
		return fmt.Errorf("checkpoint: delete %q: %w", id, err)
	}
	return nil
}

// Close flushes pending writes and releases the database file handle.
// Must be called during graceful shutdown to avoid corruption.
func (s *BoltCheckPointStore) Close() error {
	if s.db != nil {
		slog.Info("closing checkpoint store", "component", "checkpoint", "path", s.path)
		return s.db.Close()
	}
	return nil
}

// Compile-time interface check.
var _ compose.CheckPointStore = (*BoltCheckPointStore)(nil)
