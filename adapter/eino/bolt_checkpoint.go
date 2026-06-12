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
	"log"
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
		log.Fatalf("[checkpoint] failed to create directory %s: %v", dir, err)
	}

	db, err := bbolt.Open(path, 0600, &bbolt.Options{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("[checkpoint] failed to open BoltDB at %s: %v", path, err)
	}

	// Ensure the bucket exists.
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(checkpointBucket))
		return err
	}); err != nil {
		log.Fatalf("[checkpoint] failed to create bucket: %v", err)
	}

	log.Printf("[checkpoint] BoltDB store opened at %s", path)
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

// Close flushes pending writes and releases the database file handle.
// Must be called during graceful shutdown to avoid corruption.
func (s *BoltCheckPointStore) Close() error {
	if s.db != nil {
		log.Printf("[checkpoint] closing BoltDB store at %s", s.path)
		return s.db.Close()
	}
	return nil
}

// Compile-time interface check.
var _ compose.CheckPointStore = (*BoltCheckPointStore)(nil)
