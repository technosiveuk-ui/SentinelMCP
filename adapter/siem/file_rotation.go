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

// Package siem provides SIEM audit sink implementations for SentinelMCP.
package siem

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// FileRotationSink — writes audit entries to a file with rotation
// ---------------------------------------------------------------------------

const (
	defaultMaxSizeMB  = 100
	defaultMaxBackups = 5
)

// FileRotationSink implements gateway.AuditSink by writing JSON lines to a file
// with size-based rotation and optional gzip compression.
//
// Rotation rules:
//   - When the current file exceeds maxSizeMB, it is rotated:
//     audit.jsonl → audit.jsonl.1, audit.jsonl.1 → audit.jsonl.2, etc.
//   - Up to maxBackups rotated files are kept; older ones are deleted.
//   - If compress is true, rotated files are gzip-compressed (.jsonl.1.gz).
//
// Thread-safe: concurrent Write calls are serialized via mutex.
type FileRotationSink struct {
	mu         sync.Mutex
	file       *os.File
	encoder    *json.Encoder
	path       string
	maxBytes   int64
	maxBackups int
	compress   bool
}

// NewFileRotationSink creates a file-based audit sink with rotation.
//
// Parameters:
//   - path: file path (e.g. "/var/log/sentinelmcp/audit.jsonl")
//   - maxSizeMB: rotate when file exceeds this many MB (0 = default 100MB)
//   - maxBackups: number of rotated files to keep (0 = default 5)
//   - compress: gzip-compress rotated files
func NewFileRotationSink(path string, maxSizeMB, maxBackups int, compress bool) (*FileRotationSink, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = defaultMaxSizeMB
	}
	if maxBackups <= 0 {
		maxBackups = defaultMaxBackups
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("siem/file: create directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("siem/file: open %s: %w", path, err)
	}

	slog.Info("file rotation sink initialized",
		"component", "siem.file", "path", path, "maxSizeMB", maxSizeMB, "backups", maxBackups, "compress", compress)

	return &FileRotationSink{
		file:       f,
		encoder:    json.NewEncoder(f),
		path:       path,
		maxBytes:   int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
		compress:   compress,
	}, nil
}

// Write implements gateway.AuditSink. Thread-safe.
func (s *FileRotationSink) Write(_ context.Context, entry gateway.AuditEvent) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.encoder.Encode(entry); err != nil {
		return fmt.Errorf("siem/file: encode: %w", err)
	}

	// Check if rotation is needed after writing.
	if err := s.maybeRotate(); err != nil {
		slog.Warn("file rotation check failed", "component", "siem.file", "error", err)
		// Non-fatal — entry was already written.
	}

	return nil
}

// Close implements gateway.AuditSink.
func (s *FileRotationSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file != nil {
		err := s.file.Close()
		s.file = nil
		slog.Info("file rotation sink closed", "component", "siem.file")
		return err
	}
	return nil
}

// maybeRotate checks the file size and rotates if needed.
// Caller must hold s.mu.
func (s *FileRotationSink) maybeRotate() error {
	if s.file == nil {
		return nil
	}

	info, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("stat: %w", err)
	}

	if info.Size() < s.maxBytes {
		return nil
	}

	// Rotate: close current file, shift backups, open new file.
	if err := s.file.Close(); err != nil {
		return fmt.Errorf("close for rotation: %w", err)
	}

	if err := s.rotateBackups(); err != nil {
		slog.Error("file rotation error", "component", "siem.file", "error", err)
	}

	// Open new file.
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open after rotation: %w", err)
	}
	s.file = f
	s.encoder = json.NewEncoder(f)

	slog.Info("rotated audit file", "component", "siem.file", "path", s.path)
	return nil
}

// rotateBackups shifts backup files and optionally compresses.
// Caller must hold s.mu.
func (s *FileRotationSink) rotateBackups() error {
	// Delete the oldest backup if we'd exceed maxBackups.
	oldest := s.backupPath(s.maxBackups)
	if _, err := os.Stat(oldest); err == nil {
		os.Remove(oldest) // best-effort
	}

	// Shift backups: .N-1 → .N, .N-2 → .N-1, etc.
	for i := s.maxBackups; i >= 2; i-- {
		src := s.backupPath(i - 1)
		dst := s.backupPath(i)
		if _, err := os.Stat(src); err == nil {
			os.Rename(src, dst) // best-effort
		}
	}

	// Move/compress current → .1
	if s.compress {
		if err := s.compressFile(s.path, s.backupPath(1)); err != nil {
			slog.Warn("file compress failed, falling back to rename", "component", "siem.file", "error", err)
			os.Rename(s.path, s.backupPath(1)) // best-effort
		}
	} else {
		os.Rename(s.path, s.backupPath(1)) // best-effort
	}

	return nil
}

// compressFile gzip-compresses src to dst.
func (s *FileRotationSink) compressFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	gw, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer gw.Close()

	if _, err := io.Copy(gw, in); err != nil {
		return err
	}

	// Remove original after successful compression.
	os.Remove(src)
	return nil
}

// backupPath returns the file path for the Nth backup.
// If compress is true, appends .gz.
func (s *FileRotationSink) backupPath(n int) string {
	name := s.path + "." + strconv.Itoa(n)
	if s.compress {
		name += ".gz"
	}
	return name
}

// ---------------------------------------------------------------------------
// Backward-compatible constructor for simple (no-rotation) usage
// ---------------------------------------------------------------------------

// NewSimpleFileSink creates a file sink without rotation.
// Provided for backward compatibility with Sprint 1 config wiring.
func NewSimpleFileSink(path string) (*FileRotationSink, error) {
	return NewFileRotationSink(path, 0, 0, false)
}

// ---------------------------------------------------------------------------
// Backup listing helper (for admin/metrics)
// ---------------------------------------------------------------------------

// BackupInfo describes a rotated backup file.
type BackupInfo struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// ListBackups returns information about existing backup files.
// Useful for admin dashboards and monitoring.
func (s *FileRotationSink) ListBackups() ([]BackupInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pattern := s.path + ".*"
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return nil, err
	}

	var backups []BackupInfo
	for _, m := range matches {
		info, err := os.Stat(m)
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{
			Path:    m,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		})
	}

	// Sort by modification time (newest first).
	sort.Slice(backups, func(i, j int) bool {
		return backups[i].ModTime.After(backups[j].ModTime)
	})

	return backups, nil
}

// ParseBackupNumber extracts the backup number from a filename.
// Returns 0 if the filename doesn't match the pattern.
func ParseBackupNumber(filename string) int {
	base := filepath.Base(filename)
	parts := strings.Split(base, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		if n, err := strconv.Atoi(parts[i]); err == nil {
			return n
		}
		// Skip .gz extension
		if parts[i] == "gz" {
			continue
		}
	}
	return 0
}
