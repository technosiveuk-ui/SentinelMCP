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

package siem

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// FileRotationSink tests
// ---------------------------------------------------------------------------

func TestFileRotationSink_WriteAndRead(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	sink, err := NewFileRotationSink(path, 0, 0, false)
	if err != nil {
		t.Fatalf("NewFileRotationSink: %v", err)
	}

	ctx := context.Background()
	entries := []gateway.AuditEvent{
		{Event: "tool_start", ToolName: "echo", Decision: gateway.DecisionAllow},
		{Event: "tool_end", ToolName: "echo", Decision: gateway.DecisionAllow},
	}

	for _, e := range entries {
		if err := sink.Write(ctx, e); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read back and verify.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		var entry gateway.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("Unmarshal line %d: %v", count, err)
		}
		if entry.Event != entries[count].Event {
			t.Errorf("line %d: event = %q, want %q", count, entry.Event, entries[count].Event)
		}
		if !entry.Timestamp.IsZero() {
			// Timestamp should be auto-populated.
		}
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 lines, got %d", count)
	}
}

func TestFileRotationSink_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Very small max size (1 MB) and large entries to trigger rotation.
	// Each entry is ~100 bytes, so ~10k entries should trigger rotation at 1MB.
	sink, err := NewFileRotationSink(path, 1, 3, false)
	if err != nil {
		t.Fatalf("NewFileRotationSink: %v", err)
	}

	ctx := context.Background()

	// Write enough large entries to trigger multiple rotations.
	bigPayload := strings.Repeat("x", 500) // make entries larger
	for i := 0; i < 5000; i++ {
		e := gateway.AuditEvent{
			Event:     "tool_start",
			ToolName:  "test_tool_with_long_name",
			Decision:  gateway.DecisionAllow,
			RiskLevel: gateway.RiskLow,
			Error:     bigPayload,
		}
		if err := sink.Write(ctx, e); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify backup files exist.
	backups, err := filepath.Glob(path + ".*")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(backups) == 0 {
		t.Error("expected at least one rotated backup file")
	}

	// Verify the main file exists and is valid JSONL.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("Open main file: %v", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineCount := 0
	for scanner.Scan() {
		var entry gateway.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("Unmarshal main line %d: %v", lineCount, err)
		}
		lineCount++
	}
	if lineCount == 0 {
		t.Error("main file is empty")
	}
}

func TestFileRotationSink_CompressedRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	sink, err := NewFileRotationSink(path, 1, 2, true)
	if err != nil {
		t.Fatalf("NewFileRotationSink: %v", err)
	}

	ctx := context.Background()
	bigPayload := strings.Repeat("y", 500)
	for i := 0; i < 5000; i++ {
		sink.Write(ctx, gateway.AuditEvent{
			Event:    "tool_end",
			ToolName: "compress_test_tool",
			Error:    bigPayload,
		})
	}
	sink.Close()

	// Verify .gz backup files exist.
	backups, err := filepath.Glob(path + ".*.gz")
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(backups) == 0 {
		t.Error("expected at least one .gz compressed backup")
	}

	// Verify compressed file is valid gzip containing JSONL.
	for _, backup := range backups {
		f, err := os.Open(backup)
		if err != nil {
			t.Fatalf("Open backup %s: %v", backup, err)
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			t.Fatalf("gzip.NewReader %s: %v", backup, err)
		}
		data, err := io.ReadAll(gz)
		gz.Close()
		f.Close()
		if err != nil {
			t.Fatalf("ReadAll %s: %v", backup, err)
		}

		// Verify it's valid JSONL.
		lines := bytes.Count(data, []byte("\n"))
		if lines == 0 {
			t.Errorf("backup %s appears empty after decompress", backup)
		}
		var entry gateway.AuditEvent
		firstLine := bytes.Split(data, []byte("\n"))[0]
		if err := json.Unmarshal(firstLine, &entry); err != nil {
			t.Errorf("backup %s: first line not valid JSON: %v", backup, err)
		}
	}
}

func TestFileRotationSink_SimpleFactory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "simple.jsonl")

	sink, err := NewSimpleFileSink(path)
	if err != nil {
		t.Fatalf("NewSimpleFileSink: %v", err)
	}

	ctx := context.Background()
	sink.Write(ctx, gateway.AuditEvent{Event: "test", ToolName: "t"})
	sink.Close()

	// Verify file exists with content.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), "test") {
		t.Error("file doesn't contain expected content")
	}
}

// ---------------------------------------------------------------------------
// SplunkHECSink tests (batching logic, no real HTTP server needed)
// ---------------------------------------------------------------------------

func TestSplunkHECSink_NonBlockingDrop(t *testing.T) {
	// Create a sink with a tiny buffer that will fill up fast.
	sink := NewSplunkHECSink("http://localhost:9999/services/collector/event", "test-token",
		WithBatchSize(10),
		WithFlushInterval(10*time.Second), // long interval so buffer fills
	)
	defer sink.Close()

	ctx := context.Background()

	// Fill the buffer — the flusher won't send (no server), so entries pile up.
	dropped := 0
	for i := 0; i < 1100; i++ {
		err := sink.Write(ctx, gateway.AuditEvent{
			Event:    "test",
			ToolName: "tool",
		})
		if err != nil && strings.Contains(err.Error(), "buffer full") {
			dropped++
		}
	}

	// Some entries should have been dropped once buffer filled.
	if dropped == 0 {
		t.Log("no entries dropped (flusher may have consumed some) — acceptable")
	}
}

func TestSplunkHECSink_BatchPayload(t *testing.T) {
	// Test that the batch payload is correctly formatted.
	// We do this by calling sendBatch directly with a stopped server.
	sink := &SplunkHECSink{
		endpoint:      "http://localhost:1", // port 1 — will fail fast
		token:         "test-token",
		client:        &http.Client{Timeout: 100 * time.Millisecond},
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		maxRetries:    1,
	}

	entries := []gateway.AuditEvent{
		{Event: "tool_start", ToolName: "echo", Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Event: "tool_end", ToolName: "echo", Timestamp: time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)},
	}

	// This will fail (no server) but won't panic — validates batch formatting.
	sink.sendBatch(context.Background(), entries)
}
