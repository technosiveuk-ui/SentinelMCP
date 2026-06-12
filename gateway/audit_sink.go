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

package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// AuditSink interface — single-destination audit writer
// ---------------------------------------------------------------------------

// AuditSink writes audit events to a single destination.
// Implementations: stdout, file+rotation, Splunk HEC, etc.
//
// OSS provides WriterAuditSink (stdout/file). Enterprise provides Splunk HEC,
// Datadog, and Control Plane sinks via the same interface.
type AuditSink interface {
	// Write writes one audit event to the sink.
	// Implementations must not block the caller for extended periods.
	Write(ctx context.Context, event AuditEvent) error

	// Close flushes and releases resources. Called once during shutdown.
	Close() error
}

// ---------------------------------------------------------------------------
// WriterAuditSink — writes JSON lines to any io.Writer
// ---------------------------------------------------------------------------

// WriterAuditSink implements AuditSink by writing JSON lines to an io.Writer.
type WriterAuditSink struct {
	encoder *json.Encoder
	writer  io.Writer
	closer  io.Closer
}

// NewWriterAuditSink creates an AuditSink writing JSON lines to w.
// If w implements io.Closer, Close() will close it.
func NewWriterAuditSink(w io.Writer) *WriterAuditSink {
	var closer io.Closer
	if c, ok := w.(io.Closer); ok {
		closer = c
	}
	return &WriterAuditSink{
		encoder: json.NewEncoder(w),
		writer:  w,
		closer:  closer,
	}
}

// Write implements AuditSink.
func (s *WriterAuditSink) Write(_ context.Context, event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return s.encoder.Encode(event)
}

// Close implements AuditSink.
func (s *WriterAuditSink) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// CompositeAuditEmitter — fans out to multiple AuditSinks
// ---------------------------------------------------------------------------

// CompositeAuditEmitter implements AuditEmitter by fanning out each event
// to multiple AuditSinks. Failures in one sink do not affect others.
//
// This is the primary AuditEmitter for the sidecar binary. It composes
// sinks like: stdout + file + Splunk HEC.
type CompositeAuditEmitter struct {
	mu    sync.Mutex
	sinks []AuditSink
}

// NewCompositeAuditEmitter creates an AuditEmitter that fans out to all sinks.
func NewCompositeAuditEmitter(sinks ...AuditSink) *CompositeAuditEmitter {
	return &CompositeAuditEmitter{sinks: sinks}
}

// Emit implements AuditEmitter. Writes to all sinks, isolating failures.
func (e *CompositeAuditEmitter) Emit(ctx context.Context, event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	var firstErr error
	for _, sink := range e.sinks {
		if err := sink.Write(ctx, event); err != nil && firstErr == nil {
			firstErr = err
			log.Printf("[audit] sink write error: %v", err)
		}
	}
	return firstErr
}

// Close closes all sinks. Errors are logged but do not stop closing remaining sinks.
func (e *CompositeAuditEmitter) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	var firstErr error
	for _, sink := range e.sinks {
		if err := sink.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close audit sink: %w", err)
		}
	}
	e.sinks = nil
	return firstErr
}

// StdoutAuditSink is a convenience constructor for a WriterAuditSink to stdout.
func StdoutAuditSink() *WriterAuditSink {
	return NewWriterAuditSink(os.Stdout)
}
