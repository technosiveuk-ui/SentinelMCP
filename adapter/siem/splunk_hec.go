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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// SplunkHECSink — sends audit entries to Splunk HTTP Event Collector
// ---------------------------------------------------------------------------

const (
	defaultBatchSize     = 100
	defaultFlushInterval = 5 * time.Second
	defaultMaxRetries    = 3
	bufferSize           = 1000 // max buffered entries before dropping
)

// SplunkHECSink implements gateway.AuditSink by sending JSON events to a
// Splunk HEC endpoint with batching and retry.
//
// Events are buffered in a channel. A background goroutine flushes:
//   - Every flushInterval (default 5s)
//   - When batchSize entries accumulate (default 100)
//   - On explicit Close()
//
// Retries use exponential backoff: 1s, 2s, 4s (capped at 4s).
// If the buffer is full, entries are dropped with a log warning (non-blocking).
type SplunkHECSink struct {
	endpoint      string
	token         string
	client        *http.Client
	batchSize     int
	flushInterval time.Duration
	maxRetries    int

	mu     sync.Mutex
	buf    chan gateway.AuditEvent
	cancel context.CancelFunc
	done   chan struct{}
}

// SplunkHECOption configures optional Splunk HEC parameters.
type SplunkHECOption func(*SplunkHECSink)

// WithBatchSize sets the number of entries to accumulate before flushing.
func WithBatchSize(n int) SplunkHECOption {
	return func(s *SplunkHECSink) { s.batchSize = n }
}

// WithFlushInterval sets the maximum time between flushes.
func WithFlushInterval(d time.Duration) SplunkHECOption {
	return func(s *SplunkHECSink) { s.flushInterval = d }
}

// WithMaxRetries sets the number of retry attempts per batch.
func WithMaxRetries(n int) SplunkHECOption {
	return func(s *SplunkHECSink) { s.maxRetries = n }
}

// NewSplunkHECSink creates a Splunk HEC audit sink with batching.
func NewSplunkHECSink(endpoint, token string, opts ...SplunkHECOption) *SplunkHECSink {
	s := &SplunkHECSink{
		endpoint:      endpoint,
		token:         token,
		client:        &http.Client{Timeout: 10 * time.Second},
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		maxRetries:    defaultMaxRetries,
		buf:           make(chan gateway.AuditEvent, bufferSize),
		done:          make(chan struct{}),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Start background flusher.
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.flushLoop(ctx)

	slog.Info("Splunk HEC sink initialized",
		"component", "siem.splunk", "endpoint", endpoint, "batch", s.batchSize, "flush", s.flushInterval)

	return s
}

// Write implements gateway.AuditSink. Non-blocking: drops entry if buffer full.
func (s *SplunkHECSink) Write(_ context.Context, entry gateway.AuditEvent) error {
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now().UTC()
	}

	select {
	case s.buf <- entry:
		return nil
	default:
		slog.Warn("Splunk HEC buffer full, dropping audit entry", "component", "siem.splunk", "tool", entry.ToolName)
		return fmt.Errorf("siem/splunk: buffer full, entry dropped")
	}
}

// Close flushes remaining entries and stops the background flusher.
func (s *SplunkHECSink) Close() error {
	// Signal flusher to stop.
	s.cancel()

	// Drain remaining entries synchronously.
	s.drain()

	// Wait for flusher to exit.
	<-s.done

	slog.Info("Splunk HEC sink closed", "component", "siem.splunk")
	return nil
}

// flushLoop is the background goroutine that periodically flushes batches.
func (s *SplunkHECSink) flushLoop(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.flushInterval)
	defer ticker.Stop()

	var batch []gateway.AuditEvent

	for {
		select {
		case entry, ok := <-s.buf:
			if !ok {
				// Channel closed — flush remaining and exit.
				if len(batch) > 0 {
					s.sendBatch(ctx, batch)
				}
				return
			}
			batch = append(batch, entry)
			if len(batch) >= s.batchSize {
				s.sendBatch(ctx, batch)
				batch = nil
			}

		case <-ticker.C:
			if len(batch) > 0 {
				s.sendBatch(ctx, batch)
				batch = nil
			}

		case <-ctx.Done():
			// Flush remaining and exit.
			if len(batch) > 0 {
				s.sendBatch(ctx, batch)
			}
			return
		}
	}
}

// drain flushes any entries remaining in the buffer channel.
func (s *SplunkHECSink) drain() {
	var batch []gateway.AuditEvent
	for {
		select {
		case entry, ok := <-s.buf:
			if !ok {
				break
			}
			batch = append(batch, entry)
		default:
			if len(batch) > 0 {
				s.sendBatch(context.Background(), batch)
			}
			return
		}
	}
}

// sendBatch sends a batch of entries to Splunk HEC with retry.
func (s *SplunkHECSink) sendBatch(ctx context.Context, entries []gateway.AuditEvent) {
	if len(entries) == 0 {
		return
	}

	// Build the batch payload (Splunk HEC accepts newline-delimited JSON).
	var body bytes.Buffer
	for _, entry := range entries {
		event := splunkEvent{
			Time:  entry.Timestamp.Unix(),
			Event: entry,
		}
		line, err := json.Marshal(event)
		if err != nil {
			slog.Error("Splunk HEC marshal entry", "component", "siem.splunk", "error", err)
			continue
		}
		body.Write(line)
		body.WriteByte('\n')
	}

	if body.Len() == 0 {
		return
	}

	// Retry with exponential backoff.
	var lastErr error
	for attempt := 0; attempt < s.maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second
			if backoff > 4*time.Second {
				backoff = 4 * time.Second
			}
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
		}

		lastErr = s.doPost(ctx, body.Bytes())
		if lastErr == nil {
			return
		}
		slog.Warn("Splunk HEC send attempt failed", "component", "siem.splunk", "attempt", attempt+1, "attempts", s.maxRetries, "error", lastErr)
	}

	slog.Error("Splunk HEC batch dropped after retries",
		"component", "siem.splunk", "entries", len(entries), "retries", s.maxRetries, "error", lastErr)
}

// doPost sends a single HTTP POST to the Splunk HEC endpoint.
func (s *SplunkHECSink) doPost(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Splunk "+s.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("endpoint returned %d", resp.StatusCode)
	}

	return nil
}

// splunkEvent is the JSON payload sent to Splunk HEC.
type splunkEvent struct {
	Time  int64 `json:"time"`
	Event any   `json:"event"`
}
