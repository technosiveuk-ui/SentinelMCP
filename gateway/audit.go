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
	"io"
	"log"
	"os"
	"time"
)

// ---------------------------------------------------------------------------
// AuditEmitter interface (framework-agnostic)
// ---------------------------------------------------------------------------

// AuditEmitter is the framework-agnostic audit interface.
// The gateway emits structured security events via this interface whenever it
// enforces an action (ALLOW, BLOCK, REDACT, INTERRUPT).
//
// The AuditEvent is a first-class domain object. The emitter is only the
// delivery mechanism — stdout, OTel, file, or Enterprise Control Plane API.
// Domain logic NEVER calls log.Printf or OTel directly; it only calls Emit.
//
// OSS extension point: the OSS sidecar ships StdoutAuditEmitter, FileAuditEmitter,
// and OTelAuditEmitter. Enterprise adds ControlPlaneEmitter (API push to Control Plane)
// via the commercial Control Plane.
type AuditEmitter interface {
	// Emit sends a structured audit event.
	// Implementations must not block the caller for extended periods.
	Emit(ctx context.Context, event AuditEvent) error
}

// ---------------------------------------------------------------------------
// StdoutAuditEmitter — writes structured JSON to a writer
// ---------------------------------------------------------------------------

// StdoutAuditEmitter writes one JSON line per audit event to a writer.
// Default output is os.Stdout.
type StdoutAuditEmitter struct {
	encoder *json.Encoder
}

// NewStdoutAuditEmitter creates an audit emitter writing to w.
// If w is nil, defaults to os.Stdout.
func NewStdoutAuditEmitter(w io.Writer) *StdoutAuditEmitter {
	if w == nil {
		w = os.Stdout
	}
	return &StdoutAuditEmitter{
		encoder: json.NewEncoder(w),
	}
}

// Emit implements AuditEmitter.
func (e *StdoutAuditEmitter) Emit(_ context.Context, event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return e.encoder.Encode(event)
}

// ---------------------------------------------------------------------------
// FileAuditEmitter — writes structured JSON to a file
// ---------------------------------------------------------------------------

// FileAuditEmitter writes one JSON line per audit event to a file.
type FileAuditEmitter struct {
	logger  *log.Logger
	file    *os.File
	encoder *json.Encoder
}

// NewFileAuditEmitter creates an audit emitter writing to the given file path.
// The file is opened in append mode; created if it doesn't exist.
func NewFileAuditEmitter(path string) (*FileAuditEmitter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	return &FileAuditEmitter{
		file:    f,
		encoder: json.NewEncoder(f),
	}, nil
}

// Emit implements AuditEmitter.
func (e *FileAuditEmitter) Emit(_ context.Context, event AuditEvent) error {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return e.encoder.Encode(event)
}

// Close closes the underlying file.
func (e *FileAuditEmitter) Close() error {
	if e.file != nil {
		return e.file.Close()
	}
	return nil
}

// ---------------------------------------------------------------------------
// ApprovalProvider interface (framework-agnostic)
// ---------------------------------------------------------------------------

// ApprovalProvider notifies external systems about pending approvals.
// It does NOT handle the resume — that's done by the gateway graph
// when it receives the approval data via ResumeWithData.
//
// OSS extension point: the OSS sidecar ships WebhookApprovalProvider and
// CLIApprovalProvider. Enterprise implementations (Slack, Microsoft Teams,
// Email Adaptive Cards) are provided via the commercial Control Plane.
type ApprovalProvider interface {
	// SendApprovalRequest notifies the provider that a tool call needs approval.
	SendApprovalRequest(ctx context.Context, info InterruptInfo) error
}

// ---------------------------------------------------------------------------
// CLIApprovalProvider — terminal prompt for development
// ---------------------------------------------------------------------------

// CLIApprovalProvider implements ApprovalProvider with a terminal prompt.
// Suitable for development and demo use.
type CLIApprovalProvider struct{}

// NewCLIApprovalProvider creates a CLI-based approval provider.
func NewCLIApprovalProvider() *CLIApprovalProvider {
	return &CLIApprovalProvider{}
}

// SendApprovalRequest prints the approval request to stdout.
// The actual approve/deny/modify interaction is handled by the gateway graph's
// interrupt/resume mechanism, not by this provider.
func (p *CLIApprovalProvider) SendApprovalRequest(_ context.Context, info InterruptInfo) error {
	log.Printf("[APPROVAL REQUIRED] Tool: %s | Risk: %s | Reason: %s",
		info.ToolName, info.RiskLevel, info.Reason)
	return nil
}
