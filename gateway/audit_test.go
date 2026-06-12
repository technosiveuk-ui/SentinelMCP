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
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStdoutAuditEmitter_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdoutAuditEmitter(&buf)

	entry := AuditEvent{
		Event:     "tool_start",
		ToolName:  "echo",
		RiskLevel: RiskLow,
		Decision:  DecisionAllow,
	}

	if err := logger.Emit(context.Background(), entry); err != nil {
		t.Fatalf("Log error: %v", err)
	}

	var logged AuditEvent
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if logged.Event != "tool_start" {
		t.Errorf("expected event tool_start, got %s", logged.Event)
	}
	if logged.ToolName != "echo" {
		t.Errorf("expected tool echo, got %s", logged.ToolName)
	}
	if logged.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

func TestStdoutAuditEmitter_SetsTimestamp(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStdoutAuditEmitter(&buf)

	entry := AuditEvent{Event: "test"} // zero timestamp
	_ = logger.Emit(context.Background(), entry)

	var logged AuditEvent
	_ = json.Unmarshal(buf.Bytes(), &logged)

	if logged.Timestamp.IsZero() {
		t.Error("expected auto-set timestamp")
	}
}

func TestInterruptError_Error(t *testing.T) {
	err := &InterruptError{
		Info: InterruptInfo{
			ToolName:  "exec_command",
			RiskLevel: RiskHigh,
			Reason:    "dangerous",
		},
	}

	msg := err.Error()
	if !strings.Contains(msg, "exec_command") {
		t.Errorf("error message should contain tool name: %s", msg)
	}
	if !strings.Contains(msg, "high") {
		t.Errorf("error message should contain risk level: %s", msg)
	}
}

func TestInterruptError_IsNil(t *testing.T) {
	var err *InterruptError
	if err != nil {
		t.Error("nil InterruptError should be nil")
	}
}

func TestGatewayConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  GatewayConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: GatewayConfig{
				Policy:       NewDefaultPolicy(),
				RiskDB:       NewYAMLRiskDB(nil, ToolRisk{Level: RiskLow}),
				DLPScanner:   mustNewScanner(),
				AuditEmitter: NewStdoutAuditEmitter(nil),
				ToolInvoker:  &testInvoker{},
			},
			wantErr: false,
		},
		{
			name: "missing policy",
			config: GatewayConfig{
				RiskDB:       NewYAMLRiskDB(nil, ToolRisk{Level: RiskLow}),
				DLPScanner:   mustNewScanner(),
				AuditEmitter: NewStdoutAuditEmitter(nil),
				ToolInvoker:  &testInvoker{},
			},
			wantErr: true,
		},
		{
			name: "missing tool invoker",
			config: GatewayConfig{
				Policy:       NewDefaultPolicy(),
				RiskDB:       NewYAMLRiskDB(nil, ToolRisk{Level: RiskLow}),
				DLPScanner:   mustNewScanner(),
				AuditEmitter: NewStdoutAuditEmitter(nil),
			},
			wantErr: true,
		},
		{
			name: "default redaction mask",
			config: GatewayConfig{
				Policy:       NewDefaultPolicy(),
				RiskDB:       NewYAMLRiskDB(nil, ToolRisk{Level: RiskLow}),
				DLPScanner:   mustNewScanner(),
				AuditEmitter: NewStdoutAuditEmitter(nil),
				ToolInvoker:  &testInvoker{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.config
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	// Verify default redaction mask is set.
	cfg := GatewayConfig{
		Policy:       NewDefaultPolicy(),
		RiskDB:       NewYAMLRiskDB(nil, ToolRisk{Level: RiskLow}),
		DLPScanner:   mustNewScanner(),
		AuditEmitter: NewStdoutAuditEmitter(nil),
		ToolInvoker:  &testInvoker{},
	}
	_ = cfg.Validate()
	if cfg.RedactionMask != "***REDACTED***" {
		t.Errorf("expected default redaction mask, got %s", cfg.RedactionMask)
	}
	if cfg.Redactor == nil {
		t.Error("expected default Redactor to be created")
	}
}

// testInvoker is a simple ToolInvoker for tests.
type testInvoker struct{}

func (t *testInvoker) Invoke(_ context.Context, toolName string, args map[string]any) (string, error) {
	return "result from " + toolName, nil
}

func mustNewScanner() *RegexDLPScanner {
	s, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		panic(err)
	}
	return s
}

func TestAuditEvent_Timestamp(t *testing.T) {
	entry := AuditEvent{
		Timestamp: time.Now().UTC(),
		Event:     "tool_end",
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if !strings.Contains(string(data), `"ts"`) {
		t.Error("expected ts field in JSON output")
	}
}
