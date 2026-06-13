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
	"log/slog"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// OTelAuditEmitter — emits audit events as OTel span events
// ---------------------------------------------------------------------------

// OTelAuditEmitter implements gateway.AuditEmitter by adding structured audit
// events as span events to the active OpenTelemetry span from the context.
//
// This is the OTel observability path for audit events. When combined with
// StdoutAuditEmitter via CompositeAuditEmitter, audit events flow to both
// JSON stdout AND the OTel trace — giving operators full visibility.
//
// Enterprise alternative: ControlPlaneEmitter (API push to Control Plane).
type OTelAuditEmitter struct{}

// NewOTelAuditEmitter creates an AuditEmitter that adds events to the active OTel span.
func NewOTelAuditEmitter() *OTelAuditEmitter {
	return &OTelAuditEmitter{}
}

// Emit implements gateway.AuditEmitter.
// If there is no active span in the context, the event is silently dropped
// (graceful degradation — never blocks the gateway pipeline).
func (e *OTelAuditEmitter) Emit(ctx context.Context, event gateway.AuditEvent) error {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return nil // no active span — gracefully skip
	}

	attrs := []attribute.KeyValue{
		auditEventKey.String(event.Event),
		auditToolKey.String(event.ToolName),
		auditDecisionKey.String(string(event.Decision)),
		auditRiskKey.String(string(event.RiskLevel)),
	}

	if event.PolicyName != "" {
		attrs = append(attrs, auditPolicyKey.String(event.PolicyName))
	}
	if event.Error != "" {
		attrs = append(attrs, auditErrorKey.String(event.Error))
	}
	if event.SessionID != "" {
		attrs = append(attrs, auditSessionKey.String(event.SessionID))
	}
	if event.TraceID != "" {
		attrs = append(attrs, auditTraceIDKey.String(event.TraceID))
	}
	span.AddEvent("mcp.security.enforcement", trace.WithAttributes(attrs...))

	return nil
}

// Close is a no-op for OTel (spans are managed by the provider).
func (e *OTelAuditEmitter) Close() error { return nil }

// ---------------------------------------------------------------------------
// OTel audit attribute keys
// ---------------------------------------------------------------------------

var (
	auditEventKey    = attribute.Key("audit.event")
	auditToolKey     = attribute.Key("audit.tool_name")
	auditDecisionKey = attribute.Key("audit.decision")
	auditRiskKey     = attribute.Key("audit.risk_level")
	auditPolicyKey   = attribute.Key("audit.policy_name")
	auditErrorKey    = attribute.Key("audit.error")
	auditSessionKey  = attribute.Key("audit.session_id")
	auditTraceIDKey  = attribute.Key("audit.trace_id")
)

// ensure OTelAuditEmitter satisfies gateway.AuditEmitter at compile time.
var _ gateway.AuditEmitter = (*OTelAuditEmitter)(nil)

// init logs the availability of the OTel audit emitter.
func init() {
	slog.Debug("OTelAuditEmitter available", "component", "audit")
}
