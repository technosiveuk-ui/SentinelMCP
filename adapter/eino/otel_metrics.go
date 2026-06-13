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
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// OTelMetricsRecorder — OpenTelemetry metrics via OTLP gRPC
// ---------------------------------------------------------------------------

const (
	meterName = "sentinelmcp"

	// Metric instrument names — follow OTel semantic conventions.
	metricToolCallsTotal   = "sentinelmcp_tool_calls_total"
	metricToolCallDuration = "sentinelmcp_tool_call_duration_seconds"
	metricDLPFindingsTotal = "sentinelmcp_dlp_findings_total"
	metricApprovalsTotal   = "sentinelmcp_approvals_total"
)

// OTelConfig holds OpenTelemetry initialization parameters.
type OTelConfig struct {
	Endpoint       string        // e.g. "localhost:4317"
	ServiceName    string        // e.g. "sentinelmcp"
	ExportInterval time.Duration // e.g. 15s
}

// OTelMetricsRecorder implements gateway.MetricsRecorder via OpenTelemetry.
//
// Exposes four instruments:
//   - Counter:   sentinelmcp_tool_calls_total{tool, decision, risk}
//   - Histogram: sentinelmcp_tool_call_duration_seconds{tool, decision}
//   - Counter:   sentinelmcp_dlp_findings_total{type, pattern}
//   - Counter:   sentinelmcp_approvals_total{action, tool}
//
// Graceful shutdown is handled by Shutdown(), which flushes pending metrics
// and releases the gRPC connection.
type OTelMetricsRecorder struct {
	provider *sdkmetric.MeterProvider
	meter    metric.Meter

	toolCalls   metric.Int64Counter
	duration    metric.Float64Histogram
	dlpFindings metric.Int64Counter
	approvals   metric.Int64Counter
}

// NewOTelMetricsRecorder initializes OTel metrics with an OTLP gRPC exporter.
// If endpoint is empty, falls back to "localhost:4317".
// Returns a recorder that must be shut down via Close() on process exit.
func NewOTelMetricsRecorder(cfg OTelConfig) (*OTelMetricsRecorder, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "localhost:4317"
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sentinelmcp"
	}
	if cfg.ExportInterval == 0 {
		cfg.ExportInterval = 15 * time.Second
	}

	// Create OTLP gRPC exporter.
	exporter, err := otlpmetricgrpc.New(context.Background(),
		otlpmetricgrpc.WithEndpoint(cfg.Endpoint),
		otlpmetricgrpc.WithInsecure(), // sidecar typically talks to local collector
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create exporter: %w", err)
	}

	// Create resource with service name.
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create resource: %w", err)
	}

	// Create MeterProvider with periodic reader.
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
			sdkmetric.WithInterval(cfg.ExportInterval),
		)),
		sdkmetric.WithResource(res),
	)

	// Set global meter provider so any OTel-instrumented library picks it up.
	otel.SetMeterProvider(provider)

	meter := provider.Meter(meterName)

	// Initialize instruments.
	toolCalls, err := meter.Int64Counter(metricToolCallsTotal,
		metric.WithDescription("Total number of tool calls processed by the gateway"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create tool_calls counter: %w", err)
	}

	duration, err := meter.Float64Histogram(metricToolCallDuration,
		metric.WithDescription("Duration of tool calls through the gateway in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create duration histogram: %w", err)
	}

	dlpFindings, err := meter.Int64Counter(metricDLPFindingsTotal,
		metric.WithDescription("Total DLP findings detected by the gateway"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create dlp_findings counter: %w", err)
	}

	approvals, err := meter.Int64Counter(metricApprovalsTotal,
		metric.WithDescription("Total human approval decisions"),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create approvals counter: %w", err)
	}

	slog.Info("OTel metrics recorder initialized",
		"component", "otel", "endpoint", cfg.Endpoint, "service", cfg.ServiceName, "interval", cfg.ExportInterval)

	return &OTelMetricsRecorder{
		provider:    provider,
		meter:       meter,
		toolCalls:   toolCalls,
		duration:    duration,
		dlpFindings: dlpFindings,
		approvals:   approvals,
	}, nil
}

// RecordToolCall records a completed tool call observation.
func (r *OTelMetricsRecorder) RecordToolCall(ctx context.Context, info gateway.ToolCallMetric) {
	r.toolCalls.Add(ctx, 1,
		metric.WithAttributes(
			toolNameKey.String(info.ToolName),
			decisionKey.String(string(info.Decision)),
			riskLevelKey.String(string(info.RiskLevel)),
		),
	)
	r.duration.Record(ctx, info.Duration.Seconds(),
		metric.WithAttributes(
			toolNameKey.String(info.ToolName),
			decisionKey.String(string(info.Decision)),
		),
	)
}

// RecordDLPFinding records a single DLP finding.
func (r *OTelMetricsRecorder) RecordDLPFinding(ctx context.Context, finding gateway.DLPFinding) {
	r.dlpFindings.Add(ctx, 1,
		metric.WithAttributes(
			findingTypeKey.String(string(finding.Type)),
			patternKey.String(finding.Pattern),
		),
	)
}

// RecordApproval records a human approval decision.
func (r *OTelMetricsRecorder) RecordApproval(ctx context.Context, action gateway.ApprovalAction, toolName string) {
	r.approvals.Add(ctx, 1,
		metric.WithAttributes(
			approvalActionKey.String(string(action)),
			toolNameKey.String(toolName),
		),
	)
}

// Close flushes pending metrics and shuts down the OTel provider.
// Call this during graceful shutdown to ensure all metrics are exported.
func (r *OTelMetricsRecorder) Close() error {
	if r.provider != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		slog.Info("shutting down OTel meter provider", "component", "otel")
		return r.provider.Shutdown(ctx)
	}
	return nil
}

// ---------------------------------------------------------------------------
// OTel attribute keys (defined once, reused across all recordings)
// ---------------------------------------------------------------------------

var (
	toolNameKey       = attribute.Key("tool_name")
	decisionKey       = attribute.Key("decision")
	riskLevelKey      = attribute.Key("risk_level")
	findingTypeKey    = attribute.Key("finding_type")
	patternKey        = attribute.Key("pattern")
	approvalActionKey = attribute.Key("approval_action")
)
