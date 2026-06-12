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
	"time"
)

// ---------------------------------------------------------------------------
// MetricsRecorder interface (framework-agnostic)
// ---------------------------------------------------------------------------

// MetricsRecorder tracks gateway operational metrics.
// Nil-safe: callers must guard with nil checks before invoking.
//
// OSS provides a no-op implementation. Enterprise provides OTel/Datadog impls
// via the same interface — zero gateway/ code changes required.
type MetricsRecorder interface {
	// RecordToolCall records a completed tool call observation.
	RecordToolCall(ctx context.Context, info ToolCallMetric)

	// RecordDLPFinding records a single DLP finding.
	RecordDLPFinding(ctx context.Context, finding DLPFinding)

	// RecordApproval records a human approval decision.
	RecordApproval(ctx context.Context, action ApprovalAction, toolName string)
}

// ToolCallMetric records a completed tool call observation.
type ToolCallMetric struct {
	ToolName  string
	Decision  Decision
	RiskLevel RiskLevel
	Duration  time.Duration
}

// NOPMetricsRecorder is a no-op MetricsRecorder. Used when metrics are disabled.
type NOPMetricsRecorder struct{}

// RecordToolCall implements MetricsRecorder (no-op).
func (NOPMetricsRecorder) RecordToolCall(context.Context, ToolCallMetric) {}

// RecordDLPFinding implements MetricsRecorder (no-op).
func (NOPMetricsRecorder) RecordDLPFinding(context.Context, DLPFinding) {}

// RecordApproval implements MetricsRecorder (no-op).
func (NOPMetricsRecorder) RecordApproval(context.Context, ApprovalAction, string) {}
