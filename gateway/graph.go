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
)

// ---------------------------------------------------------------------------
// ToolInvoker — framework-agnostic tool execution interface
// ---------------------------------------------------------------------------

// ToolInvoker executes a single MCP tool call and returns the raw result string.
// Implementations may wrap MCP SDK clients, mock tools for testing, or any
// other tool execution backend.
//
// OSS extension point: the OSS sidecar uses SidecarInvoker (routes to upstream
// MCP servers). Enterprise implementations may add caching, rate limiting, or
// audit enrichment via the commercial Control Plane.
type ToolInvoker interface {
	// Invoke calls the named tool with the given arguments and returns the
	// raw string result. The args map has already been through DLP scanning
	// and redaction if applicable.
	Invoke(ctx context.Context, toolName string, args map[string]any) (string, error)
}

// ---------------------------------------------------------------------------
// Pipeline — framework-agnostic gateway interface
// ---------------------------------------------------------------------------

// Pipeline wraps an MCP tool call with inspection, policy enforcement,
// and audit logging. It is the primary interface consumers use to route
// tool calls through SentinelMCP.
//
// Implementations may use different orchestration backends (Eino graph,
// custom pipeline, etc.) without the caller knowing or caring.
//
// OSS extension point: the OSS sidecar uses an Eino graph-based pipeline.
// Enterprise implementations may add distributed tracing, audit enrichment,
// or alternative orchestration backends via the commercial Control Plane.
type Pipeline interface {
	// Run executes a single tool call through the gateway.
	// Returns the (possibly redacted) result string, or an error if
	// the call was blocked or the pipeline failed.
	//
	// If the tool call requires human approval, returns *InterruptError.
	// The caller should collect approval and call Resume.
	Run(ctx context.Context, toolName string, args map[string]any) (string, error)

	// Resume continues a previously interrupted tool call with an approval
	// decision from a human.
	//
	// The interruptInfo comes from the InterruptError returned by Run.
	// The approval contains the human's decision (approve/deny/modify).
	Resume(ctx context.Context, interruptInfo InterruptInfo, approval *ApprovalDecision) (string, error)
}

// ---------------------------------------------------------------------------
// Gateway config — framework-agnostic dependency container
// ---------------------------------------------------------------------------

// GatewayConfig holds the dependencies for constructing a gateway Pipeline.
// All fields reference framework-agnostic interfaces defined in this package.
type GatewayConfig struct {
	Policy           Policy
	RiskDB           RiskDB
	DLPScanner       DLPScanner
	Redactor         Redactor
	AuditEmitter     AuditEmitter
	ApprovalProvider ApprovalProvider
	ToolInvoker      ToolInvoker
	RedactionMask    string          // default: "***REDACTED***"
	MetricsRecorder  MetricsRecorder // optional: nil = no-op (Sprint 1: not wired)
}

// Validate checks that all required dependencies are present.
// Sets defaults for optional fields.
func (c *GatewayConfig) Validate() error {
	if c.Policy == nil {
		return fmt.Errorf("gateway: Policy is required")
	}
	if c.RiskDB == nil {
		return fmt.Errorf("gateway: RiskDB is required")
	}
	if c.DLPScanner == nil {
		return fmt.Errorf("gateway: DLPScanner is required")
	}
	if c.AuditEmitter == nil {
		return fmt.Errorf("gateway: AuditEmitter is required")
	}
	if c.ToolInvoker == nil {
		return fmt.Errorf("gateway: ToolInvoker is required")
	}
	if c.RedactionMask == "" {
		c.RedactionMask = "***REDACTED***"
	}
	if c.Redactor == nil {
		c.Redactor = NewDefaultRedactor(c.RedactionMask)
	}
	return nil
}

// ---------------------------------------------------------------------------
// JSON boundary helpers
// ---------------------------------------------------------------------------

// WrapToolArgs serializes tool call arguments for pipeline entry.
func WrapToolArgs(toolName string, args map[string]any) (string, error) {
	gc := &GatewayContext{
		ToolName: toolName,
		Args:     args,
	}
	b, err := json.Marshal(gc)
	if err != nil {
		return "", fmt.Errorf("gateway: marshal args: %w", err)
	}
	return string(b), nil
}

// UnwrapToolResult extracts the result string from the pipeline output.
func UnwrapToolResult(output string) (string, error) {
	var gc GatewayContext
	if err := json.Unmarshal([]byte(output), &gc); err != nil {
		return "", fmt.Errorf("gateway: unmarshal result: %w", err)
	}
	if gc.Blocked {
		return "", fmt.Errorf("gateway: tool call blocked: %s", gc.Reason)
	}
	return gc.Result, nil
}
