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
	"fmt"
	"time"
)

// ---------------------------------------------------------------------------
// DLPEndpoint interface — contract for external DLP APIs
// ---------------------------------------------------------------------------

// DLPEndpoint is the Enterprise integration contract for external DLP scanning APIs.
// This is the interface that vendors implement to connect Nightfall, Netskope,
// Palantir, Symantec, Microsoft Purview, etc. to the SentinelMCP pipeline.
//
// OSS extension point: the OSS sidecar does not ship any DLPEndpoint implementations.
// Enterprise implementations are provided via the commercial Control Plane.
//
// Implementations should populate DLPFinding.EndIdx (not Value) and set
// DLPFinding.Severity and DLPFinding.Metadata with vendor-specific context.
// The DefaultRedactor prefers EndIdx for redaction — no need to expose the
// sensitive Value field.
type DLPEndpoint interface {
	// Scan sends content to the external DLP service and returns findings.
	Scan(ctx context.Context, content string) ([]DLPFinding, error)
}

// ---------------------------------------------------------------------------
// ExternalDLPScanner — adapts DLPEndpoint to DLPScanner interface
// ---------------------------------------------------------------------------

// ExternalDLPScanner implements DLPScanner by delegating to a DLPEndpoint.
// This is the adapter that lets Enterprise DLP APIs plug into the gateway
// without any code changes to the core pipeline.
type ExternalDLPScanner struct {
	endpoint DLPEndpoint
	timeout  time.Duration
}

// NewExternalDLPScanner creates a DLPScanner backed by an external API endpoint.
func NewExternalDLPScanner(endpoint DLPEndpoint, timeout time.Duration) *ExternalDLPScanner {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	return &ExternalDLPScanner{
		endpoint: endpoint,
		timeout:  timeout,
	}
}

// Scan implements DLPScanner. Delegates to the external DLPEndpoint with a timeout.
func (s *ExternalDLPScanner) Scan(ctx context.Context, content string) ([]DLPFinding, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	findings, err := s.endpoint.Scan(ctx, content)
	if err != nil {
		return nil, fmt.Errorf("external DLP scan: %w", err)
	}
	if findings == nil {
		return []DLPFinding{}, nil
	}
	return findings, nil
}
