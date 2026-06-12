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
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Mock DLPEndpoint for testing external scanner integration
// ---------------------------------------------------------------------------

// mockEndpoint implements DLPEndpoint for tests.
type mockEndpoint struct {
	findings []DLPFinding
	err      error
	delay    time.Duration // simulate latency
}

func (m *mockEndpoint) Scan(ctx context.Context, content string) ([]DLPFinding, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.err != nil {
		return nil, m.err
	}
	if m.findings == nil {
		return []DLPFinding{}, nil
	}
	return m.findings, nil
}

// ---------------------------------------------------------------------------
// Test 1: EndIdx-based redaction (external scanner path)
// ---------------------------------------------------------------------------

func TestDLPFinding_EndIdx_Redaction(t *testing.T) {
	// External scanners set EndIdx but NOT Value (Value is json:"-").
	// The DefaultRedactor must use EndIdx when non-zero.
	content := "user SSN is 123-45-6789 please verify"
	findings := []DLPFinding{
		{
			Type:     FindingPII,
			Pattern:  "SSN",
			Value:    "", // empty — external scanner doesn't expose sensitive data
			Position: 12, // byte offset of "123-45-6789"
			EndIdx:   23, // byte offset end of "123-45-6789"
			Severity: SeverityHigh,
			Metadata: map[string]any{"vendor": "nightfall", "confidence": 0.97},
		},
	}

	r := NewDefaultRedactor("[REDACTED]")
	result := r.Redact(content, findings)

	expected := "user SSN is [REDACTED] please verify"
	if result != expected {
		t.Errorf("EndIdx redaction failed:\n  expected: %q\n  got:      %q", expected, result)
	}

	// Verify the sensitive value is completely gone.
	if strings.Contains(result, "123-45-6789") {
		t.Error("redacted content still contains sensitive SSN")
	}
}

// ---------------------------------------------------------------------------
// Test 2: MultiDLPScanner composes regex + external scanners
// ---------------------------------------------------------------------------

func TestMultiDLPScanner_RegexPlusExternal(t *testing.T) {
	// Regex scanner catches password=secret in the content.
	regexScanner, err := NewRegexDLPScanner(map[string]PatternDef{
		"PASSWORD": {Regex: `(?i)password\s*[=:]\s*\S+`, Type: "secret"},
	})
	if err != nil {
		t.Fatalf("NewRegexDLPScanner: %v", err)
	}

	// External scanner catches a credit card the regex doesn't know about.
	externalScanner := NewExternalDLPScanner(&mockEndpoint{
		findings: []DLPFinding{
			{
				Type:     FindingCreditCard,
				Pattern:  "CREDIT_CARD",
				Value:    "",
				Position: 60,
				EndIdx:   76,
				Severity: SeverityHigh,
				Metadata: map[string]any{"vendor": "symantec"},
			},
		},
	}, 5*time.Second)

	multi := NewMultiDLPScanner(regexScanner, externalScanner)

	content := "password=supersecret and some filler text then card 4111111111111111 done"
	findings, err := multi.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("MultiDLPScanner.Scan: %v", err)
	}

	// Should have findings from both scanners.
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (regex + external), got %d", len(findings))
	}

	// Verify both sources contributed.
	hasPassword := false
	hasCC := false
	for _, f := range findings {
		if f.Pattern == "PASSWORD" {
			hasPassword = true
		}
		if f.Pattern == "CREDIT_CARD" {
			hasCC = true
			if f.Severity != SeverityHigh {
				t.Errorf("expected HIGH severity from external, got %s", f.Severity)
			}
			if f.Metadata["vendor"] != "symantec" {
				t.Errorf("expected symantec metadata, got %v", f.Metadata["vendor"])
			}
		}
	}
	if !hasPassword {
		t.Error("MultiDLPScanner missing regex scanner finding (PASSWORD)")
	}
	if !hasCC {
		t.Error("MultiDLPScanner missing external scanner finding (CREDIT_CARD)")
	}
}

// ---------------------------------------------------------------------------
// Test 3: ExternalDLPScanner timeout behavior
// ---------------------------------------------------------------------------

func TestExternalDLPScanner_Timeout(t *testing.T) {
	// Endpoint that takes 5 seconds — timeout is 100ms.
	slowEndpoint := &mockEndpoint{
		delay: 5 * time.Second,
	}
	scanner := NewExternalDLPScanner(slowEndpoint, 100*time.Millisecond)

	_, err := scanner.Scan(context.Background(), "some content")
	if err == nil {
		t.Fatal("expected timeout error from ExternalDLPScanner, got nil")
	}

	// Error should mention "external DLP scan" (wrapped by adapter).
	if !strings.Contains(err.Error(), "external DLP scan") {
		t.Errorf("error should wrap with 'external DLP scan', got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Severity passthrough from external scanner
// ---------------------------------------------------------------------------

func TestExternalDLPScanner_SeverityPassthrough(t *testing.T) {
	// External vendor returns findings with different severity levels.
	endpoint := &mockEndpoint{
		findings: []DLPFinding{
			{
				Type:     FindingPII,
				Pattern:  "EMAIL",
				Position: 5,
				EndIdx:   24,
				Severity: SeverityLow,
				Metadata: map[string]any{"confidence": 0.72},
			},
			{
				Type:     FindingSecret,
				Pattern:  "API_KEY",
				Position: 30,
				EndIdx:   50,
				Severity: SeverityHigh,
				Metadata: map[string]any{"confidence": 0.99, "rule_id": "SEC-001"},
			},
		},
	}

	scanner := NewExternalDLPScanner(endpoint, 5*time.Second)
	findings, err := scanner.Scan(context.Background(), "user alice@example.com key=ak-1234567890abcdef")
	if err != nil {
		t.Fatalf("ExternalDLPScanner.Scan: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Verify severity levels preserved exactly as set by the external vendor.
	if findings[0].Severity != SeverityLow {
		t.Errorf("finding 0: expected LOW severity, got %s", findings[0].Severity)
	}
	if findings[1].Severity != SeverityHigh {
		t.Errorf("finding 1: expected HIGH severity, got %s", findings[1].Severity)
	}

	// Verify metadata preserved.
	if findings[0].Metadata["confidence"] != 0.72 {
		t.Errorf("finding 0 metadata confidence: expected 0.72, got %v", findings[0].Metadata["confidence"])
	}
	if findings[1].Metadata["rule_id"] != "SEC-001" {
		t.Errorf("finding 1 metadata rule_id: expected SEC-001, got %v", findings[1].Metadata["rule_id"])
	}

	// Verify EndIdx preserved for redaction.
	if findings[0].EndIdx != 24 {
		t.Errorf("finding 0 EndIdx: expected 24, got %d", findings[0].EndIdx)
	}
	if findings[1].EndIdx != 50 {
		t.Errorf("finding 1 EndIdx: expected 50, got %d", findings[1].EndIdx)
	}
}
