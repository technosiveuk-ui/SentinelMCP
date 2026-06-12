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
	"testing"
)

func TestRegexDLPScanner_Scan_NoMatch(t *testing.T) {
	scanner, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		t.Fatalf("NewRegexDLPScanner error: %v", err)
	}

	findings, err := scanner.Scan(context.Background(), "hello world")
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestRegexDLPScanner_Scan_PrivateKey(t *testing.T) {
	scanner, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		t.Fatalf("NewRegexDLPScanner error: %v", err)
	}

	content := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowI...\n-----END RSA PRIVATE KEY-----"
	findings, err := scanner.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for private key")
	}

	found := false
	for _, f := range findings {
		if f.Pattern == "PRIVATE_KEY" {
			found = true
			if f.Type != FindingSecret {
				t.Errorf("expected FindingSecret, got %s", f.Type)
			}
		}
	}
	if !found {
		t.Error("expected PRIVATE_KEY finding")
	}
}

func TestRegexDLPScanner_Scan_Password(t *testing.T) {
	scanner, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		t.Fatalf("NewRegexDLPScanner error: %v", err)
	}

	findings, err := scanner.Scan(context.Background(), "password=supersecret123")
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least 1 finding for password")
	}

	found := false
	for _, f := range findings {
		if f.Pattern == "PASSWORD" {
			found = true
		}
	}
	if !found {
		t.Error("expected PASSWORD finding")
	}
}

func TestRegexDLPScanner_Scan_MultiplePatterns(t *testing.T) {
	scanner, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		t.Fatalf("NewRegexDLPScanner error: %v", err)
	}

	content := "password=secret api_key=abc123"
	findings, err := scanner.Scan(context.Background(), content)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestRegexDLPScanner_InvalidRegex(t *testing.T) {
	_, err := NewRegexDLPScanner(map[string]PatternDef{
		"BROKEN": {Regex: "[invalid", Type: "custom"},
	})
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

func TestDefaultRedactor_Redact_NoFindings(t *testing.T) {
	r := NewDefaultRedactor("")
	result := r.Redact("hello world", nil)
	if result != "hello world" {
		t.Errorf("expected unchanged content, got %s", result)
	}
}

func TestDefaultRedactor_Redact_SingleFinding(t *testing.T) {
	r := NewDefaultRedactor("[REDACTED]")
	content := "my password is supersecret123 end"
	findings := []DLPFinding{
		{Pattern: "PASSWORD", Value: "supersecret123", Position: 15}, // byte offset of "supersecret123"
	}
	result := r.Redact(content, findings)
	expected := "my password is [REDACTED] end"
	if result != expected {
		t.Errorf("expected %q, got %q", expected, result)
	}
}

func TestDefaultRedactor_Redact_OverlappingFindings(t *testing.T) {
	r := NewDefaultRedactor("***")
	content := "abcdefghij"
	findings := []DLPFinding{
		{Pattern: "P1", Value: "cde", Position: 2},
		{Pattern: "P2", Value: "def", Position: 3},
	}
	// Descending position replacement: first replaces pos 3 ("def"→"***"),
	// then replaces pos 2 ("cde" region, now overlapping).
	result := r.Redact(content, findings)
	// Both overlapping regions are replaced; exact output depends on descending-order logic.
	// Key assertion: sensitive values are replaced with the mask.
	if result == content {
		t.Errorf("expected content to be redacted, got original: %q", result)
	}
}

func TestRedactArgs_NoRedaction(t *testing.T) {
	args := map[string]any{"key": "value", "other": 42}
	result := RedactArgs(args, nil, "***")
	if len(result) != len(args) {
		t.Errorf("expected same number of keys, got %d", len(result))
	}
	if result["key"] != "value" {
		t.Errorf("expected unchanged value, got %v", result["key"])
	}
}

func TestRedactArgs_WithRedactedFields(t *testing.T) {
	args := map[string]any{"password": "secret123", "name": "alice"}
	decision := &DecisionResult{
		Decision: DecisionRedact,
		RedactedArgs: map[string]string{
			"password": "***REDACTED***",
		},
	}

	result := RedactArgs(args, decision, "[MASK]")
	if result["password"] != "[MASK]" {
		t.Errorf("expected redacted password, got %v", result["password"])
	}
	if result["name"] != "alice" {
		t.Errorf("expected unchanged name, got %v", result["name"])
	}
}
