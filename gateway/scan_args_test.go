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
	"errors"
	"testing"
)

func mustScanner(t *testing.T) *RegexDLPScanner {
	t.Helper()
	s, err := NewRegexDLPScanner(BuiltinPatterns())
	if err != nil {
		t.Fatalf("build scanner: %v", err)
	}
	return s
}

func TestScanArgs_AttributesValueFindingsToField(t *testing.T) {
	scanner := mustScanner(t)

	findings, err := ScanArgs(context.Background(), scanner, map[string]any{
		"user":   "alice",
		"ssn":    "123-45-6789",
		"card":   "4111111111111111",
		"unused": "clean",
	})
	if err != nil {
		t.Fatalf("ScanArgs error: %v", err)
	}

	// Two sensitive values → two findings, each attributed to its field.
	fields := map[string]bool{}
	for _, f := range findings {
		if f.Field == "" {
			t.Errorf("finding for pattern %q has empty Field", f.Pattern)
		}
		fields[f.Field] = true
	}
	if !fields["ssn"] {
		t.Error("expected a finding attributed to the 'ssn' field")
	}
	if !fields["card"] {
		t.Error("expected a finding attributed to the 'card' field")
	}
	if fields["user"] || fields["unused"] {
		t.Error("clean fields should not produce findings")
	}
}

func TestScanArgs_CatchesCredentialNamedField(t *testing.T) {
	scanner := mustScanner(t)

	// The field is named like a credential, but the value matches no value-side
	// pattern. The "name=" rendering still triggers the PASSWORD pattern, so the
	// field is flagged for redaction — a pure value scan would miss this.
	findings, err := ScanArgs(context.Background(), scanner, map[string]any{
		"password": "x",
		"api_key":  "abc",
	})
	if err != nil {
		t.Fatalf("ScanArgs error: %v", err)
	}

	fields := map[string]bool{}
	for _, f := range findings {
		fields[f.Field] = true
	}
	if !fields["password"] {
		t.Error("expected the 'password' field (by name) to be flagged")
	}
	if !fields["api_key"] {
		t.Error("expected the 'api_key' field (by name) to be flagged")
	}
}

func TestScanArgs_NestedValueIsScannable(t *testing.T) {
	scanner := mustScanner(t)

	// A nested config map containing a password renders to JSON and is caught.
	findings, err := ScanArgs(context.Background(), scanner, map[string]any{
		"config": map[string]any{"password": "hunter2"},
	})
	if err != nil {
		t.Fatalf("ScanArgs error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.Field == "config" {
			found = true
		}
	}
	if !found {
		t.Error("expected nested password in 'config' to be flagged on the 'config' field")
	}
}

func TestScanArgs_EmptyArgs(t *testing.T) {
	scanner := mustScanner(t)
	findings, err := ScanArgs(context.Background(), scanner, map[string]any{})
	if err != nil {
		t.Fatalf("ScanArgs error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty args, got %d", len(findings))
	}
}

func TestScanArgs_CleanArgs(t *testing.T) {
	scanner := mustScanner(t)
	findings, err := ScanArgs(context.Background(), scanner, map[string]any{
		"path": "/etc/hosts",
		"n":    42,
	})
	if err != nil {
		t.Fatalf("ScanArgs error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean args, got %d (%v)", len(findings), findings)
	}
}

// failingScanner returns an error to verify ScanArgs propagates scanner errors.
type failingScanner struct{}

func (failingScanner) Scan(context.Context, string) ([]DLPFinding, error) {
	return nil, errors.New("scanner down")
}

func TestScanArgs_ScannerErrorPropagates(t *testing.T) {
	_, err := ScanArgs(context.Background(), failingScanner{}, map[string]any{"x": "y"})
	if err == nil {
		t.Fatal("expected error from failing scanner")
	}
}
