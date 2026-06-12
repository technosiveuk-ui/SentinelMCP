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
	"regexp"
	"sort"
	"sync"
)

// ---------------------------------------------------------------------------
// DLPScanner interface (framework-agnostic)
// ---------------------------------------------------------------------------

// DLPScanner scans content for sensitive patterns.
// Called twice per tool invocation:
//
//  1. Pre-call: on tool arguments (serialized to JSON string)
//  2. Post-call: on tool response (string)
//
// OSS extension point: the OSS sidecar ships RegexDLPScanner (local patterns).
// Enterprise adds Nightfall, Palantir, and Symantec connectors via DLPEndpoint.
type DLPScanner interface {
	// Scan returns all findings in the content.
	// Returns an empty (non-nil) slice if nothing found.
	Scan(ctx context.Context, content string) ([]DLPFinding, error)
}

// ---------------------------------------------------------------------------
// Regex-based DLP scanner
// ---------------------------------------------------------------------------

// RegexDLPScanner implements DLPScanner using pure Go regexps (no CGO, TR-02).
type RegexDLPScanner struct {
	mu       sync.RWMutex
	patterns []compiledPattern
}

type compiledPattern struct {
	Name  string
	Type  DLPFindingType
	Regex *regexp.Regexp
}

// NewRegexDLPScanner creates a DLP scanner with the given pattern definitions.
// Patterns are compiled at construction time — invalid regexps return an error.
func NewRegexDLPScanner(patterns map[string]PatternDef) (*RegexDLPScanner, error) {
	s := &RegexDLPScanner{}
	for name, def := range patterns {
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			return nil, err
		}
		s.patterns = append(s.patterns, compiledPattern{
			Name:  name,
			Type:  dlpTypeFromString(def.Type),
			Regex: re,
		})
	}
	return s, nil
}

// Scan implements DLPScanner.
func (s *RegexDLPScanner) Scan(_ context.Context, content string) ([]DLPFinding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var findings []DLPFinding
	for _, p := range s.patterns {
		locs := p.Regex.FindAllStringIndex(content, -1)
		for _, loc := range locs {
			findings = append(findings, DLPFinding{
				Type:     p.Type,
				Pattern:  p.Name,
				Value:    content[loc[0]:loc[1]], // json:"-" prevents logging
				Position: loc[0],
				EndIdx:   loc[1],
				Severity: SeverityHigh, // regex matches default to high severity
			})
		}
	}
	if findings == nil {
		findings = []DLPFinding{}
	}
	return findings, nil
}

// dlpTypeFromString converts a YAML type string to DLPFindingType.
func dlpTypeFromString(s string) DLPFindingType {
	switch s {
	case "secret":
		return FindingSecret
	case "pii":
		return FindingPII
	case "custom":
		return FindingCustom
	default:
		return FindingCustom
	}
}

// PatternDef defines a single DLP pattern.
type PatternDef struct {
	Regex string `yaml:"regex" json:"regex"`
	Type  string `yaml:"type"  json:"type"` // "secret" | "pii" | "custom"
}

// ---------------------------------------------------------------------------
// Built-in DLP patterns
// ---------------------------------------------------------------------------

// BuiltinPatterns returns the standard set of DLP patterns shipped with SentinelMCP.
func BuiltinPatterns() map[string]PatternDef {
	return map[string]PatternDef{
		"PRIVATE_KEY": {
			Regex: `-----BEGIN[A-Z ]*PRIVATE KEY-----`,
			Type:  "secret",
		},
		"PASSWORD": {
			Regex: `(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*\S+`,
			Type:  "secret",
		},
		"API_KEY": {
			Regex: `(?i)(?:api[_-]?key|apikey|access[_-]?token)\s*[=:]\s*\S+`,
			Type:  "secret",
		},
		"CREDIT_CARD": {
			Regex: `\b(?:4\d{12}\d{3}?|5[1-5]\d{14})\b`,
			Type:  "pii",
		},
		"SSN": {
			Regex: `\b\d{3}-\d{2}-\d{4}\b`,
			Type:  "pii",
		},
		"EMAIL": {
			Regex: `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
			Type:  "pii",
		},
	}
}

// ---------------------------------------------------------------------------
// Redactor interface (framework-agnostic)
// ---------------------------------------------------------------------------

// Redactor replaces sensitive content found by DLPScanner.
//
// OSS extension point: the OSS sidecar ships DefaultRedactor.
// Enterprise implementations may add format-aware redaction (e.g., structured
// JSON field masking) via the commercial Control Plane.
type Redactor interface {
	// Redact replaces all DLP finding values in the content with the mask.
	// Returns the redacted content (does not modify input).
	Redact(content string, findings []DLPFinding) string
}

// DefaultRedactor implements Redactor using simple string replacement.
type DefaultRedactor struct {
	Mask string // default: "***REDACTED***"
}

// NewDefaultRedactor creates a Redactor with the given mask.
func NewDefaultRedactor(mask string) *DefaultRedactor {
	if mask == "" {
		mask = "***REDACTED***"
	}
	return &DefaultRedactor{Mask: mask}
}

// Redact implements Redactor.
// Handles overlapping matches by sorting findings by position (descending)
// and replacing from end to start.
func (r *DefaultRedactor) Redact(content string, findings []DLPFinding) string {
	if len(findings) == 0 {
		return content
	}

	// Sort by position descending to replace from end (preserves offsets).
	sorted := make([]DLPFinding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Position > sorted[j].Position
	})

	result := content
	for _, f := range sorted {
		end := f.EndIdx
		if end == 0 {
			end = f.Position + len(f.Value)
		}
		if end > len(result) {
			continue // out of bounds, skip
		}
		result = result[:f.Position] + r.Mask + result[end:]
	}
	return result
}

// ---------------------------------------------------------------------------
// RedactArgs — helper for redacting individual argument fields
// ---------------------------------------------------------------------------

// RedactArgs redacts argument fields identified in the DecisionResult.
// Returns a new map; does not modify the input.
func RedactArgs(args map[string]any, result *DecisionResult, mask string) map[string]any {
	if result == nil || len(result.RedactedArgs) == 0 {
		return args
	}
	redacted := make(map[string]any, len(args))
	for k, v := range args {
		if _, ok := result.RedactedArgs[k]; ok {
			redacted[k] = mask
		} else {
			redacted[k] = v
		}
	}
	return redacted
}

// ---------------------------------------------------------------------------
// ScanArgs — field-attributed argument scanning
// ---------------------------------------------------------------------------

// ScanArgs scans tool arguments field-by-field and stamps every finding with
// the argument name it came from (DLPFinding.Field). This is what makes
// argument-level redaction work: on a "redact" decision, redactedFields keys
// off Field, so findings must carry it. Scanning one opaque JSON blob (as the
// graph used to) loses the field boundary and leaves RedactedArgs empty.
//
// Each argument is rendered as "name=value" before scanning. The "name=" prefix
// is deliberate: the built-in PASSWORD / API_KEY patterns match on a credential
// key adjacent to a separator (e.g. "password=hunter2", "api_key=..."), so a
// field literally named "password" is still caught even when its value matches
// no value-side pattern (SSN, card, email, private key).
//
// Keys are scanned in sorted order for stable audit output. Findings keep their
// pattern-relative positions; arg redaction only uses Field, so positions are
// not meaningful here (response redaction, which does use positions, scans the
// response string directly via DLPScanner.Scan).
func ScanArgs(ctx context.Context, scanner DLPScanner, args map[string]any) ([]DLPFinding, error) {
	if len(args) == 0 {
		return []DLPFinding{}, nil
	}

	names := make([]string, 0, len(args))
	for name := range args {
		names = append(names, name)
	}
	sort.Strings(names)

	var findings []DLPFinding
	for _, name := range names {
		rendered := name + "=" + argToString(args[name])
		fieldFindings, err := scanner.Scan(ctx, rendered)
		if err != nil {
			return nil, fmt.Errorf("gateway: scan argument %q: %w", name, err)
		}
		for i := range fieldFindings {
			fieldFindings[i].Field = name
			findings = append(findings, fieldFindings[i])
		}
	}
	if findings == nil {
		findings = []DLPFinding{}
	}
	return findings, nil
}

// argToString renders an argument value for regex scanning. Strings are used
// verbatim; other values use fmt.Sprint. The Sprint form keeps credential keys
// adjacent to a separator the built-in patterns expect — a nested map renders as
// map[password:x] (note the ":"), whereas JSON-marshalling would insert a quote
// (password":"x) and break the pattern. Go's fmt sorts map keys, so output is
// deterministic.
func argToString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}
