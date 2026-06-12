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
	"sort"
)

// ---------------------------------------------------------------------------
// MultiDLPScanner — composes multiple DLPScanners
// ---------------------------------------------------------------------------

// MultiDLPScanner implements DLPScanner by running multiple scanners
// and deduplicating findings by (pattern, position).
//
// Use this to combine the built-in RegexDLPScanner with external DLP APIs
// (Nightfall, Netskope, etc.) without changing any gateway code.
type MultiDLPScanner struct {
	scanners []DLPScanner
}

// NewMultiDLPScanner creates a DLPScanner that fans out to all scanners.
func NewMultiDLPScanner(scanners ...DLPScanner) *MultiDLPScanner {
	return &MultiDLPScanner{scanners: scanners}
}

// Scan implements DLPScanner. Runs all scanners and deduplicates findings
// by (pattern, position) pair.
func (m *MultiDLPScanner) Scan(ctx context.Context, content string) ([]DLPFinding, error) {
	var allFindings []DLPFinding
	for _, scanner := range m.scanners {
		findings, err := scanner.Scan(ctx, content)
		if err != nil {
			// One scanner failing should not prevent others from running,
			// but we do return the error to preserve the existing contract.
			return nil, err
		}
		allFindings = append(allFindings, findings...)
	}

	return deduplicateFindings(allFindings), nil
}

// deduplicateFindings removes duplicate findings by (pattern, position) pair.
func deduplicateFindings(findings []DLPFinding) []DLPFinding {
	if len(findings) == 0 {
		return []DLPFinding{}
	}

	type key struct {
		pattern  string
		position int
	}
	seen := make(map[key]bool, len(findings))

	result := make([]DLPFinding, 0, len(findings))
	for _, f := range findings {
		k := key{pattern: f.Pattern, position: f.Position}
		if !seen[k] {
			seen[k] = true
			result = append(result, f)
		}
	}

	// Sort by position for deterministic output.
	sort.Slice(result, func(i, j int) bool {
		return result[i].Position < result[j].Position
	})

	return result
}
