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

// Package secrets provides outbound credential resolution for upstream MCP
// servers. It is pure with respect to transport: no net/http, no mcp-go. The
// adapter layer (adapter/sidecar) injects resolved headers via mcp-go transport
// options. This is the open-core seam — OSS ships FileEnvProvider; Enterprise
// plugs HashiCorp Vault / AWS Secrets Manager / GCP Secret Manager in behind
// Provider.
package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Credential is a resolved set of outbound credentials for an upstream. Headers
// is general (not a single token) so it can carry any auth scheme — Bearer,
// Basic, or a custom API-key header. Header VALUES MUST NOT be logged or
// serialized to audit (NFR-06); treat the whole Credential as secret.
type Credential struct {
	Headers map[string]string
}

// Provider resolves credentials for an upstream by its credentials_ref key.
//
// OSS extension point: FileEnvProvider. Enterprise adds Vault / ASM / GCP SM
// behind this interface in the private SentinelENT repo.
type Provider interface {
	// Fetch returns the Credential for key, or an error if it cannot be
	// resolved. Callers treat any error as fail-closed: block the upstream's
	// calls rather than dial without credentials (NFR-07).
	Fetch(ctx context.Context, key string) (*Credential, error)
}

// FileEnvProvider resolves credentials from a loaded secrets map (typically
// from a secrets.yaml) with an environment-variable fallback. OSS implementation.
type FileEnvProvider struct {
	upstreams map[string]map[string]string // credentials_ref -> headers
}

// NewFileEnvProvider builds a provider from a pre-loaded map (normally the
// result of LoadSecretsFile). A nil/empty map makes it env-only.
func NewFileEnvProvider(upstreams map[string]map[string]string) *FileEnvProvider {
	copied := make(map[string]map[string]string, len(upstreams))
	for key, headers := range upstreams {
		hc := make(map[string]string, len(headers))
		for hk, hv := range headers {
			hc[hk] = hv
		}
		copied[key] = hc
	}
	return &FileEnvProvider{upstreams: copied}
}

// Fetch implements Provider. The loaded map is consulted first; if no entry is
// found, the env var SENTINELMCP_UPSTREAM_<KEY>_TOKEN is used (as a Bearer
// token). If neither yields a credential, Fetch returns an error (fail-closed).
func (p *FileEnvProvider) Fetch(_ context.Context, key string) (*Credential, error) {
	if headers, ok := p.upstreams[key]; ok && len(headers) > 0 {
		return &Credential{Headers: headers}, nil
	}
	if tok := os.Getenv(EnvUpstreamToken(key)); tok != "" {
		return &Credential{Headers: map[string]string{"Authorization": "Bearer " + tok}}, nil
	}
	return nil, fmt.Errorf("no credentials found for %q (checked the secrets file and %s)",
		key, EnvUpstreamToken(key))
}

// EnvUpstreamToken returns the environment-variable name for a credentials_ref.
func EnvUpstreamToken(key string) string {
	return "SENTINELMCP_UPSTREAM_" + sanitizeEnvKey(key) + "_TOKEN"
}

// sanitizeEnvKey uppercases key and replaces every character outside [A-Z0-9_]
// with an underscore so the result is a valid env-var fragment.
func sanitizeEnvKey(key string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(key) {
		switch {
		case (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// secrets.yaml loading (0600 enforced)
// ---------------------------------------------------------------------------

type secretEntry struct {
	Headers map[string]string `yaml:"headers"`
}

type secretsFile struct {
	Upstreams map[string]secretEntry `yaml:"upstreams"`
}

// LoadSecretsFile reads and parses a secrets.yaml into a credentials_ref ->
// headers map. Fail-closed (NFR-06 family): a group/world-readable file is
// rejected — secrets at rest must be owner-only. An empty path returns an empty
// map, yielding an env-only provider.
func LoadSecretsFile(path string) (map[string]map[string]string, error) {
	if path == "" {
		return map[string]map[string]string{}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("%s is group/world-readable (mode %o): a secrets file must be mode 0600",
			path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var sf secretsFile
	if err := yaml.Unmarshal(data, &sf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	out := make(map[string]map[string]string, len(sf.Upstreams))
	for key, entry := range sf.Upstreams {
		out[key] = entry.Headers
	}
	return out, nil
}
