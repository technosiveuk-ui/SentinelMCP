# Transport Security

SentinelMCP enforces strong **application-layer** security — policy decisions, data-loss-prevention (DLP) redaction, structured audit, and default-deny on every failure. This document covers the **transport and connection-authentication** layer: how communications are protected on both legs of the sidecar proxy.

```
MCP client ──(inbound)──▶ SentinelMCP sidecar ──(outbound)──▶ upstream MCP server
```

A security gateway that itself runs plaintext, unauthenticated HTTP defeats its own purpose the moment it leaves loopback. The controls below close that gap.

---

## Governing principles

1. **Loopback-plaintext-default.** On a loopback address (`127.0.0.1`, `::1`, `localhost`) the sidecar may run plaintext HTTP with no auth — the host boundary carries trust, the same model as `redis`, `postgres`, or `dockerd` on a local socket. TLS and client authentication are **opt-in**, and required only when binding a non-loopback interface or dialing a network upstream.
2. **Fail-closed transport.** Every transport failure refuses or blocks rather than degrading: a missing TLS config, an unverifiable upstream certificate, an unresolved credential, a non-allowlisted egress host, or a group/world-readable secret file all prevent the call or the startup — **never** a silent fallback to plaintext or anonymous access.
3. **Open-core boundary.** Pure auth/secrets interfaces live in `gateway/auth` and `gateway/secrets` with **no** `net/http` or transport imports. The adapter layer extracts credentials from requests and injects them into outbound calls. Enterprise implementations (mTLS, OAuth2/OIDC, Vault) plug in behind these interfaces in the commercial build; the OSS release ships static, file/env-backed implementations.
4. **Auth feeds policy.** A resolved caller identity (`auth.Context`) is threaded onto the request context and reaches the policy and audit layers, so enforcement can become per-principal.

---

## Inbound — MCP client → SentinelMCP

### Bind policy (fail-closed)

| `listen_addr` | TLS | Auth | Result |
|:--|:--|:--|:--|
| loopback | — | optional | **Plaintext OK.** The host boundary carries trust. |
| non-loopback | configured | configured | **Allowed.** TLS terminates at the sidecar; API keys enforced. |
| non-loopback | missing | — | **Refuse to start.** |
| non-loopback | configured | missing | **Refuse to start.** |

Non-loopback exposure without TLS or auth is rejected at startup. To run a non-loopback plaintext listener anyway (a local demo on a trusted private network, never production), pass `--insecure-dev-mode`, which prints a loud stderr warning.

### TLS

Inbound TLS is opt-in via `sidecar.tls`:

```yaml
sidecar:
  listen_addr: "0.0.0.0:8443"
  tls:
    cert_file: "/etc/sentinelmcp/tls.crt"
    key_file:  "/etc/sentinelmcp/tls.key"
```

Self-signed certificate generation is deliberately **not** automated. The only path to a non-CA-issued cert is `--insecure-dev-mode`, which exists for local development — production deployments present a certificate from their own PKI or a public CA.

### API-key authentication

When `auth.api_keys` is non-empty, every inbound MCP call must present a valid key:

```yaml
auth:
  api_keys:
    "key-alpha-123": "agent-prod"     # key -> principal
    "key-beta-456":  "agent-staging"
```

Keys are accepted via `Authorization: Bearer <key>` or `X-API-Key: <key>`, validated in **constant time** across all configured keys (no early-exit timing side channel on which keys exist). A missing or invalid key returns `401`; the request never reaches the gateway pipeline. On success the resolved `auth.Context` (principal) is stamped onto the request and propagated into the tool-handler context, where policy and audit can read it.

### The admin / resume endpoint

The `/api/v1/approval/resume` endpoint releases blocked high-risk tool calls, so it is **always** privileged — it requires `sidecar.admin_token` (or `SENTINELMCP_ADMIN_TOKEN`) on every bind, including loopback. With no token configured, resume is disabled (`401`). Health probes (`/healthz`, `/readyz`) remain unauthenticated for kube/lb probes. The admin server also defaults to a loopback bind; a non-loopback admin bind requires `--insecure-admin-bind` and a configured token.

---

## Outbound — SentinelMCP → upstream MCP server

### Strict mode

`sidecar.strict` (default **true**) governs the upstream posture. At config load, strict mode **rejects**:

- plaintext `http://` upstream URLs (downgrade / exfiltration hole), and
- IP-literal host names (they defeat SNI, certificate SAN matching, and hostname-based allowlisting),

with a clear, actionable error. Set `strict: false` only for a trusted private-network upstream — the sidecar prints a loud warning when strict is off.

### Upstream TLS identity

Each upstream can pin its TLS identity independently:

```yaml
sidecar:
  upstream_servers:
    - name: "filesystem"
      url: "https://fs.internal/mcp"
      ca_bundle: "/etc/sentinelmcp/internal-ca.pem"   # PEM file path or inline PEM
      server_name: "fs.internal"                       # SNI / verification override
      pinned_sha256: "c3a...spki-hash..."              # hex SHA-256 of the leaf SPKI
```

- `ca_bundle` seeds the RootCAs used to validate the upstream chain (file path or inline PEM; empty = system roots).
- `server_name` overrides the TLS SNI and verification hostname.
- `pinned_sha256` adds a `VerifyPeerCertificate` check asserting the leaf certificate's SubjectPublicKeyInfo matches the pinned hash (constant-time compare).

`InsecureSkipVerify` is **never** set. Pinning is applied *on top of* normal chain validation, never instead of it — a pinned upstream must still present a chain valid against `ca_bundle` (or the system roots). A TLS verification failure blocks all calls to that upstream.

### Outbound credentials

Upstreams that require authentication declare a `credentials_ref`; SentinelMCP resolves it through the secrets provider and injects it as headers:

```yaml
sidecar:
  upstream_servers:
    - name: "crm"
      url: "https://crm.internal/mcp"
      credentials_ref: "crm"          # resolved via the secrets provider
```

The OSS `FileEnvProvider` resolves `credentials_ref` from a mode-0600 `secrets.yaml`, falling back to the `SENTINELMCP_UPSTREAM_<KEY>_TOKEN` environment variable (injected as `Authorization: Bearer <token>`):

```yaml
# secrets.yaml (chmod 0600)
upstreams:
  crm:
    headers:
      Authorization: "Bearer <token>"
      X-Tenant: "acme"
```

Headers are **general** (any auth scheme, not just a bearer token). If a declared `credentials_ref` cannot be resolved, the upstream is **never dialed** — fail-closed. Credential values are treated as secret and are never logged or written to audit.

### Egress allowlist

`sidecar.egress_allowlist` bounds which upstream hosts the sidecar may dial. When non-empty, every upstream host must match an entry — hostnames by exact or suffix (subdomain) match, IP literals by exact entry only (suffix-matching IPs is unsafe). A non-matching upstream is rejected at config load. An empty allowlist imposes no restriction; under strict mode with upstreams configured, the sidecar logs a warning that egress is unrestricted rather than silently denying everything.

```yaml
sidecar:
  egress_allowlist:
    - ".internal.company.com"   # matches fs.internal, db.internal, ...
    - "10.0.0.5"                # exact IP only
```

Strict mode's IP-literal rejection is allowlist-aware: an IP literal is permitted when it is an exact `egress_allowlist` entry, so a pinned internal upstream can be expressed explicitly.

> **Note.** Egress validation is load-time, which is the security-relevant gate. Call-time / dial-time enforcement (live reload and IP-level DNS-rebinding defense via a custom dialer) is a planned follow-up; host-suffix matching already mitigates DNS rebinding at the hostname level.

---

## Secrets at rest

Secret-bearing files must be owner-only (`0600`):

- A `config.yaml` containing `sidecar.admin_token` or `auth.api_keys`, and a `secrets.yaml`, are **refused at load** if they are group- or world-readable.
- The environment is the safe path for secrets in shared/audited environments: `SENTINELMCP_ADMIN_TOKEN` and `SENTINELMCP_UPSTREAM_<KEY>_TOKEN` never touch disk.
- Matched credential and DLP values are marked non-serializable and excluded from audit and log output (NFR-06).

---

## The fail-closed contract

| Condition | Behavior |
|:--|:--|
| Non-loopback inbound, no TLS | Refuse to start |
| Non-loopback inbound, no `auth.api_keys` | Refuse to start |
| Resume call with no / wrong admin token | `401` (resume disabled when token unset) |
| Strict mode + `http://` upstream | Refuse to start |
| Strict mode + IP-literal upstream (not exact-allowlisted) | Refuse to start |
| Upstream TLS verify / pin failure | Block all calls to that upstream |
| Unresolved `credentials_ref` | Upstream never dialed |
| Upstream host outside `egress_allowlist` | Refuse to start |
| Group/world-readable `config.yaml` with secrets, or `secrets.yaml` | Refuse to load |

None of these fall back to plaintext or anonymous access.

---

## Open-core seams

Two pure interfaces in `gateway/` define where Enterprise implementations attach. Both are free of `net/http` and transport types:

| Interface (OSS package) | OSS implementation | Enterprise implementation |
|:--|:--|:--|
| `gateway/auth.Authenticator` | `APIKeyAuthenticator` (static key → principal, constant-time) | mTLS, OAuth2 / OIDC client auth |
| `gateway/secrets.Provider` | `FileEnvProvider` (`secrets.yaml` + env) | HashiCorp Vault, AWS Secrets Manager, GCP Secret Manager |

The adapter layer (`cmd/sentinelmcp`, `adapter/sidecar`) is the only place that touches `net/http` and MCP transport options — it extracts credentials from inbound requests, calls the pure interfaces, and injects resolved headers into outbound clients.

---

## Configuration reference

| Field | Default | Purpose |
|:--|:--|:--|
| `sidecar.listen_addr` | `localhost:8080` | MCP proxy bind. Loopback = plaintext OK. |
| `sidecar.health_addr` | `localhost:9090` | Admin (health + resume) bind. Loopback enforced. |
| `sidecar.admin_token` | *(env recommended)* | Gates `/api/v1/approval/resume`; override via `SENTINELMCP_ADMIN_TOKEN`. |
| `sidecar.strict` | `true` | Reject `http://` + IP-literal upstreams at load. |
| `sidecar.egress_allowlist` | `[]` | Permitted upstream host suffixes / exact IPs. |
| `sidecar.tls.cert_file` / `key_file` | *(empty)* | Inbound TLS; required off-loopback. |
| `auth.api_keys` | `{}` | Inbound key → principal map; enforced when non-empty. |
| `secrets.file` | *(empty)* | `secrets.yaml` path (mode 0600); empty = env-only. |
| `upstream_servers[].url` | — | Upstream URL (`https://` under strict). |
| `upstream_servers[].ca_bundle` | *(empty)* | Upstream CA bundle (file or inline PEM). |
| `upstream_servers[].server_name` | *(empty)* | Upstream TLS SNI / verification override. |
| `upstream_servers[].pinned_sha256` | *(empty)* | Upstream leaf SPKI pin (hex SHA-256). |
| `upstream_servers[].credentials_ref` | *(empty)* | Key into the secrets provider; empty = no credentials. |

**CLI flags:** `--config <path>`, `--insecure-admin-bind` (allow non-loopback admin), `--insecure-dev-mode` (allow non-loopback plaintext/no-auth inbound — local dev/demo only).

---

## The Docker demo

The bundled demo (`docker compose up --build`) runs three containers on a private compose network. Because the test client reaches the sidecar from a *separate* container, both the admin server (`:9090`) and the MCP proxy (`:8080`) bind all interfaces, and the upstream is plaintext. The demo therefore launches with `--insecure-admin-bind`, `--insecure-dev-mode`, and `strict: false` — each prints a loud warning and is documented as a private-network exception. **Production deployments never set these flags**; they present a real certificate, configure `auth.api_keys`, use `https://` upstreams, and leave `strict: true`.

See [`SECURITY.md`](../SECURITY.md) for the vulnerability reporting policy, and [`INLINE-SDK.md`](INLINE-SDK.md) for in-process enforcement without a sidecar.
