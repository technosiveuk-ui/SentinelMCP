# Security Policy

## Supported versions

SentinelMCP is currently in **Alpha** (`v0.1.x`). Only the latest release line
receives security fixes.

| Version | Supported          |
|:--------|:-------------------|
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

As the project stabilizes toward a stable `v1.0`, this table will be updated
with a formal support window per release line.

## Reporting a vulnerability

We take security vulnerabilities seriously. **Please do not open a public
GitHub issue for security vulnerabilities.**

Report them privately to
**[security@technosive.co.uk](mailto:security@technosive.co.uk)**.

To help us reproduce and fix the issue quickly, please include:

- A description of the vulnerability and its impact.
- The affected component (gateway core, orchestration adapter, sidecar proxy,
  or Inline SDK) and the version you are running.
- Step-by-step reproduction — a minimal config, the exact commands, or a
  proof-of-concept.
- Any relevant logs, audit output, or stack traces.
- Your assessment of severity, and any suggested remediation.

## Disclosure process

1. We acknowledge your report within **two business days**.
2. We investigate and confirm the vulnerability, then coordinate a fix and a
   disclosure timeline with you.
3. Once a fix is available, we publish a patched release and a security
   advisory (a GitHub Security Advisory, and a CVE where applicable), crediting
   you unless you prefer to remain anonymous.

We ask that you give us reasonable time to remediate before any public
disclosure. **90 days** is our default window, extendable by mutual agreement.

## Scope

This policy covers the open-source SentinelMCP repository
([`technosiveuk-ui/SentinelMCP`](https://github.com/technosiveuk-ui/SentinelMCP)),
including the gateway core, the orchestration adapter, the sidecar proxy, and
the Inline SDK.

Out of scope:

- Vulnerabilities in third-party dependencies that are already fixed in a
  released version — please update your dependencies.
- Theoretical attacks without a concrete exploit path in a default
  configuration.
- Issues in Technosive Ltd.'s commercial Enterprise Control Plane — report
  those through your enterprise support channel.

## Security-relevant design notes

- **Default-deny on failure.** Every failure path in the enforcement pipeline
  blocks the tool call rather than allowing it through (NFR-07), so a fault
  cannot silently downgrade protection.
- **Sensitive values are never logged.** Matched DLP values are marked
  non-serializable and are excluded from audit and span output.
- **Alpha caveat.** SentinelMCP is Alpha software and should not be your sole
  defense in a highly regulated production environment without thorough
  testing. See the project [README](README.md) for the current status.
