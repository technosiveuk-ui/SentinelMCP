# Changelog

All notable changes to SentinelMCP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-12

### Added

**Sprint 1 — Core Gateway (Weeks 3-6)**
- Gateway pipeline with 3-node security graph: inspect_tool_call → run_tool → inspect_tool_response
- `Policy` interface with `DefaultPolicy` (risk-level routing: low→allow, medium→redact, high→interrupt)
- `RiskDB` interface with `YAMLRiskDB` (exact match + glob patterns, hot-reloadable)
- `DLPScanner` interface with `RegexDLPScanner` (6 built-in patterns: private keys, passwords, API keys, credit cards, SSNs, emails)
- `Redactor` interface with `DefaultRedactor` (overlapping-match safe, position-descending replacement)
- `AuditEmitter` interface with `StdoutAuditEmitter` (structured JSON)
- `ApprovalProvider` interface with `CLIApprovalProvider` (terminal prompt)
- YAML config loading, validation, and conversion (`config/` package)
- In-process demo with 4 MCP servers (`cmd/demo/`)
- 35+ tests across gateway and config packages

**Sprint 2 — Production Hardening (Weeks 7-10)**
- Sidecar proxy binary (`cmd/sentinelmcp/`) with StreamableHTTP transport
- `SidecarInvoker` routing to upstream MCP servers via discovery
- Admin server with `/healthz`, `/readyz`, and `/api/v1/approval/resume` endpoints
- `WebhookApprovalProvider` for production HITL workflows
- BoltDB checkpoint store for durable interrupt/resume across restarts
- `OTelMetricsRecorder` with counters and histograms (tool calls, latency, DLP findings, approvals)
- `OTelAuditEmitter` bridging audit events into OTel spans
- `SplunkHECSink` with batching and retry for SIEM integration
- `FileRotationSink` with size-based rotation and gzip compression
- Config hot-reload via `fsnotify` with atomic swap and debouncing
- `CompositeAuditEmitter` for fan-out to multiple audit destinations
- `MultiDLPScanner` for composing regex + external scanners
- `ExternalDLPScanner` adapter with timeout for Enterprise DLP APIs
- `DLPEndpoint` interface as Enterprise integration contract

**Sprint 3 — Hardening & OSS Release (Weeks 11-12)**
- `DLPFinding` extended with `EndIdx`, `Severity`, `Metadata` for Enterprise adapters
- 5 load tests validating NFR-03 (1000 concurrent calls, 0 deadlocks)
- 2 memory profiling tests validating NFR-02 (0.73MB heap per 1k concurrent calls)
- 5 graceful degradation tests validating NFR-07 (default-deny on all failure paths)
- 6 sidecar E2E integration tests (proxy, health, resume API)
- 4 DLP integration tests (EndIdx redaction, multi-scanner, timeout, severity)
- Docker demo: multi-stage distroless build, docker-compose with 3 services
- `AuditEmitter` refactor: `AuditLogger` → `AuditEmitter`, `Log` → `Emit` (13 files)
- 90+ tests total, 7 benchmarks, all passing with `-race`
- NFR-01 validated: 19μs p99 Allow (26× under 500μs budget)

### Performance

| Path | Latency | Allocations |
|------|---------|-------------|
| Allow (critical path) | 19μs | 182 |
| Redact | 19μs | 185 |
| Interrupt | 33μs | 303 |
| DLP scan | 9.3μs | 0 |

[0.1.0]: https://github.com/technosiveuk-ui/sentinelmcp/releases/tag/v0.1.0
