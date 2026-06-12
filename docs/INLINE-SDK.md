# Inline SDK Mode

Secure AI agent tool calls **inside your Go process** — no sidecar, no network hop. The Inline SDK wraps your tool calls with inspection, data-loss-prevention (DLP), policy enforcement, human-in-the-loop approval, and audit logging, all through a small builder API.

> **Inline SDK vs. Proxy Mode.** Proxy Mode ([`cmd/sentinelmcp`](../cmd/sentinelmcp)) is a standalone sidecar that intercepts MCP traffic and works with any language. Inline SDK Mode is a Go library for applications that want in-process enforcement with sub-millisecond overhead and deep context awareness. Use the SDK when your agent and your tools live in the same Go binary.

This is the recommended integration for Go-based AI runtimes, gateways, and agent frameworks.

---

## Install

Requires **Go 1.26+** and **SentinelMCP v0.2.0+** (the Inline SDK shipped in v0.2.0).

```bash
go get github.com/technosiveuk-ui/sentinelmcp/sdk@v0.2.0
```

```go
import (
    "github.com/technosiveuk-ui/sentinelmcp/gateway"
    "github.com/technosiveuk-ui/sentinelmcp/sdk"
)
```

---

## Quickstart

Register your tools as Go functions, build a pipeline, and run calls through it. Every call is inspected, DLP-scanned, policy-checked, and audited.

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/technosiveuk-ui/sentinelmcp/gateway"
    "github.com/technosiveuk-ui/sentinelmcp/sdk"
)

func main() {
    invoker := sdk.NewFuncInvoker().
        Register("get_weather", func(_ context.Context, args map[string]any) (string, error) {
            return fmt.Sprintf("sunny, %v°C", args["city"]), nil
        }).
        Register("exec_command", func(_ context.Context, args map[string]any) (string, error) {
            return fmt.Sprintf("ran: %v", args["cmd"]), nil
        })

    pipeline, err := sdk.New(invoker).
        WithRisk("exec_command", gateway.RiskHigh). // needs human approval
        StrictDefaults().                           // unknown tools → redact
        Build()
    if err != nil {
        log.Fatal(err)
    }

    // Low/unknown risk → runs (redacted under StrictDefaults).
    out, err := pipeline.Run(context.Background(), "get_weather", map[string]any{"city": "London"})
    fmt.Println(out, err)
}
```

A runnable version of all three flows (allow / redact / interrupt) lives at [`examples/inline-sdk`](../examples/inline-sdk). Run it with:

```bash
go run ./examples/inline-sdk
```

---

## The enforcement model

Each tool call flows through a three-stage pipeline: **inspect call → run tool → inspect response**. The policy decision is driven by the tool's **risk level**, which comes from your risk configuration:

| Risk level | DefaultPolicy action | What happens |
|:-----------|:---------------------|:-------------|
| `low`      | **Allow**            | Tool runs; arguments and response are still DLP-scanned and the response is redacted if it leaks secrets. |
| `medium`   | **Redact**           | Sensitive argument fields are masked *before* the tool runs; response is redacted. |
| `high`     | **Interrupt**        | Execution pauses for human approval (approve / deny / modify), then runs or blocks. |

Risk is assigned with `WithRisk(tool, level)`. Tools with no explicit entry use the **default risk** (`low` by default).

### StrictDefaults

For regulated environments, flip the default to a stricter posture in one call:

```go
pipeline, _ := sdk.New(invoker).StrictDefaults().Build()
// Equivalent to WithDefaultRisk(gateway.RiskMedium).
```

Under `StrictDefaults`, any tool without an explicit entry is treated as **medium → redact**: sensitive argument fields (a `password` field, an SSN value, a leaked API key) are masked before the tool sees them, rather than passed through. This is the recommended baseline for production.

---

## Securing your own Go functions

`FuncInvoker` turns plain Go functions into fully secured tools — no MCP transport required. This is the simplest way to wrap application code, agent skills, or internal services.

```go
invoker := sdk.NewFuncInvoker().
    Register("search_docs", func(ctx context.Context, args map[string]any) (string, error) {
        return search(ctx, args["query"].(string))
    }).
    Register("charge_card", func(ctx context.Context, args map[string]any) (string, error) {
        return charge(ctx, args["token"].(string), args["amount"].(float64))
    })
```

The function receives args that have already been DLP-scanned and redacted if the policy required it.

### Wrapping real MCP servers in-process

To secure tools discovered from upstream MCP servers (instead of Go functions), use the MCP-tool invoker in the [`adapter/eino`](../adapter/eino) package after discovering tools from your MCP clients. The reference wiring lives in [`cmd/demo`](../cmd/demo). Once you have an invoker, the rest of the builder API is identical.

---

## Human-in-the-loop approval

High-risk tools interrupt and surface an `InterruptError`. Present the request to a human, collect a decision, and call `Resume`:

```go
out, err := pipeline.Run(ctx, "exec_command", map[string]any{"cmd": "rm -rf /tmp/cache"})

var ie *gateway.InterruptError
if errors.As(err, &ie) {
    // ie.Info carries ToolName, Args, RiskLevel, Reason, CheckpointID.
    out, err = pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
        Action: gateway.ApprovalApprove, // or ApprovalDeny / ApprovalModify
        Reason: "approved by operator",
        // ModifiedArgs: map[string]any{"cmd": "ls /tmp"} // for ApprovalModify
    })
}
```

By default the interrupt is logged to stdout (the CLI provider). For production workflows, swap in a webhook provider so approvals route to Slack, Teams, or an internal portal:

```go
sdk.New(invoker).
    WithApproval(sdk.WebhookApproval(
        "https://hooks.example.com/sentinelmcp", // receives the approval request
        "https://api.example.com/resume",        // resumes the interrupted call
    )).
    Build()
```

To make interrupted calls survive process restarts, persist checkpoints to BoltDB:

```go
sdk.New(invoker).WithBoltCheckpoints("/var/lib/sentinelmcp/checkpoints.db").Build()
```

---

## DLP & redaction

The built-in scanner ships six regex patterns: **private keys, passwords, API keys, credit cards, SSNs, and emails**. Add your own:

```go
scanner, _ := gateway.NewRegexDLPScanner(gateway.BuiltinPatterns())
// Compose external/Enterprise scanners with gateway.MultiDLPScanner (see godoc).

pipeline, _ := sdk.New(invoker).
    WithDLPScanner(scanner).
    WithRedactionMask("[REDACTED]"). // default: ***REDACTED***
    Build()
```

Two redaction paths run automatically:

- **Arguments** — scanned field-by-field. Each finding is attributed to its argument name, so a *redact* decision masks exactly the sensitive field. A field literally named `password` (or `api_key`, `secret`, …) is flagged even when its value matches no value-side pattern.
- **Responses** — scanned as a whole and redacted by position, regardless of the decision. So even an *allowed* low-risk call will mask a private key leaked in its output.

Customize the mask with `WithRedactionMask`.

---

## Configuration reference

All options are optional; `Build()` supplies sensible defaults.

| Method | Default | Purpose |
|:-------|:--------|:--------|
| `New(invoker)` | *(required)* | Start a builder around your tool invoker. |
| `WithRisk(tool, level)` | — | Set the risk for a named tool. Call multiple times. |
| `WithDefaultRisk(level)` | `low` | Risk for tools with no explicit entry. |
| `StrictDefaults()` | — | Shorthand for a `medium` default (redact posture). |
| `WithPolicy(p)` | `DefaultPolicy` | Custom `gateway.Policy` for non-risk-level routing. |
| `WithDLPScanner(s)` | built-in regex | Custom or composed `gateway.DLPScanner`. |
| `WithRedactor(r)` | mask-based | Custom `gateway.Redactor`. |
| `WithRedactionMask(m)` | `***REDACTED***` | Mask substituted for redacted values. |
| `WithAuditEmitter(a)` | JSON to stdout | Custom `gateway.AuditEmitter` (file, OTel, SIEM). |
| `WithApproval(a)` | CLI/stdout | Approval provider for high-risk interrupts (webhook). |
| `WithMetrics(m)` | no-op | `gateway.MetricsRecorder` (e.g. OpenTelemetry). |
| `WithBoltCheckpoints(path)` | in-memory | Persist interrupt/resume state across restarts. |

Convenience constructors in the `sdk` package: `BuiltinDLP()`, `StdoutAudit()`, `CLIApproval()`, `WebhookApproval(url, resumeURL)`.

---

## Extending

Every enforcement concern is an interface in the [`gateway`](../gateway) package: `Policy`, `DLPScanner`, `Redactor`, `AuditEmitter`, `ApprovalProvider`, `RiskDB`, `MetricsRecorder`. Implement any of them and inject via the matching `With*` method. Your implementations stay in your own codebase and are not required to be open-sourced.

---

## Under the hood

The SDK is a thin composition root over two packages:

- **[`gateway`](../gateway)** — the framework-agnostic core: all security interfaces and domain logic, with **zero** dependencies on any orchestration engine or MCP transport. Policy evaluation, DLP, risk, and audit all live here and are unit-testable in isolation.
- **[`adapter/eino`](../adapter/eino)** — the only package that imports the underlying graph engine ([Eino](https://github.com/cloudwego/eino)), which provides the runtime-native interrupt/resume and checkpointing the SDK relies on.

This boundary is deliberate: the engine is an implementation detail behind the `gateway` interfaces. If a project ever needs a different orchestration runtime, only a new adapter is required — security configuration and behavior are unchanged. See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the rule that keeps `gateway` dependency-free.
