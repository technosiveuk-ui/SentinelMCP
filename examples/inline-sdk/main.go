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

// Command inline-sdk demonstrates securing plain Go functions in-process with
// the SentinelMCP Inline SDK. It registers three tools and runs each through the
// pipeline to show the three enforcement outcomes: allow, redact, and
// human-in-the-loop approval.
//
// Run it with:
//
//	go run ./examples/inline-sdk
package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
	"github.com/technosiveuk-ui/sentinelmcp/sdk"
)

func main() {
	ctx := context.Background()

	// Register plain Go functions as secured tools. No MCP transport, no server
	// — the SDK wraps each function with inspection, DLP, policy, and audit.
	invoker := sdk.NewFuncInvoker().
		Register("get_weather", func(_ context.Context, args map[string]any) (string, error) {
			return fmt.Sprintf("sunny, %v°C", args["city"]), nil
		}).
		Register("lookup_user", func(_ context.Context, args map[string]any) (string, error) {
			// Echo the args so the demo shows what the function actually received.
			return fmt.Sprintf("lookup(name=%v, ssn=%v)", args["name"], args["ssn"]), nil
		}).
		Register("exec_command", func(_ context.Context, args map[string]any) (string, error) {
			return fmt.Sprintf("executed: %v", args["cmd"]), nil
		})

	// Build the pipeline:
	//   - get_weather:   explicitly low-risk  -> allow (runs verbatim)
	//   - exec_command:  explicitly high-risk -> interrupt for human approval
	//   - lookup_user:   no explicit entry    -> StrictDefaults makes the
	//                                            default medium -> redact, so its
	//                                            sensitive args are masked first
	pipeline, err := sdk.New(invoker).
		WithRisk("get_weather", gateway.RiskLow).
		WithRisk("exec_command", gateway.RiskHigh).
		StrictDefaults().
		Build()
	if err != nil {
		log.Fatalf("build pipeline: %v", err)
	}

	// 1) Low-risk tool: allowed, args unchanged.
	out, err := pipeline.Run(ctx, "get_weather", map[string]any{"city": "London"})
	report("get_weather", out, err)

	// 2) Unknown tool under StrictDefaults: the SSN is redacted BEFORE the
	//    function runs, so it arrives masked.
	out, err = pipeline.Run(ctx, "lookup_user", map[string]any{
		"name": "alice",
		"ssn":  "123-45-6789",
	})
	report("lookup_user", out, err)

	// 3) High-risk tool: interrupts for human approval, then runs once approved.
	out, err = pipeline.Run(ctx, "exec_command", map[string]any{"cmd": "rm -rf /tmp/cache"})
	var ie *gateway.InterruptError
	if errors.As(err, &ie) {
		fmt.Printf("⏸  exec_command interrupted for approval (risk=%s) — approving...\n", ie.Info.RiskLevel)
		out, err = pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
			Action: gateway.ApprovalApprove,
			Reason: "approved by operator",
		})
	}
	report("exec_command", out, err)
}

// report prints the outcome of a tool call or fails the demo on unexpected error.
func report(tool, out string, err error) {
	if err != nil {
		log.Fatalf("%s: %v", tool, err)
	}
	fmt.Printf("✓ %-12s -> %s\n", tool, out)
}
