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

// cmd/demo demonstrates SentinelMCP's gateway wrapping real MCP tools with
// policy enforcement, DLP scanning, and human-in-the-loop approval.
//
// Usage:
//
//	go run cmd/demo/main.go [-config config/config.yaml]
//
// It creates four in-process MCP servers (echo, calculator, filesystem, shell),
// discovers their tools via the MCP protocol, and routes calls through the
// SentinelMCP gateway pipeline — demonstrating all three risk flows:
//   - low risk  (echo_message)    → pass through
//   - medium risk (filesystem_read) → DLP detects secrets, redacts response
//   - high risk (exec_command)    → require human approval
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

	einomcp "github.com/cloudwego/eino-ext/components/tool/mcp"
	"github.com/cloudwego/eino/components/tool"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/eino"
	shieldconfig "github.com/technosiveuk-ui/sentinelmcp/config"
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

func main() {
	configPath := flag.String("config", "config/config.yaml", "path to SentinelMCP config YAML")
	flag.Parse()

	ctx := context.Background()

	// ---------------------------------------------------------------
	// Step 1: Create MCP servers and discover tools.
	// ---------------------------------------------------------------
	echoSrv := newEchoServer()
	calcSrv := newCalcServer()
	fsSrv := newFilesystemServer()
	shellSrv := newShellServer()

	fmt.Fprintln(os.Stderr, "Created 4 MCP servers (echo, calculator, filesystem, shell)")

	allTools, err := discoverAllTools(ctx,
		"echo", echoSrv,
		"calculator", calcSrv,
		"filesystem", fsSrv,
		"shell", shellSrv,
	)
	if err != nil {
		log.Fatalf("Failed to discover MCP tools: %v", err)
	}

	toolInvoker, err := eino.NewMCPToolInvoker(allTools)
	if err != nil {
		log.Fatalf("Failed to create MCP tool invoker: %v", err)
	}

	fmt.Fprintf(os.Stderr, "Discovered %d MCP tools:\n", len(toolInvoker.ToolNames()))
	for _, name := range toolInvoker.ToolNames() {
		fmt.Fprintf(os.Stderr, "  - %s\n", name)
	}
	fmt.Fprintln(os.Stderr)

	// ---------------------------------------------------------------
	// Step 2: Load SentinelMCP configuration.
	// ---------------------------------------------------------------
	cfg, err := shieldconfig.LoadOrDefault(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}
	fmt.Fprintf(os.Stderr, "SentinelMCP config loaded (schema=%s, default_risk=%s)\n",
		cfg.SchemaVersion, cfg.Global.DefaultRisk)

	// ---------------------------------------------------------------
	// Step 3: Build gateway pipeline.
	// ---------------------------------------------------------------
	riskDB := cfg.ToRiskDB()
	policy := gateway.NewDefaultPolicy()

	dlpScanner, err := gateway.NewRegexDLPScanner(cfg.ToDLPPatterns())
	if err != nil {
		log.Fatalf("Failed to compile DLP patterns: %v", err)
	}

	gwCfg := &gateway.GatewayConfig{
		Policy:           policy,
		RiskDB:           riskDB,
		DLPScanner:       dlpScanner,
		Redactor:         gateway.NewDefaultRedactor(cfg.Global.RedactionMask),
		AuditEmitter:     gateway.NewStdoutAuditEmitter(nil),
		ApprovalProvider: gateway.NewCLIApprovalProvider(),
		ToolInvoker:      toolInvoker,
		RedactionMask:    cfg.Global.RedactionMask,
	}

	pipeline, err := eino.BuildGraph(gwCfg)
	if err != nil {
		log.Fatalf("Failed to build gateway graph: %v", err)
	}

	fmt.Fprintln(os.Stderr, "Gateway pipeline constructed.")
	fmt.Fprintln(os.Stderr)

	// ---------------------------------------------------------------
	// Step 4: Run demo flows.
	// ---------------------------------------------------------------
	fmt.Fprintln(os.Stderr, "=== SentinelMCP Demo (Real MCP Transport) ===")
	fmt.Fprintln(os.Stderr)

	// --- Flow 1: Low-risk echo (passes through) ---
	fmt.Fprintln(os.Stderr, "--- Flow 1: echo_message (low risk → allow) ---")
	result, err := pipeline.Run(ctx, "echo_message", map[string]any{"msg": "Hello from SentinelMCP!"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Result: %s\n", result)
	}
	fmt.Fprintln(os.Stderr)

	// --- Flow 2: Medium-risk filesystem read (DLP redaction in response) ---
	fmt.Fprintln(os.Stderr, "--- Flow 2: filesystem_read (medium risk → DLP redact) ---")
	result, err = pipeline.Run(ctx, "filesystem_read", map[string]any{"path": "/etc/secrets/db"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Result: %s\n", result)
	}
	fmt.Fprintln(os.Stderr)

	// --- Flow 3: High-risk shell command (interrupt → approve) ---
	fmt.Fprintln(os.Stderr, "--- Flow 3: exec_command (high risk → interrupt → approve) ---")
	result, err = pipeline.Run(ctx, "exec_command", map[string]any{"cmd": "rm -rf /tmp/old"})
	if err != nil {
		var ie *gateway.InterruptError
		if errors.As(err, &ie) {
			fmt.Fprintf(os.Stderr, "  ⏸ Interrupted: %s\n", ie.Error())
			fmt.Fprintf(os.Stderr, "  Tool: %s, Risk: %s, Checkpoint: %s\n",
				ie.Info.ToolName, ie.Info.RiskLevel, ie.Info.CheckpointID)
			fmt.Fprintln(os.Stderr, "  Auto-approving for demo...")

			result, err = pipeline.Resume(ctx, ie.Info, &gateway.ApprovalDecision{
				Action: gateway.ApprovalApprove,
				Reason: "demo auto-approve",
			})
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ✗ Resume error: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  ✓ Result: %s\n", result)
			}
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ Error: %v\n", err)
		}
	}
	fmt.Fprintln(os.Stderr)

	// --- Flow 4: Calculator (medium risk, clean content) ---
	fmt.Fprintln(os.Stderr, "--- Flow 4: calculator (medium risk → allow) ---")
	result, err = pipeline.Run(ctx, "calculator", map[string]any{"operation": "42 * 3"})
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ Error: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "  ✓ Result: %s\n", result)
	}
	fmt.Fprintln(os.Stderr)

	fmt.Fprintln(os.Stderr, "=== Demo complete ===")
}

// discoverAllTools connects to multiple MCP servers via in-process transport,
// discovers tools from each, and returns the combined list.
func discoverAllTools(ctx context.Context, nameServerPairs ...any) ([]tool.BaseTool, error) {
	var allTools []tool.BaseTool

	for i := 0; i < len(nameServerPairs); i += 2 {
		name := nameServerPairs[i].(string)
		srv := nameServerPairs[i+1].(*mcpserver.MCPServer)

		cli, err := client.NewInProcessClient(srv)
		if err != nil {
			return nil, fmt.Errorf("connect to %s: %w", name, err)
		}
		if err := cli.Start(ctx); err != nil {
			return nil, fmt.Errorf("start client for %s: %w", name, err)
		}

		// Initialize the MCP protocol handshake.
		if _, err := cli.Initialize(ctx, mcp.InitializeRequest{
			Params: mcp.InitializeParams{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ClientInfo: mcp.Implementation{
					Name:    "sentinelmcp-demo",
					Version: "1.0.0",
				},
			},
		}); err != nil {
			return nil, fmt.Errorf("initialize client for %s: %w", name, err)
		}

		tools, err := einomcp.GetTools(ctx, &einomcp.Config{Cli: cli})
		if err != nil {
			return nil, fmt.Errorf("discover tools from %s: %w", name, err)
		}
		allTools = append(allTools, tools...)
	}

	return allTools, nil
}
