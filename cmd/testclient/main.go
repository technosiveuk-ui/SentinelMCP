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

// Package main is the SentinelMCP demo test client.
//
// Connects to the SentinelMCP sidecar proxy and demonstrates all 3 enforcement paths:
// 1. Low-risk: ALLOW — tool call passes through
// 2. Medium-risk: REDACT — DLP scanning redacts sensitive content
// 3. High-risk: INTERRUPT — requires human approval via resume API
//
// Exit code: 0 if all flows pass, 1 if any fail.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
)

func main() {
	sidecarURL := os.Getenv("SENTINELMCP_URL")
	if sidecarURL == "" {
		sidecarURL = "http://localhost:8080/mcp"
	}
	adminURL := os.Getenv("SENTINELMCP_ADMIN_URL")
	if adminURL == "" {
		adminURL = "http://localhost:9090"
	}

	log.Printf("[testclient] Connecting to sidecar at %s", sidecarURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to the sidecar MCP proxy.
	c, err := client.NewStreamableHttpClient(sidecarURL)
	if err != nil {
		log.Fatalf("Failed to connect to sidecar: %v", err)
	}

	initResult, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2025-03-26",
			ClientInfo:      mcp.Implementation{Name: "sentinelmcp-testclient", Version: "1.0.0"},
		},
	})
	if err != nil {
		log.Fatalf("Failed to initialize: %v", err)
	}
	log.Printf("[testclient] Connected: %s v%s", initResult.ServerInfo.Name, initResult.ServerInfo.Version)

	passed := 0
	failed := 0

	// --- Flow 1: Low-risk ALLOW ---
	log.Println("\n=== Flow 1: Low-risk ALLOW ===")
	result, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "echo_message",
			Arguments: map[string]any{"msg": "Hello from test client"},
		},
	})
	if err != nil {
		log.Printf("FAIL: echo_message error: %v", err)
		failed++
	} else if result.IsError {
		log.Printf("FAIL: echo_message returned error: %s", contentText(result))
		failed++
	} else {
		log.Printf("PASS: echo_message → %s", contentText(result))
		passed++
	}

	// --- Flow 2: Medium-risk REDACT ---
	log.Println("\n=== Flow 2: Medium-risk REDACT ===")
	result, err = c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "filesystem_read",
			Arguments: map[string]any{"path": "/etc/config.yaml"},
		},
	})
	if err != nil {
		log.Printf("FAIL: filesystem_read error: %v", err)
		failed++
	} else {
		text := contentText(result)
		if strings.Contains(text, "admin123") {
			log.Printf("FAIL: DLP did NOT redact password in response")
			failed++
		} else if strings.Contains(text, "***") {
			log.Printf("PASS: filesystem_read → DLP redacted sensitive content")
			passed++
		} else {
			log.Printf("PASS: filesystem_read → %s", text)
			passed++
		}
	}

	// --- Flow 3: High-risk INTERRUPT + RESUME ---
	log.Println("\n=== Flow 3: High-risk INTERRUPT + RESUME ===")
	result, err = c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      "exec_command",
			Arguments: map[string]any{"cmd": "rm -rf /tmp/old-data"},
		},
	})
	if err != nil {
		log.Printf("FAIL: exec_command error: %v", err)
		failed++
	} else if !result.IsError {
		log.Printf("FAIL: exec_command should have been interrupted (high-risk)")
		failed++
	} else {
		text := contentText(result)
		if !strings.Contains(text, "human approval") {
			log.Printf("FAIL: expected interrupt message, got: %s", text)
			failed++
		} else {
			log.Printf("PASS: exec_command → interrupted for approval: %s", text)
			passed++

			// Auto-approve via admin API.
			log.Println("\n=== Auto-approving via resume API ===")
			interruptID, checkpointID := extractIDs(text)
			if interruptID != "" && checkpointID != "" {
				ok := approveResume(adminURL, interruptID, checkpointID)
				if ok {
					log.Println("PASS: Resume approved successfully")
					passed++
				} else {
					log.Println("FAIL: Resume approval failed")
					failed++
				}
			} else {
				log.Println("SKIP: Could not extract interrupt IDs for auto-approve")
			}
		}
	}

	// Summary.
	log.Printf("\n=== Summary: %d passed, %d failed ===", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func contentText(result *mcp.CallToolResult) string {
	var parts []string
	for _, c := range result.Content {
		if tc, ok := c.(mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func extractIDs(text string) (string, string) {
	var interruptID, checkpointID string
	if idx := strings.Index(text, "Interrupt ID:"); idx >= 0 {
		rest := text[idx+len("Interrupt ID:"):]
		rest = strings.TrimSpace(rest)
		if comma := strings.Index(rest, ","); comma >= 0 {
			interruptID = strings.TrimSpace(rest[:comma])
		}
	}
	if idx := strings.Index(text, "Checkpoint:"); idx >= 0 {
		rest := text[idx+len("Checkpoint:"):]
		rest = strings.TrimSpace(rest)
		for i, ch := range rest {
			if ch == '.' || ch == ',' {
				checkpointID = strings.TrimSpace(rest[:i])
				break
			}
		}
	}
	return interruptID, checkpointID
}

func approveResume(adminURL, interruptID, checkpointID string) bool {
	body := fmt.Sprintf(`{"interrupt_id":"%s","checkpoint_id":"%s","action":"approve","reason":"test auto-approve"}`,
		interruptID, checkpointID)

	resp, err := http.Post(adminURL+"/api/v1/approval/resume", "application/json", bytes.NewBufferString(body))
	if err != nil {
		log.Printf("Resume API error: %v", err)
		return false
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("Resume API returned %d: %s", resp.StatusCode, respBody)
		return false
	}

	var result map[string]string
	if err := json.Unmarshal(respBody, &result); err != nil {
		log.Printf("Resume API unmarshal error: %v", err)
		return false
	}

	log.Printf("Resume result: status=%s, result=%s", result["status"], result["result"])
	return result["status"] == "completed"
}
