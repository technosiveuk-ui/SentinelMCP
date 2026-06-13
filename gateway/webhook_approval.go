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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// ---------------------------------------------------------------------------
// WebhookApprovalProvider — generic HTTP POST for HITL approval
// ---------------------------------------------------------------------------

// WebhookApprovalProvider implements ApprovalProvider by sending interrupt
// information to a generic HTTP endpoint. This is the OSS production approval
// provider — Phase 1 used CLIApprovalProvider for demos.
//
// The webhook payload includes a resume_url so the external system can POST
// back to the sidecar's /api/v1/approval/resume endpoint after human review.
//
// Enterprise adds Slack/Teams providers via the same ApprovalProvider interface.
type WebhookApprovalProvider struct {
	WebhookURL string       // URL to POST interrupt payload to
	ResumeURL  string       // injected by sidecar binary (e.g. http://localhost:9090/api/v1/approval/resume)
	HTTPClient *http.Client // configurable; defaults to 10s timeout client
}

// NewWebhookApprovalProvider creates a webhook-based approval provider.
func NewWebhookApprovalProvider(webhookURL, resumeURL string) *WebhookApprovalProvider {
	return &WebhookApprovalProvider{
		WebhookURL: webhookURL,
		ResumeURL:  resumeURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// webhookPayload is the JSON body POSTed to the webhook URL.
type webhookPayload struct {
	InterruptID  string         `json:"interrupt_id"`
	CheckpointID string         `json:"checkpoint_id"`
	Tool         string         `json:"tool"`
	Args         map[string]any `json:"args"`
	Risk         string         `json:"risk"`
	Reason       string         `json:"reason"`
	ResumeURL    string         `json:"resume_url"`
}

// SendApprovalRequest implements ApprovalProvider.
// POSTs interrupt info to the configured webhook URL (best-effort, non-blocking).
func (p *WebhookApprovalProvider) SendApprovalRequest(ctx context.Context, info InterruptInfo) error {
	payload := webhookPayload{
		InterruptID:  info.ID,
		CheckpointID: info.CheckpointID,
		Tool:         info.ToolName,
		Args:         info.Args,
		Risk:         string(info.RiskLevel),
		Reason:       info.Reason,
		ResumeURL:    p.ResumeURL,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook approval: marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook approval: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "SentinelMCP/1.0")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		slog.Error("webhook approval request failed", "component", "webhook", "error", err)
		return fmt.Errorf("webhook approval: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		slog.Warn("webhook approval endpoint returned non-success", "component", "webhook", "status", resp.StatusCode)
		return fmt.Errorf("webhook approval: endpoint returned %d", resp.StatusCode)
	}

	slog.Info("webhook approval request sent", "component", "webhook", "tool", info.ToolName, "interrupt", info.ID)
	return nil
}
