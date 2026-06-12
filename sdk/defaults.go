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

package sdk

import (
	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// BuiltinDLP returns a DLP scanner using the built-in regex patterns
// (private keys, passwords, API keys, credit cards, SSNs, emails).
func BuiltinDLP() (gateway.DLPScanner, error) {
	return gateway.NewRegexDLPScanner(gateway.BuiltinPatterns())
}

// StdoutAudit returns the default structured-JSON stdout audit emitter.
func StdoutAudit() gateway.AuditEmitter {
	return gateway.NewStdoutAuditEmitter(nil)
}

// CLIApproval returns an approval provider that logs interrupts to stdout.
// The approve/deny/modify decision is supplied by calling Pipeline.Resume.
func CLIApproval() gateway.ApprovalProvider {
	return gateway.NewCLIApprovalProvider()
}

// WebhookApproval returns a webhook-based approval provider for production
// human-in-the-loop workflows. webhookURL receives the approval request;
// resumeURL is the endpoint that resumes the interrupted call.
func WebhookApproval(webhookURL, resumeURL string) gateway.ApprovalProvider {
	return gateway.NewWebhookApprovalProvider(webhookURL, resumeURL)
}
