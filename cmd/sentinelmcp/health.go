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

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Admin HTTP server — health probes + resume API
// ---------------------------------------------------------------------------

// AdminServer provides health endpoints and the approval resume API.
type AdminServer struct {
	server   *http.Server
	pipeline gateway.Pipeline
	ready    bool
}

// NewAdminServer creates the admin HTTP server for health checks and resume API.
func NewAdminServer(addr string, pipeline gateway.Pipeline) *AdminServer {
	mux := http.NewServeMux()
	a := &AdminServer{
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		pipeline: pipeline,
	}

	mux.HandleFunc("/healthz", a.handleHealthz)
	mux.HandleFunc("/readyz", a.handleReadyz)
	mux.HandleFunc("/api/v1/approval/resume", a.handleResume)

	return a
}

// SetReady marks the sidecar as ready (all upstreams discovered, pipeline compiled).
func (a *AdminServer) SetReady(ready bool) {
	a.ready = ready
}

// Start starts the admin HTTP server in a goroutine.
func (a *AdminServer) Start() error {
	go func() {
		log.Printf("[admin] listening on %s", a.server.Addr)
		if err := a.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("[admin] server error: %v", err)
		}
	}()
	return nil
}

// Shutdown gracefully stops the admin HTTP server.
func (a *AdminServer) Shutdown(ctx context.Context) error {
	return a.server.Shutdown(ctx)
}

// handleHealthz returns 200 if the process is alive.
func (a *AdminServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

// handleReadyz returns 200 if the sidecar is ready, 503 otherwise.
func (a *AdminServer) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if a.ready {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	fmt.Fprintln(w, "not ready")
}

// resumeRequest is the JSON body for the resume API.
type resumeRequest struct {
	InterruptID  string         `json:"interrupt_id"`
	CheckpointID string         `json:"checkpoint_id"`
	Action       string         `json:"action"` // "approve" | "deny" | "modify"
	Reason       string         `json:"reason"`
	ModifiedArgs map[string]any `json:"modified_args,omitempty"`
}

// handleResume resumes an interrupted tool call with an approval decision.
// Sprint 1: basic implementation. Sprint 2 adds proper error handling, timeout, and audit.
func (a *AdminServer) handleResume(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if a.pipeline == nil {
		http.Error(w, "pipeline not initialized", http.StatusServiceUnavailable)
		return
	}

	var req resumeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	action, err := parseApprovalAction(req.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	interruptInfo := gateway.InterruptInfo{
		ID:           req.InterruptID,
		CheckpointID: req.CheckpointID,
	}

	approval := &gateway.ApprovalDecision{
		Action:       action,
		Reason:       req.Reason,
		ModifiedArgs: req.ModifiedArgs,
	}

	result, err := a.pipeline.Resume(r.Context(), interruptInfo, approval)
	if err != nil {
		http.Error(w, fmt.Sprintf("resume failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "completed",
		"result": result,
	})
}

// parseApprovalAction converts a string action to gateway.ApprovalAction.
func parseApprovalAction(s string) (gateway.ApprovalAction, error) {
	switch s {
	case "approve":
		return gateway.ApprovalApprove, nil
	case "deny":
		return gateway.ApprovalDeny, nil
	case "modify":
		return gateway.ApprovalModify, nil
	default:
		return "", fmt.Errorf("invalid action %q: must be approve, deny, or modify", s)
	}
}
