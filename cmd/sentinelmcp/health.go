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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/technosiveuk-ui/sentinelmcp/gateway"
)

// ---------------------------------------------------------------------------
// Admin HTTP server — health probes + resume API
// ---------------------------------------------------------------------------

// AdminServer provides health endpoints and the approval resume API.
//
// Security model (transport-security hardening):
//   - /healthz and /readyz are unauthenticated (read-only probes).
//   - /api/v1/approval/resume is privileged (it releases a blocked high-risk
//     call) and always requires the admin token, including on loopback. With no
//     token configured the endpoint is disabled (401).
//   - Non-loopback binds require explicit opt-in (--insecure-admin-bind) and a
//     configured token; see ValidateBind.
type AdminServer struct {
	server     *http.Server
	pipeline   gateway.Pipeline
	ready      bool
	adminToken string // gates /api/v1/approval/resume; empty = resume disabled (401)
}

// AdminServerOption configures an AdminServer.
type AdminServerOption func(*AdminServer)

// WithAdminToken sets the token required to call /api/v1/approval/resume.
// If unset, the resume endpoint is disabled (always returns 401).
func WithAdminToken(token string) AdminServerOption {
	return func(a *AdminServer) { a.adminToken = token }
}

// NewAdminServer creates the admin HTTP server for health checks and resume API.
func NewAdminServer(addr string, pipeline gateway.Pipeline, opts ...AdminServerOption) *AdminServer {
	mux := http.NewServeMux()
	a := &AdminServer{
		server: &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		},
		pipeline: pipeline,
	}
	for _, opt := range opts {
		opt(a)
	}

	mux.HandleFunc("/healthz", a.handleHealthz)
	mux.HandleFunc("/readyz", a.handleReadyz)
	mux.HandleFunc("/api/v1/approval/resume", a.handleResume)

	return a
}

// ValidateBind enforces the admin bind policy (fail-closed, NFR-07 family).
// Loopback binds are always allowed (the host boundary carries trust). A
// non-loopback bind requires explicit opt-in via allowNonLoopback
// (--insecure-admin-bind) AND a configured admin token, because the resume
// endpoint becomes reachable over the network.
func (a *AdminServer) ValidateBind(allowNonLoopback bool) error {
	if isLoopbackBind(a.server.Addr) {
		return nil
	}
	if !allowNonLoopback {
		return fmt.Errorf("admin health_addr %q is non-loopback: refusing to start "+
			"(pass --insecure-admin-bind to expose the admin server on a network interface)",
			a.server.Addr)
	}
	if a.adminToken == "" {
		return fmt.Errorf("admin health_addr %q is non-loopback but no admin_token is configured: "+
			"set sidecar.admin_token (or the SENTINELMCP_ADMIN_TOKEN env var) before exposing the admin server",
			a.server.Addr)
	}
	return nil
}

// isLoopbackBind reports whether addr binds to a loopback interface only.
// Wildcard hosts ("", ":port") and non-loopback hosts are treated as exposed.
func isLoopbackBind(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false // malformed/ambiguous: conservatively treat as exposed
	}
	if host == "" {
		return false // wildcard, binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false // resolvable hostname other than localhost: conservatively exposed
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

	// The resume endpoint releases a blocked high-risk call — it is privileged.
	// Require the admin token on every bind (including loopback); with no token
	// configured the endpoint is disabled (401). Constant-time compare to avoid
	// leaking the token via timing.
	provided := extractAdminToken(r)
	if a.adminToken == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(a.adminToken)) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
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

// extractAdminToken reads the admin token from the X-Admin-Token header, or
// from the Authorization header (as "Bearer <token>").
func extractAdminToken(r *http.Request) string {
	if h := strings.TrimSpace(r.Header.Get("X-Admin-Token")); h != "" {
		return h
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		return ""
	}
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		return strings.TrimSpace(auth[len(prefix):])
	}
	return auth
}
