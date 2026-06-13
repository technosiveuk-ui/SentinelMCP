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
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/technosiveuk-ui/sentinelmcp/gateway/auth"
)

// ---------------------------------------------------------------------------
// Inbound MCP listener — TLS + API-key auth (transport-security, Step 3)
// ---------------------------------------------------------------------------

// validateInboundBind enforces the MCP inbound bind policy (fail-closed,
// NFR-07 family). Loopback binds are always allowed (plaintext + optional auth
// — the host boundary carries trust; loopback-plaintext-default). A non-loopback
// bind requires TLS (cert+key) AND a configured Authenticator, unless
// insecureDevMode is set (local dev/demo escape hatch; caller emits a warning).
func validateInboundBind(addr, certFile, keyFile string, authenticator auth.Authenticator, insecureDevMode bool) error {
	if isLoopbackBind(addr) {
		return nil
	}
	if insecureDevMode {
		return nil
	}
	if certFile == "" || keyFile == "" {
		return fmt.Errorf("listen_addr %q is non-loopback but no inbound TLS is configured: "+
			"provide sidecar.tls.cert_file and sidecar.tls.key_file, or pass --insecure-dev-mode for local dev", addr)
	}
	if authenticator == nil {
		return fmt.Errorf("listen_addr %q is non-loopback but no auth.api_keys are configured: "+
			"set auth.api_keys (key -> principal), or pass --insecure-dev-mode for local dev", addr)
	}
	return nil
}

// authMiddleware enforces inbound API-key authentication on the MCP endpoint.
// With a nil Authenticator it is a pass-through (anonymous: loopback or dev mode
// — the bind policy gates which of those is permitted). On success the resolved
// auth.Context is stamped onto the request context for the contextFunc seam.
func authMiddleware(authenticator auth.Authenticator, next http.Handler) http.Handler {
	if authenticator == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac, err := authenticator.Authenticate(r.Context(), extractCredential(r))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(auth.WithContext(r.Context(), ac)))
	})
}

// extractCredential reads the API key from X-API-Key, then the Authorization
// header (Bearer token, or raw). Returns "" when none is present.
func extractCredential(r *http.Request) string {
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); k != "" {
		return k
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return ""
	}
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimSpace(authHeader[len("Bearer "):])
	}
	return authHeader
}

// authContextFunc is the WithHTTPContextFunc seam: it copies the auth.Context
// stamped on the request (by authMiddleware) into the context mcp-go threads
// down into the tool handlers, so the gateway/policy layer can read it.
func authContextFunc(ctx context.Context, r *http.Request) context.Context {
	if ac := auth.FromContext(r.Context()); ac != nil {
		return auth.WithContext(ctx, ac)
	}
	return ctx
}

// startStreamableHTTP serves the MCP proxy over Streamable HTTP. The mcp-go
// handler is wrapped with authMiddleware, and the listener uses TLS when
// cert/key are provided (plaintext otherwise — loopback or dev mode).
func startStreamableHTTP(ctx context.Context, proxy *Proxy, addr, certFile, keyFile string, authenticator auth.Authenticator) {
	handler := mcpserver.NewStreamableHTTPServer(proxy.Server(), mcpserver.WithHTTPContextFunc(authContextFunc))
	wrapped := authMiddleware(authenticator, handler)

	mux := http.NewServeMux()
	mux.Handle("/mcp", wrapped)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		if certFile != "" && keyFile != "" {
			log.Printf("[mcp] StreamableHTTP proxy listening on %s (HTTPS)", addr)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("MCP TLS server error: %v", err)
			}
		} else {
			log.Printf("[mcp] StreamableHTTP proxy listening on %s (HTTP)", addr)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("MCP server error: %v", err)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	fmt.Fprintf(os.Stderr, "\nReceived %s, shutting down...\n", sig)

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
