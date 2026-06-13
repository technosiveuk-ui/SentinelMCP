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

package eino

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// tracerName is the instrumentation scope for the gateway pipeline. graph.go
// resolves it via otel.Tracer(tracerName), which returns the no-op tracer when
// no provider is installed (OTel disabled) — so per-node span instrumentation
// is zero-cost in the default path.
const tracerName = "sentinelmcp"

// InitTracer initializes the global OpenTelemetry tracer provider, exporting
// spans via OTLP gRPC to the same collector that receives metrics (typically
// localhost:4317). The returned shutdown function flushes pending spans and
// releases the gRPC connection; it must be called on process exit.
//
// Once installed, every tracer.Start call records and exports — the
// pipeline.run / pipeline.resume roots and the per-node spans (dlp.scan_args,
// policy.decide, tool.invoke, dlp.scan_response) defined in graph.go. With no
// provider installed (OTel disabled) the global tracer is a no-op, so span
// code is free in the default configuration.
func InitTracer(cfg OTelConfig) (shutdown func() error, err error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "localhost:4317"
	}
	if cfg.ServiceName == "" {
		cfg.ServiceName = "sentinelmcp"
	}

	exporter, err := otlptracegrpc.New(context.Background(),
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(), // sidecar typically talks to a local collector
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create trace exporter: %w", err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceNameKey.String(cfg.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: create resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		// Batch exporter: spans accumulate and flush every 5s (or on shutdown),
		// keeping the per-call hot path allocation-free of network waits.
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
	)

	// Install globally so otel.Tracer(tracerName) in graph.go resolves here.
	otel.SetTracerProvider(provider)

	slog.Info("OTel tracer provider initialized",
		"component", "otel", "endpoint", cfg.Endpoint, "service", cfg.ServiceName)

	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		slog.Info("shutting down OTel tracer provider", "component", "otel")
		return provider.Shutdown(ctx)
	}, nil
}
