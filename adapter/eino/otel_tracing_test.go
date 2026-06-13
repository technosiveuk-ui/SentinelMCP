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
	"sort"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// withTestTracer installs an in-memory tracer provider with a synchronous span
// processor so a test can inspect exactly the spans a pipeline run emits, then
// restores the previous global provider on cleanup. The synchronous processor
// exports each span on End(), so spans are available as soon as Run returns.
func withTestTracer(t *testing.T) *tracetest.InMemoryExporter {
	t.Helper()
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		otel.SetTracerProvider(prev)
	})
	return exporter
}

// spanStubs returns the captured span stubs.
func spanStubs(exporter *tracetest.InMemoryExporter) []tracetest.SpanStub {
	return exporter.GetSpans()
}

// attrsMap flattens a span's attributes into a string map for assertions.
func attrsMap(s tracetest.SpanStub) map[string]string {
	m := make(map[string]string, len(s.Attributes))
	for _, kv := range s.Attributes {
		m[string(kv.Key)] = kv.Value.AsString()
	}
	return m
}

// TestPipeline_EmitsPerNodeSpans runs a low-risk (allow) call through the full
// pipeline and asserts the per-node OTel spans fire: the pipeline.run root plus
// the dlp.scan_args, policy.decide, tool.invoke, and dlp.scan_response children
// added in graph.go. The children parent to pipeline.run because Eino threads
// the root span's context through the graph lambdas.
func TestPipeline_EmitsPerNodeSpans(t *testing.T) {
	exporter := withTestTracer(t)

	cfg, _ := testConfig(nil)
	pipeline, err := BuildGraph(cfg)
	if err != nil {
		t.Fatalf("BuildGraph: %v", err)
	}

	if _, err := pipeline.Run(context.Background(), "echo_message", map[string]any{"msg": "hello"}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	stubs := spanStubs(exporter)
	names := make(map[string]bool, len(stubs))
	for _, s := range stubs {
		names[s.Name] = true
	}
	for _, want := range []string{"pipeline.run", "dlp.scan_args", "policy.decide", "tool.invoke", "dlp.scan_response"} {
		if !names[want] {
			got := make([]string, 0, len(stubs))
			for _, s := range stubs {
				got = append(got, s.Name)
			}
			sort.Strings(got)
			t.Errorf("expected span %q; captured spans = %v", want, got)
		}
	}

	// The root span carries the tool name, a terminal outcome, and has no
	// parent — it roots the trace for this call.
	var sawRoot bool
	for _, s := range stubs {
		if s.Name != "pipeline.run" {
			continue
		}
		sawRoot = true
		attrs := attrsMap(s)
		if attrs["tool_name"] != "echo_message" {
			t.Errorf("pipeline.run tool_name attr = %q, want echo_message", attrs["tool_name"])
		}
		if attrs["outcome"] != "ok" {
			t.Errorf("pipeline.run outcome attr = %q, want ok", attrs["outcome"])
		}
		if s.Parent.IsValid() {
			t.Errorf("pipeline.run should be a root span; got parent %s", s.Parent.SpanID())
		}
	}
	if !sawRoot {
		t.Error("pipeline.run root span not captured")
	}
}
