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
	"context"
	"fmt"
	"sync"
)

// ToolFunc is a Go function executed as a secured tool. The args map has
// already been DLP-scanned and redacted if the policy required it.
type ToolFunc func(ctx context.Context, args map[string]any) (string, error)

// FuncInvoker routes tool calls to registered Go functions. It implements
// gateway.ToolInvoker, so a set of plain Go functions can be secured with no
// MCP transport at all — the simplest way to wrap application code.
//
// For wrapping real MCP servers in-process, see the eino.NewMCPToolInvoker
// helper and the cmd/demo reference program.
type FuncInvoker struct {
	mu    sync.RWMutex
	tools map[string]ToolFunc
}

// NewFuncInvoker returns an empty FuncInvoker.
func NewFuncInvoker() *FuncInvoker {
	return &FuncInvoker{tools: map[string]ToolFunc{}}
}

// Register maps a tool name to a Go function. Chainable.
func (f *FuncInvoker) Register(name string, fn ToolFunc) *FuncInvoker {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tools[name] = fn
	return f
}

// Invoke implements gateway.ToolInvoker.
func (f *FuncInvoker) Invoke(ctx context.Context, toolName string, args map[string]any) (string, error) {
	f.mu.RLock()
	fn, ok := f.tools[toolName]
	f.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("sdk: unknown tool %q", toolName)
	}
	return fn(ctx, args)
}
