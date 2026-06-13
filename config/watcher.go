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

package config

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ---------------------------------------------------------------------------
// ConfigWatcher — watches config file for changes and triggers reload
// ---------------------------------------------------------------------------

// ConfigWatcher monitors a config file for changes and invokes a callback
// when the file is modified. It uses fsnotify for efficient file watching.
//
// Usage:
//
//	watcher, err := config.NewWatcher("config/config.yaml", func(cfg *config.Config) {
//	    // Apply new config (e.g. reload RiskDB, DLP patterns)
//	})
//	watcher.Start(ctx)
//	// ... later ...
//	watcher.Close()
type ConfigWatcher struct {
	path     string
	onChange func(*Config)

	mu      sync.Mutex
	watcher *fsnotify.Watcher
	done    chan struct{}
}

// NewWatcher creates a config file watcher. The onChange callback is invoked
// with the new config whenever the file is modified. Debouncing is built-in:
// rapid successive writes (e.g. from editors) are coalesced.
func NewWatcher(path string, onChange func(*Config)) (*ConfigWatcher, error) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Watch the file's directory instead of the file itself.
	// Editors like vim may replace the file (atomic save), which removes
	// the watch. Watching the directory catches CREATE events for the new file.
	if err := w.Add(path); err != nil {
		w.Close()
		return nil, err
	}

	return &ConfigWatcher{
		path:     path,
		onChange: onChange,
		watcher:  w,
		done:     make(chan struct{}),
	}, nil
}

// Start begins watching for config changes. Blocks until context is cancelled
// or Close() is called. Should be run in a goroutine.
func (cw *ConfigWatcher) Start(ctx context.Context) {
	defer close(cw.done)

	// Debounce timer — coalesce rapid writes (editors often do multiple writes).
	var debounceTimer *time.Timer
	debounceC := func() <-chan time.Time {
		if debounceTimer != nil {
			return debounceTimer.C
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
				// Reset debounce timer.
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.NewTimer(500 * time.Millisecond)
			}

		case <-debounceC():
			// Debounce period elapsed — reload config.
			debounceTimer.Stop()
			debounceTimer = nil
			cw.reload()

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			slog.Error("config watcher error", "component", "config", "error", err)
		}
	}
}

// reload loads the config file and invokes the callback.
func (cw *ConfigWatcher) reload() {
	cfg, err := Load(cw.path)
	if err != nil {
		slog.Error("config reload failed, keeping previous config", "component", "config", "error", err)
		return
	}

	cw.mu.Lock()
	fn := cw.onChange
	cw.mu.Unlock()

	if fn != nil {
		slog.Info("config reload triggered", "component", "config", "path", cw.path)
		fn(cfg)
	}
}

// Close stops the watcher and releases resources.
func (cw *ConfigWatcher) Close() error {
	if cw.watcher != nil {
		return cw.watcher.Close()
	}
	return nil
}

// UpdateCallback replaces the onChange callback. Thread-safe.
func (cw *ConfigWatcher) UpdateCallback(fn func(*Config)) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.onChange = fn
}
