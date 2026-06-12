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
	"fmt"

	"github.com/technosiveuk-ui/sentinelmcp/adapter/siem"
	shieldconfig "github.com/technosiveuk-ui/sentinelmcp/config"
)

// createFileSink creates a file rotation audit sink from config.
func createFileSink(sc shieldconfig.SinkConfig) (*siem.FileRotationSink, error) {
	if sc.Path == "" {
		return nil, fmt.Errorf("file sink requires 'path'")
	}
	return siem.NewFileRotationSink(sc.Path, sc.MaxSizeMB, sc.MaxBackups, sc.Compress)
}

// createSplunkSink creates a Splunk HEC audit sink from config.
func createSplunkSink(sc shieldconfig.SinkConfig) *siem.SplunkHECSink {
	return siem.NewSplunkHECSink(sc.Endpoint, sc.Token)
}
