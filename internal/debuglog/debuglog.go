// Package debuglog is a development-only structured logger used to inspect
// pipeline execution. It is enabled exclusively via the --debug flag or
// the TERRAVIEW_DEBUG env var. When disabled, every call is a no-op so
// production builds pay no runtime cost beyond an atomic check.
//
// IMPORTANT: payloads (prompts, AI output, subprocess stderr) are written
// verbatim — DO NOT enable in shared environments.
package debuglog

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

var (
	enabled atomic.Bool
	file    *os.File
	mu      sync.Mutex
	once    sync.Once
)

func init() {
	if os.Getenv("TERRAVIEW_DEBUG") != "" {
		Enable()
	}
}

// Enable turns on debug logging and opens ~/.terraview/debug.log for
// append. Safe to call multiple times — subsequent calls are no-ops.
// Returns the absolute path of the log file (or empty on failure).
func Enable() string {
	var path string
	once.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil {
			return
		}
		dir := filepath.Join(home, ".terraview")
		_ = os.MkdirAll(dir, 0o755)
		path = filepath.Join(dir, "debug.log")
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return
		}
		file = f
		enabled.Store(true)
		_, _ = fmt.Fprintf(f, "{\"ts\":%q,\"event\":\"session_start\",\"pid\":%d}\n",
			time.Now().Format(time.RFC3339Nano), os.Getpid())
	})
	if !enabled.Load() {
		return ""
	}
	if path == "" {
		home, _ := os.UserHomeDir()
		path = filepath.Join(home, ".terraview", "debug.log")
	}
	return path
}

// Enabled reports whether debug logging is active. Callers can guard
// expensive payload construction with this check.
func Enabled() bool { return enabled.Load() }

// Log writes a single JSON-Lines record to the debug file. The record
// always carries `ts` and `event`; remaining fields come from `kv`.
// Errors are silently dropped — debug logging must never break a scan.
func Log(event string, kv map[string]any) {
	if !enabled.Load() || file == nil {
		return
	}
	if kv == nil {
		kv = map[string]any{}
	}
	kv["ts"] = time.Now().Format(time.RFC3339Nano)
	kv["event"] = event
	b, err := json.Marshal(kv)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	_, _ = file.Write(append(b, '\n'))
}

// Logf is a convenience wrapper for free-form text events.
func Logf(event, format string, args ...any) {
	if !enabled.Load() {
		return
	}
	Log(event, map[string]any{"msg": fmt.Sprintf(format, args...)})
}
