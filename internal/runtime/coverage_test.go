package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// noop
// ---------------------------------------------------------------------------

func TestNoop_Coverage(t *testing.T) {
	noop() // just ensure it doesn't panic — adds coverage
}

// ---------------------------------------------------------------------------
// isHealthy edge cases
// ---------------------------------------------------------------------------

func TestIsHealthy_StatusCodes(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		healthy bool
	}{
		{"200 ok", http.StatusOK, true},
		{"201 created", http.StatusCreated, false},
		{"404 not found", http.StatusNotFound, false},
		{"500 error", http.StatusInternalServerError, false},
		{"503 unavailable", http.StatusServiceUnavailable, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			lc := NewOllamaLifecycle(DefaultResourceLimits(), srv.URL)
			got := lc.isHealthy(context.Background())
			if got != tc.healthy {
				t.Errorf("isHealthy() = %v, want %v for status %d", got, tc.healthy, tc.status)
			}
		})
	}
}

func TestIsHealthy_SlowServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
	}))
	defer srv.Close()

	lc := NewOllamaLifecycle(DefaultResourceLimits(), srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if lc.isHealthy(ctx) {
		t.Error("expected unhealthy for slow server with short timeout")
	}
}

// ---------------------------------------------------------------------------
// Monitor run — test that context cancellation stops the monitor
// ---------------------------------------------------------------------------

func TestMonitor_RunContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := NewMonitor(DefaultResourceLimits(), cancel)

	m.Start(ctx)
	time.Sleep(50 * time.Millisecond) // let goroutine start
	cancel()                          // cancel context should cause run() to return
	time.Sleep(50 * time.Millisecond) // give time for cleanup

	// Calling Stop after context cancel should still be safe
	m.Stop()
}

func TestMonitor_StopBeforeStart(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMonitor(DefaultResourceLimits(), cancel)
	m.Stop() // should not panic
}

// ---------------------------------------------------------------------------
// OllamaLifecycle.stop — NilCmd and NotManaged paths
// ---------------------------------------------------------------------------

func TestOllamaLifecycle_StopNilCmd_Coverage(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://localhost:1")
	lc.cmd = nil
	lc.managed = true
	lc.stop() // should be a no-op, no panic
}

func TestOllamaLifecycle_StopNotManaged_Coverage(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://localhost:1")
	lc.managed = false
	lc.stop() // should be a no-op
}

// ---------------------------------------------------------------------------
// OllamaLifecycle.kill — NilCmd
// ---------------------------------------------------------------------------

func TestOllamaLifecycle_KillNilCmd_Coverage(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://localhost:1")
	lc.cmd = nil
	lc.kill() // should not panic
}

// ---------------------------------------------------------------------------
// ResourceLimits
// ---------------------------------------------------------------------------

func TestSafeResourceLimits_Values(t *testing.T) {
	s := SafeResourceLimits()
	if s.MaxMemoryMB != 2048 {
		t.Errorf("MaxMemoryMB = %d, want 2048", s.MaxMemoryMB)
	}
	if s.MinFreeMemoryMB != 1500 {
		t.Errorf("MinFreeMemoryMB = %d, want 1500", s.MinFreeMemoryMB)
	}
}

// ---------------------------------------------------------------------------
// parseLoadAvg edge cases
// ---------------------------------------------------------------------------

func TestParseLoadAvg_MalformedInput(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  float64
	}{
		{"empty string", "", 0},
		{"non-numeric", "abc", 0},
		{"spaces only", "   ", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseLoadAvg(tc.input)
			if got != tc.want {
				t.Errorf("parseLoadAvg(%q) = %f, want %f", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// parseDarwinFreeMemory edge cases
// ---------------------------------------------------------------------------

func TestParseDarwinFreeMemory_EmptyInput(t *testing.T) {
	got := parseDarwinFreeMemory("")
	if got != 0 {
		t.Errorf("expected 0 for empty input, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// parseLinuxMeminfo edge case
// ---------------------------------------------------------------------------

func TestParseLinuxMeminfo_PartialInput(t *testing.T) {
	// Only MemTotal, missing MemAvailable
	input := "MemTotal:       16384 kB\nMemFree:           1024 kB\n"
	res := &SystemResources{}
	parseLinuxMeminfo(input, res)
	if res.TotalMemoryMB != 16 {
		t.Errorf("TotalMemoryMB = %d, want 16", res.TotalMemoryMB)
	}
}

func TestParseLinuxMeminfo_EmptyInput(t *testing.T) {
	res := &SystemResources{}
	parseLinuxMeminfo("", res)
	if res.TotalMemoryMB != 0 {
		t.Errorf("TotalMemoryMB = %d, want 0", res.TotalMemoryMB)
	}
}

func TestParseLinuxMeminfo_WithAvailable(t *testing.T) {
	input := "MemTotal:       16384 kB\nMemAvailable:    8192 kB\nMemFree:         4096 kB\n"
	res := &SystemResources{}
	parseLinuxMeminfo(input, res)
	if res.TotalMemoryMB != 16 {
		t.Errorf("TotalMemoryMB = %d, want 16", res.TotalMemoryMB)
	}
	if res.AvailableMemoryMB != 8 {
		t.Errorf("AvailableMemoryMB = %d, want 8", res.AvailableMemoryMB)
	}
}
