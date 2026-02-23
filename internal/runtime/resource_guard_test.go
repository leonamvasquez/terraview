package runtime

import (
	"context"
	"runtime"
	"testing"
)

func TestDefaultResourceLimits(t *testing.T) {
	limits := DefaultResourceLimits()

	if limits.MaxThreads != runtime.NumCPU() {
		t.Errorf("expected MaxThreads %d, got %d", runtime.NumCPU(), limits.MaxThreads)
	}
	if limits.MinFreeMemoryMB != 1024 {
		t.Errorf("expected MinFreeMemoryMB 1024, got %d", limits.MinFreeMemoryMB)
	}
}

func TestSafeResourceLimits(t *testing.T) {
	limits := SafeResourceLimits()

	expectedThreads := runtime.NumCPU() / 2
	if expectedThreads < 1 {
		expectedThreads = 1
	}

	if limits.MaxThreads != expectedThreads {
		t.Errorf("expected MaxThreads %d, got %d", expectedThreads, limits.MaxThreads)
	}
	if limits.MaxMemoryMB != 2048 {
		t.Errorf("expected MaxMemoryMB 2048, got %d", limits.MaxMemoryMB)
	}
	if limits.MinFreeMemoryMB != 1500 {
		t.Errorf("expected MinFreeMemoryMB 1500, got %d", limits.MinFreeMemoryMB)
	}
}

func TestMeasureResources(t *testing.T) {
	res, err := measureResources()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.CPUCount <= 0 {
		t.Errorf("expected CPUCount > 0, got %d", res.CPUCount)
	}
	if res.TotalMemoryMB <= 0 {
		t.Errorf("expected TotalMemoryMB > 0, got %d", res.TotalMemoryMB)
	}
	if res.AvailableMemoryMB <= 0 {
		t.Errorf("expected AvailableMemoryMB > 0, got %d", res.AvailableMemoryMB)
	}
}

func TestCheckResources_Passes(t *testing.T) {
	// Very low limits should always pass
	limits := ResourceLimits{
		MinFreeMemoryMB: 1,
	}

	res, err := CheckResources(limits)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res == nil {
		t.Fatal("expected non-nil resources")
	}
}

func TestCheckResources_InsufficientMemory(t *testing.T) {
	// Absurdly high limit should fail
	limits := ResourceLimits{
		MinFreeMemoryMB: 999999,
	}

	_, err := CheckResources(limits)
	if err == nil {
		t.Fatal("expected error for insufficient memory")
	}
}

func TestParseDarwinFreeMemory(t *testing.T) {
	vmstat := `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                              100000.
Pages active:                            200000.
Pages inactive:                           50000.
Pages speculative:                         1000.
Pages throttled:                              0.
Pages wired down:                         80000.`

	result := parseDarwinFreeMemory(vmstat)
	// (100000 + 50000) * 16384 / 1024 / 1024 = 2343 MB approx
	if result <= 0 {
		t.Errorf("expected positive free memory, got %d", result)
	}
}

func TestParseLoadAvg(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"{ 1.23 4.56 7.89 }", 1.23},
		{"1.23 4.56 7.89 1/234 5678", 1.23},
		{"0.50 0.60 0.70", 0.50},
		{"", 0},
	}

	for _, tt := range tests {
		got := parseLoadAvg(tt.input)
		if got != tt.expected {
			t.Errorf("parseLoadAvg(%q) = %f, want %f", tt.input, got, tt.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// parseLinuxMeminfo
// ---------------------------------------------------------------------------

func TestParseLinuxMeminfo(t *testing.T) {
	meminfo := `MemTotal:       16384000 kB
MemFree:         2048000 kB
MemAvailable:    8192000 kB
Buffers:          512000 kB
Cached:          4096000 kB
SwapCached:            0 kB
`
	var res SystemResources
	parseLinuxMeminfo(meminfo, &res)

	// 16384000 kB / 1024 = 16000 MB
	if res.TotalMemoryMB != 16000 {
		t.Errorf("TotalMemoryMB = %d, want 16000", res.TotalMemoryMB)
	}
	// 8192000 kB / 1024 = 8000 MB
	if res.AvailableMemoryMB != 8000 {
		t.Errorf("AvailableMemoryMB = %d, want 8000", res.AvailableMemoryMB)
	}
}

func TestParseLinuxMeminfo_Empty(t *testing.T) {
	var res SystemResources
	parseLinuxMeminfo("", &res)

	if res.TotalMemoryMB != 0 || res.AvailableMemoryMB != 0 {
		t.Errorf("expected zeros for empty input, got total=%d avail=%d", res.TotalMemoryMB, res.AvailableMemoryMB)
	}
}

func TestParseLinuxMeminfo_MalformedLines(t *testing.T) {
	meminfo := `MemTotal: notanumber kB
InvalidLine
MemAvailable:    4096000 kB
`
	var res SystemResources
	parseLinuxMeminfo(meminfo, &res)

	// MemTotal should be 0 due to parsing error, MemAvailable should work
	if res.TotalMemoryMB != 0 {
		t.Errorf("TotalMemoryMB = %d, want 0 (parse error)", res.TotalMemoryMB)
	}
	if res.AvailableMemoryMB != 4000 {
		t.Errorf("AvailableMemoryMB = %d, want 4000", res.AvailableMemoryMB)
	}
}

// ---------------------------------------------------------------------------
// NewMonitor
// ---------------------------------------------------------------------------

func TestNewMonitor(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewMonitor(ResourceLimits{MinFreeMemoryMB: 100}, cancel)
	if m == nil {
		t.Fatal("expected non-nil Monitor")
	}
}

func TestMonitor_StartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := NewMonitor(ResourceLimits{MinFreeMemoryMB: 1}, cancel)
	m.Start(ctx)
	m.Stop()
	// Double-stop should not panic
	m.Stop()
}

// ---------------------------------------------------------------------------
// NewOllamaLifecycle
// ---------------------------------------------------------------------------

func TestNewOllamaLifecycle_DefaultURL(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "")
	if lc == nil {
		t.Fatal("expected non-nil lifecycle")
	}
	if lc.baseURL != "http://localhost:11434" {
		t.Errorf("baseURL = %q, want default", lc.baseURL)
	}
}

func TestNewOllamaLifecycle_CustomURL(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://custom:1234")
	if lc.baseURL != "http://custom:1234" {
		t.Errorf("baseURL = %q, want custom", lc.baseURL)
	}
}

func TestNewOllamaLifecycle_Limits(t *testing.T) {
	limits := ResourceLimits{MaxThreads: 4, MinFreeMemoryMB: 2048}
	lc := NewOllamaLifecycle(limits, "")
	if lc.limits.MaxThreads != 4 {
		t.Errorf("MaxThreads = %d, want 4", lc.limits.MaxThreads)
	}
	if lc.limits.MinFreeMemoryMB != 2048 {
		t.Errorf("MinFreeMemoryMB = %d, want 2048", lc.limits.MinFreeMemoryMB)
	}
}

func TestNoop(t *testing.T) {
	// noop should not panic
	noop()
}
