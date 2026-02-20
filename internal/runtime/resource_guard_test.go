package runtime

import (
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
