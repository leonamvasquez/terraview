package runtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// OllamaLifecycle — isHealthy tests (via httptest)
// ---------------------------------------------------------------------------

func TestIsHealthy_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tags" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()

	lc := NewOllamaLifecycle(DefaultResourceLimits(), srv.URL)
	if !lc.isHealthy(context.Background()) {
		t.Error("expected healthy with 200 response")
	}
}

func TestIsHealthy_Unhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	lc := NewOllamaLifecycle(DefaultResourceLimits(), srv.URL)
	if lc.isHealthy(context.Background()) {
		t.Error("expected unhealthy with 500 response")
	}
}

func TestIsHealthy_ConnectionRefused(t *testing.T) {
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://localhost:1")
	if lc.isHealthy(context.Background()) {
		t.Error("expected unhealthy with connection refused")
	}
}

func TestIsHealthy_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately
	lc := NewOllamaLifecycle(DefaultResourceLimits(), "http://localhost:11434")
	if lc.isHealthy(ctx) {
		t.Error("expected unhealthy with cancelled context")
	}
}

// ---------------------------------------------------------------------------
// Monitor.check edge cases
// ---------------------------------------------------------------------------

func TestMonitor_Check_NoLimits(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMonitor(ResourceLimits{}, cancel)
	// With zero limits, check should always pass
	err := m.check()
	if err != nil {
		t.Errorf("check with zero limits should pass, got: %v", err)
	}
}

func TestMonitor_Check_VeryHighLimits(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Set absurdly high max memory limit that should never be exceeded
	m := NewMonitor(ResourceLimits{
		MaxMemoryMB:     999999,
		MinFreeMemoryMB: 1,
	}, cancel)
	err := m.check()
	if err != nil {
		t.Errorf("check with very high limits should pass, got: %v", err)
	}
}

func TestMonitor_DoubleStop(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMonitor(DefaultResourceLimits(), cancel)
	// Should not panic
	m.Stop()
	m.Stop()
}

// ---------------------------------------------------------------------------
// stop() / kill() edge cases
// ---------------------------------------------------------------------------

func TestOllamaLifecycle_StopNilCmd(t *testing.T) {
	lc := &OllamaLifecycle{managed: true}
	// Should not panic when cmd is nil
	lc.stop()
}

func TestOllamaLifecycle_StopNotManaged(t *testing.T) {
	lc := &OllamaLifecycle{managed: false}
	// Should not panic when not managed
	lc.stop()
}

func TestOllamaLifecycle_KillNilCmd(t *testing.T) {
	lc := &OllamaLifecycle{}
	// Should not panic when cmd is nil
	lc.kill()
}
