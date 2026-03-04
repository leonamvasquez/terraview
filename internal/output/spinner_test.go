package output

import (
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// spinnerManager
// ---------------------------------------------------------------------------

func TestSpinnerManager_PushPopIsActive(t *testing.T) {
	var mgr spinnerManager

	s1 := &Spinner{message: "first"}
	s2 := &Spinner{message: "second"}

	mgr.push(s1)
	if !mgr.isActive(s1) {
		t.Error("s1 should be active after push")
	}

	mgr.push(s2)
	if mgr.isActive(s1) {
		t.Error("s1 should NOT be active when s2 is on top")
	}
	if !mgr.isActive(s2) {
		t.Error("s2 should be active")
	}

	mgr.pop(s2)
	if !mgr.isActive(s1) {
		t.Error("s1 should be active again after s2 popped")
	}

	mgr.pop(s1)
	if mgr.isActive(s1) {
		t.Error("nothing should be active after all popped")
	}
}

func TestSpinnerManager_PopMiddle(t *testing.T) {
	var mgr spinnerManager

	s1 := &Spinner{message: "a"}
	s2 := &Spinner{message: "b"}
	s3 := &Spinner{message: "c"}

	mgr.push(s1)
	mgr.push(s2)
	mgr.push(s3)

	// Pop middle element
	mgr.pop(s2)

	if !mgr.isActive(s3) {
		t.Error("s3 should still be active")
	}
	mgr.pop(s3)
	if !mgr.isActive(s1) {
		t.Error("s1 should become active")
	}
}

func TestSpinnerManager_PopNonexistent(t *testing.T) {
	var mgr spinnerManager
	s := &Spinner{message: "x"}
	// Should not panic
	mgr.pop(s)
}

func TestSpinnerManager_IsActive_Empty(t *testing.T) {
	var mgr spinnerManager
	s := &Spinner{message: "x"}
	if mgr.isActive(s) {
		t.Error("nothing should be active in empty stack")
	}
}

// ---------------------------------------------------------------------------
// clearLineSeq
// ---------------------------------------------------------------------------

func TestClearLineSeq_ColorEnabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	seq := clearLineSeq()
	if seq != "\r\033[K" {
		t.Errorf("expected ANSI clear, got %q", seq)
	}
}

func TestClearLineSeq_ColorDisabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = false
	seq := clearLineSeq()
	if !strings.HasPrefix(seq, "\r") {
		t.Error("expected \\r prefix")
	}
	if !strings.HasSuffix(seq, "\r") {
		t.Error("expected \\r suffix")
	}
}

// ---------------------------------------------------------------------------
// truncateToTermWidth
// ---------------------------------------------------------------------------

func TestTruncateToTermWidth_Short(t *testing.T) {
	// Short string should not be truncated
	s := "hello"
	got := truncateToTermWidth(s)
	if got != s {
		t.Errorf("short string should not be truncated, got %q", got)
	}
}

func TestTruncateToTermWidth_WithANSI(t *testing.T) {
	// ANSI codes should not count toward visible width
	s := "\033[1mhello\033[0m"
	got := truncateToTermWidth(s)
	// Should contain the full string since "hello" is only 5 visible chars
	if !strings.Contains(got, "hello") {
		t.Errorf("expected hello in output, got %q", got)
	}
}

func TestTruncateToTermWidth_TermWidthZero(t *testing.T) {
	// termWidth()-1 could be 0 or negative on non-TTY, but function handles it
	got := truncateToTermWidth("")
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// writeRaw
// ---------------------------------------------------------------------------

func TestWriteRaw_NoPanic(t *testing.T) {
	// Should not panic
	writeRaw("")
	writeRaw("test")
}

// ---------------------------------------------------------------------------
// termWidth
// ---------------------------------------------------------------------------

func TestTermWidth_ReturnsPositive(t *testing.T) {
	w := termWidth()
	if w <= 0 {
		t.Errorf("expected positive width, got %d", w)
	}
}

// ---------------------------------------------------------------------------
// NewSpinner
// ---------------------------------------------------------------------------

func TestNewSpinner_Creates(t *testing.T) {
	s := NewSpinner("test operation")
	if s == nil {
		t.Fatal("expected non-nil spinner")
	}
	if s.message != "test operation" {
		t.Errorf("message = %q, want %q", s.message, "test operation")
	}
	if len(s.frames) == 0 {
		t.Error("expected non-empty frames")
	}
}

func TestNewSpinner_NoopOnNonTTY(t *testing.T) {
	// In test environment, stderr is typically not a TTY
	s := NewSpinner("test")
	// noop should be true in test (no TTY)
	if !s.noop {
		t.Log("spinner is not noop - stderr is a TTY")
	}
}

// ---------------------------------------------------------------------------
// Start/Stop in noop mode
// ---------------------------------------------------------------------------

func TestSpinner_StartStop_Noop(t *testing.T) {
	s := &Spinner{
		message:  "testing",
		frames:   asciiFrames,
		noop:     true,
		interval: 0,
	}

	// Start in noop mode - just prints a line
	s.Start()
	if !s.running {
		t.Error("spinner should be running after Start")
	}

	// Stop
	s.Stop(true)
	if s.running {
		t.Error("spinner should not be running after Stop")
	}

	// Double stop should not panic
	s.Stop(false)
}

func TestSpinner_StartStop_DoubleStart(t *testing.T) {
	s := &Spinner{
		message:  "testing",
		frames:   asciiFrames,
		noop:     true,
		interval: 0,
	}

	s.Start()
	s.Start() // second start should be no-op
	s.Stop(true)
}

// ---------------------------------------------------------------------------
// SpinWhile / SpinWhileE
// ---------------------------------------------------------------------------

func TestSpinWhile_Success(t *testing.T) {
	result, err := SpinWhile("testing", func() (string, error) {
		return "ok", nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("expected 'ok', got %q", result)
	}
}

func TestSpinWhile_Error(t *testing.T) {
	_, err := SpinWhile("testing", func() (string, error) {
		return "", errors.New("fail")
	})
	if err == nil {
		t.Error("expected error")
	}
}

func TestSpinWhileE_Success(t *testing.T) {
	err := SpinWhileE("testing", func() error {
		return nil
	})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSpinWhileE_Error(t *testing.T) {
	err := SpinWhileE("testing", func() error {
		return errors.New("fail")
	})
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// Spinner.Stop with success=false while running (noop mode)
// ---------------------------------------------------------------------------

func TestSpinner_StopFailed_Noop(t *testing.T) {
	s := NewSpinner("failure test")
	s.noop = true
	s.Start()
	// Stop with success=false while running
	s.Stop(false)
	// Should not panic; verify it's no longer running
	s.mu.Lock()
	running := s.running
	s.mu.Unlock()
	if running {
		t.Error("expected spinner to be stopped")
	}
}

func TestSpinner_StopSuccess_ThenStopAgain(t *testing.T) {
	s := NewSpinner("double stop test")
	s.noop = true
	s.Start()
	s.Stop(true)
	// Second stop should be a no-op (already stopped)
	s.Stop(false)
}
