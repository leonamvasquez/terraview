package installer

import (
	"runtime"
	"testing"
)

func TestDetectSystem(t *testing.T) {
	info, err := DetectSystem()
	if err != nil {
		t.Fatalf("unexpected error on current platform: %v", err)
	}

	if info.OS != runtime.GOOS {
		t.Errorf("expected OS %q, got %q", runtime.GOOS, info.OS)
	}

	if info.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %q, got %q", runtime.GOARCH, info.Arch)
	}
}

func TestSystemInfo_DisplayOS(t *testing.T) {
	tests := []struct {
		os       string
		expected string
	}{
		{"darwin", "macOS"},
		{"linux", "Linux"},
		{"windows", "windows"},
	}

	for _, tt := range tests {
		info := SystemInfo{OS: tt.os}
		got := info.DisplayOS()
		if got != tt.expected {
			t.Errorf("DisplayOS(%q) = %q, want %q", tt.os, got, tt.expected)
		}
	}
}

func TestOllamaVersion_Format(t *testing.T) {
	// This test just verifies OllamaVersion doesn't panic.
	// It may return empty string if ollama is not installed.
	_ = OllamaVersion()
}

func TestNewInstaller_DefaultModel(t *testing.T) {
	inst := NewInstaller("", nil)
	if inst.model != defaultModel {
		t.Errorf("expected default model %q, got %q", defaultModel, inst.model)
	}
}

func TestNewInstaller_CustomModel(t *testing.T) {
	inst := NewInstaller("codellama:13b", nil)
	if inst.model != "codellama:13b" {
		t.Errorf("expected model 'codellama:13b', got %q", inst.model)
	}
}
