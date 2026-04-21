package installer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOllamaInstalled_WithFakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary test requires Unix shell")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if !OllamaInstalled() {
		t.Error("OllamaInstalled should return true when binary is in PATH")
	}
}

func TestOllamaInstalled_NotInPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if OllamaInstalled() {
		t.Error("OllamaInstalled should return false when ollama is not in PATH")
	}
}
