package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// EnsureBinDirInPath
// ---------------------------------------------------------------------------

func TestEnsureBinDirInPath_AddsToPath(t *testing.T) {
	originalPath := os.Getenv("PATH")
	defer os.Setenv("PATH", originalPath)

	// Remove any existing ~/.terraview/bin from PATH
	home, _ := os.UserHomeDir()
	binDir := filepath.Join(home, ".terraview", "bin")
	parts := strings.Split(originalPath, string(os.PathListSeparator))
	var filtered []string
	for _, p := range parts {
		if p != binDir {
			filtered = append(filtered, p)
		}
	}
	os.Setenv("PATH", strings.Join(filtered, string(os.PathListSeparator)))

	EnsureBinDirInPath()

	newPath := os.Getenv("PATH")
	if !strings.Contains(newPath, binDir) {
		t.Error("expected bin dir to be added to PATH")
	}
}

func TestEnsureBinDirInPath_Idempotent(t *testing.T) {
	originalPath := os.Getenv("PATH")
	defer os.Setenv("PATH", originalPath)

	EnsureBinDirInPath()
	pathAfterFirst := os.Getenv("PATH")

	EnsureBinDirInPath()
	pathAfterSecond := os.Getenv("PATH")

	if pathAfterFirst != pathAfterSecond {
		t.Error("EnsureBinDirInPath should be idempotent")
	}
}

// ---------------------------------------------------------------------------
// binaryInBinDir
// ---------------------------------------------------------------------------

func TestBinaryInBinDir_NotFound(t *testing.T) {
	if binaryInBinDir("nonexistent-scanner-xyz") {
		t.Error("expected false for nonexistent scanner")
	}
}

func TestBinaryInBinDir_Found(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("cannot get home dir")
	}
	binDir := filepath.Join(home, ".terraview", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		t.Skipf("cannot create bin dir: %v", err)
	}

	// Create a dummy binary
	testBin := filepath.Join(binDir, "test-scanner-dummy")
	if err := os.WriteFile(testBin, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("write test binary: %v", err)
	}
	defer os.Remove(testBin)

	if !binaryInBinDir("test-scanner-dummy") {
		t.Error("expected true for existing scanner binary")
	}
}

// ---------------------------------------------------------------------------
// commandExists
// ---------------------------------------------------------------------------

func TestCommandExists_KnownCommand(t *testing.T) {
	// "echo" should exist on all Unix systems
	if !commandExists("echo") {
		t.Error("expected 'echo' to exist")
	}
}

func TestCommandExists_NonexistentCommand(t *testing.T) {
	if commandExists("nonexistent-command-xyz-12345") {
		t.Error("expected false for nonexistent command")
	}
}
