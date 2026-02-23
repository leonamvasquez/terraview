package terraformexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// WorkDir
// ---------------------------------------------------------------------------

func TestWorkDir(t *testing.T) {
	e := &Executor{workDir: "/some/path"}
	if got := e.WorkDir(); got != "/some/path" {
		t.Errorf("WorkDir() = %q, want %q", got, "/some/path")
	}
}

func TestWorkDir_Empty(t *testing.T) {
	e := &Executor{}
	if got := e.WorkDir(); got != "" {
		t.Errorf("WorkDir() = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// NeedsInit
// ---------------------------------------------------------------------------

func TestNeedsInit_NoTerraformDir(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir}
	if !e.NeedsInit() {
		t.Error("NeedsInit() should return true when .terraform doesn't exist")
	}
}

func TestNeedsInit_WithTerraformDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".terraform"), 0755); err != nil {
		t.Fatal(err)
	}
	e := &Executor{workDir: dir}
	if e.NeedsInit() {
		t.Error("NeedsInit() should return false when .terraform exists")
	}
}

// ---------------------------------------------------------------------------
// acquireLock
// ---------------------------------------------------------------------------

func TestAcquireLock_Success(t *testing.T) {
	dir := t.TempDir()
	unlock, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("acquireLock failed: %v", err)
	}
	defer unlock()

	lockPath := filepath.Join(dir, ".terraview.lock")
	if _, err := os.Stat(lockPath); err != nil {
		t.Error("expected lock file to exist")
	}

	// Lock file should contain pid info
	data, _ := os.ReadFile(lockPath)
	if !strings.Contains(string(data), "pid=") {
		t.Error("expected lock file to contain pid=")
	}
}

func TestAcquireLock_Cleanup(t *testing.T) {
	dir := t.TempDir()
	unlock, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("acquireLock failed: %v", err)
	}

	lockPath := filepath.Join(dir, ".terraview.lock")

	// Verify lock file exists
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatal("lock file should exist before cleanup")
	}

	// Call cleanup
	unlock()

	// Verify lock file is removed
	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Error("expected lock file to be removed after cleanup")
	}
}

func TestAcquireLock_AlreadyLocked(t *testing.T) {
	dir := t.TempDir()
	unlock, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("first acquireLock failed: %v", err)
	}
	defer unlock()

	// Second lock should fail
	_, err = acquireLock(dir)
	if err == nil {
		t.Fatal("expected error when lock already exists")
	}
	if !strings.Contains(err.Error(), "another terraview process") {
		t.Errorf("expected 'another terraview process' error, got: %v", err)
	}
}

func TestAcquireLock_AfterRelease(t *testing.T) {
	dir := t.TempDir()

	// Acquire and release
	unlock, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("first acquireLock failed: %v", err)
	}
	unlock()

	// Should be able to acquire again
	unlock2, err := acquireLock(dir)
	if err != nil {
		t.Fatalf("second acquireLock should succeed: %v", err)
	}
	defer unlock2()
}

func TestAcquireLock_InvalidDir(t *testing.T) {
	_, err := acquireLock("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}

// ---------------------------------------------------------------------------
// NewExecutor
// ---------------------------------------------------------------------------

func TestNewExecutor_InvalidDir(t *testing.T) {
	_, err := NewExecutor("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
	if !strings.Contains(err.Error(), "workspace directory does not exist") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewExecutor_FileNotDir(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := NewExecutor(filePath)
	if err == nil {
		t.Fatal("expected error when path is a file, not a directory")
	}
}

func TestNewExecutor_ValidDir(t *testing.T) {
	dir := t.TempDir()
	exec, err := NewExecutor(dir)
	if err != nil {
		// terraform might not be installed — that's OK, test the error message
		if strings.Contains(err.Error(), "terraform not found") {
			t.Skip("terraform not installed, skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.WorkDir() != dir {
		// WorkDir returns abs, TempDir already returns abs
		absDir, _ := filepath.Abs(dir)
		if exec.WorkDir() != absDir {
			t.Errorf("WorkDir() = %q, want %q", exec.WorkDir(), absDir)
		}
	}
}

// ---------------------------------------------------------------------------
// resolveTerraformBinary
// ---------------------------------------------------------------------------

func TestResolveTerraformBinary(t *testing.T) {
	path, err := resolveTerraformBinary()
	if err != nil {
		// terraform might not be installed — that's expected in some CI environments
		if strings.Contains(err.Error(), "terraform not found") {
			t.Skip("terraform not installed, skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

func TestInit_AlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".terraform"), 0755); err != nil {
		t.Fatal(err)
	}
	e := &Executor{workDir: dir, binaryPath: "terraform"}
	// Should return nil since .terraform already exists
	err := e.Init()
	if err != nil {
		t.Errorf("Init with existing .terraform dir should succeed, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

func TestApply_NoTfplan(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "terraform"}
	err := e.Apply()
	if err == nil {
		t.Fatal("expected error when tfplan file doesn't exist")
	}
	if !strings.Contains(err.Error(), "no tfplan file found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// run/runSilent
// ---------------------------------------------------------------------------

func TestRun_EchoCommand(t *testing.T) {
	e := &Executor{workDir: t.TempDir(), binaryPath: "echo"}
	out, err := e.run("hello", "world")
	if err != nil {
		t.Fatalf("run echo: %v", err)
	}
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world' in output, got %q", out)
	}
}

func TestRunSilent_EchoCommand(t *testing.T) {
	e := &Executor{workDir: t.TempDir(), binaryPath: "echo"}
	// echo writes to stdout, runSilent captures stderr
	stderr, err := e.runSilent("test")
	if err != nil {
		t.Fatalf("runSilent echo: %v", err)
	}
	// stderr should be empty since echo writes to stdout
	if stderr != "" {
		t.Errorf("expected empty stderr, got %q", stderr)
	}
}

func TestRun_InvalidBinary(t *testing.T) {
	e := &Executor{workDir: t.TempDir(), binaryPath: "/nonexistent/binary"}
	_, err := e.run("test")
	if err == nil {
		t.Fatal("expected error with invalid binary")
	}
}

func TestRunSilent_FailingCommand(t *testing.T) {
	e := &Executor{workDir: t.TempDir(), binaryPath: "false"}
	_, err := e.runSilent()
	if err == nil {
		t.Fatal("expected error from 'false' command")
	}
}
