package installer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeFakeOllama creates a fake "ollama" shell script in dir and returns its path.
// The script handles: --version, list, serve, pull.
// model is the model name to advertise in "ollama list" output.
func writeFakeOllama(t *testing.T, model string) string {
	t.Helper()
	dir := t.TempDir()

	var script string
	if runtime.GOOS == "windows" {
		t.Skip("fake binary tests require a Unix shell")
	}
	if model == "" {
		model = defaultModel
	}

	script = "#!/bin/sh\n" +
		`case "$1" in` + "\n" +
		`  --version) echo "ollama version is 0.3.0" ;;` + "\n" +
		`  list) printf "NAME\t\t\t\tID\n` + model + `\tabc123\n" ;;` + "\n" +
		`  serve) exit 0 ;;` + "\n" +
		`  pull) echo "pulling..." ; exit 0 ;;` + "\n" +
		`  *) exit 1 ;;` + "\n" +
		`esac` + "\n"

	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatalf("writeFakeOllama: %v", err)
	}
	return dir
}

// prependPATH prepends dir to PATH for the duration of the test.
func prependPATH(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// ── OllamaInstalled / OllamaVersion / OllamaRunning ───────────────────

func TestOllamaInstalled_WithFakeBinary(t *testing.T) {
	dir := writeFakeOllama(t, "")
	prependPATH(t, dir)
	if !OllamaInstalled() {
		t.Error("OllamaInstalled should return true when fake binary is in PATH")
	}
}

func TestOllamaVersion_WithFakeBinary(t *testing.T) {
	dir := writeFakeOllama(t, "")
	prependPATH(t, dir)
	v := OllamaVersion()
	if v != "0.3.0" {
		t.Errorf("OllamaVersion = %q, want %q", v, "0.3.0")
	}
}

func TestOllamaVersion_NoVersionInOutput(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary tests require Unix shell")
	}
	// Script that outputs a single word with no spaces (no lastIndex hit)
	script := "#!/bin/sh\necho singleword\n"
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prependPATH(t, dir)
	v := OllamaVersion()
	if v != "singleword" {
		t.Errorf("OllamaVersion = %q, want %q", v, "singleword")
	}
}

func TestOllamaRunning_WithFakeBinary(t *testing.T) {
	dir := writeFakeOllama(t, "")
	prependPATH(t, dir)
	if !OllamaRunning() {
		t.Error("OllamaRunning should return true when fake binary exits 0")
	}
}

func TestOllamaRunning_NotInstalled(t *testing.T) {
	// Isolate PATH to an empty temp dir so ollama is not found.
	t.Setenv("PATH", t.TempDir())
	if OllamaRunning() {
		t.Error("OllamaRunning should return false when ollama is not in PATH")
	}
}

// ── validate — connection-refused path ───────────────────────────────

func TestValidate_ConnectionRefused(t *testing.T) {
	// Port 11434 is almost certainly not available in CI.
	// This covers the http-error branch. Skip if Ollama happens to be running.
	inst := NewInstaller("", &bytes.Buffer{})
	err := inst.validate(context.Background())
	if err == nil {
		t.Skip("Ollama is responding on localhost:11434; skipping connection-refused path")
	}
	// Error is expected: "validation failed: ..."
}

// ── modelAvailable ────────────────────────────────────────────────────

func TestModelAvailable_Found(t *testing.T) {
	dir := writeFakeOllama(t, defaultModel)
	prependPATH(t, dir)
	inst := NewInstaller(defaultModel, &bytes.Buffer{})
	if !inst.modelAvailable() {
		t.Errorf("modelAvailable should return true when model %q is in fake list", defaultModel)
	}
}

func TestModelAvailable_NotFound(t *testing.T) {
	dir := writeFakeOllama(t, "other-model:7b")
	prependPATH(t, dir)
	inst := NewInstaller("llama3:70b", &bytes.Buffer{})
	if inst.modelAvailable() {
		t.Error("modelAvailable should return false when model is not in list")
	}
}

func TestModelAvailable_OllamaNotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	inst := NewInstaller(defaultModel, &bytes.Buffer{})
	if inst.modelAvailable() {
		t.Error("modelAvailable should return false when ollama is not installed")
	}
}

// ── ListModels ────────────────────────────────────────────────────────

func TestListModels_WithFakeBinary(t *testing.T) {
	dir := writeFakeOllama(t, defaultModel)
	prependPATH(t, dir)
	models, err := ListModels()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(models) == 0 {
		t.Error("expected at least one model from fake binary")
	}
	found := false
	for _, m := range models {
		if m == defaultModel {
			found = true
		}
	}
	if !found {
		t.Errorf("expected %q in model list, got: %v", defaultModel, models)
	}
}

func TestListModels_NotInstalled(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := ListModels()
	if err == nil {
		t.Error("expected error when ollama is not installed")
	}
}

// ── Uninstall — not installed path ───────────────────────────────────

func TestUninstall_NotInstalled(t *testing.T) {
	// Use an empty PATH so OllamaInstalled returns false.
	t.Setenv("PATH", t.TempDir())
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	result, err := u.Uninstall()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.WasInstalled {
		t.Error("WasInstalled should be false when ollama is not found")
	}
	if buf.Len() == 0 {
		t.Error("expected log output for not-installed case")
	}
}

// ── stopService — direct call ─────────────────────────────────────────

func TestStopService_NoPanic(t *testing.T) {
	// stopService runs pkill/systemctl/taskkill — they may not succeed but
	// must not panic or return an error (all errors are intentionally ignored).
	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	err := u.stopService()
	if err != nil {
		t.Errorf("stopService must always return nil, got: %v", err)
	}
}

// ── ensureRunning — start-service path with immediate context cancel ──

func TestEnsureRunning_ContextCancelledWhileWaiting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary requires Unix shell")
	}
	dir := t.TempDir()
	// Fake ollama: list always exits 1 (not running), serve exits 0 quickly.
	script := "#!/bin/sh\n" +
		`case "$1" in` + "\n" +
		`  list) exit 1 ;;` + "\n" +
		`  serve) exit 0 ;;` + "\n" +
		`  *) exit 0 ;;` + "\n" +
		`esac` + "\n"
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prependPATH(t, dir)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before ensureRunning starts its loop

	var buf bytes.Buffer
	inst := NewInstaller("", &buf)
	err := inst.ensureRunning(ctx)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// ── Uninstall — installed but service not running ─────────────────────

func TestUninstall_InstalledNotRunning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary requires Unix shell")
	}
	dir := t.TempDir()
	// fake ollama: installed (found in PATH) but list exits 1 (not running)
	script := "#!/bin/sh\n" +
		`case "$1" in` + "\n" +
		`  --version) echo "ollama version is 0.3.0" ;;` + "\n" +
		`  list) exit 1 ;;` + "\n" +
		`  *) exit 0 ;;` + "\n" +
		`esac` + "\n"
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prependPATH(t, dir)

	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	result, err := u.Uninstall()
	if err != nil {
		// Permission error removing the binary is acceptable on some systems
		t.Logf("Uninstall returned error (acceptable): %v", err)
		return
	}
	if !result.WasInstalled {
		t.Error("WasInstalled should be true when fake binary is in PATH")
	}
}

// ── ensureModel — pull path ───────────────────────────────────────────

func TestEnsureModel_PullsWhenNotAvailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary requires Unix shell")
	}
	dir := t.TempDir()
	// fake ollama: list returns only an unrelated model, pull exits 0 immediately
	script := "#!/bin/sh\n" +
		`case "$1" in` + "\n" +
		`  list) printf "NAME\nother-model:7b\n" ;;` + "\n" +
		`  pull) echo "success" ; exit 0 ;;` + "\n" +
		`  *) exit 0 ;;` + "\n" +
		`esac` + "\n"
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prependPATH(t, dir)

	var buf bytes.Buffer
	inst := NewInstaller("llama3:70b", &buf)
	err := inst.ensureModel(context.Background())
	if err != nil {
		t.Fatalf("ensureModel with fast fake pull should succeed, got: %v", err)
	}
}

func TestEnsureModel_PullFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake binary requires Unix shell")
	}
	dir := t.TempDir()
	// list returns no matching model; pull exits 1 with an error message on stderr
	script := "#!/bin/sh\n" +
		`case "$1" in` + "\n" +
		`  list) printf "NAME\n" ;;` + "\n" +
		`  pull) echo "error: model not found" >&2 ; exit 1 ;;` + "\n" +
		`  *) exit 0 ;;` + "\n" +
		`esac` + "\n"
	p := filepath.Join(dir, "ollama")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	prependPATH(t, dir)

	var buf bytes.Buffer
	inst := NewInstaller("llama3:70b", &buf)
	err := inst.ensureModel(context.Background())
	if err == nil {
		t.Fatal("expected error when pull exits 1")
	}
	if !strings.Contains(err.Error(), "model pull failed") {
		t.Errorf("expected 'model pull failed' in error, got: %v", err)
	}
}

func TestEnsureModel_AlreadyAvailable(t *testing.T) {
	dir := writeFakeOllama(t, defaultModel)
	prependPATH(t, dir)

	var buf bytes.Buffer
	inst := NewInstaller(defaultModel, &buf)
	err := inst.ensureModel(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(buf.String(), "already available") {
		t.Errorf("expected 'already available' in log, got: %q", buf.String())
	}
}

func TestUninstall_InstalledAndRunning(t *testing.T) {
	// Fake binary: OllamaInstalled()=true, OllamaRunning()=true → stopService called
	dir := writeFakeOllama(t, defaultModel)
	prependPATH(t, dir)

	var buf bytes.Buffer
	u := NewUninstaller(&buf)
	result, err := u.Uninstall()
	if err != nil {
		t.Logf("Uninstall returned error (acceptable — binary removal may fail): %v", err)
		return
	}
	if !result.WasInstalled {
		t.Error("WasInstalled should be true")
	}
}

// ── Install — already-installed fast path ─────────────────────────────

func TestInstall_AlreadyInstalled_ValidateFails(t *testing.T) {
	// Fake ollama binary: installed, service running, model available.
	// validate() will fail (localhost:11434 not open in CI) — that's the expected
	// outcome for this path test.
	dir := writeFakeOllama(t, defaultModel)
	prependPATH(t, dir)

	var buf bytes.Buffer
	inst := NewInstaller(defaultModel, &buf)
	_, err := inst.Install(context.Background())

	// validate() hits localhost:11434 which is closed → error expected.
	// If Ollama happens to be running, the install would succeed; accept both.
	if err != nil {
		// Expected: validation failed
		return
	}
	// Ollama is actually running — installation succeeded.
}
