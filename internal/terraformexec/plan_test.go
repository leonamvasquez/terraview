package terraformexec

// Tests for Plan() paths in Executor and TerragruntExecutor that require
// fake binaries to simulate specific terraform/terragrunt exit codes.
//
// Strategy: write a shell script to a temp dir, set it as the binary path,
// and prepend the dir to PATH so resolveTerraformBinary() finds it too.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFakeBinary writes a shell script to dir/<name> and makes it executable.
func writeFakeBinary(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	content := "#!/bin/sh\n" + script
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("writeFakeBinary %s: %v", name, err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Executor.Plan — exit code 1 (generic failure)
// ---------------------------------------------------------------------------

func TestPlan_Exit1_GenericError(t *testing.T) {
	dir := t.TempDir()
	// Script exits 1 for all invocations.
	writeFakeBinary(t, dir, "terraform", `exit 1`)
	e := &Executor{workDir: dir, binaryPath: filepath.Join(dir, "terraform")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error for exit code 1")
	}
	if !strings.Contains(err.Error(), "terraform plan failed") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Executor.Plan — exit code 2 (changes present) + show fails
// ---------------------------------------------------------------------------

func TestPlan_Exit2ThenShowFails(t *testing.T) {
	dir := t.TempDir()
	// plan exits 2 (changes) → tfplan is NOT created, so Plan checks stat and fails.
	writeFakeBinary(t, dir, "terraform", `exit 2`)
	e := &Executor{workDir: dir, binaryPath: filepath.Join(dir, "terraform")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when tfplan file not created")
	}
}

// ---------------------------------------------------------------------------
// Executor.Plan — exit code 2 + tfplan exists but show fails
// ---------------------------------------------------------------------------

func TestPlan_Exit2TfplanExistsShowFails(t *testing.T) {
	dir := t.TempDir()
	tfplan := filepath.Join(dir, "tfplan")

	// Script: plan exits 2 but creates tfplan; show -json fails.
	script := fmt.Sprintf(`
case "$1" in
  plan)  touch '%s'; exit 2 ;;
  show)  exit 1 ;;
esac
exit 0
`, tfplan)
	writeFakeBinary(t, dir, "terraform", script)
	e := &Executor{workDir: dir, binaryPath: filepath.Join(dir, "terraform")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when terraform show -json fails")
	}
}

// ---------------------------------------------------------------------------
// Executor.Plan — happy path (exit 2 + tfplan exists + show succeeds)
// ---------------------------------------------------------------------------

func TestPlan_HappyPath_Exit2(t *testing.T) {
	dir := t.TempDir()
	tfplan := filepath.Join(dir, "tfplan")

	script := fmt.Sprintf(`
case "$1" in
  plan)  touch '%s'; exit 2 ;;
  show)  echo '{"format_version":"1.0","resource_changes":[]}'; exit 0 ;;
esac
exit 0
`, tfplan)
	writeFakeBinary(t, dir, "terraform", script)
	e := &Executor{workDir: dir, binaryPath: filepath.Join(dir, "terraform")}

	path, err := e.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if path == "" {
		t.Error("Plan returned empty path")
	}
}

// ---------------------------------------------------------------------------
// Executor.Plan — lock held (pre-existing lock file)
// ---------------------------------------------------------------------------

func TestPlan_LockHeld(t *testing.T) {
	dir := t.TempDir()
	// Create lock file to simulate another process.
	lockPath := filepath.Join(dir, ".terraview.lock")
	if err := os.WriteFile(lockPath, []byte("pid=99999\n"), 0644); err != nil {
		t.Fatalf("create lock: %v", err)
	}
	writeFakeBinary(t, dir, "terraform", `exit 0`)
	e := &Executor{workDir: dir, binaryPath: filepath.Join(dir, "terraform")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when lock file exists")
	}
	if !strings.Contains(err.Error(), "another terraview process") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// resolveTerraformBinary — not found in PATH
// ---------------------------------------------------------------------------

func TestResolveTerraformBinary_NotFound(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	_, err := resolveTerraformBinary()
	if err == nil {
		t.Fatal("expected error when terraform not in PATH")
	}
	if !strings.Contains(err.Error(), "terraform not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// resolveTerragruntBinary — not found in PATH
// ---------------------------------------------------------------------------

func TestResolveTerragruntBinary_NotFound(t *testing.T) {
	emptyDir := t.TempDir()
	t.Setenv("PATH", emptyDir)

	_, err := resolveTerragruntBinary()
	if err == nil {
		t.Fatal("expected error when terragrunt not in PATH")
	}
	if !strings.Contains(err.Error(), "terragrunt not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor.Plan — entry points
// ---------------------------------------------------------------------------

func TestTerragruntPlan_Exit1(t *testing.T) {
	dir := t.TempDir()
	writeFakeBinary(t, dir, "terragrunt", `exit 1`)
	e := &TerragruntExecutor{workDir: dir, binaryPath: filepath.Join(dir, "terragrunt")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error for exit code 1")
	}
}

func TestTerragruntPlan_Exit2ThenShowFails(t *testing.T) {
	dir := t.TempDir()
	tfplan := filepath.Join(dir, "tfplan")

	// plan exits 2 + creates tfplan; show fails.
	script := fmt.Sprintf(`
case "$1" in
  plan)  touch '%s'; exit 2 ;;
  show)  exit 1 ;;
esac
exit 0
`, tfplan)
	writeFakeBinary(t, dir, "terragrunt", script)
	e := &TerragruntExecutor{workDir: dir, binaryPath: filepath.Join(dir, "terragrunt")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when terragrunt show -json fails")
	}
}

func TestTerragruntPlan_HappyPath(t *testing.T) {
	dir := t.TempDir()
	tfplan := filepath.Join(dir, "tfplan")

	script := fmt.Sprintf(`
case "$1" in
  plan)  touch '%s'; exit 2 ;;
  show)  echo '{"format_version":"1.0","resource_changes":[]}'; exit 0 ;;
esac
exit 0
`, tfplan)
	writeFakeBinary(t, dir, "terragrunt", script)
	e := &TerragruntExecutor{workDir: dir, binaryPath: filepath.Join(dir, "terragrunt")}

	path, err := e.Plan()
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if path == "" {
		t.Error("Plan returned empty path")
	}
}

func TestTerragruntPlan_LockHeld(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, ".terraview.lock")
	if err := os.WriteFile(lockPath, []byte("pid=99999\n"), 0644); err != nil {
		t.Fatalf("create lock: %v", err)
	}
	writeFakeBinary(t, dir, "terragrunt", `exit 0`)
	e := &TerragruntExecutor{workDir: dir, binaryPath: filepath.Join(dir, "terragrunt")}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when lock file exists")
	}
}

// ---------------------------------------------------------------------------
// NewExecutor — terraform not in PATH
// ---------------------------------------------------------------------------

func TestNewExecutor_NoTerraform(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // empty PATH with no terraform binary

	_, err := NewExecutor(dir)
	if err == nil {
		t.Fatal("expected error when terraform not in PATH")
	}
	if !strings.Contains(err.Error(), "terraform not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewTerragruntExecutor — terragrunt not in PATH
// ---------------------------------------------------------------------------

func TestNewTerragruntExecutor_NoTerragrunt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir) // empty PATH with no terragrunt binary

	_, err := NewTerragruntExecutor(dir, "")
	if err == nil {
		t.Fatal("expected error when terragrunt not in PATH")
	}
	if !strings.Contains(err.Error(), "terragrunt not found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TerragruntMultiExecutor — basic methods (WorkDir, NeedsInit, Init, Apply)
// ---------------------------------------------------------------------------

func TestTerragruntMultiExecutor_BasicMethods(t *testing.T) {
	e := &TerragruntMultiExecutor{rootDir: "/tmp/root"}

	if e.WorkDir() != "/tmp/root" {
		t.Errorf("WorkDir() = %q, want /tmp/root", e.WorkDir())
	}
	if e.NeedsInit() {
		t.Error("NeedsInit() should always return false")
	}
	if err := e.Init(); err != nil {
		t.Errorf("Init() should be no-op, got %v", err)
	}
	err := e.Apply()
	if err == nil {
		t.Error("Apply() should return error for multi-module executor")
	}
	if !strings.Contains(err.Error(), "multi-module apply is not supported") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NewTerragruntMultiExecutor — no terragrunt binary
// ---------------------------------------------------------------------------

func TestNewTerragruntMultiExecutor_NoTerragrunt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)

	_, err := NewTerragruntMultiExecutor(dir, "")
	if err == nil {
		t.Fatal("expected error when terragrunt not in PATH")
	}
}

// ---------------------------------------------------------------------------
// NewTerragruntMultiExecutor — no modules found
// ---------------------------------------------------------------------------

func TestNewTerragruntMultiExecutor_NoModules(t *testing.T) {
	dir := t.TempDir()
	// Put a fake terragrunt binary in PATH.
	fakeBin := t.TempDir()
	writeFakeBinary(t, fakeBin, "terragrunt", `exit 0`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	// dir has no child modules.
	_, err := NewTerragruntMultiExecutor(dir, "")
	if err == nil {
		t.Fatal("expected error when no modules found")
	}
	if !strings.Contains(err.Error(), "no Terragrunt modules found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TerragruntMultiExecutor.Plan — all modules fail
// ---------------------------------------------------------------------------

func TestTerragruntMultiExecutor_Plan_AllFail(t *testing.T) {
	root := t.TempDir()

	// Create fake child modules.
	for _, name := range []string{"mod-a", "mod-b"} {
		d := filepath.Join(root, name)
		os.MkdirAll(d, 0755)
		os.WriteFile(filepath.Join(d, "terragrunt.hcl"), []byte("# "+name), 0644)
	}

	// Fake terragrunt that always fails — modules cannot be planned.
	fakeBin := t.TempDir()
	writeFakeBinary(t, fakeBin, "terragrunt", `exit 1`)
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))

	e := &TerragruntMultiExecutor{
		rootDir: root,
		modules: []string{
			filepath.Join(root, "mod-a"),
			filepath.Join(root, "mod-b"),
		},
	}

	_, err := e.Plan()
	if err == nil {
		t.Fatal("expected error when all modules fail")
	}
}
