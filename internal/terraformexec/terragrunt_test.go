package terraformexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// TerragruntExecutor — WorkDir
// ---------------------------------------------------------------------------

func TestTerragruntWorkDir(t *testing.T) {
	e := &TerragruntExecutor{workDir: "/some/path"}
	if got := e.WorkDir(); got != "/some/path" {
		t.Errorf("WorkDir() = %q, want %q", got, "/some/path")
	}
}

func TestTerragruntWorkDir_Empty(t *testing.T) {
	e := &TerragruntExecutor{}
	if got := e.WorkDir(); got != "" {
		t.Errorf("WorkDir() = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor — NeedsInit
// ---------------------------------------------------------------------------

func TestTerragruntNeedsInit_NoCache(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir}
	if !e.NeedsInit() {
		t.Error("NeedsInit() should return true when .terragrunt-cache doesn't exist")
	}
}

func TestTerragruntNeedsInit_WithCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".terragrunt-cache"), 0755); err != nil {
		t.Fatal(err)
	}
	e := &TerragruntExecutor{workDir: dir}
	if e.NeedsInit() {
		t.Error("NeedsInit() should return false when .terragrunt-cache exists")
	}
}

// ---------------------------------------------------------------------------
// NewTerragruntExecutor
// ---------------------------------------------------------------------------

func TestNewTerragruntExecutor_InvalidDir(t *testing.T) {
	_, err := NewTerragruntExecutor("/nonexistent/path/xyz", "")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
	if !strings.Contains(err.Error(), "workspace directory does not exist") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewTerragruntExecutor_FileNotDir(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "notadir")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := NewTerragruntExecutor(filePath, "")
	if err == nil {
		t.Fatal("expected error when path is a file, not a directory")
	}
}

func TestNewTerragruntExecutor_ValidDir(t *testing.T) {
	dir := t.TempDir()
	exec, err := NewTerragruntExecutor(dir, "")
	if err != nil {
		// terragrunt might not be installed — that's OK
		if strings.Contains(err.Error(), "terragrunt not found") {
			t.Skip("terragrunt not installed, skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	absDir, _ := filepath.Abs(dir)
	if exec.WorkDir() != absDir {
		t.Errorf("WorkDir() = %q, want %q", exec.WorkDir(), absDir)
	}
}

// ---------------------------------------------------------------------------
// resolveTerragruntBinary
// ---------------------------------------------------------------------------

func TestResolveTerragruntBinary(t *testing.T) {
	path, err := resolveTerragruntBinary()
	if err != nil {
		if strings.Contains(err.Error(), "terragrunt not found") {
			t.Skip("terragrunt not installed, skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor — Apply (no tfplan)
// ---------------------------------------------------------------------------

func TestTerragruntApply_NoTfplan(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir, binaryPath: "terragrunt"}
	err := e.Apply()
	if err == nil {
		t.Fatal("expected error when tfplan file doesn't exist")
	}
	if !strings.Contains(err.Error(), "no tfplan file found") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor — run / runSilent
// ---------------------------------------------------------------------------

func TestTerragruntRun_EchoCommand(t *testing.T) {
	e := &TerragruntExecutor{workDir: t.TempDir(), binaryPath: "echo"}
	out, err := e.run("hello", "world")
	if err != nil {
		t.Fatalf("run echo: %v", err)
	}
	// --terragrunt-non-interactive is always injected after the subcommand
	if !strings.Contains(out, "hello") || !strings.Contains(out, "world") {
		t.Errorf("expected 'hello' and 'world' in output, got %q", out)
	}
}

func TestTerragruntRunSilent_EchoCommand(t *testing.T) {
	e := &TerragruntExecutor{workDir: t.TempDir(), binaryPath: "echo"}
	stderr, err := e.runSilent("test")
	if err != nil {
		t.Fatalf("runSilent echo: %v", err)
	}
	if stderr != "" {
		t.Errorf("expected empty stderr, got %q", stderr)
	}
}

func TestTerragruntRun_InvalidBinary(t *testing.T) {
	e := &TerragruntExecutor{workDir: t.TempDir(), binaryPath: "/nonexistent/binary"}
	_, err := e.run("test")
	if err == nil {
		t.Fatal("expected error with invalid binary")
	}
}

func TestTerragruntRunSilent_FailingCommand(t *testing.T) {
	e := &TerragruntExecutor{workDir: t.TempDir(), binaryPath: "false"}
	_, err := e.runSilent()
	if err == nil {
		t.Fatal("expected error from 'false' command")
	}
}

// ---------------------------------------------------------------------------
// IsTerragruntProject
// ---------------------------------------------------------------------------

func TestIsTerragruntProject_WithHCL(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# config"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsTerragruntProject(dir) {
		t.Error("expected true when terragrunt.hcl exists")
	}
}

func TestIsTerragruntProject_WithCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".terragrunt-cache"), 0755); err != nil {
		t.Fatal(err)
	}
	if !IsTerragruntProject(dir) {
		t.Error("expected true when .terragrunt-cache exists")
	}
}

func TestIsTerragruntProject_Empty(t *testing.T) {
	dir := t.TempDir()
	if IsTerragruntProject(dir) {
		t.Error("expected false for empty directory")
	}
}

func TestIsTerragruntProject_NonexistentDir(t *testing.T) {
	if IsTerragruntProject("/nonexistent/path/xyz") {
		t.Error("expected false for non-existent directory")
	}
}

func TestIsTerragruntProject_ParentHCL(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "module-a")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	// Parent has terragrunt.hcl
	if err := os.WriteFile(filepath.Join(parent, "terragrunt.hcl"), []byte("# root config"), 0644); err != nil {
		t.Fatal(err)
	}
	// Child also has terragrunt.hcl
	if err := os.WriteFile(filepath.Join(child, "terragrunt.hcl"), []byte("# child config"), 0644); err != nil {
		t.Fatal(err)
	}
	if !IsTerragruntProject(child) {
		t.Error("expected true when parent+child both have terragrunt.hcl")
	}
}

func TestIsTerragruntProject_ParentOnly(t *testing.T) {
	parent := t.TempDir()
	child := filepath.Join(parent, "subdir")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	// Only parent has terragrunt.hcl, child does not
	if err := os.WriteFile(filepath.Join(parent, "terragrunt.hcl"), []byte("# root"), 0644); err != nil {
		t.Fatal(err)
	}
	if IsTerragruntProject(child) {
		t.Error("expected false when only parent (not child) has terragrunt.hcl")
	}
}

// ---------------------------------------------------------------------------
// ValidateTerragruntWorkspace
// ---------------------------------------------------------------------------

func TestValidateTerragruntWorkspace_Valid(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# config"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTerragruntWorkspace(dir); err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestValidateTerragruntWorkspace_NoHCL(t *testing.T) {
	dir := t.TempDir()
	err := ValidateTerragruntWorkspace(dir)
	if err == nil {
		t.Fatal("expected error when no terragrunt.hcl")
	}
	if !strings.Contains(err.Error(), "no terragrunt.hcl found") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTerragruntWorkspace_InvalidDir(t *testing.T) {
	err := ValidateTerragruntWorkspace("/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent directory")
	}
	if !strings.Contains(err.Error(), "not a valid directory") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateTerragruntWorkspace_RootWithChildModules(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# root"), 0644); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "vpc")
	if err := os.MkdirAll(child, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(child, "terragrunt.hcl"), []byte("# child"), 0644); err != nil {
		t.Fatal(err)
	}
	err := ValidateTerragruntWorkspace(dir)
	if err == nil {
		t.Fatal("expected error for root dir with child modules")
	}
	if !strings.Contains(err.Error(), "root directory with child modules") {
		t.Errorf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// PlanExecutor interface compliance
// ---------------------------------------------------------------------------

func TestTerragruntExecutor_ImplementsPlanExecutor(t *testing.T) {
	var _ PlanExecutor = (*TerragruntExecutor)(nil)
}

func TestExecutor_ImplementsPlanExecutor(t *testing.T) {
	var _ PlanExecutor = (*Executor)(nil)
}

// ---------------------------------------------------------------------------
// configFile / injectConfig
// ---------------------------------------------------------------------------

func TestInjectConfig_Empty(t *testing.T) {
	e := &TerragruntExecutor{configFile: ""}
	args := e.injectConfig([]string{"plan", "-out=tfplan"})
	// --terragrunt-non-interactive is always injected
	if len(args) != 3 || args[0] != "plan" || args[1] != "--terragrunt-non-interactive" {
		t.Errorf("expected [plan --terragrunt-non-interactive -out=tfplan], got %v", args)
	}
}

func TestInjectConfig_WithConfig(t *testing.T) {
	e := &TerragruntExecutor{configFile: "/path/to/dev.hcl"}
	args := e.injectConfig([]string{"plan", "-out=tfplan"})
	if len(args) != 5 {
		t.Fatalf("expected 5 args, got %d: %v", len(args), args)
	}
	if args[0] != "plan" {
		t.Errorf("expected subcommand first, got %q", args[0])
	}
	if args[1] != "--terragrunt-non-interactive" {
		t.Errorf("expected --terragrunt-non-interactive second, got %q", args[1])
	}
	if args[2] != "--terragrunt-config" || args[3] != "/path/to/dev.hcl" {
		t.Errorf("expected --terragrunt-config after non-interactive, got %v", args[2:4])
	}
	if args[4] != "-out=tfplan" {
		t.Errorf("expected original args preserved, got %v", args[4:])
	}
}

func TestInjectConfig_EmptyArgs(t *testing.T) {
	e := &TerragruntExecutor{configFile: "/path/to/dev.hcl"}
	args := e.injectConfig([]string{})
	if len(args) != 0 {
		t.Errorf("expected empty args, got %v", args)
	}
}

func TestNewTerragruntExecutor_WithConfigFile(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "custom.hcl")
	if err := os.WriteFile(configFile, []byte("# custom config"), 0644); err != nil {
		t.Fatal(err)
	}
	exec, err := NewTerragruntExecutor(dir, configFile)
	if err != nil {
		if strings.Contains(err.Error(), "terragrunt not found") {
			t.Skip("terragrunt not installed, skipping")
		}
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.configFile != configFile {
		t.Errorf("configFile = %q, want %q", exec.configFile, configFile)
	}
}

func TestNewTerragruntExecutor_WithMissingConfigFile(t *testing.T) {
	dir := t.TempDir()
	_, err := NewTerragruntExecutor(dir, "/nonexistent/config.hcl")
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
	if !strings.Contains(err.Error(), "config file not found") {
		// terragrunt might not be installed, in which case we get a different error
		if !strings.Contains(err.Error(), "terragrunt not found") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}
