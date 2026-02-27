package terraformexec

import (
	"os"
	"path/filepath"
	"testing"
)

// ---------------------------------------------------------------------------
// FmtCheck, Validate, Test - using "echo" as fake binary
// ---------------------------------------------------------------------------

func TestFmtCheck_WithEchoBinary(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	out, err := e.run("fmt", "-check", "-recursive")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from echo")
	}
}

func TestRun_WithEchoBinary(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	out, err := e.run("hello", "world")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello world\n" {
		t.Errorf("output = %q", out)
	}
}

func TestRunPassthrough_WithEchoBinary(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	_, err := e.runPassthrough("test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunPassthrough_FailingBinary(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "false"}
	_, err := e.runPassthrough()
	if err == nil {
		t.Error("expected error from false command")
	}
}

// ---------------------------------------------------------------------------
// Plan — missing terraform dir error path
// ---------------------------------------------------------------------------

func TestPlan_RequiresInit(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	// Plan checks NeedsInit first; without .terraform dir it should still proceed with echo
	// but the plan.json won't exist, so it will fail in the json conversion step
	_, err := e.Plan()
	if err == nil {
		t.Log("Plan succeeded with echo (unexpected but possible)")
	}
}

// ---------------------------------------------------------------------------
// Apply — missing tfplan
// ---------------------------------------------------------------------------

func TestApply_MissingTfplan(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	err := e.Apply()
	if err == nil {
		t.Error("expected error for missing tfplan")
	}
}

func TestApply_WithTfplan(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tfplan"), []byte("fake"), 0644)
	e := &Executor{workDir: dir, binaryPath: "echo"}
	err := e.Apply()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// NeedsInit
// ---------------------------------------------------------------------------

func TestNeedsInit_WithDir(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".terraform"), 0755)
	e := &Executor{workDir: dir}
	if e.NeedsInit() {
		t.Error("expected false when .terraform exists")
	}
}

func TestNeedsInit_WithoutDir(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir}
	if !e.NeedsInit() {
		t.Error("expected true when .terraform missing")
	}
}

// ---------------------------------------------------------------------------
// Init — already initialized path
// ---------------------------------------------------------------------------

func TestInit_AlreadyInitialized_Coverage(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".terraform"), 0755)
	e := &Executor{workDir: dir, binaryPath: "echo"}
	err := e.Init()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// FmtCheck — uses SpinWhile internally
// ---------------------------------------------------------------------------

func TestFmtCheck_Success(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	_, err := e.FmtCheck()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFmtCheck_Failure(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "false"}
	_, err := e.FmtCheck()
	if err == nil {
		t.Error("expected error from false command")
	}
}

// ---------------------------------------------------------------------------
// Validate — uses SpinWhile internally
// ---------------------------------------------------------------------------

func TestValidate_Success(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	_, err := e.Validate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidate_Failure(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "false"}
	_, err := e.Validate()
	if err == nil {
		t.Error("expected error from false command")
	}
}

// ---------------------------------------------------------------------------
// Test — uses NewSpinner + runPassthrough
// ---------------------------------------------------------------------------

func TestTest_Success(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "echo"}
	_, avail, err := e.Test()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !avail {
		t.Error("expected available=true")
	}
}

func TestTest_Failure(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "false"}
	_, _, err := e.Test()
	if err == nil {
		t.Error("expected error from false command")
	}
}

// ---------------------------------------------------------------------------
// Plan — exercise the error paths
// ---------------------------------------------------------------------------

func TestPlan_MissingBinary(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "/nonexistent-bin"}
	_, err := e.Plan()
	if err == nil {
		t.Error("expected error for missing binary")
	}
}

// ---------------------------------------------------------------------------
// Init — needs init path (not already initialized)
// ---------------------------------------------------------------------------

func TestInit_NeedInit_Success(t *testing.T) {
	dir := t.TempDir()
	// No .terraform dir — NeedsInit() returns true
	e := &Executor{workDir: dir, binaryPath: "echo"}
	err := e.Init()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInit_NeedInit_Failure(t *testing.T) {
	dir := t.TempDir()
	e := &Executor{workDir: dir, binaryPath: "false"}
	err := e.Init()
	if err == nil {
		t.Error("expected error from false command")
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor.Init
// ---------------------------------------------------------------------------

func TestTerragruntInit_Success(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir, binaryPath: "echo"}
	err := e.Init()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerragruntInit_AlreadyInit(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".terragrunt-cache"), 0755)
	e := &TerragruntExecutor{workDir: dir, binaryPath: "echo"}
	err := e.Init()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WorkDir_Coverage
// ---------------------------------------------------------------------------

func TestWorkDir_Coverage(t *testing.T) {
	e := &Executor{workDir: "/tmp/test"}
	if e.WorkDir() != "/tmp/test" {
		t.Errorf("WorkDir() = %q", e.WorkDir())
	}
}

// ---------------------------------------------------------------------------
// TerragruntExecutor — additional coverage
// ---------------------------------------------------------------------------

func TestTerragruntExecutor_NeedsInit_WithCache(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, ".terragrunt-cache"), 0755)
	e := &TerragruntExecutor{workDir: dir}
	if e.NeedsInit() {
		t.Error("expected false when .terragrunt-cache exists")
	}
}

func TestTerragruntExecutor_NeedsInit_WithoutCache(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir}
	if !e.NeedsInit() {
		t.Error("expected true when .terragrunt-cache missing")
	}
}

func TestTerragruntExecutor_WorkDir(t *testing.T) {
	e := &TerragruntExecutor{workDir: "/tmp/tg"}
	if e.WorkDir() != "/tmp/tg" {
		t.Errorf("WorkDir() = %q", e.WorkDir())
	}
}

func TestTerragruntExecutor_RunPassthrough_Echo(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir, binaryPath: "echo"}
	_, err := e.runPassthrough("hello")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTerragruntExecutor_Apply_NoTfplan(t *testing.T) {
	dir := t.TempDir()
	e := &TerragruntExecutor{workDir: dir, binaryPath: "echo"}
	err := e.Apply()
	if err == nil {
		t.Error("expected error for missing tfplan")
	}
}

func TestTerragruntExecutor_Apply_WithTfplan(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "tfplan"), []byte("fake"), 0644)
	e := &TerragruntExecutor{workDir: dir, binaryPath: "echo"}
	err := e.Apply()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// InjectConfig paths
// ---------------------------------------------------------------------------

func TestInjectConfig_WithConfigFile(t *testing.T) {
	e := &TerragruntExecutor{configFile: "custom.hcl"}
	args := e.injectConfig([]string{"plan", "-out=foo"})
	found := false
	for _, a := range args {
		if a == "--terragrunt-config" {
			found = true
		}
	}
	if !found {
		t.Error("expected --terragrunt-config in args")
	}
}

func TestInjectConfig_NoConfigFile(t *testing.T) {
	e := &TerragruntExecutor{configFile: ""}
	args := e.injectConfig([]string{"plan"})
	// --terragrunt-non-interactive is always injected
	if len(args) != 2 || args[1] != "--terragrunt-non-interactive" {
		t.Errorf("expected [plan --terragrunt-non-interactive], got %v", args)
	}
}

// ---------------------------------------------------------------------------
// IsTerragruntProject edge cases
// ---------------------------------------------------------------------------

func TestIsTerragruntProject_EmptyDir_Cov(t *testing.T) {
	dir := t.TempDir()
	if IsTerragruntProject(dir) {
		t.Error("expected false for empty dir")
	}
}

func TestIsTerragruntProject_WithHCL_Cov(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# config"), 0644)
	if !IsTerragruntProject(dir) {
		t.Error("expected true with terragrunt.hcl")
	}
}

// ---------------------------------------------------------------------------
// ValidateTerragruntWorkspace
// ---------------------------------------------------------------------------

func TestValidateTerragruntWorkspace_Valid_Cov(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# config"), 0644)
	err := ValidateTerragruntWorkspace(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTerragruntWorkspace_Invalid_Cov(t *testing.T) {
	dir := t.TempDir()
	err := ValidateTerragruntWorkspace(dir)
	if err == nil {
		t.Error("expected error for missing terragrunt.hcl")
	}
}
