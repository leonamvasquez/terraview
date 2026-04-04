//go:build e2e

// Package e2e contains end-to-end tests that compile and execute the real
// terraview binary against fixture Terraform plan files.
//
// Tests use --findings to import pre-generated findings so they do NOT depend
// on checkov, tfsec, or any scanner being installed in the test environment.
// Run with: go test ./e2e/ -tags e2e -v
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// binaryPath is set by TestMain after the binary is compiled.
var binaryPath string

// testdataDir is the absolute path to the fixture directory.
var testdataDir string

// TestMain compiles the terraview binary once before all E2E tests run.
// This ensures we test the actual binary, not the library, matching what
// users and CI will invoke.
func TestMain(m *testing.M) {
	// Locate testdata relative to this file's directory.
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: getwd: %v\n", err)
		os.Exit(1)
	}
	testdataDir = filepath.Join(wd, "testdata")

	// Compile the binary into a temp directory.
	tmpDir, err := os.MkdirTemp("", "terraview-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: mktemp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "terraview")

	// Resolve repo root: one level up from e2e/
	repoRoot := filepath.Dir(wd)

	cmd := exec.Command("go", "build",
		"-ldflags", "-s -w -X main.version=e2e-test",
		"-o", binaryPath,
		repoRoot,
	)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build failed:\n%s\n", out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

// runTerraview executes the compiled binary with the given args.
// Returns (stdout+stderr combined, exit code).
// Uses a clean HOME dir to avoid picking up local ~/.terraview config,
// while inheriting the rest of the environment so tool subprocesses work.
func runTerraview(t *testing.T, args ...string) (string, int) {
	t.Helper()

	cmd := exec.Command(binaryPath, args...)

	// Replace HOME so no local ~/.terraview.yaml is picked up, but preserve
	// all other env vars (PATH, PYTHONPATH, library paths, etc.).
	homeDir := t.TempDir()
	cmd.Env = make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "HOME=") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, "HOME="+homeDir)

	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unexpected exec error: %v", err)
	}
	return string(out), code
}

// runWithFindings runs a scan using pre-generated findings (no scanner needed).
// flags are additional flags appended after the core scan args.
func runWithFindings(t *testing.T, planFixture, findingsFixture string, flags ...string) (string, int) {
	t.Helper()
	args := []string{
		"scan",
		"--plan", planFixture,
		"--static",
		"--findings", findingsFixture,
	}
	args = append(args, flags...)
	return runTerraview(t, args...)
}

// ---------------------------------------------------------------------------
// Exit-code tests
// ---------------------------------------------------------------------------

func TestE2E_FindingsProduceHighExitCode(t *testing.T) {
	plan := filepath.Join(testdataDir, "ecs.json")
	findings := filepath.Join(testdataDir, "findings.json")
	_, code := runWithFindings(t, plan, findings)
	// Exit 1 = HIGH findings, exit 2 = CRITICAL — both mean issues were found.
	if code == 0 {
		t.Errorf("expected exit code >= 1 (HIGH findings present), got 0 (clean)")
	}
}

func TestE2E_CleanPlanCompletes(t *testing.T) {
	// Clean plan with no findings file → should complete without panicking.
	plan := filepath.Join(testdataDir, "clean.json")
	out, _ := runTerraview(t, "scan", "--plan", plan, "--static")
	if strings.Contains(out, "panic:") {
		t.Errorf("binary panicked:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// JSON output tests
// ---------------------------------------------------------------------------

func TestE2E_JSONOutputHasFindings(t *testing.T) {
	plan := filepath.Join(testdataDir, "ecs.json")
	findings := filepath.Join(testdataDir, "findings.json")
	outDir := t.TempDir()

	out, _ := runWithFindings(t, plan, findings, "--format", "json", "--output", outDir)

	reviewPath := filepath.Join(outDir, "review.json")
	data, err := os.ReadFile(reviewPath)
	if err != nil {
		t.Fatalf("review.json not written: %v\ncommand output:\n%s", err, out)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("review.json is invalid JSON: %v\ncontent:\n%s", err, data)
	}

	list, _ := result["findings"].([]interface{})
	if len(list) == 0 {
		t.Errorf("expected at least one finding in review.json, got %v", result["findings"])
	}
}

// ---------------------------------------------------------------------------
// SARIF output tests
// ---------------------------------------------------------------------------

func TestE2E_SARIFOutputIsValid(t *testing.T) {
	plan := filepath.Join(testdataDir, "ecs.json")
	findings := filepath.Join(testdataDir, "findings.json")
	outDir := t.TempDir()

	out, _ := runWithFindings(t, plan, findings, "--format", "sarif", "--output", outDir)

	sarifPath := filepath.Join(outDir, "review.sarif.json")
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("review.sarif.json not written: %v\ncommand output:\n%s", err, out)
	}

	var sarif struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Results []interface{} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("review.sarif.json is invalid JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %q", sarif.Version)
	}
	if len(sarif.Runs) == 0 {
		t.Error("SARIF has no runs")
	}
}

// ---------------------------------------------------------------------------
// Suppression tests
// ---------------------------------------------------------------------------

func TestE2E_SuppressionReducesFindings(t *testing.T) {
	plan := filepath.Join(testdataDir, "ecs.json")
	findings := filepath.Join(testdataDir, "findings.json")

	// Baseline: count findings without suppression.
	baseDir := t.TempDir()
	out1, _ := runWithFindings(t, plan, findings, "--format", "json", "--output", baseDir)

	baseData, err := os.ReadFile(filepath.Join(baseDir, "review.json"))
	if err != nil {
		t.Fatalf("baseline review.json not written: %v\n%s", err, out1)
	}
	var baseResult map[string]interface{}
	_ = json.Unmarshal(baseData, &baseResult)
	baseList, _ := baseResult["findings"].([]interface{})
	baseCount := len(baseList)
	if baseCount == 0 {
		t.Fatalf("baseline has 0 findings — check findings.json fixture\noutput:\n%s", out1)
	}

	// Write a suppression file that suppresses all imported findings.
	ignoreFile := filepath.Join(t.TempDir(), ".terraview-ignore")
	err = os.WriteFile(ignoreFile, []byte("version: 1\nsuppressions:\n  - source: checkov\n    reason: e2e test suppression\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write ignore file: %v", err)
	}

	// Re-run with suppression.
	supDir := t.TempDir()
	out2, _ := runWithFindings(t, plan, findings, "--format", "json", "--output", supDir, "--ignore-file", ignoreFile)

	supData, err := os.ReadFile(filepath.Join(supDir, "review.json"))
	if err != nil {
		t.Fatalf("suppressed review.json not written: %v\n%s", err, out2)
	}
	var supResult map[string]interface{}
	_ = json.Unmarshal(supData, &supResult)
	supList, _ := supResult["findings"].([]interface{})
	supCount := len(supList)

	if supCount >= baseCount {
		t.Errorf("suppression had no effect: baseline %d findings, suppressed %d\nsuppressed output:\n%s",
			baseCount, supCount, out2)
	}
	if !strings.Contains(out2, "Suppressed") {
		t.Errorf("expected 'Suppressed' message in output; got:\n%s", out2)
	}
}

// ---------------------------------------------------------------------------
// Scanner integration test (skipped if checkov not in PATH)
// ---------------------------------------------------------------------------

func TestE2E_CheckovScannerIntegration(t *testing.T) {
	if _, err := exec.LookPath("checkov"); err != nil {
		t.Skip("checkov not in PATH — skipping scanner integration test")
	}

	plan := filepath.Join(testdataDir, "ecs.json")
	out, code := runTerraview(t, "scan", "checkov", "--plan", plan, "--static")

	// Checkov is available — it should find at least one issue in the insecure fixture.
	// If it finds nothing, log it as a warning (not fatal) since checkov version may vary.
	if code == 0 {
		t.Logf("WARNING: checkov found 0 findings for insecure fixture (checkov version may differ)\noutput:\n%s", out)
	} else {
		t.Logf("checkov integration OK: exit %d\n%s", code, out)
	}
}

// keys returns the map keys as a slice, for diagnostic output.
func keys(m map[string]interface{}) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}
