//go:build e2e

// Package e2e contains end-to-end tests that compile and execute the real
// terraview binary against fixture Terraform plan files.
//
// These tests require checkov to be installed (pip install checkov).
// Run with: go test ./e2e/ -tags e2e -v
// Skip AI entirely: tests use --static so no API keys are needed.
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

// runScan executes the compiled binary with the given extra args.
// It always adds: scan checkov --plan <fixture> --static
// Returns (stdout+stderr combined, exit code).
func runScan(t *testing.T, fixture string, extraArgs ...string) (string, int) {
	t.Helper()
	args := []string{"scan", "checkov", "--plan", fixture, "--static"}
	args = append(args, extraArgs...)

	cmd := exec.Command(binaryPath, args...)
	// Avoid picking up any local .terraview.yaml or AI provider configuration.
	cmd.Env = []string{"HOME=" + t.TempDir(), "PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("unexpected exec error: %v", err)
	}
	return string(out), code
}

// ---------------------------------------------------------------------------
// Exit-code tests
// ---------------------------------------------------------------------------

func TestE2E_ECSPlanFindsHighFindings(t *testing.T) {
	fixture := filepath.Join(testdataDir, "ecs.json")
	_, code := runScan(t, fixture)
	// Exit 1 = HIGH findings, exit 2 = CRITICAL — both mean issues were found.
	if code == 0 {
		t.Errorf("expected exit code >= 1 (findings found), got 0 (clean)")
	}
}

func TestE2E_CleanPlanCompletes(t *testing.T) {
	fixture := filepath.Join(testdataDir, "clean.json")
	out, _ := runScan(t, fixture)
	// We don't assert exit 0 since checkov rules may differ by version,
	// but the binary must complete without crashing.
	if strings.Contains(out, "panic:") {
		t.Errorf("binary panicked:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// JSON output tests
// ---------------------------------------------------------------------------

func TestE2E_JSONOutputHasFindings(t *testing.T) {
	fixture := filepath.Join(testdataDir, "ecs.json")
	outDir := t.TempDir()

	out, _ := runScan(t, fixture, "--format", "json", "--output", outDir)

	reviewPath := filepath.Join(outDir, "review.json")
	data, err := os.ReadFile(reviewPath)
	if err != nil {
		t.Fatalf("review.json not written: %v\ncommand output:\n%s", err, out)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("review.json is invalid JSON: %v\ncontent:\n%s", err, data)
	}

	findings, ok := result["findings"]
	if !ok {
		t.Fatalf("review.json missing 'findings' key; keys: %v", keys(result))
	}

	list, ok := findings.([]interface{})
	if !ok || len(list) == 0 {
		t.Errorf("expected at least one finding in review.json, got %v", findings)
	}
}

// ---------------------------------------------------------------------------
// SARIF output tests
// ---------------------------------------------------------------------------

func TestE2E_SARIFOutputIsValid(t *testing.T) {
	fixture := filepath.Join(testdataDir, "ecs.json")
	outDir := t.TempDir()

	out, _ := runScan(t, fixture, "--format", "sarif", "--output", outDir)

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
	fixture := filepath.Join(testdataDir, "ecs.json")

	// Baseline: count findings without suppression.
	baseDir := t.TempDir()
	out1, _ := runScan(t, fixture, "--format", "json", "--output", baseDir)

	baseData, err := os.ReadFile(filepath.Join(baseDir, "review.json"))
	if err != nil {
		t.Fatalf("baseline review.json not written: %v\n%s", err, out1)
	}
	var baseResult map[string]interface{}
	_ = json.Unmarshal(baseData, &baseResult)
	baseCount := len(baseResult["findings"].([]interface{}))

	// Write a suppression file that suppresses all checkov findings.
	ignoreFile := filepath.Join(t.TempDir(), ".terraview-ignore")
	err = os.WriteFile(ignoreFile, []byte("version: 1\nsuppressions:\n  - source: checkov\n    reason: e2e test suppression\n"), 0644)
	if err != nil {
		t.Fatalf("failed to write ignore file: %v", err)
	}

	// Re-run with suppression.
	supDir := t.TempDir()
	out2, _ := runScan(t, fixture, "--format", "json", "--output", supDir, "--ignore-file", ignoreFile)

	supData, err := os.ReadFile(filepath.Join(supDir, "review.json"))
	if err != nil {
		t.Fatalf("suppressed review.json not written: %v\n%s", err, out2)
	}
	var supResult map[string]interface{}
	_ = json.Unmarshal(supData, &supResult)
	supCount := len(supResult["findings"].([]interface{}))

	if supCount >= baseCount {
		t.Errorf("suppression had no effect: baseline %d findings, suppressed %d findings\nsuppressed output:\n%s",
			baseCount, supCount, out2)
	}

	// Suppression notice must appear in combined output.
	if !strings.Contains(out2, "Suppressed") {
		t.Errorf("expected 'Suppressed' message in output; got:\n%s", out2)
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
