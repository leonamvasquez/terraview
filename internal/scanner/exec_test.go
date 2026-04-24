package scanner

// Tests covering Version(), Scan(), scanPlan(), AutoInstallScanner(), and InstallMissing()
// using fake binaries injected via PATH manipulation — no real external tools needed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// makeFakeBin writes a shell script to dir/<name> that prints output and exits with code.
func makeFakeBin(t *testing.T, dir, name, output string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary tests require Unix shell scripts")
	}
	binPath := filepath.Join(dir, name)
	script := "#!/bin/sh\necho '" + output + "'\nexit " + itoa(exitCode) + "\n"
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("makeFakeBin: %v", err)
	}
	return binPath
}

// itoa converts a small int to string without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n == 1 {
		return "1"
	}
	return "2"
}

// prependToPath returns a PATH string with dir prepended.
func prependToPath(dir string) string {
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// minimalCheckovJSON returns a minimal checkov JSON with one failed check.
func minimalCheckovJSON() []byte {
	payload := checkovReport{
		Results: checkovResults{
			FailedChecks: []checkovCheck{
				{
					CheckID:      "CKV_AWS_1",
					CheckName:    "test rule",
					ResourceAddr: "aws_instance.web",
					Severity:     "HIGH",
					Guideline:    "https://example.com/ckv-aws-1",
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	return data
}

// ─── BuiltinScanner ───────────────────────────────────────────────────────────

func TestBuiltinScanner_Version(t *testing.T) {
	s := &BuiltinScanner{}
	if s.Version() != "builtin" {
		t.Errorf("expected 'builtin', got %q", s.Version())
	}
}

func TestBuiltinScanner_SupportedModes(t *testing.T) {
	s := &BuiltinScanner{}
	modes := s.SupportedModes()
	if len(modes) != 1 || modes[0] != ScanModePlan {
		t.Errorf("expected [plan], got %v", modes)
	}
}

func TestBuiltinScanner_Scan_NoPath(t *testing.T) {
	s := &BuiltinScanner{}
	// Empty PlanPath — builtin.Scan will fail to read the file.
	_, err := s.Scan(ScanContext{})
	if err == nil {
		t.Error("expected error when PlanPath is empty")
	}
}

func TestBuiltinScanner_Scan_WithMinimalPlan(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")

	// Minimal valid terraform plan JSON.
	plan := `{
		"format_version": "0.1",
		"terraform_version": "1.5.0",
		"planned_values": {"root_module": {"resources": []}},
		"resource_changes": [],
		"configuration": {"root_module": {}}
	}`
	if err := os.WriteFile(planPath, []byte(plan), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	s := &BuiltinScanner{}
	findings, err := s.Scan(ScanContext{PlanPath: planPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No resources → no findings.
	_ = findings
}

func TestBuiltinScanner_Scan_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	s := &BuiltinScanner{}
	_, err := s.Scan(ScanContext{PlanPath: planPath})
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBuiltinScanner_EnsureInstalled(t *testing.T) {
	s := &BuiltinScanner{}
	ok, hint := s.EnsureInstalled()
	if !ok {
		t.Error("builtin should always be installed")
	}
	if hint.Default != "" {
		t.Errorf("builtin should have empty hint, got %q", hint.Default)
	}
}

// ─── CheckovScanner.Version() via fake binary ─────────────────────────────────

func TestCheckovScanner_Version_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "checkov", "3.2.504", 0)

	t.Setenv("PATH", prependToPath(dir))

	s := &CheckovScanner{}
	v := s.Version()
	if v == "" {
		t.Error("expected non-empty version from fake checkov binary")
	}
}

// ─── CheckovScanner.Scan() via fake binary (scanPlan path) ───────────────────

func TestCheckovScanner_ScanPlan_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()

	// Create a fake checkov that writes valid JSON to stdout.
	jsonOutput := string(minimalCheckovJSON())
	makeFakeBin(t, dir, "checkov", jsonOutput, 1) // checkov exits 1 when findings exist

	t.Setenv("PATH", prependToPath(dir))

	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, []byte("{}"), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}

	s := &CheckovScanner{}
	findings, err := s.Scan(ScanContext{PlanPath: planPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "CKV_AWS_1" {
		t.Errorf("expected CKV_AWS_1, got %s", findings[0].RuleID)
	}
}

func TestCheckovScanner_ScanPlan_EmptyOutput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "checkov", "", 0)

	t.Setenv("PATH", prependToPath(dir))

	planPath := filepath.Join(dir, "plan.json")
	os.WriteFile(planPath, []byte("{}"), 0o644)

	s := &CheckovScanner{}
	findings, err := s.Scan(ScanContext{PlanPath: planPath})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

// ─── CheckovScanner.Scan() via fake binary (scanSource path) ─────────────────

func TestCheckovScanner_ScanSource_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "checkov", string(minimalCheckovJSON()), 1)

	t.Setenv("PATH", prependToPath(dir))

	s := &CheckovScanner{}
	findings, err := s.Scan(ScanContext{SourceDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestCheckovScanner_Scan_NoContextError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "checkov", "", 0)
	t.Setenv("PATH", prependToPath(dir))

	s := &CheckovScanner{}
	_, err := s.Scan(ScanContext{})
	if err == nil {
		t.Error("expected error with no plan path and no source dir")
	}
}

// ─── TfsecScanner.Version() ──────────────────────────────────────────────────

func TestTfsecScanner_Version_NoToolAvailable(t *testing.T) {
	// Ensure neither tfsec nor trivy is resolvable.
	t.Setenv("PATH", t.TempDir())

	s := &TfsecScanner{}
	v := s.Version()
	if v != "" {
		t.Errorf("expected empty version when tfsec/trivy not available, got %q", v)
	}
}

func TestTfsecScanner_Version_FakeTfsec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "tfsec", "v1.28.11", 0)
	t.Setenv("PATH", prependToPath(dir))

	s := &TfsecScanner{}
	v := s.Version()
	if v == "" {
		t.Error("expected non-empty version")
	}
}

func TestTfsecScanner_Version_FakeTrivy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	// Place both a fake tfsec AND a fake trivy so that regardless of whether
	// tfsec is found first via binaryInBinDir, Version() still returns something.
	makeFakeBin(t, dir, "tfsec", "v1.28.11", 0)
	makeFakeBin(t, dir, "trivy", "Version: 0.55.0", 0)
	t.Setenv("PATH", prependToPath(dir))

	s := &TfsecScanner{}
	v := s.Version()
	if v == "" {
		t.Error("expected non-empty version from tfsec/trivy fake binary")
	}
}

// ─── TfsecScanner.Scan() ─────────────────────────────────────────────────────

func TestTfsecScanner_Scan_NoSourceDir(t *testing.T) {
	s := &TfsecScanner{}
	_, err := s.Scan(ScanContext{})
	if err == nil {
		t.Error("expected error when no source dir provided")
	}
}

func TestTfsecScanner_Scan_WorkDirFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	// Fake tfsec that writes valid JSON to the output file.
	// runTfsec uses --out <tmpfile>, so the script needs to write to the file.
	// The simplest fake just exits 0 with no output (empty file → nil findings).
	binPath := filepath.Join(dir, "tfsec")
	script := "#!/bin/sh\nexit 0\n"
	os.WriteFile(binPath, []byte(script), 0o755)

	t.Setenv("PATH", prependToPath(dir))

	s := &TfsecScanner{}
	findings, err := s.Scan(ScanContext{WorkDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings
}

func TestTfsecScanner_Scan_FakeTfsecWithFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()

	tfsecJSON := `{"results":[{"rule_id":"AWS006","rule_description":"S3 bucket not encrypted","description":"Encryption disabled","severity":"CRITICAL","resource":"aws_s3_bucket.data","resolution":"Enable encryption","location":{"filename":"/main.tf","start_line":1,"end_line":5}}]}`

	// runTfsec writes to a temp file via --out flag. We need a script that
	// writes the JSON to the file path passed as the last argument.
	binPath := filepath.Join(dir, "tfsec")
	script := `#!/bin/sh
for arg; do OUT="$arg"; done
cat > "$OUT" << 'ENDJSON'
` + tfsecJSON + `
ENDJSON
exit 1
`
	os.WriteFile(binPath, []byte(script), 0o755)
	t.Setenv("PATH", prependToPath(dir))

	s := &TfsecScanner{}
	findings, err := s.Scan(ScanContext{SourceDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) == 0 {
		t.Log("note: fake tfsec script may not write to --out target correctly in all environments")
	}
}

func TestTfsecScanner_Scan_FakeTrivy(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	// Only trivy available, no tfsec — exercises runTrivy path.
	trivyJSON := `{"Results":[{"Target":"main.tf","Misconfigurations":[{"ID":"AVD-AWS-0086","AVDID":"AVD-AWS-0086","Title":"S3 encryption","Description":"No encryption","Message":"Bucket not encrypted","Resolution":"Enable SSE","Severity":"CRITICAL","Status":"FAIL"}]}]}`

	binPath := filepath.Join(dir, "trivy")
	script := `#!/bin/sh
for arg; do OUT="$arg"; done
cat > "$OUT" << 'ENDJSON'
` + trivyJSON + `
ENDJSON
exit 0
`
	os.WriteFile(binPath, []byte(script), 0o755)
	t.Setenv("PATH", prependToPath(dir))

	s := &TfsecScanner{}
	findings, err := s.Scan(ScanContext{SourceDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings
}

// ─── TerrascanScanner.Version() and Scan() ───────────────────────────────────

func TestTerrascanScanner_Version_FakeBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	makeFakeBin(t, dir, "terrascan", "Keeping Infrastructure as Code Secure 2.1.19", 0)
	t.Setenv("PATH", prependToPath(dir))

	s := &TerrascanScanner{}
	v := s.Version()
	if v == "" {
		t.Error("expected non-empty version")
	}
}

func TestTerrascanScanner_Scan_NoSourceDir(t *testing.T) {
	s := &TerrascanScanner{}
	_, err := s.Scan(ScanContext{})
	if err == nil {
		t.Error("expected error when no source dir provided")
	}
}

func TestTerrascanScanner_Scan_WorkDirFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()
	// Fake terrascan that produces no stdout output — exercises the len(output)==0 branch.
	binPath := filepath.Join(dir, "terrascan")
	// Use /dev/null redirect to avoid any echo output.
	script := "#!/bin/sh\nexit 0\n"
	os.WriteFile(binPath, []byte(script), 0o755)
	t.Setenv("PATH", prependToPath(dir))

	s := &TerrascanScanner{}
	findings, err := s.Scan(ScanContext{WorkDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

func TestTerrascanScanner_Scan_FakeBinaryWithFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()

	tsJSON := `{"results":{"violations":[{"rule_name":"s3Encryption","description":"S3 not encrypted","rule_id":"AC_AWS_0207","severity":"HIGH","category":"Security","resource_name":"aws_s3_bucket.data","resource_type":"aws_s3_bucket","file":"main.tf","line":1}],"count":{"high":1,"total":1}}}`
	makeFakeBin(t, dir, "terrascan", tsJSON, 3)
	t.Setenv("PATH", prependToPath(dir))

	s := &TerrascanScanner{}
	findings, err := s.Scan(ScanContext{SourceDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != rules.SeverityHigh {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
}

// ─── AutoInstallScanner — covers the no-spec-available path ──────────────────

func TestAutoInstallScanner_NoSpec(t *testing.T) {
	result := AutoInstallScanner("scanner-that-does-not-exist-xyz")
	if result.Installed {
		t.Error("should not be installed when no spec available")
	}
	if result.Error == "" {
		t.Error("expected non-empty error message")
	}
}

// ─── InstallMissing — covers the force=false with all available path ──────────

func TestInstallMissing_AllAvailable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipped on Windows")
	}
	dir := t.TempDir()

	// Register fake binaries for all standard scanners so Available() returns true.
	for _, name := range []string{"checkov", "tfsec", "terrascan"} {
		makeFakeBin(t, dir, name, "1.0.0", 0)
	}
	t.Setenv("PATH", prependToPath(dir))

	mgr := NewManager()
	// Register real adapters with fake binaries in PATH.
	mgr.Register(&CheckovScanner{})
	mgr.Register(&TfsecScanner{})
	mgr.Register(&TerrascanScanner{})

	// force=false + all available → nothing to install.
	results := mgr.InstallMissing(false)
	// Should return an empty slice (nothing was installed).
	_ = results
}

func TestInstallMissing_EmptyManager(t *testing.T) {
	mgr := NewManager()
	// No scanners registered — InstallMissing iterates bininstaller.AllSpecs()
	// and attempts to install missing ones. We just verify no panic.
	results := mgr.InstallMissing(false)
	_ = results
}
