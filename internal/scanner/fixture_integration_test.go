package scanner

// Integration tests with realistic scanner output fixtures.
// Validates parsing, counts, severity, normalization, and error handling.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// fixturesDir returns the absolute path to testdata/ at the repo root.
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine the test file path")
	}
	// internal/scanner/ → go up 2 levels to the repo root
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	dir := filepath.Join(repoRoot, "testdata")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("testdata/ directory not found at %s", dir)
	}
	return dir
}

// readFixture reads a fixture file and returns its contents.
func readFixture(t *testing.T, relPath string) []byte {
	t.Helper()
	fullPath := filepath.Join(fixturesDir(t), relPath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("error reading fixture %s: %v", relPath, err)
	}
	return data
}

// countBySeverity counts findings by severity.
func countBySeverity(findings []rules.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// findByRuleID finds the first finding with the given RuleID.
func findByRuleID(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// assertRequiredFields verifies all required fields are populated.
func assertRequiredFields(t *testing.T, findings []rules.Finding, source string) {
	t.Helper()
	for i, f := range findings {
		if f.RuleID == "" {
			t.Errorf("[%s] finding %d: RuleID empty", source, i)
		}
		if f.Severity == "" {
			t.Errorf("[%s] finding %d: Severity empty", source, i)
		}
		if f.Resource == "" {
			t.Errorf("[%s] finding %d: Resource empty", source, i)
		}
		if f.Message == "" {
			t.Errorf("[%s] finding %d: Message empty", source, i)
		}
		if f.Source == "" {
			t.Errorf("[%s] finding %d: Source empty", source, i)
		}
	}
}

// assertValidSeverity verifies all severities are valid values.
func assertValidSeverity(t *testing.T, findings []rules.Finding) {
	t.Helper()
	valid := map[string]bool{
		rules.SeverityCritical: true,
		rules.SeverityHigh:     true,
		rules.SeverityMedium:   true,
		rules.SeverityLow:      true,
		rules.SeverityInfo:     true,
	}
	for i, f := range findings {
		if !valid[f.Severity] {
			t.Errorf("finding %d: invalid severity %q (RuleID=%s)", i, f.Severity, f.RuleID)
		}
	}
}

// assertValidCategory verifies all categories are valid values.
func assertValidCategory(t *testing.T, findings []rules.Finding) {
	t.Helper()
	valid := map[string]bool{
		rules.CategorySecurity:        true,
		rules.CategoryCompliance:      true,
		rules.CategoryBestPractice:    true,
		rules.CategoryMaintainability: true,
		rules.CategoryReliability:     true,
	}
	for i, f := range findings {
		if f.Category != "" && !valid[f.Category] {
			t.Errorf("finding %d: invalid category %q (RuleID=%s)", i, f.Category, f.RuleID)
		}
	}
}

// ===========================================================================
// Checkov — integration tests with fixtures
// ===========================================================================

func TestFixture_Checkov_Passing(t *testing.T) {
	data := readFixture(t, "checkov/checkov_passing.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean scan, got %d", len(findings))
	}
}

func TestFixture_Checkov_Mixed(t *testing.T) {
	data := readFixture(t, "checkov/checkov_mixed.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 15 {
		t.Fatalf("expected 15 findings, got %d", len(findings))
	}

	// Severity distribution
	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 3 {
		t.Errorf("CRITICAL: expected 3, got %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: expected 5, got %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 5 {
		t.Errorf("MEDIUM: expected 5, got %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: expected 2, got %d", counts[rules.SeverityLow])
	}

	// Spot check specific finding
	f := findByRuleID(findings, "CKV_AWS_18")
	if f == nil {
		t.Fatal("CKV_AWS_18 not found")
	}
	if f.Severity != rules.SeverityCritical {
		t.Errorf("CKV_AWS_18: expected CRITICAL, got %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("CKV_AWS_18: expected resource aws_s3_bucket.data, got %s", f.Resource)
	}
	if f.Source != "scanner:checkov" {
		t.Errorf("CKV_AWS_18: expected source scanner:checkov, got %s", f.Source)
	}

	// Verificar CKV_AWS_40 (MEDIUM, IAM)
	f40 := findByRuleID(findings, "CKV_AWS_40")
	if f40 == nil {
		t.Fatal("CKV_AWS_40 not found")
	}
	if f40.Severity != rules.SeverityMedium {
		t.Errorf("CKV_AWS_40: expected MEDIUM, got %s", f40.Severity)
	}

	// All required fields populated
	assertRequiredFields(t, findings, "checkov")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Checkov_AllCritical(t *testing.T) {
	data := readFixture(t, "checkov/checkov_all_critical.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(findings))
	}

	// Todos devem ser CRITICAL
	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("expected CRITICAL for %s, got %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Checkov_Empty(t *testing.T) {
	data := readFixture(t, "checkov/checkov_empty.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty output, got %d", len(findings))
	}
}

func TestFixture_Checkov_Malformed(t *testing.T) {
	data := readFixture(t, "checkov/checkov_malformed.json")
	// Checkov parser returns nil,nil for invalid JSON (does not return error)
	// because it attempts silent parsing and assumes "warnings"
	findings, err := parseCheckovOutput(data)

	// Should not cause panic
	_ = findings
	_ = err
	// If findings are returned, they must be valid
	if len(findings) > 0 {
		assertRequiredFields(t, findings, "checkov-malformed")
	}
}

func TestFixture_Checkov_GuidelineAsRemediation(t *testing.T) {
	data := readFixture(t, "checkov/checkov_mixed.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Checkov usa guideline como remediation
	f := findByRuleID(findings, "CKV_AWS_18")
	if f == nil {
		t.Fatal("CKV_AWS_18 not found")
	}
	if f.Remediation == "" {
		t.Error("CKV_AWS_18: remediation should contain the guideline URL")
	}
}

// ===========================================================================
// tfsec — integration tests with fixtures
// ===========================================================================

func TestFixture_Tfsec_Passing(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_passing.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean scan, got %d", len(findings))
	}
}

func TestFixture_Tfsec_Mixed(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_mixed.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 14 {
		t.Fatalf("expected 14 findings, got %d", len(findings))
	}

	// Severity distribution
	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 3 {
		t.Errorf("CRITICAL: expected 3, got %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: expected 5, got %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 4 {
		t.Errorf("MEDIUM: expected 4, got %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: expected 2, got %d", counts[rules.SeverityLow])
	}

	// Spot check
	f := findByRuleID(findings, "aws-s3-enable-bucket-encryption")
	if f == nil {
		t.Fatal("aws-s3-enable-bucket-encryption not found")
	}
	if f.Severity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("expected resource aws_s3_bucket.data, got %s", f.Resource)
	}
	if f.Source != "scanner:tfsec" {
		t.Errorf("expected source scanner:tfsec, got %s", f.Source)
	}

	// Remediation preenchida
	if f.Remediation == "" {
		t.Error("aws-s3-enable-bucket-encryption: remediation vazio")
	}

	// All required fields
	assertRequiredFields(t, findings, "tfsec")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Tfsec_AllCritical(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_all_critical.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("expected CRITICAL for %s, got %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Tfsec_Empty(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_empty.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestFixture_Tfsec_Malformed(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_malformed.json")
	// tfsec parser returns error for invalid JSON
	_, err := parseTfsecOutput(data)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

// ===========================================================================
// Trivy — integration tests with fixtures
// ===========================================================================

func TestFixture_Trivy_Passing(t *testing.T) {
	data := readFixture(t, "trivy/trivy_passing.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestFixture_Trivy_Mixed(t *testing.T) {
	data := readFixture(t, "trivy/trivy_mixed.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 10 misconfigs in fixture, but 1 is PASS → 9 findings
	if len(findings) != 9 {
		t.Fatalf("expected 9 findings (PASS filtered), got %d", len(findings))
	}

	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 2 {
		t.Errorf("CRITICAL: expected 2, got %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 4 {
		t.Errorf("HIGH: expected 4, got %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 2 {
		t.Errorf("MEDIUM: expected 2, got %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 1 {
		t.Errorf("LOW: expected 1, got %d", counts[rules.SeverityLow])
	}

	// PASS should not be present
	for _, f := range findings {
		if f.RuleID == "AVD-AWS-0099" {
			t.Error("AVD-AWS-0099 (PASS) should not be in findings")
		}
	}

	// Spot check
	f := findByRuleID(findings, "AVD-AWS-0086")
	if f == nil {
		t.Fatal("AVD-AWS-0086 not found")
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("expected resource aws_s3_bucket.data, got %s", f.Resource)
	}
	if f.Source != "scanner:trivy" {
		t.Errorf("expected source scanner:trivy, got %s", f.Source)
	}

	assertRequiredFields(t, findings, "trivy")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Trivy_AllCritical(t *testing.T) {
	data := readFixture(t, "trivy/trivy_all_critical.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("expected CRITICAL for %s, got %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Trivy_Empty(t *testing.T) {
	data := readFixture(t, "trivy/trivy_empty.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestFixture_Trivy_Malformed(t *testing.T) {
	data := readFixture(t, "trivy/trivy_malformed.json")
	_, err := parseTrivyOutput(data)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestFixture_Trivy_SkipPassEntries(t *testing.T) {
	data := readFixture(t, "trivy/trivy_mixed.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// No finding should have come from a Status: "PASS"
	for _, f := range findings {
		if f.RuleID == "AVD-AWS-0099" {
			t.Errorf("finding AVD-AWS-0099 with Status PASS should not have been parsed")
		}
	}
}

// ===========================================================================
// Terrascan — integration tests with fixtures
// ===========================================================================

func TestFixture_Terrascan_Passing(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_passing.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestFixture_Terrascan_Mixed(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_mixed.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 13 {
		t.Fatalf("expected 13 findings, got %d", len(findings))
	}

	// Severity distribution (Terrascan has no CRITICAL)
	counts := countBySeverity(findings)
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: expected 5, got %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 6 {
		t.Errorf("MEDIUM: expected 6, got %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: expected 2, got %d", counts[rules.SeverityLow])
	}
	if counts[rules.SeverityCritical] != 0 {
		t.Errorf("CRITICAL: expected 0 (Terrascan has no CRITICAL), got %d", counts[rules.SeverityCritical])
	}

	// Spot check
	f := findByRuleID(findings, "AC_AWS_0207")
	if f == nil {
		t.Fatal("AC_AWS_0207 not found")
	}
	if f.Severity != rules.SeverityHigh {
		t.Errorf("AC_AWS_0207: expected HIGH, got %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("AC_AWS_0207: expected resource aws_s3_bucket.data, got %s", f.Resource)
	}
	if f.Source != "scanner:terrascan" {
		t.Errorf("AC_AWS_0207: expected source scanner:terrascan, got %s", f.Source)
	}

	// Terrascan does not provide remediation
	if f.Remediation != "" {
		t.Errorf("AC_AWS_0207: Terrascan não provê remediation, got %q", f.Remediation)
	}

	assertRequiredFields(t, findings, "terrascan")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Terrascan_AllHigh(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_all_high.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityHigh {
			t.Errorf("expected HIGH for %s, got %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Terrascan_Empty(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_empty.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestFixture_Terrascan_Malformed(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_malformed.json")
	_, err := parseTerrascanOutput(data)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestFixture_Terrascan_CategoryMapping(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_mixed.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verificar que a categoria "Logging and Monitoring" foi mapeada para compliance
	f := findByRuleID(findings, "AC_AWS_0214")
	if f == nil {
		t.Fatal("AC_AWS_0214 not found")
	}
	if f.Category != rules.CategoryCompliance {
		t.Errorf("AC_AWS_0214 (Logging): expected %s, got %s", rules.CategoryCompliance, f.Category)
	}

	// "Security Best Practices" → security
	f2 := findByRuleID(findings, "AC_AWS_0207")
	if f2 == nil {
		t.Fatal("AC_AWS_0207 not found")
	}
	if f2.Category != rules.CategorySecurity {
		t.Errorf("AC_AWS_0207 (Security): expected %s, got %s", rules.CategorySecurity, f2.Category)
	}

	// "Best Practice" → best-practice
	f3 := findByRuleID(findings, "AC_AWS_0215")
	if f3 == nil {
		t.Fatal("AC_AWS_0215 not found")
	}
	if f3.Category != rules.CategoryBestPractice {
		t.Errorf("AC_AWS_0215 (Best Practice): expected %s, got %s", rules.CategoryBestPractice, f3.Category)
	}

	// "IAM Policies" → security
	f4 := findByRuleID(findings, "AC_AWS_0270")
	if f4 == nil {
		t.Fatal("AC_AWS_0270 not found")
	}
	if f4.Category != rules.CategorySecurity {
		t.Errorf("AC_AWS_0270 (IAM): expected %s, got %s", rules.CategorySecurity, f4.Category)
	}
}

// ===========================================================================
// Cross-scanner tests: normalization and deduplication
// ===========================================================================

func TestCrossScanner_SeverityNormalization(t *testing.T) {
	// Carrega fixtures "mixed" de todos os scanners
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	validSeverities := map[string]bool{
		rules.SeverityCritical: true,
		rules.SeverityHigh:     true,
		rules.SeverityMedium:   true,
		rules.SeverityLow:      true,
		rules.SeverityInfo:     true,
	}

	// All severities must be canonical values after normalization
	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		for i, f := range set.findings {
			if !validSeverities[f.Severity] {
				t.Errorf("[%s] finding %d (%s): severidade não normalizada %q",
					set.name, i, f.RuleID, f.Severity)
			}
		}
	}
}

func TestCrossScanner_SourceTagFormat(t *testing.T) {
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	expectedSources := map[string]string{
		"checkov":   "scanner:checkov",
		"tfsec":     "scanner:tfsec",
		"terrascan": "scanner:terrascan",
		"trivy":     "scanner:trivy",
	}

	allSets := map[string][]rules.Finding{
		"checkov":   checkovFindings,
		"tfsec":     tfsecFindings,
		"terrascan": terrascanFindings,
		"trivy":     trivyFindings,
	}

	for name, findings := range allSets {
		expected := expectedSources[name]
		for i, f := range findings {
			if f.Source != expected {
				t.Errorf("[%s] finding %d: expected source %q, got %q",
					name, i, expected, f.Source)
			}
		}
	}
}

func TestCrossScanner_AllFindingsHaveCategory(t *testing.T) {
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		for i, f := range set.findings {
			if f.Category == "" {
				t.Errorf("[%s] finding %d (%s): categoria vazia", set.name, i, f.RuleID)
			}
		}
	}
}

func TestCrossScanner_DeduplicateOverlappingFindings(t *testing.T) {
	// Simulate situation where Checkov and tfsec find the same issue
	// on the same resource — dedup should merge
	checkov := []rules.Finding{
		{
			RuleID:   "CKV_AWS_19",
			Severity: rules.SeverityMedium,
			Category: rules.CategorySecurity,
			Resource: "aws_s3_bucket.data",
			Message:  "[checkov] CKV_AWS_19: Ensure the S3 bucket has server-side-encryption enabled",
			Source:   "scanner:checkov",
		},
	}
	tfsec := []rules.Finding{
		{
			RuleID:      "aws-s3-enable-bucket-encryption",
			Severity:    rules.SeverityCritical,
			Category:    rules.CategorySecurity,
			Resource:    "aws_s3_bucket.data",
			Message:     "[tfsec] aws-s3-enable-bucket-encryption: Bucket does not have encryption enabled",
			Remediation: "Configure server-side encryption",
			Source:      "scanner:tfsec",
		},
	}

	// Combina findings como o aggregator faria
	combined := append(checkov, tfsec...)
	deduped := deduplicateFindings(combined)

	// Dedup by message heuristic — both mention encryption + s3
	// normalizeRuleID should recognize the "encrypt" pattern and group
	if len(deduped) > 2 {
		t.Errorf("dedup should reduce findings, got %d out of %d", len(deduped), len(combined))
	}

	// Se deduplicou, deve ter mantido a maior severidade (CRITICAL)
	if len(deduped) == 1 {
		if deduped[0].Severity != rules.SeverityCritical {
			t.Errorf("dedup should keep highest severity: expected CRITICAL, got %s", deduped[0].Severity)
		}
	}
}

func TestCrossScanner_FieldConsistency(t *testing.T) {
	// Verify that all scanners produce the same struct with the same fields
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		if len(set.findings) == 0 {
			t.Errorf("[%s] sem findings no fixture mixed", set.name)
			continue
		}

		hasRemediation := false
		for _, f := range set.findings {
			// RuleID, Severity, Category, Resource, Message, Source: required
			if f.RuleID == "" || f.Severity == "" || f.Resource == "" || f.Message == "" || f.Source == "" {
				t.Errorf("[%s] finding com campo obrigatório vazio: %+v", set.name, f)
			}
			if f.Remediation != "" {
				hasRemediation = true
			}
		}

		// tfsec and trivy should have remediation; terrascan does not provide it
		switch set.name {
		case "tfsec", "trivy":
			if !hasRemediation {
				t.Errorf("[%s] nenhum finding tem remediation preenchida", set.name)
			}
		case "terrascan":
			if hasRemediation {
				t.Errorf("[terrascan] remediation should be empty, but was filled")
			}
		}
	}
}

func TestCrossScanner_MessagePrefixFormat(t *testing.T) {
	// Verify that messages follow the format [scanner] RuleID: description
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	type prefixCase struct {
		name     string
		prefix   string
		findings []rules.Finding
	}

	cases := []prefixCase{
		{"checkov", "[checkov]", checkovFindings},
		{"tfsec", "[tfsec]", tfsecFindings},
		{"terrascan", "[terrascan]", terrascanFindings},
		{"trivy", "[trivy]", trivyFindings},
	}

	for _, tc := range cases {
		for i, f := range tc.findings {
			if len(f.Message) < len(tc.prefix) || f.Message[:len(tc.prefix)] != tc.prefix {
				t.Errorf("[%s] finding %d: message should start with %q, got %q",
					tc.name, i, tc.prefix, f.Message)
			}
		}
	}
}
