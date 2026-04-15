package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// applyFixInTempDir copies the simple fixture into tempdir/main.tf and returns
// the directory + location of aws_s3_bucket.logs. Callers drive applyFix with
// a custom Suggestion and assert on the resulting file state.
func applyFixInTempDir(t *testing.T) (dir string, loc *Location) {
	t.Helper()
	file := copyFixture(t)
	dir = filepath.Dir(file)
	loc, err := FindResource(dir, "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}
	return dir, loc
}

func TestApplyFix_RejectsUnbalancedBraces(t *testing.T) {
	dir, loc := applyFixInTempDir(t)
	before, _ := os.ReadFile(loc.File)

	pf := PendingFix{
		Finding: rules.Finding{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_s3_bucket.logs"},
		Suggestion: &FixSuggestion{
			HCL: `resource "aws_s3_bucket" "logs" {
  bucket = "logs"
  versioning {
    enabled = true
  # missing closing brace for versioning
}`,
		},
		Location: loc,
	}

	s := &ApplySession{WorkDir: dir, NoColor: true}
	err := s.applyFix(pf)
	if err == nil {
		t.Fatal("expected brace-imbalance error")
	}
	if !strings.Contains(err.Error(), "chaves desbalanceadas") {
		t.Errorf("error should mention brace imbalance, got: %v", err)
	}

	// File must be untouched — no backup lingering, no partial write.
	after, _ := os.ReadFile(loc.File)
	if string(after) != string(before) {
		t.Error("file should be unchanged when fix is rejected pre-flight")
	}
	if _, err := os.Stat(loc.File + ".tvfix.bak"); !os.IsNotExist(err) {
		t.Errorf("expected no backup file when fix is rejected, err=%v", err)
	}
}

func TestApplyFix_HappyPath(t *testing.T) {
	// Happy path: balanced HCL replacement + terraform validate either absent
	// (nil error) or passing. If terraform is installed, we need the replacement
	// to still be valid HCL; keep it trivially minimal.
	dir, loc := applyFixInTempDir(t)

	pf := PendingFix{
		Finding: rules.Finding{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_s3_bucket.logs"},
		Suggestion: &FixSuggestion{
			HCL: `resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}`,
		},
		Location: loc,
	}

	// Force terraformValidate to hit the "not installed" branch regardless of
	// host toolchain — the fixture has no provider block, so a live validate
	// would fail without `terraform init`.
	t.Setenv("PATH", "")

	s := &ApplySession{WorkDir: dir, NoColor: true}
	if err := s.applyFix(pf); err != nil {
		t.Fatalf("applyFix: %v", err)
	}

	got, _ := os.ReadFile(loc.File)
	if !strings.Contains(string(got), `bucket = "company-logs"`) {
		t.Errorf("expected patched content, got:\n%s", got)
	}
	// Backup must be removed on success.
	if _, err := os.Stat(loc.File + ".tvfix.bak"); !os.IsNotExist(err) {
		t.Errorf("expected backup removed after success, err=%v", err)
	}
}

func TestApplyFix_AppendsPrerequisites(t *testing.T) {
	t.Setenv("PATH", "")

	dir, loc := applyFixInTempDir(t)

	pf := PendingFix{
		Finding: rules.Finding{RuleID: "CKV_AWS_158", Severity: "HIGH", Resource: "aws_s3_bucket.logs"},
		Suggestion: &FixSuggestion{
			HCL: `resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
}`,
			Prerequisites: []string{
				`resource "aws_kms_key" "fresh" {
  enable_key_rotation = true
}`,
			},
		},
		Location: loc,
	}

	s := &ApplySession{WorkDir: dir, NoColor: true}
	if err := s.applyFix(pf); err != nil {
		t.Fatalf("applyFix: %v", err)
	}
	got, _ := os.ReadFile(loc.File)
	if !strings.Contains(string(got), `"aws_kms_key" "fresh"`) {
		t.Errorf("expected prereq appended, got:\n%s", got)
	}
}

func TestApplyFix_BackupFailure(t *testing.T) {
	dir := t.TempDir()
	// Location points at a file that does not exist — BackupFile will fail.
	loc := &Location{
		File:      filepath.Join(dir, "missing.tf"),
		StartLine: 1,
		EndLine:   1,
	}
	pf := PendingFix{
		Finding:    rules.Finding{RuleID: "CKV_AWS_1"},
		Suggestion: &FixSuggestion{HCL: "resource \"x\" \"y\" {}"},
		Location:   loc,
	}
	s := &ApplySession{WorkDir: dir, NoColor: true}
	err := s.applyFix(pf)
	if err == nil || !strings.Contains(err.Error(), "backup") {
		t.Fatalf("expected backup error, got: %v", err)
	}
}

func TestTerraformValidate_NotInstalled(t *testing.T) {
	// Force LookPath failure by clearing PATH so we exercise the non-fatal
	// branch without depending on the host's terraform installation.
	orig := os.Getenv("PATH")
	t.Setenv("PATH", "")
	defer os.Setenv("PATH", orig)

	if err := terraformValidate(t.TempDir()); err != nil {
		t.Errorf("expected nil when terraform is not installed, got %v", err)
	}
}

func TestPrintSummary_Smoke(t *testing.T) {
	// printSummary is purely decorative; invoke it to collect coverage.
	s := &ApplySession{NoColor: true}
	s.printSummary(1, 0, 2)
	s.printSummary(0, 1, 1)
}

func TestCol_Toggle(t *testing.T) {
	on := &ApplySession{NoColor: false}
	off := &ApplySession{NoColor: true}
	if on.col(ansiRed) != ansiRed {
		t.Error("colored session should return the ANSI code")
	}
	if off.col(ansiRed) != "" {
		t.Error("no-color session should return empty string")
	}
}

func TestDeduplicatePrereqs_SkipsExisting(t *testing.T) {
	// The fixture already contains aws_iam_role.app — dedup should drop it.
	dir := filepath.Dir(copyFixture(t))
	blocks := []string{
		`resource "aws_iam_role" "app" { name = "app-role" }`,
		`resource "aws_kms_key" "fresh" { enable_key_rotation = true }`,
	}
	got := deduplicatePrereqs(blocks, dir)
	if len(got) != 1 {
		t.Fatalf("expected 1 block after dedup, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "aws_kms_key") {
		t.Errorf("expected kms block to survive, got %q", got[0])
	}
}
