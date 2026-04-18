package fix

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// newTestSession returns an ApplySession that writes to buf instead of os.Stdout.
func newTestSession(t *testing.T, workDir string) (*ApplySession, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return &ApplySession{
		WorkDir: workDir,
		NoColor: true,
		Out:     &buf,
	}, &buf
}

func makePF(ruleID, severity, resource string, loc *Location, warnings []ValidationWarning) PendingFix {
	return PendingFix{
		Finding: rules.Finding{
			RuleID:   ruleID,
			Severity: severity,
			Resource: resource,
			Message:  "test finding",
		},
		Suggestion: &FixSuggestion{
			RuleID:      ruleID,
			Resource:    resource,
			HCL:         `resource "aws_kms_key" "fixed" { enable_key_rotation = true }`,
			Explanation: "enabled key rotation",
			Effort:      "low",
		},
		Location: loc,
		Warnings: warnings,
	}
}

// ── Preview ───────────────────────────────────────────────────────────────────

func TestPreview_Empty(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	sess.Preview(nil)
	if buf.Len() != 0 {
		t.Errorf("Preview with empty slice must write nothing, got %q", buf.String())
	}
}

func TestPreview_WritesToOut(t *testing.T) {
	dir := t.TempDir()
	// Write a .tf file so ReadLines has something to show
	tf := filepath.Join(dir, "main.tf")
	content := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"test\"\n}\n"
	if err := os.WriteFile(tf, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	loc := &Location{File: tf, StartLine: 1, EndLine: 3}
	pf := makePF("CKV_AWS_1", "HIGH", "aws_s3_bucket.b", loc, nil)

	sess, buf := newTestSession(t, dir)
	sess.Preview([]PendingFix{pf})

	out := buf.String()
	if !strings.Contains(out, "Preview of 1 fix") {
		t.Errorf("expected header in Preview output, got: %q", out)
	}
	if !strings.Contains(out, "terraview fix apply") {
		t.Errorf("expected hint in Preview output, got: %q", out)
	}
}

func TestPreview_NoFileLocation(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	pf := makePF("CKV_AWS_2", "MEDIUM", "aws_s3_bucket.b", nil, nil)
	sess.Preview([]PendingFix{pf})

	out := buf.String()
	if !strings.Contains(out, "Preview of 1 fix") {
		t.Errorf("expected header, got: %q", out)
	}
	// Should mention that .tf file was not found
	if !strings.Contains(out, "não localizado") {
		t.Errorf("expected 'não localizado' warning, got: %q", out)
	}
}

// ── ApplyAll ──────────────────────────────────────────────────────────────────

func TestApplyAll_Empty(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	applied, failed := sess.ApplyAll(nil)

	if applied != 0 || failed != 0 {
		t.Errorf("expected 0/0, got applied=%d failed=%d", applied, failed)
	}
	out := buf.String()
	if !strings.Contains(out, "Applying 0 fix(es)") {
		t.Errorf("expected header in output, got: %q", out)
	}
}

func TestApplyAll_NilLocation_Skipped(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	pf := makePF("CKV_AWS_3", "HIGH", "aws_s3_bucket.b", nil, nil)

	applied, failed := sess.ApplyAll([]PendingFix{pf})

	if applied != 0 || failed != 1 {
		t.Errorf("expected applied=0 failed=1, got applied=%d failed=%d", applied, failed)
	}
	if !strings.Contains(buf.String(), "not found") {
		t.Errorf("expected 'not found' message, got: %q", buf.String())
	}
}

func TestApplyAll_CriticalWarning_Skipped(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	if err := os.WriteFile(tf, []byte("resource \"aws_s3_bucket\" \"b\" {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	loc := &Location{File: tf, StartLine: 1, EndLine: 1}
	warnings := []ValidationWarning{{Code: "PLACEHOLDER", Message: "has placeholder"}}
	pf := makePF("CKV_AWS_4", "CRITICAL", "aws_s3_bucket.b", loc, warnings)

	sess, buf := newTestSession(t, dir)
	applied, failed := sess.ApplyAll([]PendingFix{pf})

	if applied != 0 || failed != 1 {
		t.Errorf("expected applied=0 failed=1, got applied=%d failed=%d", applied, failed)
	}
	if !strings.Contains(buf.String(), "bloqueado") {
		t.Errorf("expected 'bloqueado' message, got: %q", buf.String())
	}
}

func TestApplyAll_UnbalancedHCL_Skipped(t *testing.T) {
	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	original := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"test\"\n}\n"
	if err := os.WriteFile(tf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	loc := &Location{File: tf, StartLine: 1, EndLine: 3}
	pf := PendingFix{
		Finding: rules.Finding{RuleID: "CKV_AWS_5", Severity: "HIGH", Resource: "aws_s3_bucket.b"},
		Suggestion: &FixSuggestion{
			HCL:    `resource "aws_s3_bucket" "b" { bucket = "test"`, // missing closing brace
			Effort: "low",
		},
		Location: loc,
	}

	sess, buf := newTestSession(t, dir)
	applied, failed := sess.ApplyAll([]PendingFix{pf})

	if applied != 0 || failed != 1 {
		t.Errorf("expected applied=0 failed=1, got applied=%d failed=%d", applied, failed)
	}

	// Original file must not be modified
	data, _ := os.ReadFile(tf)
	if string(data) != original {
		t.Errorf("file was modified despite unbalanced HCL: %q", string(data))
	}
	_ = buf
}

func TestApplyAll_Success(t *testing.T) {
	// Clear PATH so exec.LookPath("terraform") returns error →
	// terraformValidate returns nil (documented: non-fatal when terraform not installed).
	t.Setenv("PATH", "")

	dir := t.TempDir()
	tf := filepath.Join(dir, "main.tf")
	original := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"test\"\n}\n"
	if err := os.WriteFile(tf, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	fixedHCL := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"test\"\n  versioning { enabled = true }\n}"
	loc := &Location{File: tf, StartLine: 1, EndLine: 3}
	pf := PendingFix{
		Finding:    rules.Finding{RuleID: "CKV_AWS_6", Severity: "HIGH", Resource: "aws_s3_bucket.b"},
		Suggestion: &FixSuggestion{HCL: fixedHCL, Effort: "low"},
		Location:   loc,
	}

	sess, buf := newTestSession(t, dir)
	applied, failed := sess.ApplyAll([]PendingFix{pf})

	if applied != 1 || failed != 0 {
		t.Errorf("expected applied=1 failed=0, got applied=%d failed=%d\noutput: %s", applied, failed, buf.String())
	}
	if !strings.Contains(buf.String(), "✓") {
		t.Errorf("expected success checkmark, got: %q", buf.String())
	}
	// File must contain the fix
	data, _ := os.ReadFile(tf)
	if !strings.Contains(string(data), "versioning") {
		t.Errorf("file does not contain fix: %q", string(data))
	}
}

// ── printSummary (via ApplyAll) ───────────────────────────────────────────────

func TestApplyAll_SummaryLine(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	sess.ApplyAll(nil) // 0 applied, 0 failed, 0 total
	out := buf.String()
	if !strings.Contains(out, "0 aplicado(s)") {
		t.Errorf("expected summary line, got: %q", out)
	}
}

// ── printWarnings (via Preview) ───────────────────────────────────────────────

func TestPreview_PrintsWarnings(t *testing.T) {
	sess, buf := newTestSession(t, t.TempDir())
	warnings := []ValidationWarning{{Code: "PLACEHOLDER", Message: "contains placeholder value"}}
	pf := makePF("CKV_AWS_7", "HIGH", "aws_s3_bucket.b", nil, warnings)

	sess.Preview([]PendingFix{pf})
	if !strings.Contains(buf.String(), "contains placeholder value") {
		t.Errorf("expected warning message in output, got: %q", buf.String())
	}
}

// ── out() default fallback ────────────────────────────────────────────────────

func TestApplySession_OutDefaults(t *testing.T) {
	// When Out is nil, out() must return os.Stdout (not panic or nil).
	sess := &ApplySession{WorkDir: t.TempDir(), NoColor: true}
	w := sess.out()
	if w == nil {
		t.Error("out() returned nil when Out field is not set")
	}
}
