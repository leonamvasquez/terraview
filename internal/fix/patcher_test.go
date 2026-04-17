package fix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// copyFixture copies testdata/simple.tf into a fresh tempdir and returns the
// path to the copy, so tests can mutate it without affecting shared state.
func copyFixture(t *testing.T) string {
	t.Helper()
	src := filepath.Join("testdata", "simple.tf")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dst := filepath.Join(t.TempDir(), "main.tf")
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write fixture copy: %v", err)
	}
	return dst
}

func TestWriteAtomic_Success(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "out.tf")
	want := "resource \"aws_s3_bucket\" \"x\" {}\n"

	if err := writeAtomic(dst, []byte(want)); err != nil {
		t.Fatalf("writeAtomic: %v", err)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != want {
		t.Errorf("content mismatch: got %q, want %q", got, want)
	}

	if _, err := os.Stat(dst + ".tvfix.tmp"); !os.IsNotExist(err) {
		t.Errorf("expected tmp file to be renamed away, err=%v", err)
	}
}

func TestWriteAtomic_InvalidPath(t *testing.T) {
	// /definitely/does/not/exist/out.tf — parent dir missing → WriteFile fails.
	if err := writeAtomic("/nonexistent-dir-xyz-789/out.tf", []byte("x")); err == nil {
		t.Fatal("expected error for invalid parent dir")
	}
}

func TestBackupAndRestore_RoundTrip(t *testing.T) {
	file := copyFixture(t)
	orig, _ := os.ReadFile(file)

	bak, err := BackupFile(file)
	if err != nil {
		t.Fatalf("BackupFile: %v", err)
	}
	if !strings.HasSuffix(bak, ".tvfix.bak") {
		t.Errorf("unexpected backup path: %s", bak)
	}
	if _, err := os.Stat(bak); err != nil {
		t.Fatalf("backup file missing: %v", err)
	}

	// Mutate the original then restore from backup.
	if err := os.WriteFile(file, []byte("corrupted"), 0o644); err != nil {
		t.Fatalf("mutate file: %v", err)
	}

	if err := RestoreBackup(bak); err != nil {
		t.Fatalf("RestoreBackup: %v", err)
	}

	restored, _ := os.ReadFile(file)
	if string(restored) != string(orig) {
		t.Errorf("restored content mismatch")
	}
	if _, err := os.Stat(bak); !os.IsNotExist(err) {
		t.Errorf("expected backup to be removed after restore, err=%v", err)
	}
}

func TestBackupFile_MissingSource(t *testing.T) {
	if _, err := BackupFile("/nonexistent-file-abc.tf"); err == nil {
		t.Fatal("expected error for missing source")
	}
}

func TestRestoreBackup_MissingBackup(t *testing.T) {
	if err := RestoreBackup("/nonexistent-backup.tvfix.bak"); err == nil {
		t.Fatal("expected error for missing backup")
	}
}

func TestApplyToFile_ReplacesBlock(t *testing.T) {
	file := copyFixture(t)
	// Locate the "logs" bucket (first block, lines 1-4).
	loc, err := FindResource(filepath.Dir(file), "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}

	newHCL := `resource "aws_s3_bucket" "logs" {
  bucket = "company-logs"
  acl    = "private"
  versioning {
    enabled = true
  }
}`

	if err := ApplyToFile(loc, newHCL); err != nil {
		t.Fatalf("ApplyToFile: %v", err)
	}

	got, _ := os.ReadFile(file)
	if !strings.Contains(string(got), "versioning {") {
		t.Errorf("expected new block with versioning, got:\n%s", got)
	}
	// Sibling "data" resource must still be present and untouched.
	if !strings.Contains(string(got), `"aws_s3_bucket" "data"`) {
		t.Errorf("expected data bucket to survive, got:\n%s", got)
	}
	if !strings.Contains(string(got), `"aws_iam_role" "app"`) {
		t.Errorf("expected iam role to survive, got:\n%s", got)
	}
}

func TestApplyToFile_MissingFile(t *testing.T) {
	loc := &Location{File: "/nonexistent/main.tf", StartLine: 1, EndLine: 1}
	if err := ApplyToFile(loc, "x"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestAppendToFile_Success(t *testing.T) {
	file := copyFixture(t)
	before, _ := os.ReadFile(file)

	blocks := []string{
		"resource \"aws_kms_key\" \"new\" {\n  enable_key_rotation = true\n}",
		"resource \"aws_sns_topic\" \"alerts\" {\n  name = \"alerts\"\n}",
	}

	if err := AppendToFile(file, blocks); err != nil {
		t.Fatalf("AppendToFile: %v", err)
	}

	after, _ := os.ReadFile(file)
	if len(after) <= len(before) {
		t.Errorf("expected file to grow, before=%d after=%d", len(before), len(after))
	}
	if !strings.Contains(string(after), "aws_kms_key") {
		t.Errorf("kms block not appended, got:\n%s", after)
	}
	if !strings.Contains(string(after), "aws_sns_topic") {
		t.Errorf("sns block not appended, got:\n%s", after)
	}
}

func TestAppendToFile_MissingFile(t *testing.T) {
	if err := AppendToFile("/nonexistent/main.tf", []string{"x"}); err == nil {
		t.Fatal("expected error for missing file")
	}
}
