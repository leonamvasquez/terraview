package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetect_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.HasTFFiles {
		t.Error("should not detect .tf files in empty dir")
	}
	if result.TFFileCount != 0 {
		t.Errorf("TFFileCount = %d, want 0", result.TFFileCount)
	}
	if result.HasLockFile {
		t.Error("should not detect lock file")
	}
	if result.IsInitialized {
		t.Error("should not be initialized")
	}
	if result.HasPlanJSON {
		t.Error("should not have plan.json")
	}
	if result.HasModules {
		t.Error("should not have modules")
	}
}

func TestDetect_WithTFFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0644)
	os.WriteFile(filepath.Join(dir, "vars.tf"), []byte("variable {}"), 0644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasTFFiles {
		t.Error("should detect .tf files")
	}
	if result.TFFileCount != 2 {
		t.Errorf("TFFileCount = %d, want 2", result.TFFileCount)
	}
}

func TestDetect_WithLockFile(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte("provider {}"), 0644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasLockFile {
		t.Error("should detect lock file")
	}
}

func TestDetect_WithTerraformDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".terraform"), 0755)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsInitialized {
		t.Error("should detect .terraform directory as initialized")
	}
}

func TestDetect_WithModulesDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, ".terraform", "modules"), 0755)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasModules {
		t.Error("should detect modules directory")
	}
}

func TestDetect_WithPlanJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "plan.json"), []byte("{}"), 0644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasPlanJSON {
		t.Error("should detect plan.json")
	}
	if result.PlanJSONPath != filepath.Join(dir, "plan.json") {
		t.Errorf("PlanJSONPath = %q", result.PlanJSONPath)
	}
}

func TestDetect_InvalidDir(t *testing.T) {
	_, err := Detect("/nonexistent/path/to/nowhere")
	if err == nil {
		t.Fatal("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "not a valid directory") {
		t.Errorf("error = %q", err)
	}
}

func TestDetect_FileNotDir(t *testing.T) {
	f := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(f, []byte("x"), 0644)
	_, err := Detect(f)
	if err == nil {
		t.Fatal("expected error for file path")
	}
}

func TestDetect_FullWorkspace(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0644)
	os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(""), 0644)
	os.MkdirAll(filepath.Join(dir, ".terraform", "modules"), 0755)
	os.WriteFile(filepath.Join(dir, "plan.json"), []byte("{}"), 0644)

	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.HasTFFiles || !result.HasLockFile || !result.IsInitialized || !result.HasModules || !result.HasPlanJSON {
		t.Errorf("full workspace not fully detected: %+v", result)
	}
}

func TestDetect_AbsDir(t *testing.T) {
	dir := t.TempDir()
	result, err := Detect(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(result.Dir) {
		t.Errorf("Dir should be absolute, got %q", result.Dir)
	}
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

func TestValidate_ValidWorkspace(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource {}"), 0644)

	err := Validate(dir)
	// May or may not error depending on whether terraform is installed
	// but should not error about "no Terraform files"
	if err != nil && strings.Contains(err.Error(), "no Terraform files found") {
		t.Errorf("should accept directory with .tf files: %v", err)
	}
}

func TestValidate_WithLockFileOnly(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraform.lock.hcl"), []byte(""), 0644)

	err := Validate(dir)
	// Should accept lock file as workspace indicator
	if err != nil && strings.Contains(err.Error(), "no Terraform files found") {
		t.Errorf("should accept directory with lock file: %v", err)
	}
}

func TestValidate_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	err := Validate(dir)
	if err == nil {
		t.Fatal("expected error for empty directory")
	}
	if !strings.Contains(err.Error(), "no Terraform files found") && !strings.Contains(err.Error(), "terraform is not installed") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidate_InvalidDir(t *testing.T) {
	err := Validate("/nonexistent/dir")
	if err == nil {
		t.Fatal("expected error for invalid directory")
	}
}
