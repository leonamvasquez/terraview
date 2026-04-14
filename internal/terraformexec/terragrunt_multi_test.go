package terraformexec

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverTerragruntModules(t *testing.T) {
	root := t.TempDir()

	// Create root terragrunt.hcl
	os.WriteFile(filepath.Join(root, "terragrunt.hcl"), []byte("# root"), 0644)

	// Create child modules
	for _, name := range []string{"vpc", "eks", "rds"} {
		dir := filepath.Join(root, name)
		os.MkdirAll(dir, 0755)
		os.WriteFile(filepath.Join(dir, "terragrunt.hcl"), []byte("# "+name), 0644)
	}

	// Create hidden dir (should be skipped)
	hiddenDir := filepath.Join(root, ".terragrunt-cache")
	os.MkdirAll(hiddenDir, 0755)
	os.WriteFile(filepath.Join(hiddenDir, "terragrunt.hcl"), []byte("# cache"), 0644)

	// Create dir without terragrunt.hcl (should be skipped)
	os.MkdirAll(filepath.Join(root, "scripts"), 0755)

	modules, err := DiscoverTerragruntModules(root)
	if err != nil {
		t.Fatalf("DiscoverTerragruntModules failed: %v", err)
	}

	if len(modules) != 3 {
		t.Fatalf("found %d modules, want 3", len(modules))
	}

	// Should be sorted alphabetically
	expected := []string{"eks", "rds", "vpc"}
	for i, mod := range modules {
		base := filepath.Base(mod)
		if base != expected[i] {
			t.Errorf("module[%d] = %q, want %q", i, base, expected[i])
		}
	}
}

func TestDiscoverTerragruntModules_NoModules(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "terragrunt.hcl"), []byte("# root"), 0644)

	_, err := DiscoverTerragruntModules(root)
	if err == nil {
		t.Error("expected error for empty modules, got nil")
	}
}

func TestIsTerragruntRootWithModules_True(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "terragrunt.hcl"), []byte("# root"), 0644)

	childDir := filepath.Join(root, "vpc")
	os.MkdirAll(childDir, 0755)
	os.WriteFile(filepath.Join(childDir, "terragrunt.hcl"), []byte("# vpc"), 0644)

	if !IsTerragruntRootWithModules(root) {
		t.Error("expected true for root with child module")
	}
}

func TestIsTerragruntRootWithModules_FalseNoRoot(t *testing.T) {
	root := t.TempDir()
	// No terragrunt.hcl at root

	if IsTerragruntRootWithModules(root) {
		t.Error("expected false when no root terragrunt.hcl")
	}
}

func TestIsTerragruntRootWithModules_FalseNoChildren(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "terragrunt.hcl"), []byte("# root"), 0644)
	// No child directories with terragrunt.hcl

	if IsTerragruntRootWithModules(root) {
		t.Error("expected false when no child modules")
	}
}

func TestIsTerragruntRootWithModules_SkipsHidden(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "terragrunt.hcl"), []byte("# root"), 0644)

	// Only hidden dir has terragrunt.hcl
	hiddenDir := filepath.Join(root, ".cache")
	os.MkdirAll(hiddenDir, 0755)
	os.WriteFile(filepath.Join(hiddenDir, "terragrunt.hcl"), []byte("# cache"), 0644)

	if IsTerragruntRootWithModules(root) {
		t.Error("expected false when only hidden dirs have terragrunt.hcl")
	}
}

func TestMaxParallelModules_WithinBounds(t *testing.T) {
	if maxParallelModules < 1 {
		t.Errorf("maxParallelModules = %d, want >= 1", maxParallelModules)
	}
	if maxParallelModules > 6 {
		t.Errorf("maxParallelModules = %d, want <= 6", maxParallelModules)
	}
}

// Compile-time check that TerragruntMultiExecutor implements PlanExecutor.
var _ PlanExecutor = (*TerragruntMultiExecutor)(nil)
