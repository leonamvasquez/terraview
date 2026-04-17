package eval

import (
	"path/filepath"
	"testing"
)

func TestLoadCases_FromTestdata(t *testing.T) {
	cases, err := LoadCases(filepath.Join("testdata", "evals"))
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}
	if len(cases) < 2 {
		t.Fatalf("expected at least 2 cases, got %d", len(cases))
	}
	// Deterministic order.
	if cases[0].Name != "s3-public" {
		t.Errorf("expected first case s3-public, got %q", cases[0].Name)
	}
	// Golden loaded.
	if len(cases[0].Golden.RequiredTopics) == 0 {
		t.Error("expected s3-public golden to define required_topics")
	}
}

func TestLoadCase_MissingPlan(t *testing.T) {
	dir := t.TempDir()
	// Only golden, no plan — loader should error.
	goldenPath := filepath.Join(dir, "golden.yaml")
	if err := writeFile(goldenPath, "description: test\n"); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	if _, err := LoadCase(dir); err == nil {
		t.Fatal("expected error when plan.json is missing")
	}
}

func TestLoadCase_BadYAML(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(filepath.Join(dir, "plan.json"), "{}"); err != nil {
		t.Fatalf("writeFile plan: %v", err)
	}
	if err := writeFile(filepath.Join(dir, "golden.yaml"), "required_topics: [unclosed"); err != nil {
		t.Fatalf("writeFile golden: %v", err)
	}
	if _, err := LoadCase(dir); err == nil {
		t.Fatal("expected error for malformed golden.yaml")
	}
}

func TestLoadCases_SkipsNonCaseDirs(t *testing.T) {
	dir := t.TempDir()
	// Subdir without golden.yaml should be ignored.
	sub := filepath.Join(dir, "noise")
	if err := mkdirAll(sub); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	cases, err := LoadCases(dir)
	if err != nil {
		t.Fatalf("LoadCases: %v", err)
	}
	if len(cases) != 0 {
		t.Errorf("expected 0 cases, got %d", len(cases))
	}
}
