package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_NoFile(t *testing.T) {
	// Override HOME so global config (~/.terraview/.terraview.yaml) is not picked up
	t.Setenv("HOME", t.TempDir())

	dir := t.TempDir()
	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Model != "llama3.1:8b" {
		t.Errorf("expected default model, got %s", cfg.LLM.Model)
	}
	if !cfg.LLM.Enabled {
		t.Error("expected LLM enabled by default")
	}
	if cfg.Scoring.SeverityWeights.Critical != 5.0 {
		t.Errorf("expected critical weight 5.0, got %.1f", cfg.Scoring.SeverityWeights.Critical)
	}
}

func TestLoad_ValidFile(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  enabled: false
  model: mistral:7b
  timeout_seconds: 30

scoring:
  severity_weights:
    critical: 10
    medium: 2

rules:
  required_tags:
    - environment
    - owner

output:
  format: compact
`
	if err := os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Enabled {
		t.Error("expected LLM disabled")
	}
	if cfg.LLM.Model != "mistral:7b" {
		t.Errorf("expected mistral:7b, got %s", cfg.LLM.Model)
	}
	if cfg.LLM.TimeoutSeconds != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.LLM.TimeoutSeconds)
	}
	// Unset fields keep defaults
	if cfg.LLM.URL != "http://localhost:11434" {
		t.Errorf("expected default URL, got %s", cfg.LLM.URL)
	}
	if cfg.Scoring.SeverityWeights.Critical != 10.0 {
		t.Errorf("expected critical 10.0, got %.1f", cfg.Scoring.SeverityWeights.Critical)
	}
	if cfg.Scoring.SeverityWeights.High != 3.0 {
		t.Errorf("expected high default 3.0, got %.1f", cfg.Scoring.SeverityWeights.High)
	}
	if cfg.Scoring.SeverityWeights.Medium != 2.0 {
		t.Errorf("expected medium 2.0, got %.1f", cfg.Scoring.SeverityWeights.Medium)
	}
	if len(cfg.Rules.RequiredTags) != 2 {
		t.Errorf("expected 2 required tags, got %d", len(cfg.Rules.RequiredTags))
	}
	if cfg.Output.Format != "compact" {
		t.Errorf("expected format compact, got %s", cfg.Output.Format)
	}
}

func TestLoad_InvalidTemperature(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  temperature: 1.5
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected validation error for temperature > 1.0")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("{{invalid"), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoad_NegativeWeight(t *testing.T) {
	dir := t.TempDir()
	content := `
scoring:
  severity_weights:
    critical: -1
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected validation error for negative weight")
	}
}

func TestLoad_RulePacks(t *testing.T) {
	dir := t.TempDir()
	content := `
rules:
  rule_packs:
    - default
    - enterprise-security
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(cfg.Rules.RulePacks) != 2 {
		t.Errorf("expected 2 rule packs, got %d", len(cfg.Rules.RulePacks))
	}
	if cfg.Rules.RulePacks[0] != "default" {
		t.Errorf("expected first pack 'default', got %s", cfg.Rules.RulePacks[0])
	}
}

func TestLoad_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  model: codellama:7b
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Overridden field
	if cfg.LLM.Model != "codellama:7b" {
		t.Errorf("expected codellama:7b, got %s", cfg.LLM.Model)
	}
	// All other defaults preserved
	if !cfg.LLM.Enabled {
		t.Error("expected LLM enabled (default)")
	}
	if cfg.LLM.TimeoutSeconds != 120 {
		t.Errorf("expected default timeout 120, got %d", cfg.LLM.TimeoutSeconds)
	}
	if cfg.Scoring.SeverityWeights.Critical != 5.0 {
		t.Errorf("expected default critical 5.0, got %.1f", cfg.Scoring.SeverityWeights.Critical)
	}
}
