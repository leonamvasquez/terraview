package config

import (
	"os"
	"path/filepath"
	"strings"
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

// ---------------------------------------------------------------------------
// DefaultConfig validation
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if !cfg.LLM.Enabled {
		t.Error("expected LLM enabled by default")
	}
	if cfg.LLM.Provider != "ollama" {
		t.Errorf("expected provider ollama, got %s", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "llama3.1:8b" {
		t.Errorf("expected model llama3.1:8b, got %s", cfg.LLM.Model)
	}
	if cfg.LLM.URL != "http://localhost:11434" {
		t.Errorf("expected default URL, got %s", cfg.LLM.URL)
	}
	if cfg.LLM.TimeoutSeconds != 120 {
		t.Errorf("expected timeout 120, got %d", cfg.LLM.TimeoutSeconds)
	}
	if cfg.LLM.Temperature != 0.2 {
		t.Errorf("expected temperature 0.2, got %f", cfg.LLM.Temperature)
	}
	if cfg.LLM.Ollama.MinFreeMemoryMB != 1024 {
		t.Errorf("expected min free memory 1024, got %d", cfg.LLM.Ollama.MinFreeMemoryMB)
	}
	if cfg.Scoring.SeverityWeights.Critical != 5.0 {
		t.Errorf("expected critical weight 5.0, got %f", cfg.Scoring.SeverityWeights.Critical)
	}
	if cfg.Scoring.SeverityWeights.High != 3.0 {
		t.Errorf("expected high weight 3.0, got %f", cfg.Scoring.SeverityWeights.High)
	}
	if cfg.Scoring.SeverityWeights.Medium != 1.0 {
		t.Errorf("expected medium weight 1.0, got %f", cfg.Scoring.SeverityWeights.Medium)
	}
	if cfg.Scoring.SeverityWeights.Low != 0.5 {
		t.Errorf("expected low weight 0.5, got %f", cfg.Scoring.SeverityWeights.Low)
	}
	if cfg.Output.Format != "pretty" {
		t.Errorf("expected format pretty, got %s", cfg.Output.Format)
	}
}

// ---------------------------------------------------------------------------
// validate edge cases
// ---------------------------------------------------------------------------

func TestLoad_TemperatureZero(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  temperature: 0.0
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("temperature 0.0 should be valid: %v", err)
	}
	if cfg.LLM.Temperature != 0.0 {
		t.Errorf("expected temperature 0.0, got %f", cfg.LLM.Temperature)
	}
}

func TestLoad_TemperatureOne(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  temperature: 1.0
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("temperature 1.0 should be valid: %v", err)
	}
	if cfg.LLM.Temperature != 1.0 {
		t.Errorf("expected temperature 1.0, got %f", cfg.LLM.Temperature)
	}
}

func TestLoad_NegativeTemperature(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  temperature: -0.1
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative temperature")
	}
}

func TestLoad_ZeroTimeout(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  timeout_seconds: 0
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for timeout_seconds 0")
	}
}

func TestLoad_NegativeTimeout(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  timeout_seconds: -5
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative timeout")
	}
}

func TestLoad_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	content := `
output:
  format: xml
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for invalid format 'xml'")
	}
}

func TestLoad_ValidFormats(t *testing.T) {
	for _, format := range []string{"pretty", "compact", "json", "sarif"} {
		dir := t.TempDir()
		content := "output:\n  format: " + format + "\n"
		os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

		cfg, err := Load(dir)
		if err != nil {
			t.Fatalf("format %q should be valid: %v", format, err)
		}
		if cfg.Output.Format != format {
			t.Errorf("expected format %q, got %q", format, cfg.Output.Format)
		}
	}
}

func TestLoad_NegativeOllamaThreads(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  ollama:
    max_threads: -1
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative max_threads")
	}
}

func TestLoad_NegativeOllamaMemory(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  ollama:
    max_memory_mb: -100
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative max_memory_mb")
	}
}

func TestLoad_NegativeOllamaMinFree(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  ollama:
    min_free_memory_mb: -10
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative min_free_memory_mb")
	}
}

func TestLoad_NegativeHighWeight(t *testing.T) {
	dir := t.TempDir()
	content := `
scoring:
  severity_weights:
    high: -2
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative high weight")
	}
}

func TestLoad_NegativeMediumWeight(t *testing.T) {
	dir := t.TempDir()
	content := `
scoring:
  severity_weights:
    medium: -1
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative medium weight")
	}
}

func TestLoad_NegativeLowWeight(t *testing.T) {
	dir := t.TempDir()
	content := `
scoring:
  severity_weights:
    low: -0.5
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	_, err := Load(dir)
	if err == nil {
		t.Fatal("expected error for negative low weight")
	}
}

// ---------------------------------------------------------------------------
// merge edge cases
// ---------------------------------------------------------------------------

func TestLoad_MergeAllFields(t *testing.T) {
	dir := t.TempDir()
	content := `
llm:
  enabled: false
  provider: openrouter
  model: gpt-4
  url: https://api.example.com
  api_key: sk-test
  timeout_seconds: 60
  temperature: 0.8
  ollama:
    max_threads: 4
    max_memory_mb: 8192
    min_free_memory_mb: 2048
scoring:
  severity_weights:
    critical: 10
    high: 7
    medium: 3
    low: 1
rules:
  required_tags:
    - owner
    - env
  rule_packs:
    - enterprise
output:
  format: json
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(content), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LLM.Enabled {
		t.Error("expected disabled")
	}
	if cfg.LLM.Provider != "openrouter" {
		t.Errorf("got provider %s", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "gpt-4" {
		t.Errorf("got model %s", cfg.LLM.Model)
	}
	if cfg.LLM.URL != "https://api.example.com" {
		t.Errorf("got URL %s", cfg.LLM.URL)
	}
	if cfg.LLM.APIKey != "sk-test" {
		t.Errorf("got api_key %s", cfg.LLM.APIKey)
	}
	if cfg.LLM.TimeoutSeconds != 60 {
		t.Errorf("got timeout %d", cfg.LLM.TimeoutSeconds)
	}
	if cfg.LLM.Temperature != 0.8 {
		t.Errorf("got temperature %f", cfg.LLM.Temperature)
	}
	if cfg.LLM.Ollama.MaxThreads != 4 {
		t.Errorf("got max_threads %d", cfg.LLM.Ollama.MaxThreads)
	}
	if cfg.LLM.Ollama.MaxMemoryMB != 8192 {
		t.Errorf("got max_memory_mb %d", cfg.LLM.Ollama.MaxMemoryMB)
	}
	if cfg.LLM.Ollama.MinFreeMemoryMB != 2048 {
		t.Errorf("got min_free_memory_mb %d", cfg.LLM.Ollama.MinFreeMemoryMB)
	}
	if cfg.Scoring.SeverityWeights.Critical != 10 {
		t.Errorf("got critical %f", cfg.Scoring.SeverityWeights.Critical)
	}
	if cfg.Scoring.SeverityWeights.High != 7 {
		t.Errorf("got high %f", cfg.Scoring.SeverityWeights.High)
	}
	if cfg.Output.Format != "json" {
		t.Errorf("got format %s", cfg.Output.Format)
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	cfg, err := Load(dir)
	if err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}
	// Should have all defaults
	if cfg.LLM.Model != "llama3.1:8b" {
		t.Errorf("expected default model, got %s", cfg.LLM.Model)
	}
}

// ---------------------------------------------------------------------------
// SaveGlobalLLMProvider
// ---------------------------------------------------------------------------

func TestSaveGlobalLLMProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := SaveGlobalLLMProvider("openrouter", "claude-3.5-sonnet")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Read back and verify
	data, err := os.ReadFile(GlobalConfigPath())
	if err != nil {
		t.Fatalf("failed to read saved config: %v", err)
	}

	content := string(data)
	if !contains(content, "openrouter") {
		t.Error("expected provider in saved config")
	}
	if !contains(content, "claude-3.5-sonnet") {
		t.Error("expected model in saved config")
	}
}

func TestSaveGlobalLLMProvider_EmptyModel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := SaveGlobalLLMProvider("ollama", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(GlobalConfigPath())
	content := string(data)
	if !contains(content, "ollama") {
		t.Error("expected provider in saved config")
	}
}

func TestSaveGlobalLLMProvider_PreservesOtherSections(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Write initial config with scoring section
	dir := GlobalConfigDir()
	os.MkdirAll(dir, 0755)
	initial := "scoring:\n  severity_weights:\n    critical: 10\n"
	os.WriteFile(GlobalConfigPath(), []byte(initial), 0644)

	// Save provider
	SaveGlobalLLMProvider("openrouter", "gpt-4")

	data, _ := os.ReadFile(GlobalConfigPath())
	content := string(data)
	if !contains(content, "critical") {
		t.Error("expected scoring section preserved")
	}
	if !contains(content, "openrouter") {
		t.Error("expected provider added")
	}
}

// ---------------------------------------------------------------------------
// GlobalConfigDir/Path
// ---------------------------------------------------------------------------

func TestGlobalConfigDir(t *testing.T) {
	dir := GlobalConfigDir()
	if dir == "" {
		t.Error("expected non-empty config dir")
	}
	if !contains(dir, ".terraview") {
		t.Errorf("expected .terraview in path, got %s", dir)
	}
}

func TestGlobalConfigPath(t *testing.T) {
	path := GlobalConfigPath()
	if !contains(path, ".terraview.yaml") {
		t.Errorf("expected .terraview.yaml in path, got %s", path)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && strings.Contains(s, substr)
}
