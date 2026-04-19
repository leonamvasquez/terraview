package ai

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PromptLoader reads prompt templates from a directory.
type PromptLoader struct {
	promptDir string
}

// NewPromptLoader creates a new PromptLoader for the given directory.
func NewPromptLoader(promptDir string) *PromptLoader {
	return &PromptLoader{promptDir: promptDir}
}

// Load reads all prompt templates and returns a Prompts struct.
func (pl *PromptLoader) Load() (Prompts, error) {
	ps := Prompts{}

	system, err := pl.readPrompt("system.md")
	if err != nil {
		return ps, fmt.Errorf("failed to load system prompt: %w", err)
	}
	ps.System = system

	// These are optional — if they don't exist, we just skip them.
	ps.Security, _ = pl.readPrompt("security.md")
	ps.Architecture, _ = pl.readPrompt("architecture.md")
	ps.Standards, _ = pl.readPrompt("standards.md")
	ps.Cost, _ = pl.readPrompt("cost.md")
	ps.Compliance, _ = pl.readPrompt("compliance.md")
	ps.ContextAnalysis, _ = pl.readPrompt("context-analysis.md")

	return ps, nil
}

// LoadForModel selects the prompt tier based on provider and model name.
// Small models (ollama, ≤14B parameter counts) use simplified prompts from
// the small/ subdirectory. Falls back to the standard tier if small/ is missing.
func (pl *PromptLoader) LoadForModel(provider, model string) (Prompts, error) {
	if IsSmallModel(provider, model) {
		small := &PromptLoader{promptDir: filepath.Join(pl.promptDir, "small")}
		if ps, err := small.Load(); err == nil {
			return ps, nil
		}
	}
	return pl.Load()
}

// IsSmallModel returns true for providers and models that benefit from
// shorter, simpler prompts to stay within context and latency budgets.
// Exported so providers can use it when building per-request configs.
func IsSmallModel(provider, model string) bool {
	if provider == "ollama" {
		return true
	}
	// Split on delimiters to avoid substring false positives ("gemini" ≠ "mini").
	lower := strings.ToLower(model)
	tokens := strings.FieldsFunc(lower, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || r == '/' || r == ':' || r == ' '
	})
	for _, tok := range tokens {
		switch tok {
		case "7b", "8b", "9b", "13b", "14b", "mini", "small", "nano", "lite":
			return true
		}
	}
	return false
}

func (pl *PromptLoader) readPrompt(filename string) (string, error) {
	path := filepath.Join(pl.promptDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
