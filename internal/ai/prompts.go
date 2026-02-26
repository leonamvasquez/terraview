package ai

import (
	"fmt"
	"os"
	"path/filepath"
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

func (pl *PromptLoader) readPrompt(filename string) (string, error) {
	path := filepath.Join(pl.promptDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
