package ai

import (
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Request holds everything an AI provider needs to perform a review.
type Request struct {
	Resources []parser.NormalizedResource
	Summary   map[string]interface{}
	Prompts   Prompts
}

// Prompts holds the assembled prompt templates sent to the provider.
type Prompts struct {
	System          string
	Security        string
	Architecture    string
	Standards       string
	Cost            string // FinOps and cost optimization prompt
	Compliance      string // regulatory framework compliance prompt
	ContextAnalysis string // cross-resource contextual analysis prompt
}

// Completion is the structured result returned by a provider.
type Completion struct {
	Findings []rules.Finding
	Summary  string
	Model    string
	Provider string
}

// ProviderInfo describes a registered provider for discovery.
type ProviderInfo struct {
	Name            string
	DisplayName     string
	RequiresKey     bool
	EnvVarKey       string
	DefaultModel    string   // default model pre-selected in the picker
	SuggestedModels []string // popular models shown in the interactive picker
	CLIBinary       string   // binary name for CLI-based providers (empty for API providers)
	InstallHint     string   // install command shown when CLIBinary is missing
}
