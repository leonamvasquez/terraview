package ai

import (
	"github.com/leonam/terraview/internal/parser"
	"github.com/leonam/terraview/internal/rules"
)

// Request holds everything an AI provider needs to perform a review.
type Request struct {
	Resources []parser.NormalizedResource
	Summary   map[string]interface{}
	Prompts   Prompts
}

// Prompts holds the assembled prompt templates sent to the provider.
type Prompts struct {
	System       string
	Security     string
	Architecture string
	Standards    string
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
	Name        string
	DisplayName string
	RequiresKey bool
	EnvVarKey   string
}
