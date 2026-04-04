package ai

import "context"

// Provider is the interface that all AI backends must implement.
type Provider interface {
	// Name returns the unique identifier for this provider (e.g. "ollama", "gemini").
	Name() string

	// Validate checks that the provider is properly configured and reachable.
	Validate(ctx context.Context) error

	// Analyze sends the terraform plan context to the AI and returns structured findings.
	Analyze(ctx context.Context, req Request) (Completion, error)

	// Complete performs a single-turn text completion with the given system and user prompts.
	// Unlike Analyze, it returns raw text without parsing findings — used for fix suggestions
	// and other single-purpose AI interactions.
	Complete(ctx context.Context, system, user string) (string, error)
}

// ProviderFactory is a constructor function that creates a Provider from config.
type ProviderFactory func(cfg ProviderConfig) (Provider, error)

// ProviderConfig holds generic configuration passed to provider factories.
type ProviderConfig struct {
	Model        string
	APIKey       string
	BaseURL      string
	Temperature  float64
	TimeoutSecs  int
	MaxTokens    int
	MaxRetries   int
	MaxResources int // max resources in AI prompt (0 = default 30)
	NumCtx       int // context window size, used by Ollama (0 = default 4096)
}
