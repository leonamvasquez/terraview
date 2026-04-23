package util

import "time"

const (
	// DefaultOllamaURL is the default base URL for the Ollama API.
	DefaultOllamaURL = "http://localhost:11434"

	// ValidationTimeout is the timeout for provider connectivity checks.
	ValidationTimeout = 20 * time.Second

	// DefaultExplainTemperature is the default temperature for explain commands.
	DefaultExplainTemperature = 0.3

	// DefaultExplainMaxTokens is the default max tokens for the explain command.
	DefaultExplainMaxTokens = 8192

	// DefaultAnalyzeMaxTokens is the default max tokens for the scan/test commands.
	DefaultAnalyzeMaxTokens = 4096

	// DefaultAppleSiliconPageSize is the fallback vm_stat page size on Apple Silicon.
	DefaultAppleSiliconPageSize = 16384

	// ContextTimeoutGraceSecs adds extra seconds to provider timeouts so the
	// context outlives the provider's own internal timeout.
	ContextTimeoutGraceSecs = 30

	// HealthCheckTimeout is the timeout for quick health/validation HTTP calls.
	HealthCheckTimeout = 15 * time.Second

	// DefaultTimeoutSeconds is the default provider timeout in seconds.
	DefaultTimeoutSeconds = 120
)
