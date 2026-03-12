package util

import (
	"os"
	"time"
)

const (
	// DirPerm is the default permission for directories.
	DirPerm os.FileMode = 0755

	// FilePerm is the default permission for regular files.
	FilePerm os.FileMode = 0644

	// FilePermSecret is the permission for files containing sensitive data.
	FilePermSecret os.FileMode = 0600

	// DefaultOllamaURL is the default base URL for the Ollama API.
	DefaultOllamaURL = "http://localhost:11434"

	// ValidationTimeout is the timeout for provider connectivity checks.
	ValidationTimeout = 20 * time.Second

	// DefaultRequestTimeout is the default HTTP timeout for long downloads.
	DefaultRequestTimeout = 120 * time.Second

	// DefaultExplainTemperature is the default temperature for explain commands.
	DefaultExplainTemperature = 0.3

	// DefaultExplainMaxTokens is the default max tokens for the explain command.
	DefaultExplainMaxTokens = 8192

	// DefaultAnalyzeMaxTokens is the default max tokens for the scan/test commands.
	DefaultAnalyzeMaxTokens = 4096

	// DefaultAppleSiliconPageSize is the fallback vm_stat page size on Apple Silicon.
	DefaultAppleSiliconPageSize = 16384

	// MaxHTTPRedirects is the maximum number of HTTP redirects allowed.
	MaxHTTPRedirects = 10

	// ContextTimeoutGraceSecs adds extra seconds to provider timeouts so the
	// context outlives the provider's own internal timeout.
	ContextTimeoutGraceSecs = 30

	// HealthCheckTimeout is the timeout for quick health/validation HTTP calls.
	HealthCheckTimeout = 15 * time.Second

	// DefaultTimeoutSeconds is the default provider timeout in seconds.
	DefaultTimeoutSeconds = 120
)
