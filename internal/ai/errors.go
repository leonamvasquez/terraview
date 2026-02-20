package ai

import (
	"errors"
	"fmt"
)

var (
	// ErrProviderNotFound is returned when a requested provider is not registered.
	ErrProviderNotFound = errors.New("ai provider not found")

	// ErrProviderValidation is returned when a provider fails validation (e.g. missing API key).
	ErrProviderValidation = errors.New("ai provider validation failed")

	// ErrProviderTimeout is returned when a provider request exceeds the context deadline.
	ErrProviderTimeout = errors.New("ai provider request timed out")

	// ErrInvalidResponse is returned when the provider returns unparseable output.
	ErrInvalidResponse = errors.New("ai provider returned invalid response")
)

// ProviderError wraps an error with provider context, sanitizing sensitive details.
type ProviderError struct {
	Provider string
	Op       string
	Err      error
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("ai/%s: %s: %v", e.Provider, e.Op, e.Err)
}

func (e *ProviderError) Unwrap() error {
	return e.Err
}

// NewProviderError creates a new ProviderError.
func NewProviderError(provider, op string, err error) *ProviderError {
	return &ProviderError{Provider: provider, Op: op, Err: err}
}
