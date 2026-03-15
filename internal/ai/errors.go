package ai

import (
	"errors"
	"fmt"
	"strings"
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

	// ErrNonTransient indicates a permanent error that should not be retried.
	ErrNonTransient = errors.New("non-transient error")
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

// IsTransient returns true if the error is transient and can be retried.
// Transient errors: timeout, HTTP 429, 500, 502, 503, 504, network errors.
// Permanent errors (do NOT retry): HTTP 400, 401, 403, validation, invalid response.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	// Context errors (timeout, cancellation) are transient
	if errors.Is(err, ErrProviderTimeout) {
		return true
	}

	// Validation and invalid response errors are NOT transient
	if errors.Is(err, ErrProviderValidation) || errors.Is(err, ErrInvalidResponse) {
		return false
	}

	// Errors explicitly marked as non-transient
	if errors.Is(err, ErrNonTransient) {
		return false
	}

	msg := strings.ToLower(err.Error())

	// HTTP 401, 403, 400 → NOT transient
	for _, code := range []string{"status 400", "status 401", "status 403", "invalid api key", "unauthorized", "forbidden", "bad request"} {
		if strings.Contains(msg, code) {
			return false
		}
	}

	// HTTP 429, 500, 502, 503, 504 → transient
	for _, code := range []string{"status 429", "status 500", "status 502", "status 503", "status 504", "rate limit", "too many requests"} {
		if strings.Contains(msg, code) {
			return true
		}
	}

	// Network/timeout errors → transient
	for _, pattern := range []string{"timeout", "timed out", "connection refused", "connection reset", "no such host", "eof", "broken pipe"} {
		if strings.Contains(msg, pattern) {
			return true
		}
	}

	// Default: consider transient to avoid losing retries on unknown errors
	return true
}
