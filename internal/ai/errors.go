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

	// ErrNonTransient indica um erro permanente que não deve ser retentado.
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

// IsTransient retorna true se o erro é transiente e pode ser retentado.
// Erros transientes: timeout, HTTP 429, 500, 502, 503, 504, erros de rede.
// Erros permanentes (NÃO retentar): HTTP 400, 401, 403, validação, resposta inválida.
func IsTransient(err error) bool {
	if err == nil {
		return false
	}

	// Erros de contexto (timeout, cancelamento) são transientes
	if errors.Is(err, ErrProviderTimeout) {
		return true
	}

	// Erros de validação e resposta inválida NÃO são transientes
	if errors.Is(err, ErrProviderValidation) || errors.Is(err, ErrInvalidResponse) {
		return false
	}

	// Erros marcados explicitamente como não transientes
	if errors.Is(err, ErrNonTransient) {
		return false
	}

	msg := strings.ToLower(err.Error())

	// HTTP 401, 403, 400 → NÃO transiente
	for _, code := range []string{"status 400", "status 401", "status 403", "invalid api key", "unauthorized", "forbidden", "bad request"} {
		if strings.Contains(msg, code) {
			return false
		}
	}

	// HTTP 429, 500, 502, 503, 504 → transiente
	for _, code := range []string{"status 429", "status 500", "status 502", "status 503", "status 504", "rate limit", "too many requests"} {
		if strings.Contains(msg, code) {
			return true
		}
	}

	// Erros de rede/timeout → transiente
	for _, pattern := range []string{"timeout", "timed out", "connection refused", "connection reset", "no such host", "eof", "broken pipe"} {
		if strings.Contains(msg, pattern) {
			return true
		}
	}

	// Default: considerar transiente para não perder retentativas em erros desconhecidos
	return true
}
