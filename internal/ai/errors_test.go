package ai

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestIsTransient_NilError(t *testing.T) {
	if IsTransient(nil) {
		t.Error("nil error should not be transient")
	}
}

func TestIsTransient_SentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"ErrProviderTimeout", ErrProviderTimeout, true},
		{"ErrProviderValidation", ErrProviderValidation, false},
		{"ErrInvalidResponse", ErrInvalidResponse, false},
		{"ErrNonTransient", ErrNonTransient, false},
		{"ErrProviderNotFound", ErrProviderNotFound, true}, // unknown → default transient
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTransient(tt.err)
			if got != tt.expected {
				t.Errorf("IsTransient(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestIsTransient_WrappedSentinels(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"wrapped timeout", fmt.Errorf("call failed: %w", ErrProviderTimeout), true},
		{"wrapped validation", fmt.Errorf("bad config: %w", ErrProviderValidation), false},
		{"wrapped invalid response", fmt.Errorf("parse: %w", ErrInvalidResponse), false},
		{"wrapped non-transient", fmt.Errorf("perm: %w", ErrNonTransient), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTransient(tt.err)
			if got != tt.expected {
				t.Errorf("IsTransient(wrapped %v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

func TestIsTransient_HTTPStatusCodes(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		expected bool
	}{
		// Non-transient HTTP codes
		{"status 400", "gemini returned status 400: bad request", false},
		{"status 401", "openai returned status 401: unauthorized", false},
		{"status 403", "api returned status 403: forbidden", false},

		// Transient HTTP codes
		{"status 429", "rate limited: status 429", true},
		{"status 500", "internal server error: status 500", true},
		{"status 502", "bad gateway: status 502", true},
		{"status 503", "service unavailable: status 503", true},
		{"status 504", "gateway timeout: status 504", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.msg)
			got := IsTransient(err)
			if got != tt.expected {
				t.Errorf("IsTransient(%q) = %v, want %v", tt.msg, got, tt.expected)
			}
		})
	}
}

func TestIsTransient_StringPatterns(t *testing.T) {
	tests := []struct {
		name     string
		msg      string
		expected bool
	}{
		// Non-transient patterns
		{"invalid api key", "invalid api key provided", false},
		{"unauthorized", "request unauthorized", false},
		{"forbidden", "access forbidden for resource", false},
		{"bad request", "bad request: missing field", false},

		// Transient patterns
		{"rate limit", "rate limit exceeded, try later", true},
		{"too many requests", "too many requests", true},
		{"timeout", "request timeout after 30s", true},
		{"timed out", "connection timed out", true},
		{"connection refused", "dial tcp: connection refused", true},
		{"connection reset", "read: connection reset by peer", true},
		{"no such host", "lookup api.example.com: no such host", true},
		{"eof", "unexpected eof", true},
		{"broken pipe", "write: broken pipe", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := errors.New(tt.msg)
			got := IsTransient(err)
			if got != tt.expected {
				t.Errorf("IsTransient(%q) = %v, want %v", tt.msg, got, tt.expected)
			}
		})
	}
}

func TestIsTransient_ContextErrors(t *testing.T) {
	// context.DeadlineExceeded message contains "timeout"-like text via default
	// but is not one of our sentinel errors — should still be transient
	err := context.DeadlineExceeded
	if !IsTransient(err) {
		t.Errorf("context.DeadlineExceeded should be transient")
	}

	// context.Canceled — unknown, default transient
	err = context.Canceled
	if !IsTransient(err) {
		t.Errorf("context.Canceled should be transient (default)")
	}
}

func TestIsTransient_ProviderError(t *testing.T) {
	// ProviderError wrapping a non-transient sentinel
	pe := NewProviderError("openai", "analyze", ErrProviderValidation)
	if IsTransient(pe) {
		t.Error("ProviderError wrapping ErrProviderValidation should not be transient")
	}

	// ProviderError wrapping a transient sentinel
	pe = NewProviderError("openai", "analyze", ErrProviderTimeout)
	if !IsTransient(pe) {
		t.Error("ProviderError wrapping ErrProviderTimeout should be transient")
	}

	// ProviderError wrapping an HTTP error message
	pe = NewProviderError("gemini", "analyze", fmt.Errorf("gemini returned status 401"))
	if IsTransient(pe) {
		t.Error("ProviderError with status 401 should not be transient")
	}
}

func TestIsTransient_UnknownErrorDefaultsTransient(t *testing.T) {
	err := errors.New("something completely unexpected happened")
	if !IsTransient(err) {
		t.Error("unknown errors should default to transient (conservative)")
	}
}
