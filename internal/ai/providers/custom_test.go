package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
)

func TestNewCustom_Defaults(t *testing.T) {
	p, err := NewCustom(ai.ProviderConfig{
		APIKey:  "test-key",
		BaseURL: "https://api.example.com",
		Model:   "my-model",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "custom" {
		t.Errorf("expected name 'custom', got %s", p.Name())
	}
}

func TestNewCustom_DefaultModel(t *testing.T) {
	p, err := NewCustom(ai.ProviderConfig{
		APIKey:  "test-key",
		BaseURL: "https://api.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cp := p.(*customProvider)
	if cp.cfg.Model != "gpt-4o-mini" {
		t.Errorf("expected default model 'gpt-4o-mini', got %s", cp.cfg.Model)
	}
}

func TestCustom_ValidateNoKey(t *testing.T) {
	p := &customProvider{
		cfg: ai.ProviderConfig{
			BaseURL: "https://api.example.com",
			Model:   "test",
		},
	}
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestCustom_ValidateNoURL(t *testing.T) {
	p := &customProvider{
		cfg: ai.ProviderConfig{
			APIKey: "test-key",
			Model:  "test",
		},
	}
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing URL")
	}
}

func TestCustom_ValidateSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		resp := chatResponse{
			Choices: []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			}{
				{Message: struct {
					Content string `json:"content"`
				}{Content: "pong"}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p := &customProvider{
		cfg: ai.ProviderConfig{
			APIKey:  "test-key",
			BaseURL: srv.URL,
			Model:   "test-model",
		},
		client: http.DefaultClient,
	}

	err := p.Validate(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCustom_ValidateUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p := &customProvider{
		cfg: ai.ProviderConfig{
			APIKey:  "bad-key",
			BaseURL: srv.URL,
			Model:   "test",
		},
		client: http.DefaultClient,
	}

	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for unauthorized response")
	}
}

func TestCustom_RegisteredInRegistry(t *testing.T) {
	if !ai.Has("custom") {
		t.Error("custom provider should be registered in the AI registry")
	}

	providers := ai.List()
	found := false
	for _, info := range providers {
		if info.Name == "custom" {
			found = true
			if info.DisplayName != "Custom (OpenAI-compatible)" {
				t.Errorf("unexpected display name: %s", info.DisplayName)
			}
		}
	}
	if !found {
		t.Error("custom provider not found in List()")
	}
}
