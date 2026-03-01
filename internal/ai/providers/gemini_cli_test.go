package providers

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
)

// ---------------------------------------------------------------------------
// NewGeminiCLI
// ---------------------------------------------------------------------------

func TestNewGeminiCLI_Defaults(t *testing.T) {
	p, err := NewGeminiCLI(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := p.(*geminiCLIProvider)
	if g.cfg.Model != "gemini-2.5-pro" {
		t.Errorf("default model: got %q, want %q", g.cfg.Model, "gemini-2.5-pro")
	}
	if g.cfg.TimeoutSecs != 300 {
		t.Errorf("default timeout: got %d, want 300", g.cfg.TimeoutSecs)
	}
	if g.cfg.MaxRetries != 1 {
		t.Errorf("default retries: got %d, want 1", g.cfg.MaxRetries)
	}
}

func TestNewGeminiCLI_CustomConfig(t *testing.T) {
	p, err := NewGeminiCLI(ai.ProviderConfig{
		Model:       "gemini-2.0-flash",
		TimeoutSecs: 60,
		MaxRetries:  3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := p.(*geminiCLIProvider)
	if g.cfg.Model != "gemini-2.0-flash" {
		t.Errorf("model: got %q, want %q", g.cfg.Model, "gemini-2.0-flash")
	}
	if g.cfg.TimeoutSecs != 60 {
		t.Errorf("timeout: got %d, want 60", g.cfg.TimeoutSecs)
	}
	if g.cfg.MaxRetries != 3 {
		t.Errorf("retries: got %d, want 3", g.cfg.MaxRetries)
	}
}

func TestGeminiCLI_Name(t *testing.T) {
	p, _ := NewGeminiCLI(ai.ProviderConfig{})
	if got := p.Name(); got != "gemini-cli" {
		t.Errorf("Name(): got %q, want %q", got, "gemini-cli")
	}
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func TestGeminiCLI_Registered(t *testing.T) {
	if !ai.Has("gemini-cli") {
		t.Error("gemini-cli provider not registered")
	}
}
