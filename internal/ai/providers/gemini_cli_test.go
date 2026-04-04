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

// ---------------------------------------------------------------------------
// buildGeminiFallbackList
// ---------------------------------------------------------------------------

func TestBuildGeminiFallbackList_PrimaryFirst(t *testing.T) {
	list := buildGeminiFallbackList("gemini-2.5-pro", []string{"gemini-2.5-flash", "gemini-2.0-flash"})
	if list[0] != "gemini-2.5-pro" {
		t.Errorf("first element should be primary, got %q", list[0])
	}
	if len(list) != 3 {
		t.Errorf("expected 3 entries, got %d: %v", len(list), list)
	}
}

func TestBuildGeminiFallbackList_NoDuplicates(t *testing.T) {
	// Primary already in candidates — should not appear twice
	list := buildGeminiFallbackList("gemini-2.5-pro", []string{"gemini-2.5-pro", "gemini-2.5-flash"})
	if len(list) != 2 {
		t.Errorf("duplicate primary should be deduplicated: got %d entries: %v", len(list), list)
	}
}

func TestBuildGeminiFallbackList_EmptyCandidates(t *testing.T) {
	list := buildGeminiFallbackList("gemini-2.5-pro", nil)
	if len(list) != 1 || list[0] != "gemini-2.5-pro" {
		t.Errorf("expected only primary, got %v", list)
	}
}

func TestNewGeminiCLI_FallbackListInitialized(t *testing.T) {
	p, err := NewGeminiCLI(ai.ProviderConfig{Model: "gemini-2.5-pro"})
	if err != nil {
		t.Fatal(err)
	}
	g := p.(*geminiCLIProvider)
	if len(g.fallbackModels) == 0 {
		t.Error("fallbackModels should not be empty after construction")
	}
	if g.fallbackModels[0] != "gemini-2.5-pro" {
		t.Errorf("first fallback model should be primary, got %q", g.fallbackModels[0])
	}
}

func TestNewGeminiCLI_UnknownPrimaryStillFirst(t *testing.T) {
	// A custom/future model not in the default list should still be first
	p, _ := NewGeminiCLI(ai.ProviderConfig{Model: "gemini-99-ultra"})
	g := p.(*geminiCLIProvider)
	if g.fallbackModels[0] != "gemini-99-ultra" {
		t.Errorf("custom primary model should be first, got %q", g.fallbackModels[0])
	}
	// Default candidates should follow
	if len(g.fallbackModels) < 2 {
		t.Errorf("expected fallback candidates after custom primary, got %d", len(g.fallbackModels))
	}
}
