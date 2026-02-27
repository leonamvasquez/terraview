package providers

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
)

// ---------------------------------------------------------------------------
// NewClaudeCode
// ---------------------------------------------------------------------------

func TestNewClaudeCode_Defaults(t *testing.T) {
	p, err := NewClaudeCode(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.(*claudeCodeProvider)
	if c.cfg.Model != "claude-sonnet-4-5" {
		t.Errorf("default model: got %q, want %q", c.cfg.Model, "claude-sonnet-4-5")
	}
	if c.cfg.TimeoutSecs != 300 {
		t.Errorf("default timeout: got %d, want 300", c.cfg.TimeoutSecs)
	}
	if c.cfg.MaxRetries != 1 {
		t.Errorf("default retries: got %d, want 1", c.cfg.MaxRetries)
	}
}

func TestNewClaudeCode_CustomConfig(t *testing.T) {
	p, err := NewClaudeCode(ai.ProviderConfig{
		Model:       "claude-opus-4-5",
		TimeoutSecs: 90,
		MaxRetries:  2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.(*claudeCodeProvider)
	if c.cfg.Model != "claude-opus-4-5" {
		t.Errorf("model: got %q, want %q", c.cfg.Model, "claude-opus-4-5")
	}
	if c.cfg.TimeoutSecs != 90 {
		t.Errorf("timeout: got %d, want 90", c.cfg.TimeoutSecs)
	}
	if c.cfg.MaxRetries != 2 {
		t.Errorf("retries: got %d, want 2", c.cfg.MaxRetries)
	}
}

func TestClaudeCode_Name(t *testing.T) {
	p, _ := NewClaudeCode(ai.ProviderConfig{})
	if got := p.Name(); got != "claude-code" {
		t.Errorf("Name(): got %q, want %q", got, "claude-code")
	}
}

// ---------------------------------------------------------------------------
// extractClaudeCodeJSON
// ---------------------------------------------------------------------------

func TestExtractClaudeCodeJSON_ResultField(t *testing.T) {
	input := `{"result":"the AI response text"}`
	got := extractClaudeCodeJSON(input)
	if got != "the AI response text" {
		t.Errorf("got %q, want %q", got, "the AI response text")
	}
}

func TestExtractClaudeCodeJSON_ContentArray(t *testing.T) {
	input := `{"content":[{"type":"text","text":"hello from claude"}]}`
	got := extractClaudeCodeJSON(input)
	if got != "hello from claude" {
		t.Errorf("got %q, want %q", got, "hello from claude")
	}
}

func TestExtractClaudeCodeJSON_PlainText(t *testing.T) {
	input := "plain text not JSON"
	got := extractClaudeCodeJSON(input)
	if got != input {
		t.Errorf("got %q, want original input", got)
	}
}

func TestExtractClaudeCodeJSON_EmptyResult(t *testing.T) {
	// result is empty, content is empty → fallback to raw
	input := `{"result":"","content":[]}`
	got := extractClaudeCodeJSON(input)
	if got != input {
		t.Errorf("got %q, want original input for empty fields", got)
	}
}

func TestExtractClaudeCodeJSON_SkipsNonText(t *testing.T) {
	input := `{"content":[{"type":"tool_use","text":"ignored"},{"type":"text","text":"correct"}]}`
	got := extractClaudeCodeJSON(input)
	if got != "correct" {
		t.Errorf("got %q, want %q", got, "correct")
	}
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

func TestClaudeCode_Registered(t *testing.T) {
	if !ai.Has("claude-code") {
		t.Error("claude-code provider not registered")
	}
}
