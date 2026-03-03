package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/util"
)

// shortCtx returns a context with a short timeout to prevent retry-backoff delays
// in error-path tests (provider constructors force MaxRetries >= 1).
func shortCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	_ = cancel // cancel will fire on timeout; acceptable in short-lived test helpers
	return ctx
}

// ---------------------------------------------------------------------------
// NewOllama
// ---------------------------------------------------------------------------

func TestNewOllama_Defaults(t *testing.T) {
	p, err := NewOllama(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o := p.(*ollamaProvider)
	if o.cfg.BaseURL != "http://localhost:11434" {
		t.Errorf("BaseURL = %q, want default", o.cfg.BaseURL)
	}
	if o.cfg.Model != "llama3.1:8b" {
		t.Errorf("Model = %q, want llama3.1:8b", o.cfg.Model)
	}
	if o.cfg.MaxTokens != 2048 {
		t.Errorf("MaxTokens = %d, want 2048", o.cfg.MaxTokens)
	}
	if o.cfg.MaxRetries != 2 {
		t.Errorf("MaxRetries = %d, want 2", o.cfg.MaxRetries)
	}
	if o.cfg.TimeoutSecs != 120 {
		t.Errorf("TimeoutSecs = %d, want 120", o.cfg.TimeoutSecs)
	}
}

func TestNewOllama_CustomConfig(t *testing.T) {
	p, err := NewOllama(ai.ProviderConfig{
		BaseURL:     "http://custom:1234",
		Model:       "llama3:8b",
		MaxTokens:   4096,
		MaxRetries:  5,
		TimeoutSecs: 60,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o := p.(*ollamaProvider)
	if o.cfg.BaseURL != "http://custom:1234" {
		t.Errorf("BaseURL = %q", o.cfg.BaseURL)
	}
	if o.cfg.Model != "llama3:8b" {
		t.Errorf("Model = %q", o.cfg.Model)
	}
}

func TestOllama_Name(t *testing.T) {
	p, _ := NewOllama(ai.ProviderConfig{})
	if got := p.Name(); got != "ollama" {
		t.Errorf("Name() = %q, want ollama", got)
	}
}

func TestOllama_Validate_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/tags" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"models":[]}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOllama_Validate_Unreachable(t *testing.T) {
	p, _ := NewOllama(ai.ProviderConfig{BaseURL: "http://localhost:1"})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for unreachable server")
	}
}

func TestOllama_Validate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

func TestOllama_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ollamaResponse{
			Response: `{"findings":[{"severity":"HIGH","category":"security","resource":"aws_s3.b","message":"no encryption","remediation":"enable"}],"summary":"one issue"}`,
			Done:     true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, MaxRetries: 0})

	req := ai.Request{
		Resources: []parser.NormalizedResource{
			{Address: "aws_s3.b", Type: "aws_s3_bucket", Action: "create", Provider: "aws"},
		},
		Summary: map[string]interface{}{"total": 1},
		Prompts: ai.Prompts{System: "test"},
	}

	comp, err := p.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(comp.Findings))
	}
	if comp.Provider != "ollama" {
		t.Errorf("provider = %q", comp.Provider)
	}
}

func TestOllama_Analyze_RetryOnError(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp := ollamaResponse{
			Response: `{"findings":[],"summary":"ok"}`,
			Done:     true,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, MaxRetries: 2})

	req := ai.Request{
		Resources: []parser.NormalizedResource{
			{Address: "r", Type: "t", Action: "create", Provider: "aws"},
		},
		Summary: map[string]interface{}{},
		Prompts: ai.Prompts{System: "test"},
	}

	comp, err := p.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error after retry: %v", err)
	}
	if comp.Summary != "ok" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

func TestOllama_Analyze_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // slow response
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, MaxRetries: 0, TimeoutSecs: 1})
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	}

	_, err := p.Analyze(ctx, req)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// ---------------------------------------------------------------------------
// NewOpenAI
// ---------------------------------------------------------------------------

func TestNewOpenAI_Defaults(t *testing.T) {
	p, err := NewOpenAI(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o := p.(*openaiProvider)
	if o.cfg.Model != "gpt-4o-mini" {
		t.Errorf("Model = %q, want gpt-4o-mini", o.cfg.Model)
	}
	if o.cfg.BaseURL != "https://api.openai.com" {
		t.Errorf("BaseURL = %q, want default", o.cfg.BaseURL)
	}
	if o.cfg.MaxTokens != 4096 {
		t.Errorf("MaxTokens = %d, want 4096", o.cfg.MaxTokens)
	}
}

func TestOpenAI_Name(t *testing.T) {
	p, _ := NewOpenAI(ai.ProviderConfig{})
	if got := p.Name(); got != "openai" {
		t.Errorf("Name() = %q, want openai", got)
	}
}

func TestOpenAI_Validate_NoKey(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestOpenAI_Validate_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "pong"}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: "test-key", BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestOpenAI_Validate_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: "bad-key", BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for unauthorized")
	}
}

func TestOpenAI_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"findings":[],"summary":"clean"}`}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: "key", BaseURL: srv.URL, MaxRetries: 0})

	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comp.Summary != "clean" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

// ---------------------------------------------------------------------------
// NewGemini
// ---------------------------------------------------------------------------

func TestNewGemini_Defaults(t *testing.T) {
	p, err := NewGemini(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := p.(*geminiProvider)
	if g.cfg.Model != "gemini-2.5-flash" {
		t.Errorf("Model = %q", g.cfg.Model)
	}
}

func TestGemini_Name(t *testing.T) {
	p, _ := NewGemini(ai.ProviderConfig{})
	if got := p.Name(); got != "gemini" {
		t.Errorf("Name() = %q, want gemini", got)
	}
}

func TestGemini_Validate_NoKey(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	p, _ := NewGemini(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestGemini_Validate_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"candidates": []map[string]interface{}{
				{"content": map[string]interface{}{
					"parts": []map[string]string{{"text": "pong"}},
				}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewGemini(ai.ProviderConfig{APIKey: "test-key", BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestGemini_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"candidates": []map[string]interface{}{
				{"content": map[string]interface{}{
					"parts": []map[string]string{{"text": `{"findings":[],"summary":"ok"}`}},
				}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewGemini(ai.ProviderConfig{APIKey: "key", BaseURL: srv.URL, MaxRetries: 0})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comp.Summary != "ok" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

// ---------------------------------------------------------------------------
// NewClaude
// ---------------------------------------------------------------------------

func TestNewClaude_Defaults(t *testing.T) {
	p, err := NewClaude(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	c := p.(*claudeProvider)
	if c.cfg.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q", c.cfg.Model)
	}
}

func TestClaude_Name(t *testing.T) {
	p, _ := NewClaude(ai.ProviderConfig{})
	if got := p.Name(); got != "claude" {
		t.Errorf("Name() = %q, want claude", got)
	}
}

func TestClaude_Validate_NoKey(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	p, _ := NewClaude(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestClaude_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"content": []map[string]interface{}{
				{"type": "text", "text": `{"findings":[],"summary":"clean"}`},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewClaude(ai.ProviderConfig{APIKey: "key", BaseURL: srv.URL, MaxRetries: 0})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if comp.Summary != "clean" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

// ---------------------------------------------------------------------------
// NewDeepSeek
// ---------------------------------------------------------------------------

func TestNewDeepSeek_Defaults(t *testing.T) {
	p, err := NewDeepSeek(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	d := p.(*deepseekProvider)
	if d.cfg.Model != "deepseek-v3.2" {
		t.Errorf("Model = %q", d.cfg.Model)
	}
}

func TestDeepSeek_Name(t *testing.T) {
	p, _ := NewDeepSeek(ai.ProviderConfig{})
	if got := p.Name(); got != "deepseek" {
		t.Errorf("Name() = %q, want deepseek", got)
	}
}

func TestDeepSeek_Validate_NoKey(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "")
	p, _ := NewDeepSeek(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestDeepSeek_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"findings":[],"summary":"ok"}`}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewDeepSeek(ai.ProviderConfig{APIKey: "key", BaseURL: srv.URL, MaxRetries: 0})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if comp.Summary != "ok" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

// ---------------------------------------------------------------------------
// NewOpenRouter
// ---------------------------------------------------------------------------

func TestNewOpenRouter_Defaults(t *testing.T) {
	p, err := NewOpenRouter(ai.ProviderConfig{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	o := p.(*openrouterProvider)
	if o.cfg.Model != "google/gemini-2.5-pro" {
		t.Errorf("Model = %q", o.cfg.Model)
	}
	if o.cfg.BaseURL != "https://openrouter.ai/api/v1" {
		t.Errorf("BaseURL = %q", o.cfg.BaseURL)
	}
}

func TestOpenRouter_Name(t *testing.T) {
	p, _ := NewOpenRouter(ai.ProviderConfig{})
	if got := p.Name(); got != "openrouter" {
		t.Errorf("Name() = %q, want openrouter", got)
	}
}

func TestOpenRouter_Validate_NoKey(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "")
	p, _ := NewOpenRouter(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error for missing API key")
	}
}

func TestOpenRouter_Analyze_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": `{"findings":[],"summary":"ok"}`}},
			},
		})
	}))
	defer srv.Close()

	p, _ := NewOpenRouter(ai.ProviderConfig{APIKey: "key", BaseURL: srv.URL, MaxRetries: 0})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "r", Type: "t", Action: "create", Provider: "aws"}},
		Summary:   map[string]interface{}{},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if comp.Summary != "ok" {
		t.Errorf("summary = %q", comp.Summary)
	}
}

// ---------------------------------------------------------------------------
// truncate (util/strings.go)
// ---------------------------------------------------------------------------

func TestTruncate_Short(t *testing.T) {
	got := util.Truncate("hello", 10)
	if got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestTruncate_Exact(t *testing.T) {
	got := util.Truncate("12345", 5)
	if got != "12345" {
		t.Errorf("got %q, want %q", got, "12345")
	}
}

func TestTruncate_Long(t *testing.T) {
	got := util.Truncate("hello world this is long", 8)
	if got != "hello..." {
		t.Errorf("got %q, want %q", got, "hello...")
	}
}

// ---------------------------------------------------------------------------
// safePrefix (common.go)
// ---------------------------------------------------------------------------

func TestSafePrefix_Short(t *testing.T) {
	if got := safePrefix("ab", 5); got != "ab" {
		t.Errorf("got %q", got)
	}
}

func TestSafePrefix_Long(t *testing.T) {
	if got := safePrefix("abcdefgh", 3); got != "abc" {
		t.Errorf("got %q", got)
	}
}

func TestSafePrefix_Empty(t *testing.T) {
	if got := safePrefix("", 3); got != "" {
		t.Errorf("got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Registration check all providers
// ---------------------------------------------------------------------------

func TestAllProviders_Registered(t *testing.T) {
	providers := []string{"ollama", "openai", "gemini", "claude", "claude-code", "gemini-cli", "deepseek", "openrouter"}
	for _, name := range providers {
		if !ai.Has(name) {
			t.Errorf("provider %q not registered", name)
		}
	}
}

// GeminiCLI_Defaults and GeminiCLI_Name are tested in gemini_cli_test.go

// ---------------------------------------------------------------------------
// buildSystemPrompt - with Cost and Compliance sections
// ---------------------------------------------------------------------------

func TestBuildSystemPrompt_CostAndCompliance(t *testing.T) {
	prompts := ai.Prompts{
		System:     "base",
		Cost:       "cost rules",
		Compliance: "compliance rules",
	}
	got := buildSystemPrompt(prompts)
	if !contains(got, "Cost Optimization Guidelines") {
		t.Error("missing cost section")
	}
	if !contains(got, "Compliance Review Guidelines") {
		t.Error("missing compliance section")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ===========================================================================
// Claude — extra Validate/doRequest/Analyze branches
// ===========================================================================

func TestClaude_Validate_EmptyAPIKey(t *testing.T) {
	p, _ := NewClaude(ai.ProviderConfig{APIKey: ""})
	err := p.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestClaude_Validate_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "bad", BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

func TestClaude_Validate_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content":[{"type":"text","text":"hi"}]}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "good", BaseURL: srv.URL})
	err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClaude_Validate_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL})
	// Non-401 errors are considered "reachable"
	err := p.Validate(context.Background())
	if err != nil {
		t.Fatalf("unexpected error for 500 (should be nil): %v", err)
	}
}

func TestClaude_DoRequest_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":"bad request"}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "claude-sonnet-4-5", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "test.r", Type: "test", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 400 status")
	}
}

func TestClaude_DoRequest_EmptyContent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"content":[]}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty content")
	}
}

func TestClaude_DoRequest_ErrorInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":{"type":"invalid_request_error","message":"bad model"}}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for response error")
	}
}

func TestClaude_DoRequest_ErrorType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"error","content":[]}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for type=error")
	}
}

func TestClaude_DoRequest_NoTextBlock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"content":[{"type":"image","text":""}]}`))
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for no text block")
	}
}

func TestClaude_Analyze_Success(t *testing.T) {
	resp := map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": `{"findings":[{"severity":"HIGH","category":"Security","resource":"aws_instance.x","message":"test","remediation":"fix"}],"summary":"ok"}`},
		},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 4096, TimeoutSecs: 10})
	c, err := p.Analyze(context.Background(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "aws_instance.x", Type: "aws_instance", Action: "create"}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(c.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(c.Findings))
	}
}

// ===========================================================================
// OpenRouter — extra Validate/doRequest error branches
// ===========================================================================

func TestOpenRouter_Validate_Unreachable(t *testing.T) {
	p, _ := NewOpenRouter(ai.ProviderConfig{APIKey: "k", BaseURL: "http://127.0.0.1:1"})
	err := p.Validate(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

func TestOpenRouter_DoRequest_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`rate limited`))
	}))
	defer srv.Close()
	p, _ := NewOpenRouter(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 429 status")
	}
}

func TestOpenRouter_DoRequest_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()
	p, _ := NewOpenRouter(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
}

// ===========================================================================
// DeepSeek — extra doRequest error branches
// ===========================================================================

func TestDeepSeek_DoRequest_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`forbidden`))
	}))
	defer srv.Close()
	p, _ := NewDeepSeek(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 403 status")
	}
}

func TestDeepSeek_DoRequest_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()
	p, _ := NewDeepSeek(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
}

// ===========================================================================
// Gemini — extra doRequest error branches
// ===========================================================================

func TestGemini_DoRequest_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`service unavailable`))
	}))
	defer srv.Close()
	p, _ := NewGemini(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 503 status")
	}
}

func TestGemini_DoRequest_EmptyCandidates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"candidates":[]}`))
	}))
	defer srv.Close()
	p, _ := NewGemini(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty candidates")
	}
}

// ===========================================================================
// OpenAI — extra doRequest error branches
// ===========================================================================

func TestOpenAI_DoRequest_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		w.Write([]byte(`quota exceeded`))
	}))
	defer srv.Close()
	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 402 status")
	}
}

func TestOpenAI_DoRequest_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()
	p, _ := NewOpenAI(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty choices")
	}
}

// ===========================================================================
// Ollama — extra doRequest error branches
// ===========================================================================

func TestOllama_DoRequest_BadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`model not found`))
	}))
	defer srv.Close()
	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for 404 status")
	}
}

func TestOllama_DoRequest_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"message":{"content":""}}`))
	}))
	defer srv.Close()
	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 0, TimeoutSecs: 5})
	_, err := p.Analyze(shortCtx(), ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error for empty response content")
	}
}

// ===========================================================================
// Analyze — retry exhaustion (context cancel during backoff)
// ===========================================================================

func TestClaude_Analyze_ContextCancelledDuringRetry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`error`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	p, _ := NewClaude(ai.ProviderConfig{APIKey: "k", BaseURL: srv.URL, Model: "m", MaxTokens: 1024, MaxRetries: 3, TimeoutSecs: 5})
	_, err := p.Analyze(ctx, ai.Request{
		Resources: []parser.NormalizedResource{{Address: "t.r", Type: "t", Action: "create"}},
	})
	if err == nil {
		t.Fatal("expected error after retries")
	}
}

// ===========================================================================
// backoffWithJitter — edge cases
// ===========================================================================

func TestBackoffWithJitter_HighAttempt(t *testing.T) {
	d := backoffWithJitter(100) // Should cap at 30s
	if d > 40*time.Second {
		t.Errorf("backoff too high: %v", d)
	}
}

func TestBackoffWithJitter_SmallAttempt(t *testing.T) {
	d := backoffWithJitter(1) // 1² = 1s ±jitter
	if d < 100*time.Millisecond || d > 2*time.Second {
		t.Errorf("backoff out of range: %v", d)
	}
}

// ===========================================================================
// parseResponse — edge cases (malformed JSON, missing fields)
// ===========================================================================

func TestParseResponse_EmptyString(t *testing.T) {
	_, _, err := parseResponse("", "test")
	if err == nil {
		t.Fatal("expected error for empty string")
	}
}

func TestParseResponse_NoFindings(t *testing.T) {
	findings, summary, err := parseResponse(`{"findings":[],"summary":"all good"}`, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if summary != "all good" {
		t.Errorf("summary = %q", summary)
	}
}

func TestParseResponse_SummaryAsObject(t *testing.T) {
	input := `{"findings":[],"summary":{"text":"obj summary","risk":"low"}}`
	_, summary, err := parseResponse(input, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary == "" {
		t.Error("expected non-empty summary from object")
	}
}

func TestParseResponse_MarkdownFenced(t *testing.T) {
	input := "```json\n{\"findings\":[],\"summary\":\"fenced\"}\n```"
	_, summary, err := parseResponse(input, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary != "fenced" {
		t.Errorf("summary = %q, want fenced", summary)
	}
}

// ===========================================================================
// buildUserPrompt — edge cases
// ===========================================================================

func TestBuildUserPrompt_Nil(t *testing.T) {
	got, err := buildUserPrompt(nil, nil, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty prompt for nil resources")
	}
}

func TestBuildUserPrompt_WithSummaryMap(t *testing.T) {
	res := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create"},
	}
	summary := map[string]interface{}{"description": "This creates a web server"}
	got, err := buildUserPrompt(res, summary, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Error("expected non-empty prompt")
	}
}
