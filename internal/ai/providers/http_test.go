package providers

// Tests covering Complete(), openAIComplete(), resolveMaxResources, applyDefaults,
// newHTTPClient, readResponseBody for ollama, gemini, deepseek, openai providers.
// All HTTP calls use httptest.NewServer — no real network traffic.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
)

// testResources returns a minimal slice of NormalizedResource for AI request tests.
func testResources() []parser.NormalizedResource {
	return []parser.NormalizedResource{
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Action: "create", Provider: "aws"},
	}
}

// ─── resolveMaxResources ──────────────────────────────────────────────────────

func TestResolveMaxResources_ExplicitConfig(t *testing.T) {
	got := resolveMaxResources(50, "llama3.1:8b", 100)
	if got != 50 {
		t.Errorf("expected 50 (explicit config), got %d", got)
	}
}

func TestResolveMaxResources_ModelBased(t *testing.T) {
	got := resolveMaxResources(0, "llama3.1:8b", 100)
	if got != 35 {
		t.Errorf("expected 35 (model limit for llama3.1:8b), got %d", got)
	}
}

func TestResolveMaxResources_Default(t *testing.T) {
	got := resolveMaxResources(0, "unknown-model", 100)
	if got != defaultMaxResources {
		t.Errorf("expected %d (default), got %d", defaultMaxResources, got)
	}
}

func TestResolveMaxResources_CappedByTotal(t *testing.T) {
	// Limit exceeds total resources → cap at total.
	got := resolveMaxResources(200, "unknown-model", 5)
	if got != 5 {
		t.Errorf("expected 5 (capped by totalResources), got %d", got)
	}
}

func TestResolveMaxResources_ZeroTotal(t *testing.T) {
	// totalResources=0 means "don't cap" — return the limit as-is.
	got := resolveMaxResources(50, "unknown-model", 0)
	if got != 50 {
		t.Errorf("expected 50 (no cap when total=0), got %d", got)
	}
}

// ─── applyDefaults ────────────────────────────────────────────────────────────

func TestApplyDefaults_ZeroValues(t *testing.T) {
	cfg := &ai.ProviderConfig{}
	applyDefaults(cfg, "", "gpt-4o", "https://api.openai.com")
	if cfg.Model != "gpt-4o" {
		t.Errorf("Model = %q, want gpt-4o", cfg.Model)
	}
	if cfg.BaseURL != "https://api.openai.com" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.MaxTokens != defaultMaxTokens {
		t.Errorf("MaxTokens = %d, want %d", cfg.MaxTokens, defaultMaxTokens)
	}
	if cfg.MaxRetries != defaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, defaultMaxRetries)
	}
	if cfg.TimeoutSecs != defaultTimeoutSecs {
		t.Errorf("TimeoutSecs = %d, want %d", cfg.TimeoutSecs, defaultTimeoutSecs)
	}
}

func TestApplyDefaults_PreserveExisting(t *testing.T) {
	cfg := &ai.ProviderConfig{
		Model:       "custom-model",
		BaseURL:     "https://custom.api",
		MaxTokens:   512,
		MaxRetries:  5,
		TimeoutSecs: 30,
	}
	applyDefaults(cfg, "", "gpt-4o", "https://api.openai.com")
	if cfg.Model != "custom-model" {
		t.Errorf("Model should not be overwritten, got %q", cfg.Model)
	}
	if cfg.BaseURL != "https://custom.api" {
		t.Errorf("BaseURL should not be overwritten, got %q", cfg.BaseURL)
	}
	if cfg.MaxTokens != 512 {
		t.Errorf("MaxTokens should not be overwritten, got %d", cfg.MaxTokens)
	}
}

// ─── newHTTPClient ────────────────────────────────────────────────────────────

func TestNewHTTPClient(t *testing.T) {
	client := newHTTPClient(30)
	if client == nil {
		t.Fatal("expected non-nil HTTP client")
	}
	if client.Timeout != 30*time.Second {
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}
}

// ─── readResponseBody ─────────────────────────────────────────────────────────

func TestReadResponseBody_Normal(t *testing.T) {
	data := []byte("hello world")
	got, err := readResponseBody(strings.NewReader(string(data)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestReadResponseBody_Empty(t *testing.T) {
	got, err := readResponseBody(strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %d bytes", len(got))
	}
}

func TestReadResponseBody_LargeLimit(t *testing.T) {
	// Verify LimitReader is in place — reading a lot of data should not OOM.
	// We use io.LimitReader internally so just verify normal read works.
	r := strings.NewReader(strings.Repeat("x", 1000))
	got, err := readResponseBody(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1000 {
		t.Errorf("expected 1000 bytes, got %d", len(got))
	}
}

// ─── openAIComplete ───────────────────────────────────────────────────────────

// chatResponseJSON builds a minimal OpenAI-compatible chat completion JSON response.
// chatResponse.Choices uses anonymous structs, so we build the JSON directly.
func chatResponseJSON(content string) string {
	return `{"choices":[{"message":{"role":"assistant","content":` +
		string(mustMarshal(content)) + `},"finish_reason":"stop"}]}`
}

func mustMarshal(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}

func TestOpenAIComplete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON("test response"))
	}))
	defer srv.Close()

	cfg := ai.ProviderConfig{Model: "gpt-4o", MaxTokens: 100}
	client := newHTTPClient(10)
	got, err := openAIComplete(context.Background(), cfg, client, "Bearer test-key", srv.URL, "system", "user prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "test response" {
		t.Errorf("expected 'test response', got %q", got)
	}
}

func TestOpenAIComplete_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":"invalid key"}`)
	}))
	defer srv.Close()

	cfg := ai.ProviderConfig{Model: "gpt-4o"}
	client := newHTTPClient(10)
	_, err := openAIComplete(context.Background(), cfg, client, "Bearer bad", srv.URL, "system", "user")
	if err == nil {
		t.Error("expected error for 401 response")
	}
}

func TestOpenAIComplete_EmptyChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respond with empty choices array.
		io.WriteString(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	cfg := ai.ProviderConfig{Model: "gpt-4o"}
	client := newHTTPClient(10)
	_, err := openAIComplete(context.Background(), cfg, client, "Bearer test", srv.URL, "system", "user")
	if err == nil {
		t.Error("expected error for empty choices")
	}
}

func TestOpenAIComplete_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json")
	}))
	defer srv.Close()

	cfg := ai.ProviderConfig{Model: "gpt-4o"}
	client := newHTTPClient(10)
	_, err := openAIComplete(context.Background(), cfg, client, "Bearer test", srv.URL, "system", "user")
	if err == nil {
		t.Error("expected error for invalid JSON response")
	}
}

func TestOpenAIComplete_ContextCancelled(t *testing.T) {
	// Use an already-cancelled context — openAIComplete should fail immediately
	// without making a network connection, avoiding any server-blocking issues.
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	cfg := ai.ProviderConfig{Model: "gpt-4o"}
	client := newHTTPClient(5)
	// Use an unreachable address so the context error is detected.
	_, err := openAIComplete(ctx, cfg, client, "Bearer test", "http://localhost:1", "system", "user")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// ─── ollama.Complete ──────────────────────────────────────────────────────────

func TestOllama_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ollamaResponse{Response: "done", Done: true}
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, MaxRetries: 0})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "done" {
		t.Errorf("expected 'done', got %q", got)
	}
}

func TestOllama_Complete_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p, _ := NewOllama(ai.ProviderConfig{BaseURL: srv.URL, MaxRetries: 0})
	_, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(shortCtx(), "system", "user")
	if err == nil {
		t.Error("expected error for 500 response")
	}
}

// ─── gemini.Complete ──────────────────────────────────────────────────────────

// geminiCompleteResponseJSON builds a minimal Gemini API JSON response.
// geminiResponse.Candidates uses anonymous structs, so we build JSON directly.
func geminiCompleteResponseJSON(text string) string {
	return `{"candidates":[{"content":{"parts":[{"text":` +
		string(mustMarshal(text)) + `}]}}]}`
}

func TestGemini_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, geminiCompleteResponseJSON("gemini answer"))
	}))
	defer srv.Close()

	p, _ := NewGemini(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "gemini answer" {
		t.Errorf("expected 'gemini answer', got %q", got)
	}
}

func TestGemini_Complete_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":"forbidden"}`)
	}))
	defer srv.Close()

	p, _ := NewGemini(ai.ProviderConfig{
		BaseURL: srv.URL,
		APIKey:  "bad-key",
	})
	_, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(shortCtx(), "system", "user")
	if err == nil {
		t.Error("expected error for 403 response")
	}
}

func TestGemini_Complete_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call

	p, _ := NewGemini(ai.ProviderConfig{BaseURL: "http://localhost:1", APIKey: "key"})
	_, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(ctx, "system", "user")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// ─── deepseek.Complete ────────────────────────────────────────────────────────

func TestDeepseek_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON("deepseek answer"))
	}))
	defer srv.Close()

	p, _ := NewDeepSeek(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "deepseek answer" {
		t.Errorf("expected 'deepseek answer', got %q", got)
	}
}

func TestDeepseek_Analyze_OK(t *testing.T) {
	findingJSON := `{"findings":[{"severity":"HIGH","category":"security","resource":"aws_s3.b","message":"no enc","remediation":"fix"}],"summary":"one issue"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON(findingJSON))
	}))
	defer srv.Close()

	p, _ := NewDeepSeek(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	req := ai.Request{
		Resources: testResources(),
		Summary:   map[string]interface{}{"total": 1},
		Prompts:   ai.Prompts{System: "test"},
	}
	comp, err := p.Analyze(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(comp.Findings))
	}
}

func TestDeepseek_Validate_NoKey(t *testing.T) {
	p, _ := NewDeepSeek(ai.ProviderConfig{})
	err := p.Validate(context.Background())
	if err == nil {
		t.Error("expected error when API key is empty")
	}
}

// ─── openai.Complete ──────────────────────────────────────────────────────────

func TestOpenAI_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON("openai answer"))
	}))
	defer srv.Close()

	p, _ := NewOpenAI(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "openai answer" {
		t.Errorf("expected 'openai answer', got %q", got)
	}
}

func TestOpenAI_Analyze_WithFakeServer(t *testing.T) {
	// Variant of Analyze test — distinct from coverage_test.go's TestOpenAI_Analyze_OK
	// to exercise the Complete() delegation path specifically.
	findingJSON := `{"findings":[{"severity":"MEDIUM","category":"compliance","resource":"aws_iam.r","message":"no mfa","remediation":"enable"}],"summary":"ok"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON(findingJSON))
	}))
	defer srv.Close()

	p, _ := NewOpenAI(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: testResources(),
		Summary:   map[string]interface{}{"total": 1},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(comp.Findings))
	}
}

// ─── gemini.Analyze ───────────────────────────────────────────────────────────

func TestGemini_Analyze_WithFakeServer(t *testing.T) {
	// Variant — exercises doRequest path separately from coverage_test.go
	findingJSON := `{"findings":[{"severity":"CRITICAL","category":"security","resource":"aws_s3.b","message":"public","remediation":"disable"}],"summary":"critical"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, geminiCompleteResponseJSON(findingJSON))
	}))
	defer srv.Close()

	p, _ := NewGemini(ai.ProviderConfig{
		BaseURL:    srv.URL,
		APIKey:     "test-key",
		MaxRetries: 0,
	})
	comp, err := p.Analyze(context.Background(), ai.Request{
		Resources: testResources(),
		Summary:   map[string]interface{}{"total": 1},
		Prompts:   ai.Prompts{System: "test"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(comp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(comp.Findings))
	}
}

// ─── claude.Complete ──────────────────────────────────────────────────────────

func claudeResponseJSON(text string) string {
	return `{"content":[{"type":"text","text":` + string(mustMarshal(text)) + `}],"stop_reason":"end_turn"}`
}

func TestClaude_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, claudeResponseJSON("claude answer"))
	}))
	defer srv.Close()

	p, _ := NewClaude(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "test-key", MaxRetries: 0})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "claude answer" {
		t.Errorf("expected 'claude answer', got %q", got)
	}
}

func TestClaude_Complete_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"type":"auth","message":"invalid key"}}`)
	}))
	defer srv.Close()

	p, _ := NewClaude(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "bad"})
	_, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(shortCtx(), "system", "user")
	if err == nil {
		t.Error("expected error for 401 response")
	}
}

// ─── custom.Analyze and Complete ─────────────────────────────────────────────

func TestCustom_Analyze_OK(t *testing.T) {
	findingJSON := `{"findings":[{"severity":"HIGH","category":"security","resource":"aws_s3.b","message":"enc","remediation":"fix"}],"summary":"one"}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON(findingJSON))
	}))
	defer srv.Close()

	p, newErr := NewCustom(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "test-key", MaxRetries: 0})
	if newErr != nil {
		t.Fatalf("NewCustom: %v", newErr)
	}
	comp, analyzeErr := p.Analyze(context.Background(), ai.Request{
		Resources: testResources(),
		Summary:   map[string]interface{}{"total": 1},
		Prompts:   ai.Prompts{System: "test"},
	})
	if analyzeErr != nil {
		t.Fatalf("unexpected error: %v", analyzeErr)
	}
	if len(comp.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(comp.Findings))
	}
}

func TestCustom_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON("custom answer"))
	}))
	defer srv.Close()

	p, _ := NewCustom(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "key", MaxRetries: 0})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "custom answer" {
		t.Errorf("expected 'custom answer', got %q", got)
	}
}

// ─── openrouter.Complete ──────────────────────────────────────────────────────

func TestOpenRouter_Complete_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, chatResponseJSON("openrouter answer"))
	}))
	defer srv.Close()

	p, _ := NewOpenRouter(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "test-key", MaxRetries: 0})
	got, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(context.Background(), "system", "user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "openrouter answer" {
		t.Errorf("expected 'openrouter answer', got %q", got)
	}
}

func TestOpenRouter_Complete_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"error":"rate limit"}`)
	}))
	defer srv.Close()

	p, _ := NewOpenRouter(ai.ProviderConfig{BaseURL: srv.URL, APIKey: "key"})
	_, err := p.(interface {
		Complete(context.Context, string, string) (string, error)
	}).Complete(shortCtx(), "system", "user")
	if err == nil {
		t.Error("expected error for 429 response")
	}
}
