package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
)

const ollamaName = "ollama"

func init() {
	ai.Register(ollamaName, NewOllama, ai.ProviderInfo{
		DisplayName:     "Ollama (Local)",
		RequiresKey:     false,
		DefaultModel:    "llama3.1:8b",
		SuggestedModels: []string{
			"llama3.1:8b",
			"llama3.1:70b",
			"llama3.2:3b",
			"mistral:7b",
			"qwen2.5:7b",
			"gemma3:9b",
		},
	})
}

type ollamaProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

type ollamaRequest struct {
	Model   string        `json:"model"`
	Prompt  string        `json:"prompt"`
	System  string        `json:"system,omitempty"`
	Stream  bool          `json:"stream"`
	Options ollamaOptions `json:"options,omitempty"`
	Format  string        `json:"format,omitempty"`
}

type ollamaOptions struct {
	Temperature float64 `json:"temperature,omitempty"`
	NumCtx      int     `json:"num_ctx,omitempty"`
	NumPredict  int     `json:"num_predict,omitempty"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// NewOllama creates a new Ollama provider.
func NewOllama(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "http://localhost:11434"
	}
	if cfg.Model == "" {
		cfg.Model = "llama3.1:8b"
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 2048
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 2
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 120
	}

	return &ollamaProvider{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
	}, nil
}

func (o *ollamaProvider) Name() string { return ollamaName }

func (o *ollamaProvider) Validate(ctx context.Context) error {
	healthClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", o.cfg.BaseURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := healthClient.Do(req)
	if err != nil {
		return fmt.Errorf("ollama is not reachable at %s: %w", o.cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

func (o *ollamaProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(ollamaName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	var lastErr error
	for attempt := 0; attempt <= o.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(ollamaName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := o.doRequest(ctx, systemPrompt, userPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    o.cfg.Model,
			Provider: ollamaName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(ollamaName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", o.cfg.MaxRetries+1, lastErr))
}

func (o *ollamaProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	reqBody := ollamaRequest{
		Model:  o.cfg.Model,
		Prompt: userPrompt,
		System: systemPrompt,
		Stream: false,
		Format: "json",
		Options: ollamaOptions{
			Temperature: o.cfg.Temperature,
			NumCtx:      4096,
			NumPredict:  o.cfg.MaxTokens,
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.cfg.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("%w: %v", ai.ErrProviderTimeout, ctx.Err())
		}
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response envelope: %w", err)
	}

	return parseResponse(ollamaResp.Response, ollamaName)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
