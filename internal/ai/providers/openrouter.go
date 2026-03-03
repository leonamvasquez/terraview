package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/util"
)

const openrouterName = "openrouter"

func init() {
	ai.Register(openrouterName, NewOpenRouter, ai.ProviderInfo{
		DisplayName:  "OpenRouter",
		RequiresKey:  true,
		EnvVarKey:    "OPENROUTER_API_KEY",
		DefaultModel: "google/gemini-2.5-pro",
		SuggestedModels: []string{
			// Cost-effective
			"google/gemini-2.5-pro",
			"deepseek/deepseek-v3.2",
			// Mid-tier
			"anthropic/claude-sonnet-4-6",
			// Premium
			"anthropic/claude-opus-4.6",
			"openai/gpt-5.2",
		},
	})
}

type openrouterProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

// NewOpenRouter creates a new OpenRouter provider.
// OpenRouter exposes an OpenAI-compatible API that proxies many models,
// including Google Gemini, Anthropic Claude, Meta Llama, etc.
func NewOpenRouter(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("OPENROUTER_API_KEY")
	}
	if cfg.Model == "" {
		cfg.Model = "google/gemini-2.5-pro"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://openrouter.ai/api/v1"
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 4096
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 2
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 120
	}

	return &openrouterProvider{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
	}, nil
}

func (o *openrouterProvider) Name() string { return openrouterName }

func (o *openrouterProvider) Validate(ctx context.Context) error {
	if o.cfg.APIKey == "" {
		return fmt.Errorf("%w: OPENROUTER_API_KEY not set", ai.ErrProviderValidation)
	}

	reqBody := chatRequest{
		Model: o.cfg.Model,
		Messages: []chatMessage{
			{Role: "user", Content: "ping"},
		},
		MaxTokens: 1,
		Stream:    false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal validation request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	o.setHeaders(httpReq)

	healthClient := &http.Client{Timeout: util.HealthCheckTimeout}
	resp, err := healthClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("openrouter API is not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: invalid API key", ai.ErrProviderValidation)
	}

	return nil
}

func (o *openrouterProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, o.cfg.MaxResources)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(openrouterName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	return retryAnalyze(ctx, o.cfg, openrouterName, func() ([]rules.Finding, string, error) {
		return o.doRequest(ctx, systemPrompt, userPrompt)
	})
}

func (o *openrouterProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	reqBody := chatRequest{
		Model: o.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: o.cfg.Temperature,
		MaxTokens:   o.cfg.MaxTokens,
		Stream:      false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.cfg.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	o.setHeaders(httpReq)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("%w: %v", ai.ErrProviderTimeout, ctx.Err())
		}
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readResponseBody(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp chatResponse
		if json.Unmarshal(respBody, &errResp) == nil && errResp.Error != nil {
			return nil, "", fmt.Errorf("api error %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, "", fmt.Errorf("api error %d: %s", resp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, "", fmt.Errorf("empty response from OpenRouter")
	}

	content := chatResp.Choices[0].Message.Content
	findings, summary, err := parseResponse(content, openrouterName)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse analysis: %w", err)
	}

	return findings, summary, nil
}

// setHeaders adds the required OpenRouter headers to a request.
func (o *openrouterProvider) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)
	req.Header.Set("HTTP-Referer", "https://github.com/leonamvasquez/terraview")
	req.Header.Set("X-Title", "terraview")
}
