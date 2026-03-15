package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/util"
)

const customName = "custom"

func init() {
	ai.Register(customName, NewCustom, ai.ProviderInfo{
		DisplayName:  "Custom (OpenAI-compatible)",
		RequiresKey:  true,
		EnvVarKey:    "CUSTOM_LLM_API_KEY",
		DefaultModel: "gpt-4o-mini",
		SuggestedModels: []string{
			"gpt-4o-mini",
			"gpt-4o",
			"grok-3",
			"grok-3-mini",
			"mistral-large-latest",
			"llama-3.3-70b",
			"deepseek-v3",
		},
	})
}

type customProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

// NewCustom creates a generic OpenAI-compatible provider.
// It works with any API that follows the /v1/chat/completions standard,
// including: Grok (xAI), Groq, Mistral, Together AI, Fireworks, Perplexity,
// LM Studio, vLLM, Ollama (OpenAI mode), and others.
//
// Configuration via .terraview.yml:
//
//	llm:
//	  provider: custom
//	  model: grok-3-mini
//	  url: https://api.x.ai
//	  api_key: xai-...
func NewCustom(cfg ai.ProviderConfig) (ai.Provider, error) {
	applyDefaults(&cfg, "CUSTOM_LLM_API_KEY", "gpt-4o-mini", "https://api.openai.com")
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("%w: url is required for custom provider — set 'url' in config or CUSTOM_LLM_BASE_URL env var", ai.ErrProviderValidation)
	}
	return &customProvider{
		cfg:    cfg,
		client: newHTTPClient(cfg.TimeoutSecs),
	}, nil
}

func (c *customProvider) Name() string { return customName }

func (c *customProvider) Validate(ctx context.Context) error {
	if c.cfg.APIKey == "" {
		return fmt.Errorf("%w: API key not set — set 'api_key' in config or CUSTOM_LLM_API_KEY env var", ai.ErrProviderValidation)
	}
	if c.cfg.BaseURL == "" {
		return fmt.Errorf("%w: url is required for custom provider", ai.ErrProviderValidation)
	}

	reqBody := chatRequest{
		Model: c.cfg.Model,
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	healthClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := healthClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("API is not reachable at %s: %w", c.cfg.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: invalid API key", ai.ErrProviderValidation)
	}

	return nil
}

func (c *customProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, c.cfg.MaxResources)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(customName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	return retryAnalyze(ctx, c.cfg, customName, func() ([]rules.Finding, string, error) {
		return c.doRequest(ctx, systemPrompt, userPrompt)
	})
}

func (c *customProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	reqBody := chatRequest{
		Model: c.cfg.Model,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: c.cfg.Temperature,
		MaxTokens:   c.cfg.MaxTokens,
		Stream:      false,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)

	resp, err := c.client.Do(httpReq)
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
		return nil, "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, util.Truncate(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if chatResp.Error != nil {
		return nil, "", fmt.Errorf("API error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, "", fmt.Errorf("%w: empty response from API", ai.ErrInvalidResponse)
	}

	return parseResponse(chatResp.Choices[0].Message.Content, customName)
}
