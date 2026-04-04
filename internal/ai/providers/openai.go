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

const openaiName = "openai"

func init() {
	ai.Register(openaiName, NewOpenAI, ai.ProviderInfo{
		DisplayName:  "OpenAI",
		RequiresKey:  true,
		EnvVarKey:    "OPENAI_API_KEY",
		DefaultModel: "gpt-4o-mini",
		SuggestedModels: []string{
			"gpt-4o-mini",
			"gpt-4o",
			"gpt-4.1",
			"gpt-5",
			"gpt-5-mini",
		},
	})
}

type openaiProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

// NewOpenAI creates a new OpenAI provider.
func NewOpenAI(cfg ai.ProviderConfig) (ai.Provider, error) {
	applyDefaults(&cfg, "OPENAI_API_KEY", "gpt-4o-mini", "https://api.openai.com")
	return &openaiProvider{
		cfg:    cfg,
		client: newHTTPClient(cfg.TimeoutSecs),
	}, nil
}

func (o *openaiProvider) Name() string { return openaiName }

func (o *openaiProvider) Validate(ctx context.Context) error {
	if o.cfg.APIKey == "" {
		return fmt.Errorf("%w: OPENAI_API_KEY not set", ai.ErrProviderValidation)
	}

	// Send a minimal request to validate the key
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.cfg.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)

	healthClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := healthClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("openai API is not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: invalid API key", ai.ErrProviderValidation)
	}

	return nil
}

func (o *openaiProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, o.cfg.MaxResources, o.cfg.Model)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(openaiName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	return retryAnalyze(ctx, o.cfg, openaiName, func() ([]rules.Finding, string, error) {
		return o.doRequest(ctx, systemPrompt, userPrompt)
	})
}

func (o *openaiProvider) Complete(ctx context.Context, system, user string) (string, error) {
	return openAIComplete(ctx, o.cfg, o.client, "Bearer "+o.cfg.APIKey, o.cfg.BaseURL, system, user)
}

func (o *openaiProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
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

	httpReq, err := http.NewRequestWithContext(ctx, "POST", o.cfg.BaseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.cfg.APIKey)

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
		return nil, "", fmt.Errorf("openai returned status %d: %s", resp.StatusCode, util.Truncate(string(respBody), 200))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if chatResp.Error != nil {
		return nil, "", fmt.Errorf("openai error: %s", chatResp.Error.Message)
	}

	if len(chatResp.Choices) == 0 {
		return nil, "", fmt.Errorf("%w: empty response from openai", ai.ErrInvalidResponse)
	}

	return parseResponse(chatResp.Choices[0].Message.Content, openaiName)
}
