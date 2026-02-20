package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
)

const claudeName = "claude"

func init() {
	ai.Register(claudeName, NewClaude, ai.ProviderInfo{
		DisplayName:     "Anthropic Claude",
		RequiresKey:     true,
		EnvVarKey:       "ANTHROPIC_API_KEY",
		DefaultModel:    "claude-sonnet-4-20250514",
		SuggestedModels: []string{
			"claude-sonnet-4-20250514",
			"claude-3-5-sonnet-20241022",
			"claude-3-haiku-20240307",
			"claude-opus-4-5",
		},
	})
}

type claudeProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

// Claude Messages API types
type claudeRequest struct {
	Model       string           `json:"model"`
	MaxTokens   int              `json:"max_tokens"`
	System      string           `json:"system,omitempty"`
	Messages    []claudeMessage  `json:"messages"`
	Temperature float64          `json:"temperature,omitempty"`
}

type claudeMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type claudeResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Error      *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Type string `json:"type"`
}

// NewClaude creates a new Claude provider.
func NewClaude(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	if cfg.Model == "" {
		cfg.Model = "claude-sonnet-4-20250514"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.anthropic.com"
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

	return &claudeProvider{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
	}, nil
}

func (c *claudeProvider) Name() string { return claudeName }

func (c *claudeProvider) Validate(ctx context.Context) error {
	if c.cfg.APIKey == "" {
		return fmt.Errorf("%w: ANTHROPIC_API_KEY not set", ai.ErrProviderValidation)
	}

	// Lightweight validation: send a minimal request to verify API key
	reqBody := claudeRequest{
		Model:     c.cfg.Model,
		MaxTokens: 1,
		Messages: []claudeMessage{
			{Role: "user", Content: "ping"},
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal validation request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	healthClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := healthClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("claude API is not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("%w: invalid API key", ai.ErrProviderValidation)
	}

	// Any 2xx or even 4xx (except 401) means the API is reachable and key works
	return nil
}

func (c *claudeProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(claudeName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(claudeName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := c.doRequest(ctx, systemPrompt, userPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    c.cfg.Model,
			Provider: claudeName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(claudeName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", c.cfg.MaxRetries+1, lastErr))
}

func (c *claudeProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	reqBody := claudeRequest{
		Model:     c.cfg.Model,
		MaxTokens: c.cfg.MaxTokens,
		System:    systemPrompt,
		Messages: []claudeMessage{
			{Role: "user", Content: userPrompt},
		},
		Temperature: c.cfg.Temperature,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", c.cfg.BaseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", c.cfg.APIKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("%w: %v", ai.ErrProviderTimeout, ctx.Err())
		}
		return nil, "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("claude returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var claudeResp claudeResponse
	if err := json.Unmarshal(respBody, &claudeResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if claudeResp.Error != nil {
		return nil, "", fmt.Errorf("claude error: %s", claudeResp.Error.Message)
	}

	if claudeResp.Type == "error" {
		return nil, "", fmt.Errorf("claude returned error response")
	}

	if len(claudeResp.Content) == 0 {
		return nil, "", fmt.Errorf("%w: empty response from claude", ai.ErrInvalidResponse)
	}

	// Find the text content block
	for _, block := range claudeResp.Content {
		if block.Type == "text" {
			return parseResponse(block.Text, claudeName)
		}
	}

	return nil, "", fmt.Errorf("%w: no text content in claude response", ai.ErrInvalidResponse)
}
