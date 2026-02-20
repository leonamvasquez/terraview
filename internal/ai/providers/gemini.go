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

const geminiName = "gemini"

func init() {
	ai.Register(geminiName, NewGemini, ai.ProviderInfo{
		DisplayName:  "Google Gemini",
		RequiresKey:  true,
		EnvVarKey:    "GEMINI_API_KEY",
		DefaultModel: "gemini-2.0-flash",
		SuggestedModels: []string{
			"gemini-2.0-flash",
			"gemini-2.0-pro-exp-02-05",
			"gemini-1.5-flash",
			"gemini-1.5-pro",
		},
	})
}

type geminiProvider struct {
	cfg    ai.ProviderConfig
	client *http.Client
}

// Gemini REST API types
type geminiRequest struct {
	Contents         []geminiContent        `json:"contents"`
	SystemInstruct   *geminiContent         `json:"systemInstruction,omitempty"`
	GenerationConfig geminiGenerationConfig `json:"generationConfig,omitempty"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
	Role  string       `json:"role,omitempty"`
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiGenerationConfig struct {
	Temperature      float64 `json:"temperature,omitempty"`
	MaxOutputTokens  int     `json:"maxOutputTokens,omitempty"`
	ResponseMIMEType string  `json:"responseMimeType,omitempty"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []geminiPart `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// NewGemini creates a new Gemini provider.
func NewGemini(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("GEMINI_API_KEY")
	}
	if cfg.Model == "" {
		cfg.Model = "gemini-2.0-flash"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://generativelanguage.googleapis.com"
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

	return &geminiProvider{
		cfg: cfg,
		client: &http.Client{
			Timeout: time.Duration(cfg.TimeoutSecs) * time.Second,
		},
	}, nil
}

func (g *geminiProvider) Name() string { return geminiName }

func (g *geminiProvider) Validate(ctx context.Context) error {
	if g.cfg.APIKey == "" {
		return fmt.Errorf("%w: GEMINI_API_KEY not set", ai.ErrProviderValidation)
	}

	url := fmt.Sprintf("%s/v1beta/models?key=%s", g.cfg.BaseURL, g.cfg.APIKey)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	healthClient := &http.Client{Timeout: 10 * time.Second}
	resp, err := healthClient.Do(req)
	if err != nil {
		return fmt.Errorf("gemini API is not reachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return fmt.Errorf("%w: invalid API key", ai.ErrProviderValidation)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gemini API returned status %d", resp.StatusCode)
	}

	return nil
}

func (g *geminiProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(geminiName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	var lastErr error
	for attempt := 0; attempt <= g.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(geminiName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := g.doRequest(ctx, systemPrompt, userPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    g.cfg.Model,
			Provider: geminiName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(geminiName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", g.cfg.MaxRetries+1, lastErr))
}

func (g *geminiProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	reqBody := geminiRequest{
		SystemInstruct: &geminiContent{
			Parts: []geminiPart{{Text: systemPrompt}},
		},
		Contents: []geminiContent{
			{
				Role:  "user",
				Parts: []geminiPart{{Text: userPrompt}},
			},
		},
		GenerationConfig: geminiGenerationConfig{
			Temperature:      g.cfg.Temperature,
			MaxOutputTokens:  g.cfg.MaxTokens,
			ResponseMIMEType: "application/json",
		},
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/v1beta/models/%s:generateContent?key=%s",
		g.cfg.BaseURL, g.cfg.Model, g.cfg.APIKey)

	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(httpReq)
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
		return nil, "", fmt.Errorf("gemini returned status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var geminiResp geminiResponse
	if err := json.Unmarshal(respBody, &geminiResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response: %w", err)
	}

	if geminiResp.Error != nil {
		return nil, "", fmt.Errorf("gemini error: %s", geminiResp.Error.Message)
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return nil, "", fmt.Errorf("%w: empty response from gemini", ai.ErrInvalidResponse)
	}

	return parseResponse(geminiResp.Candidates[0].Content.Parts[0].Text, geminiName)
}
