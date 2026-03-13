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

const ollamaName = "ollama"

// defaultNumCtx is the default context window size for Ollama models.
const defaultNumCtx = 4096

func init() {
	ai.Register(ollamaName, NewOllama, ai.ProviderInfo{
		DisplayName:  "Ollama (Local)",
		RequiresKey:  false,
		DefaultModel: "llama3.1:8b",
		SuggestedModels: []string{
			"olmo2:7b",
			"olmo2:13b",
			"lfm2:text",
			"qwen3-coder:next",
			"qwen3.5",
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
	applyDefaults(&cfg, "", "llama3.1:8b", util.DefaultOllamaURL)
	// Ollama uses smaller default tokens since it runs locally
	if cfg.MaxTokens == defaultMaxTokens {
		cfg.MaxTokens = 2048
	}

	return &ollamaProvider{
		cfg:    cfg,
		client: newHTTPClient(cfg.TimeoutSecs),
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
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, o.cfg.MaxResources)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(ollamaName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)

	return retryAnalyze(ctx, o.cfg, ollamaName, func() ([]rules.Finding, string, error) {
		return o.doRequest(ctx, systemPrompt, userPrompt)
	})
}

func (o *ollamaProvider) doRequest(ctx context.Context, systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	numCtx := o.cfg.NumCtx
	if numCtx <= 0 {
		numCtx = defaultNumCtx
	}

	reqBody := ollamaRequest{
		Model:  o.cfg.Model,
		Prompt: userPrompt,
		System: systemPrompt,
		Stream: false,
		Format: "json",
		Options: ollamaOptions{
			Temperature: o.cfg.Temperature,
			NumCtx:      numCtx,
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
		respBody, _ := readResponseBody(resp.Body)
		return nil, "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, util.Truncate(string(respBody), 200))
	}

	respBody, err := readResponseBody(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	var ollamaResp ollamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse response envelope: %w", err)
	}

	return parseResponse(ollamaResp.Response, ollamaName)
}
