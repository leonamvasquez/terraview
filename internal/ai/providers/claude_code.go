package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/util"
)

const claudeCodeName = "claude-code"

func init() {
	ai.Register(claudeCodeName, NewClaudeCode, ai.ProviderInfo{
		DisplayName:  "Claude Code (subscription)",
		RequiresKey:  false,
		EnvVarKey:    "",
		DefaultModel: "claude-sonnet-4-5",
		SuggestedModels: []string{
			"claude-sonnet-4-5",
			"claude-opus-4-6",
			"claude-opus-4-1",
			"claude-sonnet-4-20250514",
			"claude-haiku-4-5",
		},
		CLIBinary:   "claude",
		InstallHint: "npm install -g @anthropic-ai/claude-code",
	})
}

type claudeCodeProvider struct {
	cfg ai.ProviderConfig
}

// NewClaudeCode creates a provider that delegates to the locally installed
// Claude Code CLI binary, using the user's Anthropic subscription for billing.
func NewClaudeCode(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.Model == "" {
		cfg.Model = "claude-sonnet-4-5"
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 300
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	return &claudeCodeProvider{cfg: cfg}, nil
}

func (c *claudeCodeProvider) Name() string { return claudeCodeName }

// Validate checks that the Claude Code CLI binary is installed.
// Note: Claude CLI may hang when invoked non-interactively with
// certain configurations, so we only verify the binary is in PATH.
func (c *claudeCodeProvider) Validate(_ context.Context) error {
	if _, err := exec.LookPath("claude"); err != nil {
		return fmt.Errorf("%w: claude CLI not found in PATH — install via: npm install -g @anthropic-ai/claude-code", ai.ErrProviderValidation)
	}
	return nil
}

// Analyze sends the terraform plan context to Claude Code CLI and parses the response.
func (c *claudeCodeProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, c.cfg.MaxResources)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(claudeCodeName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)
	fullPrompt := systemPrompt + "\n\n" + userPrompt

	var lastErr error
	for attempt := 0; attempt <= c.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := backoffWithJitter(attempt)
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(claudeCodeName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := c.doExec(ctx, fullPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    c.cfg.Model,
			Provider: claudeCodeName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(claudeCodeName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", c.cfg.MaxRetries+1, lastErr))
}

func (c *claudeCodeProvider) doExec(ctx context.Context, prompt string) ([]rules.Finding, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(c.cfg.TimeoutSecs)*time.Second)
	defer cancel()

	// Claude Code CLI: --print outputs text to stdout without interactive mode.
	// --output-format json wraps the output in a structured JSON envelope.
	args := []string{
		"--print",
		"--output-format", "json",
		"--model", c.cfg.Model,
	}

	cmd := exec.CommandContext(execCtx, "claude", args...)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if execCtx.Err() != nil {
			return nil, "", fmt.Errorf("%w: claude CLI timed out after %ds", ai.ErrProviderTimeout, c.cfg.TimeoutSecs)
		}
		return nil, "", fmt.Errorf("claude CLI failed: %w — stderr: %s", err, util.Truncate(strings.TrimSpace(stderr.String()), 300))
	}

	output := stdout.String()
	if output == "" {
		return nil, "", fmt.Errorf("%w: claude CLI returned empty output", ai.ErrInvalidResponse)
	}

	// Claude --output-format json wraps text in a JSON envelope;
	// extract the actual text content.
	text := extractClaudeCodeJSON(output)

	return parseResponse(text, claudeCodeName)
}

// claudeCodeJSONResponse represents the JSON envelope from `claude --output-format json`.
type claudeCodeJSONResponse struct {
	Result string `json:"result"`
	// Alternative shapes from different CLI versions:
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content,omitempty"`
}

// extractClaudeCodeJSON extracts the text content from the Claude Code CLI JSON output.
// Falls back to the raw string if parsing fails.
func extractClaudeCodeJSON(raw string) string {
	var resp claudeCodeJSONResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return raw
	}

	// Try "result" field first (common in newer CLI versions)
	if resp.Result != "" {
		return resp.Result
	}

	// Try "content" array (similar to API format)
	for _, block := range resp.Content {
		if block.Type == "text" && block.Text != "" {
			return block.Text
		}
	}

	// Fallback: return raw output and let parseResponse handle markdown extraction
	return raw
}
