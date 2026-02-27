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
)

const geminiCLIName = "gemini-cli"

func init() {
	ai.Register(geminiCLIName, NewGeminiCLI, ai.ProviderInfo{
		DisplayName:  "Gemini CLI (subscription)",
		RequiresKey:  false,
		EnvVarKey:    "",
		DefaultModel: "gemini-2.5-pro",
		SuggestedModels: []string{
			"gemini-3",
			"gemini-2.5-pro",
			"gemini-2.5-flash",
		},
		CLIBinary:   "gemini",
		InstallHint: "npm install -g @google/gemini-cli",
	})
}

type geminiCLIProvider struct {
	cfg ai.ProviderConfig
}

// NewGeminiCLI creates a provider that delegates to the locally installed
// Gemini CLI binary, using the user's Google subscription for billing.
func NewGeminiCLI(cfg ai.ProviderConfig) (ai.Provider, error) {
	if cfg.Model == "" {
		cfg.Model = "gemini-2.5-pro"
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = 300
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	return &geminiCLIProvider{cfg: cfg}, nil
}

func (g *geminiCLIProvider) Name() string { return geminiCLIName }

// Validate checks that the Gemini CLI binary is installed.
// Note: Gemini CLI is a TUI app that may hang when invoked
// non-interactively, so we only verify the binary is in PATH.
func (g *geminiCLIProvider) Validate(_ context.Context) error {
	if _, err := exec.LookPath("gemini"); err != nil {
		return fmt.Errorf("%w: gemini CLI not found in PATH — install via: npm install -g @google/gemini-cli or see https://github.com/google-gemini/gemini-cli", ai.ErrProviderValidation)
	}
	return nil
}

// Analyze sends the terraform plan context to Gemini CLI and parses the response.
func (g *geminiCLIProvider) Analyze(ctx context.Context, r ai.Request) (ai.Completion, error) {
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary)
	if err != nil {
		return ai.Completion{}, ai.NewProviderError(geminiCLIName, "build_prompt", err)
	}

	systemPrompt := buildSystemPrompt(r.Prompts)
	fullPrompt := systemPrompt + "\n\n" + userPrompt

	var lastErr error
	for attempt := 0; attempt <= g.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := backoffWithJitter(attempt)
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(geminiCLIName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := g.doExec(ctx, fullPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    g.cfg.Model,
			Provider: geminiCLIName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(geminiCLIName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", g.cfg.MaxRetries+1, lastErr))
}

func (g *geminiCLIProvider) doExec(ctx context.Context, prompt string) ([]rules.Finding, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(g.cfg.TimeoutSecs)*time.Second)
	defer cancel()

	// Gemini CLI enters headless (non-interactive) mode when it detects a
	// non-TTY environment OR when a positional argument is provided.
	// On Windows the .cmd shim created by npm may prevent proper non-TTY
	// detection, so we always pass a short positional argument to
	// guarantee headless mode on every platform.
	// NOTE: do NOT use --sandbox — it requires Docker, which fails on
	// Windows without elevated privileges.
	args := []string{
		"--model", g.cfg.Model,
		"Respond to the prompt provided on stdin.",
	}

	cmd := exec.CommandContext(execCtx, "gemini", args...)
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if execCtx.Err() != nil {
			return nil, "", fmt.Errorf("%w: gemini CLI timed out after %ds", ai.ErrProviderTimeout, g.cfg.TimeoutSecs)
		}
		return nil, "", fmt.Errorf("gemini CLI failed: %w — stderr: %s", err, truncate(strings.TrimSpace(stderr.String()), 300))
	}

	output := stdout.String()
	if output == "" {
		return nil, "", fmt.Errorf("%w: gemini CLI returned empty output", ai.ErrInvalidResponse)
	}

	// Try to parse as JSON directly or extract from markdown
	return parseResponse(output, geminiCLIName)
}

// geminiCLIResponse is used when Gemini CLI returns structured JSON.
type geminiCLIResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// tryExtractGeminiJSON extracts the text from a Gemini CLI JSON response.
func tryExtractGeminiJSON(raw string) string {
	var resp geminiCLIResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		return raw
	}
	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		return resp.Candidates[0].Content.Parts[0].Text
	}
	return raw
}
