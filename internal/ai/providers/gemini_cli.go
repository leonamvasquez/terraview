package providers

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/util"
)

const geminiCLIName = "gemini-cli"

// geminiCLIFallbackModels is the ordered list of models tried when the
// configured model returns a ModelNotFoundError. The primary model (from
// config) is always prepended at construction time.
var geminiCLIFallbackModels = []string{
	"gemini-2.5-pro",
	"gemini-2.5-flash",
	"gemini-2.5-flash-lite",
	"gemini-2.0-flash",
}

func init() {
	ai.Register(geminiCLIName, NewGeminiCLI, ai.ProviderInfo{
		DisplayName:  "Gemini CLI (subscription)",
		RequiresKey:  false,
		EnvVarKey:    "",
		DefaultModel: "gemini-2.5-pro",
		SuggestedModels: []string{
			// Stable
			"gemini-2.5-pro",
			"gemini-2.5-flash",
			"gemini-2.5-flash-lite",
			"gemini-2.0-flash",
		},
		CLIBinary:   "gemini",
		InstallHint: "npm install -g @google/gemini-cli",
	})
}

type geminiCLIProvider struct {
	cfg            ai.ProviderConfig
	fallbackModels []string // ordered: primary model first, then alternatives
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
	return &geminiCLIProvider{
		cfg:            cfg,
		fallbackModels: buildGeminiFallbackList(cfg.Model, geminiCLIFallbackModels),
	}, nil
}

// buildGeminiFallbackList returns an ordered slice with primary first and
// then any candidates not already in the list.
func buildGeminiFallbackList(primary string, candidates []string) []string {
	seen := map[string]bool{primary: true}
	result := []string{primary}
	for _, c := range candidates {
		if !seen[c] {
			seen[c] = true
			result = append(result, c)
		}
	}
	return result
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
	userPrompt, err := buildUserPrompt(r.Resources, r.Summary, g.cfg.MaxResources, g.cfg.Model)
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

		output, usedModel, err := g.execWithFallback(ctx, fullPrompt)
		if err != nil {
			lastErr = err
			if !ai.IsTransient(err) {
				return ai.Completion{}, ai.NewProviderError(geminiCLIName, "analyze",
					fmt.Errorf("permanent error (no retry): %w", err))
			}
			continue
		}

		findings, summary, parseErr := parseResponse(output, geminiCLIName)
		if parseErr != nil {
			return ai.Completion{}, ai.NewProviderError(geminiCLIName, "analyze", parseErr)
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    usedModel,
			Provider: geminiCLIName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(geminiCLIName, "analyze",
		fmt.Errorf("failed after %d attempts: %w", g.cfg.MaxRetries+1, lastErr))
}

// Complete performs a single-turn completion with model fallback on ModelNotFoundError.
func (g *geminiCLIProvider) Complete(ctx context.Context, system, user string) (string, error) {
	fullPrompt := system + "\n\n" + user
	output, _, err := g.execWithFallback(ctx, fullPrompt)
	return output, err
}

// execWithFallback runs the Gemini CLI with the primary model, automatically
// falling back to the next model in the fallback list on ModelNotFoundError or
// TerminalQuotaError (capacity exhausted for that specific model).
// Returns the raw stdout, the model that succeeded, and any terminal error.
func (g *geminiCLIProvider) execWithFallback(ctx context.Context, prompt string) (string, string, error) {
	var lastErr error
	for _, model := range g.fallbackModels {
		out, err := g.runCLI(ctx, prompt, model)
		if err == nil {
			return out, model, nil
		}
		if ai.IsModelNotFound(err) || isGeminiQuotaExhausted(err) {
			// Model unavailable or quota exhausted — try next candidate silently
			lastErr = fmt.Errorf("model %q unavailable (%w), trying next fallback", model, err)
			continue
		}
		// Any other error (timeout, parse, etc.) is returned immediately.
		return "", model, err
	}

	return "", "", fmt.Errorf("all gemini-cli models exhausted: %w", lastErr)
}

// isGeminiQuotaExhausted reports whether the error is a Gemini CLI
// TerminalQuotaError — capacity exhausted for the specific model.
// This should trigger fallback to the next model in the list.
func isGeminiQuotaExhausted(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "terminalquotaerror") ||
		strings.Contains(msg, "exhausted your capacity")
}

// runCLI executes the gemini CLI subprocess with the given model and prompt.
func (g *geminiCLIProvider) runCLI(ctx context.Context, prompt, model string) (string, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(g.cfg.TimeoutSecs)*time.Second)
	defer cancel()

	// Since gemini-cli v0.31.0, non-interactive (headless) mode requires the
	// -p/--prompt flag. A positional argument no longer triggers headless mode.
	// We pass the full plan prompt via stdin and use "--prompt ' '" as a minimal
	// trigger so the CLI concatenates stdin + prompt and stays non-interactive.
	// NOTE: do NOT use --sandbox — it requires Docker and fails on Windows
	// without elevated privileges.
	args := []string{
		"--model", model,
		"--prompt", " ",
	}

	cmd := exec.CommandContext(execCtx, "gemini", args...)
	setProcessGroup(cmd)
	// WaitDelay: after context cancellation, wait up to 5s for graceful exit
	// before SIGKILL. Prevents zombie processes if Cancel signal is ignored.
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if execCtx.Err() != nil {
			return "", fmt.Errorf("%w: gemini CLI timed out after %ds", ai.ErrProviderTimeout, g.cfg.TimeoutSecs)
		}
		stderrStr := util.Truncate(strings.TrimSpace(stderr.String()), 300)
		return "", fmt.Errorf("gemini CLI failed: %w — stderr: %s", err, stderrStr)
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		return "", fmt.Errorf("%w: gemini CLI returned empty output", ai.ErrInvalidResponse)
	}
	return out, nil
}
