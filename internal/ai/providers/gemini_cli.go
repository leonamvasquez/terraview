package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/debuglog"
	"github.com/leonamvasquez/terraview/internal/util"
)

const geminiCLIName = "gemini-cli"

// errGeminiQuotaExhausted is a sentinel returned by runCLI when the Gemini CLI
// subprocess emits HTTP 429 / RESOURCE_EXHAUSTED for a specific model.
// execWithFallback uses errors.Is on this sentinel to decide whether to try
// the next model in the fallback chain.
var errGeminiQuotaExhausted = errors.New("gemini CLI capacity exhausted")

// geminiCLIFallbackModels is the ordered list of models tried when the
// configured model returns a ModelNotFoundError. The primary model (from
// config) is always prepended at construction time.
var geminiCLIFallbackModels = []string{
	"gemini-3.1-pro-preview",
	"gemini-3-flash-preview",
	"gemini-3.1-flash-lite-preview",
	"gemini-2.5-pro",
	"gemini-2.5-flash",
	"gemini-2.5-flash-lite",
}

func init() {
	ai.Register(geminiCLIName, NewGeminiCLI, ai.ProviderInfo{
		DisplayName:  "Gemini CLI (subscription)",
		RequiresKey:  false,
		EnvVarKey:    "",
		DefaultModel: "gemini-3.1-pro-preview",
		SuggestedModels: []string{
			// Gemini 3.x (preview, current default in gemini-cli)
			"gemini-3.1-pro-preview",
			"gemini-3-flash-preview",
			"gemini-3.1-flash-lite-preview",
			// Gemini 2.5 (legacy fallback — capacity may be limited)
			"gemini-2.5-pro",
			"gemini-2.5-flash",
			"gemini-2.5-flash-lite",
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
		cfg.Model = "gemini-3.1-pro-preview"
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

		debuglog.Log("gemini_cli.analyze_attempt", map[string]any{"attempt": attempt, "max_retries": g.cfg.MaxRetries})
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
			debuglog.Log("gemini_cli.fallback", map[string]any{"from_model": model, "err": fmt.Sprintf("%v", err)})
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
	if errors.Is(err, errGeminiQuotaExhausted) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "terminalquotaerror") ||
		strings.Contains(msg, "exhausted your capacity") ||
		strings.Contains(msg, "no capacity available") ||
		strings.Contains(msg, "resource_exhausted") ||
		strings.Contains(msg, "ratelimitexceeded") ||
		strings.Contains(msg, "status 429") ||
		strings.Contains(msg, "code\": 429")
}

// quotaWatcher wraps a bytes.Buffer for use as stderr capture, scanning
// each write for HTTP 429 / RESOURCE_EXHAUSTED markers. After a small
// number of consecutive matches it invokes the supplied cancel func to
// abort the gemini-cli subprocess early, letting the caller fall back to
// the next model instead of waiting for the global context timeout.
type quotaWatcher struct {
	buf       *bytes.Buffer
	cancel    context.CancelFunc
	hits      int
	tripped   bool
	threshold int
}

func newQuotaWatcher(buf *bytes.Buffer, cancel context.CancelFunc) *quotaWatcher {
	return &quotaWatcher{buf: buf, cancel: cancel, threshold: 3}
}

// countQuotaMarkers returns the total number of distinct 429/quota
// signatures inside a stderr chunk. The CLI may flush several retry
// failures in one Write, so counting occurrences (not chunks) is what
// keeps the threshold meaningful.
func countQuotaMarkers(chunk string) int {
	c := strings.ToLower(chunk)
	total := 0
	total += strings.Count(c, "status 429")
	total += strings.Count(c, "resource_exhausted")
	total += strings.Count(c, "no capacity available")
	total += strings.Count(c, "model_capacity_exhausted")
	return total
}

func (w *quotaWatcher) Write(p []byte) (int, error) {
	n, err := w.buf.Write(p)
	if debuglog.Enabled() {
		debuglog.Log("gemini_cli.stderr_chunk", map[string]any{"bytes": len(p), "data": string(p)})
	}
	if !w.tripped {
		if found := countQuotaMarkers(string(p)); found > 0 {
			w.hits += found
			debuglog.Log("gemini_cli.quota_hit", map[string]any{"hits": w.hits, "threshold": w.threshold, "chunk_count": found})
			if w.hits >= w.threshold {
				w.tripped = true
				debuglog.Log("gemini_cli.quota_tripped_cancel", nil)
				w.cancel()
			}
		}
	}
	return n, err
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

	debuglog.Log("gemini_cli.spawn", map[string]any{
		"model":         model,
		"args":          args,
		"timeout_secs":  g.cfg.TimeoutSecs,
		"prompt_bytes":  len(prompt),
		"prompt_sample": util.Truncate(prompt, 4000),
	})
	startedAt := time.Now()
	cmd := exec.CommandContext(execCtx, "gemini", args...)
	setProcessGroup(cmd)
	// WaitDelay: after context cancellation, wait up to 5s for graceful exit
	// before SIGKILL. Prevents zombie processes if Cancel signal is ignored.
	cmd.WaitDelay = 5 * time.Second
	cmd.Stdin = strings.NewReader(prompt)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	// Wrap stderr in a quota watcher: once the gaxios retry loop fails
	// twice with HTTP 429 / RESOURCE_EXHAUSTED we cancel execCtx so
	// execWithFallback can switch models immediately instead of waiting
	// for the global timeout to elapse.
	cmd.Stderr = newQuotaWatcher(&stderr, cancel)

	runErr := cmd.Run()
	elapsed := time.Since(startedAt)
	debuglog.Log("gemini_cli.exit", map[string]any{
		"model":        model,
		"err":          fmt.Sprintf("%v", runErr),
		"elapsed_ms":   elapsed.Milliseconds(),
		"stdout_bytes": stdout.Len(),
		"stderr_bytes": stderr.Len(),
		"stdout":       stdout.String(),
		"stderr":       stderr.String(),
		"ctx_err":      fmt.Sprintf("%v", execCtx.Err()),
	})
	if runErr != nil {
		// Inspect full stderr first — even on context timeout, the CLI may
		// have been retrying a quota/capacity error (HTTP 429) internally.
		// Surfacing that allows execWithFallback to switch to the next model
		// instead of reporting a generic timeout. We must scan the whole
		// stderr (not a truncated view) because the CLI prints a large amount
		// of preamble (auth, hook output) before the actual API error.
		fullStderr := strings.TrimSpace(stderr.String())
		if isGeminiQuotaExhausted(fmt.Errorf("%s", fullStderr)) {
			debuglog.Log("gemini_cli.classify_error", map[string]any{"model": model, "reason": "quota_exhausted"})
			return "", fmt.Errorf("model %s: %w", model, errGeminiQuotaExhausted)
		}
		stderrStr := util.Truncate(fullStderr, 600)
		if execCtx.Err() != nil {
			debuglog.Log("gemini_cli.classify_error", map[string]any{"model": model, "reason": "timeout"})
			return "", fmt.Errorf("%w: gemini CLI timed out after %ds — stderr: %s", ai.ErrProviderTimeout, g.cfg.TimeoutSecs, stderrStr)
		}
		debuglog.Log("gemini_cli.classify_error", map[string]any{"model": model, "reason": "subprocess_failed"})
		return "", fmt.Errorf("gemini CLI failed: %w — stderr: %s", runErr, stderrStr)
	}

	out := strings.TrimSpace(stdout.String())
	if out == "" {
		debuglog.Log("gemini_cli.classify_error", map[string]any{"model": model, "reason": "empty_stdout"})
		return "", fmt.Errorf("%w: gemini CLI returned empty output", ai.ErrInvalidResponse)
	}
	debuglog.Log("gemini_cli.success", map[string]any{"model": model, "output_bytes": len(out), "output": out})
	return out, nil
}
