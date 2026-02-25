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
		DisplayName:  "Gemini CLI (assinatura)",
		RequiresKey:  false,
		EnvVarKey:    "",
		DefaultModel: "gemini-2.5-pro",
		SuggestedModels: []string{
			"gemini-3.0-pro",
			"gemini-2.5-pro",
			"gemini-2.5-flash",
			"gemini-3.0-flash",
		},
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
		cfg.TimeoutSecs = 180
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 1
	}
	return &geminiCLIProvider{cfg: cfg}, nil
}

func (g *geminiCLIProvider) Name() string { return geminiCLIName }

// Validate checks that the Gemini CLI binary is installed and authenticated.
func (g *geminiCLIProvider) Validate(ctx context.Context) error {
	path, err := exec.LookPath("gemini")
	if err != nil {
		return fmt.Errorf("%w: gemini CLI não encontrado no PATH — instale via: npm install -g @anthropic-ai/gemini-cli ou consulte https://github.com/google-gemini/gemini-cli", ai.ErrProviderValidation)
	}
	_ = path

	// Quick check: run gemini with a trivial prompt to verify auth
	checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "gemini", "-p", "responda apenas: ok")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: gemini CLI encontrado mas a autenticação falhou — execute 'gemini' interativamente para autenticar. Detalhes: %s", ai.ErrProviderValidation, strings.TrimSpace(stderr.String()))
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
		fmt.Errorf("falhou após %d tentativas: %w", g.cfg.MaxRetries+1, lastErr))
}

func (g *geminiCLIProvider) doExec(ctx context.Context, prompt string) ([]rules.Finding, string, error) {
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(g.cfg.TimeoutSecs)*time.Second)
	defer cancel()

	args := []string{
		"-p", prompt,
		"--model", g.cfg.Model,
	}

	cmd := exec.CommandContext(execCtx, "gemini", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if execCtx.Err() != nil {
			return nil, "", fmt.Errorf("%w: gemini CLI excedeu timeout de %ds", ai.ErrProviderTimeout, g.cfg.TimeoutSecs)
		}
		return nil, "", fmt.Errorf("gemini CLI falhou: %w — stderr: %s", err, truncate(strings.TrimSpace(stderr.String()), 300))
	}

	output := stdout.String()
	if output == "" {
		return nil, "", fmt.Errorf("%w: gemini CLI retornou saída vazia", ai.ErrInvalidResponse)
	}

	// Tentar parsear como JSON diretamente ou extrair de markdown
	return parseResponse(output, geminiCLIName)
}

// geminiCLIResponse é usado quando o Gemini CLI retorna JSON estruturado.
type geminiCLIResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
}

// tryExtractGeminiJSON tenta extrair o texto de uma resposta JSON do Gemini CLI.
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
