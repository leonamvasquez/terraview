package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

const (
	// maxResponseBodySize is the upper bound for reading HTTP response bodies
	// from AI provider APIs. Prevents OOM from malformed or malicious responses.
	maxResponseBodySize = 10 * 1024 * 1024 // 10 MB

	// defaultMaxResources is the default number of resources included in the
	// AI prompt. Plans with more resources are truncated to fit context limits.
	defaultMaxResources = 30

	// defaultMaxTokens is the default max output tokens for AI providers.
	defaultMaxTokens = 4096

	// defaultMaxRetries is the default number of retry attempts for transient errors.
	defaultMaxRetries = 2

	// defaultTimeoutSecs is the default HTTP timeout for AI provider requests.
	defaultTimeoutSecs = 120
)

// applyDefaults fills zero-valued fields in cfg with sensible defaults.
// envKey is the environment variable name to check for the API key.
// defaultModel and defaultBaseURL are provider-specific defaults.
func applyDefaults(cfg *ai.ProviderConfig, envKey, defaultModel, defaultBaseURL string) {
	if cfg.APIKey == "" && envKey != "" {
		cfg.APIKey = os.Getenv(envKey)
	}
	if cfg.Model == "" {
		cfg.Model = defaultModel
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultBaseURL
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = defaultMaxTokens
	}
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = defaultMaxRetries
	}
	if cfg.TimeoutSecs <= 0 {
		cfg.TimeoutSecs = defaultTimeoutSecs
	}
}

// newHTTPClient creates an HTTP client with the configured timeout.
func newHTTPClient(timeoutSecs int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeoutSecs) * time.Second,
	}
}

// readResponseBody reads an HTTP response body with a size limit to prevent OOM.
func readResponseBody(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, maxResponseBodySize))
}

// backoffWithJitter returns an exponential backoff duration with random jitter.
// Formula: base = attempt² seconds, jitter = ±25% of base, capped at 30s.
func backoffWithJitter(attempt int) time.Duration {
	base := time.Duration(attempt*attempt) * time.Second
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	// Add ±25% jitter
	jitter := time.Duration(rand.Int63n(int64(base/2))) - base/4
	result := base + jitter
	if result < 100*time.Millisecond {
		result = 100 * time.Millisecond
	}
	return result
}

// retryAnalyze executes fn with exponential backoff, retrying only transient errors.
// Permanent errors (401, 403, 400) cause immediate failure without retry.
func retryAnalyze(
	ctx context.Context,
	cfg ai.ProviderConfig,
	providerName string,
	fn func() ([]rules.Finding, string, error),
) (ai.Completion, error) {
	var lastErr error
	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := backoffWithJitter(attempt)
			select {
			case <-ctx.Done():
				return ai.Completion{}, ai.NewProviderError(providerName, "analyze", ctx.Err())
			case <-time.After(backoff):
			}
		}

		findings, summary, err := fn()
		if err != nil {
			lastErr = err
			// Não retentar erros permanentes (401, 403, 400, validação)
			if !ai.IsTransient(err) {
				return ai.Completion{}, ai.NewProviderError(providerName, "analyze",
					fmt.Errorf("erro permanente (sem retentativa): %w", err))
			}
			continue
		}

		return ai.Completion{
			Findings: findings,
			Summary:  summary,
			Model:    cfg.Model,
			Provider: providerName,
		}, nil
	}

	return ai.Completion{}, ai.NewProviderError(providerName, "analyze",
		fmt.Errorf("falhou após %d tentativas: %w", cfg.MaxRetries+1, lastErr))
}

type llmFinding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Resource    string `json:"resource"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
}

// llmResponse is the expected structured output from any LLM provider.
// Summary may arrive as a string or as a nested JSON object depending on the model.
type llmResponse struct {
	Findings []llmFinding    `json:"findings"`
	Summary  json.RawMessage `json:"summary"`
}

// extractSummary safely extracts a string from the Summary field,
// which may be a JSON string, an object, or absent.
func (r *llmResponse) extractSummary() string {
	if len(r.Summary) == 0 {
		return ""
	}

	// Try as a plain string first (most common case)
	var s string
	if err := json.Unmarshal(r.Summary, &s); err == nil {
		return s
	}

	// If it's a JSON object/array, re-serialize it as a compact string
	return string(r.Summary)
}

// buildSystemPrompt assembles the system prompt from prompt templates.
func buildSystemPrompt(prompts ai.Prompts) string {
	var sb strings.Builder

	sb.WriteString(prompts.System)
	sb.WriteString("\n\n")

	if prompts.Security != "" {
		sb.WriteString("## Security Review Guidelines\n\n")
		sb.WriteString(prompts.Security)
		sb.WriteString("\n\n")
	}

	if prompts.Architecture != "" {
		sb.WriteString("## Architecture Review Guidelines\n\n")
		sb.WriteString(prompts.Architecture)
		sb.WriteString("\n\n")
	}

	if prompts.Standards != "" {
		sb.WriteString("## Standards Review Guidelines\n\n")
		sb.WriteString(prompts.Standards)
		sb.WriteString("\n\n")
	}

	if prompts.Cost != "" {
		sb.WriteString("## Cost Optimization Guidelines\n\n")
		sb.WriteString(prompts.Cost)
		sb.WriteString("\n\n")
	}

	if prompts.Compliance != "" {
		sb.WriteString("## Compliance Review Guidelines\n\n")
		sb.WriteString(prompts.Compliance)
		sb.WriteString("\n\n")
	}

	sb.WriteString(`You MUST respond ONLY with valid JSON in this exact format:
{
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "security|compliance|best-practice|cost|architecture|maintainability|reliability",
      "resource": "resource_address",
      "message": "description of the issue",
      "remediation": "how to fix it"
    }
  ],
  "summary": "brief overall assessment"
}

If there are no findings, return: {"findings": [], "summary": "No issues found."}
Do NOT include any text outside the JSON object.
Respond with minified JSON only — no indentation, no extra whitespace, no markdown fences.

## Examples of well-formed findings

Input resource: aws_s3_bucket with acl="public-read"
Output: {"severity":"HIGH","category":"security","resource":"aws_s3_bucket.example","message":"bucket allows public read access via ACL","remediation":"set acl to private and use bucket policies for controlled access"}

Input resource: aws_security_group with ingress 0.0.0.0/0 on port 22
Output: {"severity":"HIGH","category":"security","resource":"aws_security_group.example","message":"SSH port 22 open to the entire internet","remediation":"restrict ingress to known IP ranges or use a bastion host"}`)

	return sb.String()
}

// buildUserPrompt creates the user prompt with plan context.
// maxResources controls how many resources are included; 0 means use defaultMaxResources.
func buildUserPrompt(resources []parser.NormalizedResource, summary map[string]interface{}, maxResources int) (string, error) {
	if maxResources <= 0 {
		maxResources = defaultMaxResources
	}
	var sb strings.Builder

	sb.WriteString("Review the following Terraform plan for security, architecture, and best practice issues.\n\n")

	sb.WriteString("## Plan Summary\n\n")
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return "", err
	}
	sb.Write(summaryJSON)
	sb.WriteString("\n\n")

	sb.WriteString("## Resource Changes\n\n")

	sort.SliceStable(resources, func(i, j int) bool {
		return priorityTier(resources[i].Type) < priorityTier(resources[j].Type)
	})

	for i, r := range resources {
		if i >= maxResources {
			sb.WriteString(fmt.Sprintf("\n... and %d more resources (truncated for context limit)\n", len(resources)-maxResources))
			break
		}

		sb.WriteString(fmt.Sprintf("### %s (%s)\n", r.Address, r.Action))
		sb.WriteString(fmt.Sprintf("- Type: %s | Provider: %s\n", r.Type, r.Provider))

		valJSON, err := json.Marshal(r.Values)
		if err == nil {
			truncated := truncateJSON(string(valJSON), 2000)
			sb.WriteString(fmt.Sprintf("- Values: %s\n\n", truncated))
		}
	}

	return sb.String(), nil
}

// parseResponse extracts findings from a raw JSON response string.
func parseResponse(response, providerName string) ([]rules.Finding, string, error) {
	response = strings.TrimSpace(response)

	// Extract JSON from markdown code blocks if present.
	if idx := strings.Index(response, "```json"); idx != -1 {
		endIdx := strings.Index(response[idx+7:], "```")
		if endIdx != -1 {
			response = response[idx+7 : idx+7+endIdx]
		}
	} else if idx := strings.Index(response, "```"); idx != -1 {
		endIdx := strings.Index(response[idx+3:], "```")
		if endIdx != -1 {
			response = response[idx+3 : idx+3+endIdx]
		}
	}

	response = strings.TrimSpace(response)

	if !json.Valid([]byte(response)) {
		return nil, "", fmt.Errorf("%w: response is not valid JSON", ai.ErrInvalidResponse)
	}

	var llmResp llmResponse
	if err := json.Unmarshal([]byte(response), &llmResp); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ai.ErrInvalidResponse, err)
	}

	findings := make([]rules.Finding, 0, len(llmResp.Findings))
	for _, f := range llmResp.Findings {
		if f.Resource == "" || f.Message == "" {
			continue
		}

		severity := normalizeSeverity(f.Severity)
		category := normalizeCategory(f.Category)

		findings = append(findings, rules.Finding{
			RuleID:      fmt.Sprintf("AI-%s-%s", strings.ToUpper(safePrefix(providerName, 3)), strings.ToUpper(safePrefix(category, 3))),
			Severity:    severity,
			Category:    category,
			Resource:    f.Resource,
			Message:     f.Message,
			Remediation: f.Remediation,
			Source:      "ai/" + providerName,
		})
	}

	return findings, llmResp.extractSummary(), nil
}

func normalizeSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		return s
	default:
		return "INFO"
	}
}

func normalizeCategory(c string) string {
	c = strings.ToLower(strings.TrimSpace(c))
	switch c {
	case "security", "compliance", "best-practice", "maintainability", "reliability", "cost", "architecture":
		return c
	default:
		return "best-practice"
	}
}

func truncateJSON(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "\n  ... (truncated)"
}

// priorityTier returns a sort priority for a given resource type.
// Lower number = higher priority (processed first).
func priorityTier(resourceType string) int {
	high := []string{
		"aws_iam_role", "aws_iam_policy", "aws_iam_user", "aws_iam_group",
		"aws_security_group", "aws_security_group_rule",
		"aws_s3_bucket", "aws_s3_bucket_policy", "aws_s3_bucket_acl",
		"aws_kms_key", "aws_kms_alias",
		"aws_rds_instance", "aws_db_instance",
		"aws_secretsmanager_secret", "aws_ssm_parameter",
		"google_iam_binding", "google_iam_member", "google_storage_bucket",
		"azurerm_role_assignment", "azurerm_storage_account",
	}
	medium := []string{
		"aws_lambda_function", "aws_api_gateway_rest_api",
		"aws_eks_cluster", "aws_ecs_task_definition",
		"aws_cloudtrail", "aws_config_rule",
		"aws_vpc", "aws_subnet", "aws_internet_gateway",
	}
	for _, t := range high {
		if t == resourceType {
			return 1
		}
	}
	for _, t := range medium {
		if t == resourceType {
			return 2
		}
	}
	return 3
}

// safePrefix returns the first n characters of s, or s itself if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
