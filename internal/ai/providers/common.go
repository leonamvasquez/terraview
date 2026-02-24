package providers

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

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

// llmFinding is the expected JSON shape from any LLM provider.
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

	sb.WriteString(`You MUST respond ONLY with valid JSON in this exact format:
{
  "findings": [
    {
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "security|compliance|best-practice|maintainability|reliability",
      "resource": "resource_address",
      "message": "description of the issue",
      "remediation": "how to fix it"
    }
  ],
  "summary": "brief overall assessment"
}

If there are no findings, return: {"findings": [], "summary": "No issues found."}
Do NOT include any text outside the JSON object.`)

	return sb.String()
}

// buildUserPrompt creates the user prompt with plan context.
func buildUserPrompt(resources []parser.NormalizedResource, summary map[string]interface{}) (string, error) {
	var sb strings.Builder

	sb.WriteString("Review the following Terraform plan for security, architecture, and best practice issues.\n\n")

	sb.WriteString("## Plan Summary\n\n")
	summaryJSON, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return "", err
	}
	sb.WriteString("```json\n")
	sb.Write(summaryJSON)
	sb.WriteString("\n```\n\n")

	sb.WriteString("## Resource Changes\n\n")

	for i, r := range resources {
		if i >= 30 {
			sb.WriteString(fmt.Sprintf("\n... and %d more resources (truncated for context limit)\n", len(resources)-30))
			break
		}

		sb.WriteString(fmt.Sprintf("### %s (%s)\n", r.Address, r.Action))
		sb.WriteString(fmt.Sprintf("- Type: %s\n", r.Type))
		sb.WriteString(fmt.Sprintf("- Provider: %s\n", r.Provider))

		valJSON, err := json.MarshalIndent(r.Values, "", "  ")
		if err == nil {
			truncated := truncateJSON(string(valJSON), 2000)
			sb.WriteString(fmt.Sprintf("- Values:\n```json\n%s\n```\n\n", truncated))
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
	case "security", "compliance", "best-practice", "maintainability", "reliability":
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

// safePrefix returns the first n characters of s, or s itself if shorter.
func safePrefix(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
