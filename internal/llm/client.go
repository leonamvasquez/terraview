package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Reviewer defines the interface for LLM-based review.
type Reviewer interface {
	Review(resources []parser.NormalizedResource, summary map[string]interface{}, prompts PromptSet) ([]rules.Finding, string, error)
	HealthCheck() error
}

// PromptSet holds the assembled prompts for the LLM.
type PromptSet struct {
	System       string
	Security     string
	Architecture string
	Standards    string
}

// Client implements the Reviewer interface using Ollama HTTP API.
type Client struct {
	config     ClientConfig
	httpClient *http.Client
}

// NewClient creates a new Ollama LLM client.
func NewClient(config ClientConfig) *Client {
	if config.MaxRetries <= 0 {
		config.MaxRetries = 2
	}
	if config.TimeoutSecs <= 0 {
		config.TimeoutSecs = 15
	}
	if config.MaxTokens <= 0 {
		config.MaxTokens = 2048
	}

	return &Client{
		config: config,
		httpClient: &http.Client{
			Timeout: time.Duration(config.TimeoutSecs) * time.Second,
		},
	}
}

// HealthCheck verifies that the Ollama server is reachable.
func (c *Client) HealthCheck() error {
	healthClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := healthClient.Get(c.config.BaseURL + "/api/tags")
	if err != nil {
		return fmt.Errorf("ollama is not reachable at %s: %w", c.config.BaseURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ollama returned status %d", resp.StatusCode)
	}

	return nil
}

// Review sends the terraform plan context to the LLM and parses structured findings.
// Retries with exponential backoff on failure.
func (c *Client) Review(resources []parser.NormalizedResource, summary map[string]interface{}, prompts PromptSet) ([]rules.Finding, string, error) {
	userPrompt, err := c.buildUserPrompt(resources, summary)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build user prompt: %w", err)
	}

	systemPrompt := c.buildSystemPrompt(prompts)

	var lastErr error
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(attempt*attempt) * time.Second
			fmt.Printf("[terraview] LLM retry %d/%d (backoff %v)...\n", attempt, c.config.MaxRetries, backoff)
			time.Sleep(backoff)
		}

		findings, llmSummary, err := c.doRequest(systemPrompt, userPrompt)
		if err != nil {
			lastErr = err
			continue
		}

		return findings, llmSummary, nil
	}

	return nil, "", fmt.Errorf("LLM failed after %d attempts: %w", c.config.MaxRetries+1, lastErr)
}

// doRequest performs a single LLM request and parses the response.
func (c *Client) doRequest(systemPrompt, userPrompt string) ([]rules.Finding, string, error) {
	req := OllamaRequest{
		Model:  c.config.Model,
		Prompt: userPrompt,
		System: systemPrompt,
		Stream: false,
		Format: "json",
		Options: OllamaOptions{
			Temperature: c.config.Temperature,
			NumCtx:      c.config.NumCtx,
			NumPredict:  c.config.MaxTokens,
		},
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, "", fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", fmt.Errorf("LLM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("ollama returned status %d: %s", resp.StatusCode, truncateString(string(respBody), 200))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response: %w", err)
	}

	var ollamaResp OllamaResponse
	if err := json.Unmarshal(respBody, &ollamaResp); err != nil {
		return nil, "", fmt.Errorf("failed to parse ollama response envelope: %w", err)
	}

	findings, reviewSummary, err := c.parseAndValidateResponse(ollamaResp.Response)
	if err != nil {
		return nil, "", err
	}

	return findings, reviewSummary, nil
}

// buildSystemPrompt assembles the system prompt from prompt templates.
func (c *Client) buildSystemPrompt(prompts PromptSet) string {
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
func (c *Client) buildUserPrompt(resources []parser.NormalizedResource, summary map[string]interface{}) (string, error) {
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

// parseAndValidateResponse extracts findings from the LLM JSON response,
// validating the structure before accepting it.
func (c *Client) parseAndValidateResponse(response string) ([]rules.Finding, string, error) {
	response = strings.TrimSpace(response)

	// Try to extract JSON if wrapped in markdown code blocks
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

	// Validate it's parseable JSON at all
	if !json.Valid([]byte(response)) {
		return nil, "", fmt.Errorf("LLM returned invalid JSON (not parseable): %s", truncateString(response, 200))
	}

	// Parse into our expected structure
	var llmResp LLMReviewResponse
	if err := json.Unmarshal([]byte(response), &llmResp); err != nil {
		return nil, "", fmt.Errorf("LLM JSON does not match expected schema: %w", err)
	}

	// Validate each finding has required fields
	findings := make([]rules.Finding, 0, len(llmResp.Findings))
	for _, f := range llmResp.Findings {
		if f.Resource == "" || f.Message == "" {
			continue
		}

		severity := normalizeSeverity(f.Severity)
		category := normalizeCategory(f.Category)

		findings = append(findings, rules.Finding{
			RuleID:      "LLM-" + strings.ToUpper(category[:3]),
			Severity:    severity,
			Category:    category,
			Resource:    f.Resource,
			Message:     f.Message,
			Remediation: f.Remediation,
			Source:      "llm",
		})
	}

	return findings, llmResp.Summary, nil
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

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
