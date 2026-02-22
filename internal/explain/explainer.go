package explain

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Explanation is the structured AI-generated narrative of a Terraform plan.
type Explanation struct {
	Summary     string   `json:"summary"`
	Changes     []string `json:"changes"`
	Risks       []string `json:"risks"`
	Suggestions []string `json:"suggestions"`
	RiskLevel   string   `json:"risk_level"`
}

// Explainer generates natural-language explanations of Terraform plans via AI.
type Explainer struct {
	provider ai.Provider
	lang     string // "pt-BR" for Portuguese output
}

// NewExplainer creates a new Explainer with the given AI provider.
func NewExplainer(provider ai.Provider) *Explainer {
	return &Explainer{provider: provider}
}

// NewExplainerWithLang creates a new Explainer with a specific output language.
func NewExplainerWithLang(provider ai.Provider, lang string) *Explainer {
	return &Explainer{provider: provider, lang: lang}
}

// Explain generates a natural-language explanation of the plan.
func (e *Explainer) Explain(ctx context.Context, resources []parser.NormalizedResource, findings []rules.Finding) (*Explanation, error) {
	prompt := buildExplainPrompt(resources, findings)
	if e.lang == "pt-BR" {
		prompt += "\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR). All text must be in Portuguese.\n"
	}

	req := ai.Request{
		Resources: resources,
		Summary:   buildSummaryMap(resources),
		Prompts: ai.Prompts{
			System: prompt,
		},
	}

	completion, err := e.provider.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("explain AI call failed: %w", err)
	}

	return ParseExplanation(completion.Summary)
}

func buildSummaryMap(resources []parser.NormalizedResource) map[string]interface{} {
	actionCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	for _, r := range resources {
		actionCounts[r.Action]++
		typeCounts[r.Type]++
	}
	return map[string]interface{}{
		"total_resources": len(resources),
		"actions":         actionCounts,
		"resource_types":  typeCounts,
	}
}

func buildExplainPrompt(_ []parser.NormalizedResource, findings []rules.Finding) string {
	var sb strings.Builder

	sb.WriteString("You are a senior infrastructure engineer reviewing a Terraform plan.\n\n")
	sb.WriteString("Your task is to explain this plan in clear, concise language that anyone can understand.\n\n")
	sb.WriteString("You MUST respond ONLY with valid JSON in this exact format:\n")
	sb.WriteString(`{
  "findings": [],
  "summary": "<YOUR JSON EXPLANATION HERE>"
}`)
	sb.WriteString("\n\nThe summary field MUST contain a valid JSON string with this structure:\n")
	sb.WriteString(`{
  "summary": "A 2-3 sentence overview",
  "changes": ["change 1", "change 2"],
  "risks": ["risk 1", "risk 2"],
  "suggestions": ["suggestion 1", "suggestion 2"],
  "risk_level": "low|medium|high|critical"
}`)
	sb.WriteString("\n\nFocus on:\n")
	sb.WriteString("- What resources are being created, modified, or destroyed\n")
	sb.WriteString("- Security implications of the changes\n")
	sb.WriteString("- Operational risks (downtime, data loss, blast radius)\n")
	sb.WriteString("- Cost implications if apparent\n")
	sb.WriteString("- What a human reviewer should pay attention to\n\n")

	if len(findings) > 0 {
		sb.WriteString("The following scanner findings were already detected:\n")
		for _, f := range findings {
			sb.WriteString(fmt.Sprintf("- [%s] %s: %s\n", f.Severity, f.Resource, f.Message))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// ParseExplanation parses a raw AI response into an Explanation struct.
func ParseExplanation(raw string) (*Explanation, error) {
	raw = strings.TrimSpace(raw)

	var expl Explanation
	if err := json.Unmarshal([]byte(raw), &expl); err == nil && expl.Summary != "" {
		expl.RiskLevel = normalizeRiskLevel(expl.RiskLevel)
		return &expl, nil
	}

	cleaned := raw
	if idx := strings.Index(raw, "```json"); idx != -1 {
		endIdx := strings.Index(raw[idx+7:], "```")
		if endIdx != -1 {
			cleaned = raw[idx+7 : idx+7+endIdx]
		}
	} else if idx := strings.Index(raw, "```"); idx != -1 {
		endIdx := strings.Index(raw[idx+3:], "```")
		if endIdx != -1 {
			cleaned = raw[idx+3 : idx+3+endIdx]
		}
	}

	cleaned = strings.TrimSpace(cleaned)
	if err := json.Unmarshal([]byte(cleaned), &expl); err == nil && expl.Summary != "" {
		expl.RiskLevel = normalizeRiskLevel(expl.RiskLevel)
		return &expl, nil
	}

	return &Explanation{
		Summary:   raw,
		RiskLevel: "medium",
	}, nil
}

func normalizeRiskLevel(level string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "low", "medium", "high", "critical":
		return level
	default:
		return "medium"
	}
}
