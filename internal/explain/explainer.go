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
// It tolerates structural variations: summary may be a string or a nested object.
func ParseExplanation(raw string) (*Explanation, error) {
	raw = strings.TrimSpace(raw)

	// Try direct unmarshal first
	var expl Explanation
	if err := json.Unmarshal([]byte(raw), &expl); err == nil && expl.Summary != "" {
		expl.RiskLevel = normalizeRiskLevel(expl.RiskLevel)
		return &expl, nil
	}

	// Try parsing as a generic map to handle summary-as-object
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err == nil {
		return explFromMap(m), nil
	}

	// Try extracting from code fences
	cleaned := extractFromCodeFence(raw)
	if cleaned != raw {
		if err := json.Unmarshal([]byte(cleaned), &expl); err == nil && expl.Summary != "" {
			expl.RiskLevel = normalizeRiskLevel(expl.RiskLevel)
			return &expl, nil
		}
		if err := json.Unmarshal([]byte(cleaned), &m); err == nil {
			return explFromMap(m), nil
		}
	}

	// Fallback: use raw text as summary
	return &Explanation{
		Summary:   raw,
		RiskLevel: "medium",
	}, nil
}

// extractFromCodeFence extracts JSON from markdown code fences if present.
func extractFromCodeFence(raw string) string {
	if idx := strings.Index(raw, "```json"); idx != -1 {
		endIdx := strings.Index(raw[idx+7:], "```")
		if endIdx != -1 {
			return strings.TrimSpace(raw[idx+7 : idx+7+endIdx])
		}
	}
	if idx := strings.Index(raw, "```"); idx != -1 {
		endIdx := strings.Index(raw[idx+3:], "```")
		if endIdx != -1 {
			return strings.TrimSpace(raw[idx+3 : idx+3+endIdx])
		}
	}
	return raw
}

// explFromMap builds an Explanation from a generic map, handling
// summary as either string or nested object.
func explFromMap(m map[string]interface{}) *Explanation {
	expl := &Explanation{RiskLevel: "medium"}

	switch v := m["summary"].(type) {
	case string:
		expl.Summary = v
	case map[string]interface{}:
		// Summary is a nested object — extract text content
		if s, ok := v["summary"].(string); ok {
			expl.Summary = s
		} else if s, ok := v["overview"].(string); ok {
			expl.Summary = s
		} else {
			// Serialize the object as fallback
			b, _ := json.Marshal(v)
			expl.Summary = string(b)
		}
	default:
		if v != nil {
			expl.Summary = fmt.Sprintf("%v", v)
		}
	}

	expl.Changes = toStringSlice(m["changes"])
	expl.Risks = toStringSlice(m["risks"])
	expl.Suggestions = toStringSlice(m["suggestions"])

	if rl, ok := m["risk_level"].(string); ok {
		expl.RiskLevel = normalizeRiskLevel(rl)
	}

	return expl
}

// toStringSlice converts an interface{} ([]interface{}) to []string.
func toStringSlice(v interface{}) []string {
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
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
