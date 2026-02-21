package secondopinion

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Assessment is the AI contextual evaluation of a deterministic finding.
type Assessment struct {
	RuleID      string ` json:"rule_id" `
	Resource    string ` json:"resource" `
	Agree       bool   ` json:"agree" `
	Confidence  string ` json:"confidence" `
	Context     string ` json:"context" `
	Suggestion  string ` json:"suggestion,omitempty" `
	AdjustedSev string ` json:"adjusted_severity,omitempty" `
}

// ReviewResult holds the second opinion analysis.
type ReviewResult struct {
	Assessments  []Assessment ` json:"assessments" `
	Summary      string       ` json:"summary" `
	AgreeCount   int          ` json:"agree_count" `
	DisputeCount int          ` json:"dispute_count" `
}

// Reviewer validates deterministic findings using AI contextual analysis.
type Reviewer struct {
	provider ai.Provider
}

// NewReviewer creates a new second opinion Reviewer.
func NewReviewer(provider ai.Provider) *Reviewer {
	return &Reviewer{provider: provider}
}

// Review sends deterministic findings to AI for contextual validation.
func (r *Reviewer) Review(ctx context.Context, findings []rules.Finding, resources []parser.NormalizedResource, topologyCtx string) (*ReviewResult, error) {
	if len(findings) == 0 {
		return &ReviewResult{Summary: "No findings to review."}, nil
	}

	prompt := buildSecondOpinionPrompt(findings, topologyCtx)

	req := ai.Request{
		Resources: resources,
		Summary: map[string]interface{}{
			"total_findings":   len(findings),
			"topology_context": topologyCtx,
		},
		Prompts: ai.Prompts{
			System: prompt,
		},
	}

	completion, err := r.provider.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("second opinion AI call failed: %w", err)
	}

	return parseSecondOpinionResponse(completion.Summary, findings)
}

func buildSecondOpinionPrompt(findings []rules.Finding, topologyCtx string) string {
	var sb strings.Builder

	sb.WriteString("You are a senior infrastructure security reviewer providing a SECOND OPINION.\n\n")
	sb.WriteString("Deterministic rules have already flagged the following findings.\n")
	sb.WriteString("Your job is to VALIDATE each finding with contextual analysis.\n\n")
	sb.WriteString("For each finding, determine:\n")
	sb.WriteString("1. Do you AGREE with the finding?\n")
	sb.WriteString("2. Your CONFIDENCE level (high/medium/low)\n")
	sb.WriteString("3. Additional CONTEXT a human reviewer should know\n")
	sb.WriteString("4. Any SEVERITY ADJUSTMENT you would recommend\n\n")

	if topologyCtx != "" {
		sb.WriteString("Infrastructure context:\n")
		sb.WriteString(topologyCtx)
		sb.WriteString("\n")
	}

	sb.WriteString("Respond with valid JSON containing assessments for each finding.\n\n")
	sb.WriteString("Findings to review:\n\n")

	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("Finding %d:\n", i+1))
		sb.WriteString(fmt.Sprintf("  Rule: %s\n", f.RuleID))
		sb.WriteString(fmt.Sprintf("  Severity: %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("  Category: %s\n", f.Category))
		sb.WriteString(fmt.Sprintf("  Resource: %s\n", f.Resource))
		sb.WriteString(fmt.Sprintf("  Message: %s\n", f.Message))
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("  Remediation: %s\n", f.Remediation))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

func parseSecondOpinionResponse(raw string, findings []rules.Finding) (*ReviewResult, error) {
	raw = strings.TrimSpace(raw)

	var result ReviewResult
	if err := json.Unmarshal([]byte(raw), &result); err == nil && len(result.Assessments) > 0 {
		return &result, nil
	}

	// Try extracting JSON from markdown code blocks
	cleaned := extractJSON(raw)
	if cleaned != raw {
		if err := json.Unmarshal([]byte(cleaned), &result); err == nil && len(result.Assessments) > 0 {
			return &result, nil
		}
	}

	// Fallback: create default assessments agreeing with all findings
	result = ReviewResult{
		Summary:    raw,
		AgreeCount: len(findings),
	}
	for _, f := range findings {
		result.Assessments = append(result.Assessments, Assessment{
			RuleID:     f.RuleID,
			Resource:   f.Resource,
			Agree:      true,
			Confidence: "medium",
			Context:    "AI validation unavailable; defaulting to agreement with deterministic rule.",
		})
	}

	return &result, nil
}

func extractJSON(raw string) string {
	// Look for JSON between code fences
	start := strings.Index(raw, "{")
	end := strings.LastIndex(raw, "}")
	if start != -1 && end != -1 && end > start {
		return strings.TrimSpace(raw[start : end+1])
	}
	return raw
}

// EnrichFindings adds AI assessment context to findings.
func EnrichFindings(findings []rules.Finding, result *ReviewResult) []rules.Finding {
	if result == nil || len(result.Assessments) == 0 {
		return findings
	}

	assessmentMap := make(map[string]Assessment)
	for _, a := range result.Assessments {
		key := a.RuleID + "|" + a.Resource
		assessmentMap[key] = a
	}

	enriched := make([]rules.Finding, len(findings))
	copy(enriched, findings)

	for i, f := range enriched {
		key := f.RuleID + "|" + f.Resource
		if a, ok := assessmentMap[key]; ok {
			contextPrefix := "AI agrees"
			if !a.Agree {
				contextPrefix = "AI disputes"
			}
			enriched[i].Remediation = fmt.Sprintf("[%s (%s confidence)] %s. %s",
				contextPrefix, a.Confidence, a.Context, f.Remediation)
		}
	}

	return enriched
}
