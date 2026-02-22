package aggregator

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/explain"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

// Verdict represents the safety assessment of a Terraform plan.
type Verdict struct {
	Safe       bool     `json:"safe"`
	Label      string   `json:"label"` // "SAFE" or "NOT SAFE"
	Reasons    []string `json:"reasons"`
	Confidence string   `json:"confidence"` // "high", "medium", "low"
}

// ReviewResult is the final aggregated result of a review.
type ReviewResult struct {
	PlanFile       string               `json:"plan_file"`
	TotalResources int                  `json:"total_resources"`
	Verdict        Verdict              `json:"verdict"`
	Findings       []rules.Finding      `json:"findings"`
	Score          scoring.Score        `json:"score"`
	Summary        string               `json:"summary,omitempty"`
	Explanation    *explain.Explanation `json:"explanation,omitempty"`
	Diagram        string               `json:"diagram,omitempty"`
	BlastRadius    interface{}          `json:"blast_radius,omitempty"`
	MetaAnalysis   *meta.MetaResult     `json:"meta_analysis,omitempty"`
	SeverityCounts map[string]int       `json:"severity_counts"`
	CategoryCounts map[string]int       `json:"category_counts"`
	MaxSeverity    string               `json:"max_severity"`
	ExitCode       int                  `json:"exit_code"`
}

// Aggregator combines findings from multiple sources and computes the final result.
type Aggregator struct {
	scorer *scoring.Scorer
}

// NewAggregator creates a new Aggregator.
func NewAggregator(scorer *scoring.Scorer) *Aggregator {
	return &Aggregator{scorer: scorer}
}

// Aggregate combines hard-rule findings and LLM findings into a single ReviewResult.
// When strict is true, HIGH findings also make the verdict NOT SAFE.
func (a *Aggregator) Aggregate(planFile string, totalResources int, hardRuleFindings []rules.Finding, llmFindings []rules.Finding, llmSummary string, strict bool) ReviewResult {
	allFindings := make([]rules.Finding, 0, len(hardRuleFindings)+len(llmFindings))
	allFindings = append(allFindings, hardRuleFindings...)
	allFindings = append(allFindings, llmFindings...)

	// Deduplicate findings that match on resource + similar message
	allFindings = deduplicateFindings(allFindings)

	// Sort by severity (CRITICAL first)
	sortBySeverity(allFindings)

	severityCounts := countBySeverity(allFindings)
	categoryCounts := countByCategory(allFindings)
	maxSeverity := computeMaxSeverity(allFindings)
	exitCode := computeExitCode(maxSeverity)

	score := a.scorer.Calculate(allFindings, totalResources)

	summary := llmSummary
	if summary == "" {
		summary = generateDefaultSummary(allFindings, totalResources)
	}

	verdict := computeVerdict(allFindings, strict)

	return ReviewResult{
		PlanFile:       planFile,
		TotalResources: totalResources,
		Verdict:        verdict,
		Findings:       allFindings,
		Score:          score,
		Summary:        summary,
		SeverityCounts: severityCounts,
		CategoryCounts: categoryCounts,
		MaxSeverity:    maxSeverity,
		ExitCode:       exitCode,
	}
}

// computeVerdict determines if a plan is safe to apply.
// In strict mode, HIGH findings also make the plan NOT SAFE.
func computeVerdict(findings []rules.Finding, strict bool) Verdict {
	criticalCount := 0
	highCount := 0
	var criticalIDs []string
	var highIDs []string

	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			criticalCount++
			criticalIDs = append(criticalIDs, f.RuleID)
		case rules.SeverityHigh:
			highCount++
			highIDs = append(highIDs, f.RuleID)
		}
	}

	safe := true
	var reasons []string

	if criticalCount > 0 {
		safe = false
		reasons = append(reasons, fmt.Sprintf("%d CRITICAL finding(s) detected", criticalCount))
	}
	if strict && highCount > 0 {
		safe = false
		reasons = append(reasons, fmt.Sprintf("%d HIGH finding(s) detected (strict mode)", highCount))
	}

	if safe && len(findings) == 0 {
		reasons = append(reasons, "No issues found")
	} else if safe && highCount > 0 {
		reasons = append(reasons, fmt.Sprintf("No CRITICAL issues found (%d HIGH — use --strict to block)", highCount))
	} else if safe {
		reasons = append(reasons, "No CRITICAL or HIGH severity issues")
	}

	confidence := "high"
	if criticalCount == 0 && highCount > 0 && !strict {
		confidence = "medium"
	}

	label := "SAFE"
	if !safe {
		label = "NOT SAFE"
	}

	return Verdict{
		Safe:       safe,
		Label:      label,
		Reasons:    reasons,
		Confidence: confidence,
	}
}

// deduplicateFindings removes findings that match on the same resource + rule.
// Uses a semantic key: normalised resource + rule ID (case-insensitive).
// When duplicates are found, keeps the highest severity and merges source/remediation.
func deduplicateFindings(findings []rules.Finding) []rules.Finding {
	type dedupKey struct {
		resource string
		ruleID   string
	}

	seen := make(map[dedupKey]*rules.Finding)
	var order []dedupKey

	for i := range findings {
		f := findings[i]
		key := dedupKey{
			resource: strings.ToLower(strings.TrimSpace(f.Resource)),
			ruleID:   strings.ToUpper(strings.TrimSpace(f.RuleID)),
		}

		existing, exists := seen[key]
		if !exists {
			seen[key] = &f
			order = append(order, key)
		} else {
			// Keep highest severity
			if severityOrder[f.Severity] < severityOrder[existing.Severity] {
				existing.Severity = f.Severity
			}
			// Merge remediation if existing is empty
			if existing.Remediation == "" && f.Remediation != "" {
				existing.Remediation = f.Remediation
			}
			// Merge sources
			if f.Source != "" && !strings.Contains(existing.Source, f.Source) {
				existing.Source += "+" + f.Source
			}
		}
	}

	result := make([]rules.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, *seen[key])
	}
	return result
}

var severityOrder = map[string]int{
	rules.SeverityCritical: 0,
	rules.SeverityHigh:     1,
	rules.SeverityMedium:   2,
	rules.SeverityLow:      3,
	rules.SeverityInfo:     4,
}

func sortBySeverity(findings []rules.Finding) {
	sort.Slice(findings, func(i, j int) bool {
		oi := severityOrder[findings[i].Severity]
		oj := severityOrder[findings[j].Severity]
		if oi != oj {
			return oi < oj
		}
		return findings[i].Resource < findings[j].Resource
	})
}

func countBySeverity(findings []rules.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

func countByCategory(findings []rules.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Category]++
	}
	return counts
}

func computeMaxSeverity(findings []rules.Finding) string {
	if len(findings) == 0 {
		return "NONE"
	}
	max := rules.SeverityInfo
	for _, f := range findings {
		if severityOrder[f.Severity] < severityOrder[max] {
			max = f.Severity
		}
	}
	return max
}

func computeExitCode(maxSeverity string) int {
	switch maxSeverity {
	case rules.SeverityCritical:
		return 2
	case rules.SeverityHigh:
		return 1
	default:
		return 0
	}
}

func generateDefaultSummary(findings []rules.Finding, _ int) string {
	if len(findings) == 0 {
		return "No issues found. The Terraform plan looks clean."
	}

	critical := 0
	high := 0
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			critical++
		case rules.SeverityHigh:
			high++
		}
	}

	summary := "Review complete. "
	if critical > 0 {
		summary += "CRITICAL issues found that must be addressed before applying. "
	} else if high > 0 {
		summary += "HIGH severity issues found that should be reviewed. "
	}

	return summary
}
