package aggregator

import (
	"sort"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

// ReviewResult is the final aggregated result of a review.
type ReviewResult struct {
	PlanFile        string           `json:"plan_file"`
	TotalResources  int              `json:"total_resources"`
	Findings        []rules.Finding  `json:"findings"`
	Score           scoring.Score    `json:"score"`
	Summary         string           `json:"summary,omitempty"`
	SeverityCounts  map[string]int   `json:"severity_counts"`
	CategoryCounts  map[string]int   `json:"category_counts"`
	MaxSeverity     string           `json:"max_severity"`
	ExitCode        int              `json:"exit_code"`
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
func (a *Aggregator) Aggregate(planFile string, totalResources int, hardRuleFindings []rules.Finding, llmFindings []rules.Finding, llmSummary string) ReviewResult {
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

	return ReviewResult{
		PlanFile:       planFile,
		TotalResources: totalResources,
		Findings:       allFindings,
		Score:          score,
		Summary:        summary,
		SeverityCounts: severityCounts,
		CategoryCounts: categoryCounts,
		MaxSeverity:    maxSeverity,
		ExitCode:       exitCode,
	}
}

func deduplicateFindings(findings []rules.Finding) []rules.Finding {
	seen := make(map[string]bool)
	result := make([]rules.Finding, 0, len(findings))

	for _, f := range findings {
		key := f.Resource + "|" + f.RuleID + "|" + f.Severity
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
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

func generateDefaultSummary(findings []rules.Finding, totalResources int) string {
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
