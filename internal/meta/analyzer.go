package meta

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// SourceStats holds statistics for findings from a single source.
type SourceStats struct {
	Source         string         `json:"source"`
	TotalFindings  int            `json:"total_findings"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Categories     []string       `json:"categories"`
}

// Correlation represents a finding flagged by multiple sources.
type Correlation struct {
	Resource    string   `json:"resource"`
	Message     string   `json:"message"`
	Sources     []string `json:"sources"`
	MaxSeverity string   `json:"max_severity"`
	Confidence  string   `json:"confidence"`
}

// MetaResult is the unified cross-tool analysis result.
type MetaResult struct {
	Sources      []SourceStats `json:"sources"`
	Correlations []Correlation `json:"correlations"`
	UnifiedScore float64       `json:"unified_score"`
	CoverageGaps []string      `json:"coverage_gaps"`
	Summary      string        `json:"summary"`
}

// Analyzer performs cross-tool meta-analysis on combined findings.
type Analyzer struct{}

// NewAnalyzer creates a new Meta-Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze performs unified cross-tool analysis on all findings.
func (a *Analyzer) Analyze(findings []rules.Finding) *MetaResult {
	result := &MetaResult{}

	// 1. Group findings by source
	sourceMap := make(map[string][]rules.Finding)
	for _, f := range findings {
		src := normalizeSource(f.Source)
		sourceMap[src] = append(sourceMap[src], f)
	}

	// 2. Build source stats
	for src, srcFindings := range sourceMap {
		stats := SourceStats{
			Source:         src,
			TotalFindings:  len(srcFindings),
			SeverityCounts: make(map[string]int),
		}
		catSet := make(map[string]bool)
		for _, f := range srcFindings {
			stats.SeverityCounts[f.Severity]++
			catSet[f.Category] = true
		}
		for cat := range catSet {
			stats.Categories = append(stats.Categories, cat)
		}
		sort.Strings(stats.Categories)
		result.Sources = append(result.Sources, stats)
	}
	sort.Slice(result.Sources, func(i, j int) bool {
		return result.Sources[i].Source < result.Sources[j].Source
	})

	// 3. Find correlations (same resource flagged by multiple sources)
	resourceSourceMap := make(map[string]map[string]rules.Finding)
	for _, f := range findings {
		src := normalizeSource(f.Source)
		if _, ok := resourceSourceMap[f.Resource]; !ok {
			resourceSourceMap[f.Resource] = make(map[string]rules.Finding)
		}
		existing, exists := resourceSourceMap[f.Resource][src]
		if !exists || severityRank(f.Severity) < severityRank(existing.Severity) {
			resourceSourceMap[f.Resource][src] = f
		}
	}

	for resource, sources := range resourceSourceMap {
		if len(sources) < 2 {
			continue
		}
		var sourceNames []string
		maxSev := rules.SeverityInfo
		for src, f := range sources {
			sourceNames = append(sourceNames, src)
			if severityRank(f.Severity) < severityRank(maxSev) {
				maxSev = f.Severity
			}
		}
		sort.Strings(sourceNames)
		confidence := "medium"
		if len(sourceNames) >= 3 {
			confidence = "high"
		}
		result.Correlations = append(result.Correlations, Correlation{
			Resource:    resource,
			Message:     fmt.Sprintf("Flagged by %d sources: %s", len(sourceNames), strings.Join(sourceNames, ", ")),
			Sources:     sourceNames,
			MaxSeverity: maxSev,
			Confidence:  confidence,
		})
	}
	sort.Slice(result.Correlations, func(i, j int) bool {
		return severityRank(result.Correlations[i].MaxSeverity) < severityRank(result.Correlations[j].MaxSeverity)
	})

	// 4. Detect coverage gaps
	result.CoverageGaps = detectCoverageGaps(sourceMap)

	// 5. Compute unified score
	result.UnifiedScore = computeUnifiedScore(findings, result.Correlations)

	// 6. Build summary
	result.Summary = a.buildSummary(result, len(findings))

	return result
}

func normalizeSource(source string) string {
	if source == "" {
		return "unknown"
	}
	if strings.HasPrefix(source, "external:") {
		return source[9:]
	}
	return source
}

func severityRank(sev string) int {
	ranks := map[string]int{
		rules.SeverityCritical: 0,
		rules.SeverityHigh:     1,
		rules.SeverityMedium:   2,
		rules.SeverityLow:      3,
		rules.SeverityInfo:     4,
	}
	if r, ok := ranks[sev]; ok {
		return r
	}
	return 5
}

func detectCoverageGaps(sourceMap map[string][]rules.Finding) []string {
	var gaps []string

	if len(sourceMap) == 1 {
		for src := range sourceMap {
			gaps = append(gaps, fmt.Sprintf("Only %s findings present. Consider adding more analysis tools for broader coverage.", src))
		}
	}

	allCategories := make(map[string]bool)
	for _, srcFindings := range sourceMap {
		for _, f := range srcFindings {
			allCategories[f.Category] = true
		}
	}

	expectedCategories := []string{rules.CategorySecurity, rules.CategoryCompliance, rules.CategoryBestPractice}
	for _, expected := range expectedCategories {
		if !allCategories[expected] {
			gaps = append(gaps, fmt.Sprintf("No %s findings detected. Consider adding a tool that covers %s analysis.", expected, expected))
		}
	}

	return gaps
}

// computeUnifiedScore calculates a 0–10 score from cross-tool findings using
// the same logarithmic volume-penalty approach as the scoring package. This
// avoids the unbounded linear formula (10 - Σpenalty) that collapses to 0.0
// for any plan with more than ~5 HIGH findings regardless of its size.
//
// Algorithm (mirrors scorer.go volumePenalty):
//  1. Compute a weighted sum with CRITICAL=3, HIGH=2, MEDIUM=0.8, LOW=0.3.
//  2. Apply a 0.5× correlation boost for each additional confirming source.
//  3. Normalise to "HIGH-equivalent count" (weightedSum / 2.0).
//  4. penalty = log2(1 + highEquivCount) × 1.5
//  5. score   = 10 − min(penalty, 10)   → clamped to [0, 10], rounded to 1dp.
//
// Reference points:
//
//	0 findings              → 10.0
//	1 CRITICAL              →  8.0
//	3 CRITICAL + 5 HIGH     →  6.1
//	25 HIGH                 →  2.9
//	100 HIGH                →  0.0
func computeUnifiedScore(findings []rules.Finding, correlations []Correlation) float64 {
	if len(findings) == 0 {
		return 10.0
	}

	weights := map[string]float64{
		rules.SeverityCritical: 3.0,
		rules.SeverityHigh:     2.0,
		rules.SeverityMedium:   0.8,
		rules.SeverityLow:      0.3,
		rules.SeverityInfo:     0.0,
	}

	weightedSum := 0.0
	for _, f := range findings {
		if w, ok := weights[f.Severity]; ok {
			weightedSum += w
		}
	}

	// Correlation boost: extra confidence penalty for multi-source findings.
	for _, c := range correlations {
		boost := float64(len(c.Sources)-1) * 0.5
		if w, ok := weights[c.MaxSeverity]; ok {
			weightedSum += w * boost
		}
	}

	// Logarithmic penalty normalised to HIGH-equivalent count.
	// Mirrors scorer.go: highEquivCount = weightedSum / highWeight (2.0).
	highEquivCount := weightedSum / 2.0
	penalty := math.Log2(1+highEquivCount) * 1.5

	score := 10.0 - math.Min(penalty, 10.0)
	if score < 0 {
		score = 0
	}
	return math.Round(score*10) / 10
}

func (a *Analyzer) buildSummary(result *MetaResult, totalFindings int) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Meta-analysis: %d findings from %d sources.", totalFindings, len(result.Sources)))
	if len(result.Correlations) > 0 {
		parts = append(parts, fmt.Sprintf("%d resources flagged by multiple tools (high confidence).", len(result.Correlations)))
	}
	if len(result.CoverageGaps) > 0 {
		parts = append(parts, fmt.Sprintf("%d coverage gaps identified.", len(result.CoverageGaps)))
	}
	parts = append(parts, fmt.Sprintf("Unified score: %.1f/10.", result.UnifiedScore))
	return strings.Join(parts, " ")
}
