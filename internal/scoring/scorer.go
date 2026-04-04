package scoring

import (
	"math"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// Score represents the computed quality scores.
type Score struct {
	SecurityScore        float64 `json:"security_score"`
	MaintainabilityScore float64 `json:"maintainability_score"`
	ComplianceScore      float64 `json:"compliance_score"`
	OverallScore         float64 `json:"overall_score"`
}

// Scorer computes quality scores from findings using proportional penalties.
//
// Formula per category:
//
//	weighted_sum = sum of severity weights for that category
//	penalty_ratio = weighted_sum / total_resources
//	score = 10 - min(penalty_ratio * scale_factor, 10)
//
// Constraints:
//   - MEDIUM alone can never reduce a category score below 5.0
//   - CRITICAL can reduce score to 0.0
//   - No findings = 10.0
type Scorer struct {
	severityWeights map[string]float64
}

// NewScorerWithWeights creates a Scorer with custom severity weights.
func NewScorerWithWeights(critical, high, medium, low float64) *Scorer {
	return &Scorer{
		severityWeights: map[string]float64{
			rules.SeverityCritical: critical,
			rules.SeverityHigh:     high,
			rules.SeverityMedium:   medium,
			rules.SeverityLow:      low,
			rules.SeverityInfo:     0.0,
		},
	}
}

// Calculate computes scores from a list of findings and total resources analyzed.
func (s *Scorer) Calculate(findings []rules.Finding, totalResources int) Score {
	if len(findings) == 0 || totalResources == 0 {
		return Score{
			SecurityScore:        10.0,
			MaintainabilityScore: 10.0,
			ComplianceScore:      10.0,
			OverallScore:         10.0,
		}
	}

	// Bucket findings by category
	secFindings := filterByCategories(findings, rules.CategorySecurity)
	maintFindings := filterByCategories(findings, rules.CategoryMaintainability, rules.CategoryBestPractice)
	compFindings := filterByCategories(findings, rules.CategoryCompliance)
	// Reliability splits across security and compliance
	relFindings := filterByCategories(findings, rules.CategoryReliability)

	secScore := s.computeCategoryScore(secFindings, totalResources)
	maintScore := s.computeCategoryScore(maintFindings, totalResources)
	compScore := s.computeCategoryScore(compFindings, totalResources)
	relScore := s.computeCategoryScore(relFindings, totalResources)

	// Blend reliability into security and compliance
	if len(relFindings) > 0 {
		secScore = (secScore*2 + relScore) / 3
		compScore = (compScore*2 + relScore) / 3
	}

	// Overall = weighted average of category scores.
	overall := (secScore*3 + compScore*2 + maintScore*1.5 + relScore*1) / 7.5

	return Score{
		SecurityScore:        clampScore(secScore),
		MaintainabilityScore: clampScore(maintScore),
		ComplianceScore:      clampScore(compScore),
		OverallScore:         clampScore(overall),
	}
}

func (s *Scorer) computeCategoryScore(findings []rules.Finding, totalResources int) float64 {
	if len(findings) == 0 {
		return 10.0
	}

	weightedSum := 0.0
	hasCritical := false
	hasHigh := false
	onlyMediumOrBelow := true

	for _, f := range findings {
		w := s.severityWeights[f.Severity]
		weightedSum += w

		switch f.Severity {
		case rules.SeverityCritical:
			hasCritical = true
			onlyMediumOrBelow = false
		case rules.SeverityHigh:
			hasHigh = true
			onlyMediumOrBelow = false
		}
	}

	// Density penalty: proportional to findings-per-resource (original formula)
	densityPenalty := (weightedSum / math.Max(float64(totalResources), 1.0)) * 2.0

	// Volume penalty: logarithmic penalty based on absolute count of findings.
	// Prevents large infrastructures from diluting many HIGH/CRITICAL findings.
	// Uses high-equivalent count: normalises all findings relative to the HIGH weight.
	// Multiplier 1.5 ensures many HIGH findings drive the score down aggressively
	// (e.g. 174 HIGH → penalty ≈ 11 → floor at 2.0 for HIGH-only).
	highWeight := s.severityWeights[rules.SeverityHigh]
	if highWeight == 0 {
		highWeight = 1.0
	}
	highEquivCount := weightedSum / highWeight
	volumePenalty := math.Log2(1+highEquivCount) * 1.5

	// Take the harsher of the two penalties
	penalty := math.Max(densityPenalty, volumePenalty)
	score := 10.0 - math.Min(penalty, 10.0)

	// MEDIUM alone can never reduce below 5.0
	if onlyMediumOrBelow && score < 5.0 {
		score = 5.0
	}

	// HIGH can push down to 2.0 minimum (unless also CRITICAL)
	if hasHigh && !hasCritical && score < 2.0 {
		score = 2.0
	}

	// CRITICAL can zero it out — no floor
	return score
}

func filterByCategories(findings []rules.Finding, categories ...string) []rules.Finding {
	catSet := make(map[string]bool, len(categories))
	for _, c := range categories {
		catSet[c] = true
	}

	var result []rules.Finding
	for _, f := range findings {
		if catSet[f.Category] {
			result = append(result, f)
		}
	}
	return result
}

// clampScore ensures a score stays within [0, 10] and rounds to 1 decimal.
func clampScore(score float64) float64 {
	if score < 0 {
		score = 0
	}
	if score > 10 {
		score = 10
	}
	return math.Round(score*10) / 10
}
