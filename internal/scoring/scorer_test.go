package scoring

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestScorer_NoFindings(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	score := scorer.Calculate(nil, 10)

	assertScore(t, "security", score.SecurityScore, 10.0)
	assertScore(t, "maintainability", score.MaintainabilityScore, 10.0)
	assertScore(t, "compliance", score.ComplianceScore, 10.0)
	assertScore(t, "overall", score.OverallScore, 10.0)
}

func TestScorer_ZeroResources(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	score := scorer.Calculate(nil, 0)

	assertScore(t, "overall", score.OverallScore, 10.0)
}

func TestScorer_SingleMediumNeverBelow5(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
	}

	score := scorer.Calculate(findings, 1)

	if score.ComplianceScore < 5.0 {
		t.Errorf("MEDIUM alone should not reduce compliance score below 5.0, got %.1f", score.ComplianceScore)
	}
	if score.OverallScore < 5.0 {
		t.Errorf("MEDIUM alone should not reduce overall score below 5.0, got %.1f", score.OverallScore)
	}
}

func TestScorer_MultipleMediumNeverBelow5(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
	}

	score := scorer.Calculate(findings, 2)

	if score.ComplianceScore < 5.0 {
		t.Errorf("only MEDIUM findings should not reduce compliance score below 5.0, got %.1f", score.ComplianceScore)
	}
}

func TestScorer_TwoHighFindings(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
	}

	score := scorer.Calculate(findings, 5)

	if score.SecurityScore >= 10.0 {
		t.Errorf("expected security score < 10.0 with HIGH findings, got %.1f", score.SecurityScore)
	}
	if score.SecurityScore < 2.0 {
		t.Errorf("HIGH without CRITICAL should not go below 2.0, got %.1f", score.SecurityScore)
	}
}

func TestScorer_CriticalCanZero(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityCritical, Category: rules.CategorySecurity},
	}

	score := scorer.Calculate(findings, 1)

	if score.SecurityScore >= 5.0 {
		t.Errorf("CRITICAL should heavily penalize, got security %.1f", score.SecurityScore)
	}
}

func TestScorer_ManyCriticalsClampsToZero(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := make([]rules.Finding, 0)
	for i := 0; i < 10; i++ {
		findings = append(findings, rules.Finding{
			Severity: rules.SeverityCritical,
			Category: rules.CategorySecurity,
		})
	}

	score := scorer.Calculate(findings, 3)

	if score.SecurityScore != 0.0 {
		t.Errorf("many CRITICALs should clamp to 0.0, got %.1f", score.SecurityScore)
	}
	// Overall is a weighted average: only security is affected, other categories remain at 10.0
	// overall = (sec*3 + comp*2 + maint*1.5 + rel*1) / 7.5 = (0*3 + 10*2 + 10*1.5 + 10*1) / 7.5 = 6.0
	if score.OverallScore > 7.0 {
		t.Errorf("many CRITICALs should reduce overall significantly, got %.1f", score.OverallScore)
	}
}

func TestScorer_ScoreNeverNegative(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := make([]rules.Finding, 0)
	for i := 0; i < 50; i++ {
		findings = append(findings, rules.Finding{
			Severity: rules.SeverityCritical,
			Category: rules.CategorySecurity,
		})
	}

	score := scorer.Calculate(findings, 2)

	if score.SecurityScore < 0 {
		t.Errorf("security score should be >= 0, got %.1f", score.SecurityScore)
	}
	if score.OverallScore < 0 {
		t.Errorf("overall score should be >= 0, got %.1f", score.OverallScore)
	}
}

func TestScorer_MaintainabilityFinding(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategoryMaintainability},
	}

	score := scorer.Calculate(findings, 5)

	if score.MaintainabilityScore >= 10.0 {
		t.Errorf("expected maintainability < 10.0, got %.1f", score.MaintainabilityScore)
	}
	if score.MaintainabilityScore < 5.0 {
		t.Errorf("single MEDIUM should not drop maintainability below 5.0, got %.1f", score.MaintainabilityScore)
	}
	// Security should be unaffected
	assertScore(t, "security", score.SecurityScore, 10.0)
}

func TestScorer_MixedSeverities(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityCritical, Category: rules.CategorySecurity},
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
		{Severity: rules.SeverityLow, Category: rules.CategoryMaintainability},
	}

	score := scorer.Calculate(findings, 3)

	if score.SecurityScore >= 8.0 {
		t.Errorf("CRITICAL+HIGH should reduce security significantly, got %.1f", score.SecurityScore)
	}
	if score.ComplianceScore < 5.0 {
		t.Errorf("single MEDIUM should not reduce compliance below 5.0, got %.1f", score.ComplianceScore)
	}
}

func TestScorer_SmallPlanProportional(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	// 2 resources, 2 MEDIUM compliance findings — the scenario that was zeroing before
	findings := []rules.Finding{
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
		{Severity: rules.SeverityMedium, Category: rules.CategoryCompliance},
	}

	score := scorer.Calculate(findings, 2)

	if score.OverallScore < 5.0 {
		t.Errorf("2 MEDIUM on 2 resources should NOT zero overall, got %.1f", score.OverallScore)
	}
	if score.ComplianceScore < 5.0 {
		t.Errorf("2 MEDIUM on 2 resources should NOT zero compliance, got %.1f", score.ComplianceScore)
	}
}

func assertScore(t *testing.T, name string, got, expected float64) {
	t.Helper()
	if got != expected {
		t.Errorf("expected %s score %.1f, got %.1f", name, expected, got)
	}
}

// ---------------------------------------------------------------------------
// clampScore edge cases
// ---------------------------------------------------------------------------

func TestClampScore_Negative(t *testing.T) {
	got := clampScore(-5.0)
	if got != 0 {
		t.Errorf("expected 0 for negative, got %f", got)
	}
}

func TestClampScore_AboveTen(t *testing.T) {
	got := clampScore(15.7)
	if got != 10 {
		t.Errorf("expected 10 for above ten, got %f", got)
	}
}

func TestClampScore_Normal(t *testing.T) {
	got := clampScore(7.55)
	if got != 7.6 { // Rounds to 1 decimal: 7.55 * 10 = 75.5 → Round → 76 / 10 = 7.6
		t.Errorf("expected 7.6, got %f", got)
	}
}

func TestClampScore_Zero(t *testing.T) {
	got := clampScore(0)
	if got != 0 {
		t.Errorf("expected 0, got %f", got)
	}
}

func TestClampScore_Ten(t *testing.T) {
	got := clampScore(10)
	if got != 10 {
		t.Errorf("expected 10, got %f", got)
	}
}

// ---------------------------------------------------------------------------
// filterByCategories edge cases
// ---------------------------------------------------------------------------

func TestFilterByCategories_NoMatch(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "HIGH", Category: "Security"},
	}
	result := filterByCategories(findings, "Compliance")
	if len(result) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result))
	}
}

func TestFilterByCategories_MultipleCategories(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "HIGH", Category: "Security"},
		{Severity: "MEDIUM", Category: "BestPractice"},
		{Severity: "LOW", Category: "Compliance"},
	}
	result := filterByCategories(findings, "Security", "BestPractice")
	if len(result) != 2 {
		t.Errorf("expected 2 findings, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// Scorer — Reliability blending
// ---------------------------------------------------------------------------

func TestScorer_ReliabilityBlending(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityHigh, Category: rules.CategoryReliability},
	}
	score := scorer.Calculate(findings, 10)
	// Reliability blends into security and compliance
	if score.SecurityScore >= 10.0 {
		t.Errorf("security should be affected by reliability finding, got %.1f", score.SecurityScore)
	}
}

// TestScorer_LargeInfraVolumePenalty ensures that many HIGH findings on a
// large plan are not diluted to near-perfect scores. This was the original
// bug: 174 HIGH on 380 resources scored 8.2/10 with pure density formula.
func TestScorer_LargeInfraVolumePenalty(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := make([]rules.Finding, 0, 174)
	for i := 0; i < 174; i++ {
		findings = append(findings, rules.Finding{
			Severity: rules.SeverityHigh,
			Category: rules.CategorySecurity,
		})
	}

	score := scorer.Calculate(findings, 380)

	// With volume penalty: log2(1+174)*0.5 ≈ 3.73 → score ≈ 6.3
	// Must be significantly below 8.0 (old formula gave 8.2)
	if score.SecurityScore >= 7.5 {
		t.Errorf("174 HIGH on 380 resources should score below 7.5, got %.1f (volume penalty not effective)", score.SecurityScore)
	}
	// But should not be below 2.0 (HIGH floor)
	if score.SecurityScore < 2.0 {
		t.Errorf("HIGH-only floor violated: got %.1f", score.SecurityScore)
	}
}

// TestScorer_SmallPlanDensityStillWorks ensures the density formula still
// dominates for small plans where it matters more.
func TestScorer_SmallPlanDensityStillWorks(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
	}

	score := scorer.Calculate(findings, 2)

	// density = (2*3/2)*2 = 6.0 → score = 4.0
	// volume = log2(1+2)*0.5 = 0.79 → score = 9.2
	// max(density, volume) = density → score = 4.0
	if score.SecurityScore > 5.0 {
		t.Errorf("2 HIGH on 2 resources should be significantly penalized, got %.1f", score.SecurityScore)
	}
}
