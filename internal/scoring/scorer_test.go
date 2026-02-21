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
