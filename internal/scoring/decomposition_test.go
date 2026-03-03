package scoring

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestDecompose_NoFindings(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	d := scorer.Decompose(nil, 10)

	assertScore(t, "security decomp", d.Security.FinalScore, 10.0)
	assertScore(t, "compliance decomp", d.Compliance.FinalScore, 10.0)
	assertScore(t, "maintainability decomp", d.Maintainability.FinalScore, 10.0)
	assertScore(t, "reliability decomp", d.Reliability.FinalScore, 10.0)
	assertScore(t, "overall decomp", d.Overall.FinalScore, 10.0)

	if len(d.Security.FindingsImpact) != 0 {
		t.Errorf("expected 0 findings impact, got %d", len(d.Security.FindingsImpact))
	}
}

func TestDecompose_ZeroResources(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	d := scorer.Decompose(nil, 0)

	assertScore(t, "overall decomp", d.Overall.FinalScore, 10.0)
}

func TestDecompose_MatchesCalculate(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_18", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "aws_s3_bucket.data", Source: "scanner:checkov"},
		{RuleID: "CKV_AWS_21", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "aws_s3_bucket.data", Source: "scanner:checkov"},
		{RuleID: "TAG_MISSING", Severity: rules.SeverityMedium, Category: rules.CategoryCompliance, Resource: "aws_instance.web", Source: "scanner:tfsec"},
		{RuleID: "BKP_001", Severity: rules.SeverityMedium, Category: rules.CategoryReliability, Resource: "aws_rds_instance.db", Source: "llm"},
	}

	score := scorer.Calculate(findings, 5)
	d := scorer.Decompose(findings, 5)

	// Final scores from decomposition must match Calculate()
	assertScore(t, "security final", d.Security.FinalScore, score.SecurityScore)
	assertScore(t, "compliance final", d.Compliance.FinalScore, score.ComplianceScore)
	assertScore(t, "maintainability final", d.Maintainability.FinalScore, score.MaintainabilityScore)
	assertScore(t, "overall final", d.Overall.FinalScore, score.OverallScore)
}

func TestDecompose_FindingsImpactPresent(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_18", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "aws_s3_bucket.data", Source: "scanner:checkov", Message: "Ensure the S3 bucket has encryption enabled"},
		{RuleID: "TAG_001", Severity: rules.SeverityMedium, Category: rules.CategoryCompliance, Resource: "aws_instance.web", Source: "scanner:tfsec"},
	}

	d := scorer.Decompose(findings, 3)

	// Security should have 1 finding with weight 5.0
	if len(d.Security.FindingsImpact) != 1 {
		t.Fatalf("expected 1 security finding, got %d", len(d.Security.FindingsImpact))
	}
	fi := d.Security.FindingsImpact[0]
	if fi.RuleID != "CKV_AWS_18" {
		t.Errorf("expected RuleID=CKV_AWS_18, got %s", fi.RuleID)
	}
	if fi.Weight != 5.0 {
		t.Errorf("expected weight=5.0, got %.1f", fi.Weight)
	}
	if fi.ImpactOnScore >= 0 {
		t.Errorf("expected negative impact, got %.2f", fi.ImpactOnScore)
	}

	// Compliance should have 1 finding
	if len(d.Compliance.FindingsImpact) != 1 {
		t.Fatalf("expected 1 compliance finding, got %d", len(d.Compliance.FindingsImpact))
	}

	// Maintainability and Reliability should have 0
	if len(d.Maintainability.FindingsImpact) != 0 {
		t.Errorf("expected 0 maintainability findings, got %d", len(d.Maintainability.FindingsImpact))
	}
	if len(d.Reliability.FindingsImpact) != 0 {
		t.Errorf("expected 0 reliability findings, got %d", len(d.Reliability.FindingsImpact))
	}
}

func TestDecompose_FloorConstraints(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)

	// MEDIUM-only should floor at 5.0
	medFindings := []rules.Finding{
		{RuleID: "M1", Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{RuleID: "M2", Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{RuleID: "M3", Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{RuleID: "M4", Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
		{RuleID: "M5", Severity: rules.SeverityMedium, Category: rules.CategorySecurity},
	}
	d := scorer.Decompose(medFindings, 1)
	if d.Security.FinalScore < 5.0 {
		t.Errorf("MEDIUM-only floor violated: got %.1f", d.Security.FinalScore)
	}
	if d.Security.FloorApplied == "" {
		t.Errorf("expected floor note, got empty")
	}

	// HIGH-only should floor at 2.0
	highFindings := []rules.Finding{
		{RuleID: "H1", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{RuleID: "H2", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{RuleID: "H3", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{RuleID: "H4", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{RuleID: "H5", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
		{RuleID: "H6", Severity: rules.SeverityHigh, Category: rules.CategorySecurity},
	}
	d = scorer.Decompose(highFindings, 1)
	if d.Security.FinalScore < 2.0 {
		t.Errorf("HIGH-only floor violated: got %.1f", d.Security.FinalScore)
	}
}

func TestDecompose_ReliabilityBlending(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{RuleID: "SEC1", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "r1"},
		{RuleID: "REL1", Severity: rules.SeverityHigh, Category: rules.CategoryReliability, Resource: "r2"},
	}

	d := scorer.Decompose(findings, 5)

	// Security should be blended with reliability
	if d.Security.BlendingNote == "" {
		t.Errorf("expected blending note on security, got empty")
	}
	// Compliance also gets blended
	if d.Compliance.BlendingNote == "" {
		t.Errorf("expected blending note on compliance, got empty")
	}
}

func TestDecompose_OverallComponents(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	d := scorer.Decompose(nil, 10)

	if len(d.Overall.Components) != 4 {
		t.Fatalf("expected 4 overall components, got %d", len(d.Overall.Components))
	}

	expectedWeights := map[string]float64{
		"security":        3.0,
		"compliance":      2.0,
		"maintainability": 1.5,
		"reliability":     1.0,
	}
	for _, c := range d.Overall.Components {
		expected, ok := expectedWeights[c.Category]
		if !ok {
			t.Errorf("unexpected category %s", c.Category)
			continue
		}
		if c.Weight != expected {
			t.Errorf("category %s weight: expected %.1f, got %.1f", c.Category, expected, c.Weight)
		}
	}
}

func TestDecompose_RiskVectorInference(t *testing.T) {
	scorer := NewScorerWithWeights(5, 3, 1, 0.5)
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_18", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Message: "Ensure S3 bucket has encryption enabled"},
		{RuleID: "SG_OPEN", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Message: "Security group allows 0.0.0.0/0 ingress"},
		{RuleID: "IAM_ADMIN", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Message: "IAM policy has admin privileges"},
	}

	d := scorer.Decompose(findings, 3)

	// Check that risk vectors were inferred
	for _, fi := range d.Security.FindingsImpact {
		if len(fi.RiskVectors) == 0 {
			t.Errorf("finding %s should have risk vectors", fi.RuleID)
		}
	}

	// Encryption finding should have "encryption" vector
	if d.Security.FindingsImpact[0].RiskVectors[0] != "encryption" {
		t.Errorf("expected encryption vector for CKV_AWS_18, got %v", d.Security.FindingsImpact[0].RiskVectors)
	}

	// Network finding should have "network" vector
	hasNetwork := false
	for _, v := range d.Security.FindingsImpact[1].RiskVectors {
		if v == "network" {
			hasNetwork = true
		}
	}
	if !hasNetwork {
		t.Errorf("expected network vector for SG_OPEN, got %v", d.Security.FindingsImpact[1].RiskVectors)
	}

	// IAM finding should have "identity" vector
	hasIdentity := false
	for _, v := range d.Security.FindingsImpact[2].RiskVectors {
		if v == "identity" {
			hasIdentity = true
		}
	}
	if !hasIdentity {
		t.Errorf("expected identity vector for IAM_ADMIN, got %v", d.Security.FindingsImpact[2].RiskVectors)
	}
}
