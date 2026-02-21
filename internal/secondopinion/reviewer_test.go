package secondopinion

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestParseSecondOpinionResponse_ValidJSON(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: "HIGH", Resource: "aws_instance.web", Message: "No encryption"},
	}

	raw := `{"assessments": [{"rule_id": "SEC001", "resource": "aws_instance.web", "agree": true, "confidence": "high", "context": "Valid concern"}], "summary": "All findings validated", "agree_count": 1, "dispute_count": 0}`

	result, err := parseSecondOpinionResponse(raw, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Assessments) != 1 {
		t.Errorf("expected 1 assessment, got %d", len(result.Assessments))
	}
	if !result.Assessments[0].Agree {
		t.Error("expected AI to agree")
	}
}

func TestParseSecondOpinionResponse_Fallback(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: "HIGH", Resource: "aws_instance.web", Message: "No encryption"},
		{RuleID: "SEC002", Severity: "MEDIUM", Resource: "aws_s3_bucket.data", Message: "No versioning"},
	}

	raw := "This is not valid JSON at all"

	result, err := parseSecondOpinionResponse(raw, findings)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Assessments) != 2 {
		t.Errorf("expected 2 fallback assessments, got %d", len(result.Assessments))
	}
	if result.AgreeCount != 2 {
		t.Errorf("expected agree_count=2, got %d", result.AgreeCount)
	}
}

func TestEnrichFindings_WithAssessments(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Resource: "aws_instance.web", Message: "Test", Remediation: "Fix it"},
	}

	result := &ReviewResult{
		Assessments: []Assessment{
			{RuleID: "SEC001", Resource: "aws_instance.web", Agree: false, Confidence: "high", Context: "Acceptable in dev"},
		},
	}

	enriched := EnrichFindings(findings, result)
	if len(enriched) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(enriched))
	}
	if enriched[0].Remediation == "Fix it" {
		t.Error("expected remediation to be enriched with AI context")
	}
}

func TestEnrichFindings_NilResult(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Resource: "aws_instance.web"},
	}

	enriched := EnrichFindings(findings, nil)
	if len(enriched) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(enriched))
	}
}

func TestReviewResult_EmptyFindings(t *testing.T) {
	result, err := parseSecondOpinionResponse("", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Assessments) != 0 {
		t.Errorf("expected 0 assessments for empty findings, got %d", len(result.Assessments))
	}
}
