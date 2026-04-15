package eval

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestCompare_AllSatisfied(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "AI_S3_PUBLIC", Severity: "HIGH", Resource: "aws_s3_bucket.x", Message: "Bucket is public-read"},
		{RuleID: "AI_S3_NO_KMS", Severity: "MEDIUM", Resource: "aws_s3_bucket.x", Message: "Missing KMS encryption"},
	}
	g := Golden{
		RequiredTopics:    []string{"public", "kms"},
		RequiredResources: []string{"aws_s3_bucket.x"},
		MinSeverity:       map[string]int{"HIGH": 1, "MEDIUM": 1},
		SummaryContains:   []string{"risk"},
	}
	failures := Compare(findings, "Overall risk: high", g)
	if len(failures) != 0 {
		t.Errorf("expected zero failures, got %v", failures)
	}
}

func TestCompare_MissingTopic(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "AI_1", Severity: "HIGH", Resource: "x", Message: "Something"},
	}
	g := Golden{RequiredTopics: []string{"encryption"}}
	failures := Compare(findings, "", g)
	if len(failures) != 1 || !strings.Contains(failures[0], "encryption") {
		t.Errorf("expected encryption failure, got %v", failures)
	}
}

func TestCompare_MissingResource(t *testing.T) {
	findings := []rules.Finding{{Resource: "aws_s3_bucket.a", Message: "x"}}
	g := Golden{RequiredResources: []string{"aws_s3_bucket.b"}}
	failures := Compare(findings, "", g)
	if len(failures) != 1 || !strings.Contains(failures[0], "aws_s3_bucket.b") {
		t.Errorf("expected missing resource failure, got %v", failures)
	}
}

func TestCompare_MinSeverityShortfall(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "LOW", Message: "x"},
	}
	g := Golden{MinSeverity: map[string]int{"HIGH": 1, "LOW": 2}}
	failures := Compare(findings, "", g)
	if len(failures) != 2 {
		t.Fatalf("expected 2 severity failures, got %v", failures)
	}
}

func TestCompare_MaxFindingsExceeded(t *testing.T) {
	findings := make([]rules.Finding, 5)
	g := Golden{MaxFindings: 3}
	failures := Compare(findings, "", g)
	if len(failures) != 1 || !strings.Contains(failures[0], "too many") {
		t.Errorf("expected too-many-findings failure, got %v", failures)
	}
}

func TestCompare_SummaryCaseInsensitive(t *testing.T) {
	g := Golden{SummaryContains: []string{"Critical"}}
	if failures := Compare(nil, "overall assessment: critical risk", g); len(failures) != 0 {
		t.Errorf("expected case-insensitive match, got %v", failures)
	}
	if failures := Compare(nil, "overall assessment: low risk", g); len(failures) != 1 {
		t.Errorf("expected one failure for missing summary substring, got %v", failures)
	}
}

func TestCompare_EmptyGoldenIsAlwaysPass(t *testing.T) {
	findings := []rules.Finding{{Severity: "LOW"}}
	if failures := Compare(findings, "anything", Golden{}); len(failures) != 0 {
		t.Errorf("empty golden should never fail, got %v", failures)
	}
}
