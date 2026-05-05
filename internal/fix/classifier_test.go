package fix

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func mkPending(hcl, mrr, blast string) PendingFix {
	return PendingFix{
		Finding: rules.Finding{
			RuleID:   "CKV_AWS_FAKE",
			Resource: "aws_s3_bucket.foo",
			Source:   "checkov",
			Category: "security",
		},
		Suggestion: &FixSuggestion{
			HCL:                hcl,
			ManualReviewReason: mrr,
			BlastRadius:        blast,
		},
	}
}

func TestClassify_AISelfAssessment_ManualReviewReasonPromotes(t *testing.T) {
	c := NewClassifier(nil)
	pf := mkPending(`resource "aws_s3_bucket" "foo" {}`, "removes a bucket policy used by the audit pipeline", "low")

	adv := c.Classify(pf)
	if adv == nil {
		t.Fatal("expected promotion to advisory when manual_review_reason is non-empty")
	}
	if adv.Group != AdvisoryManualReview {
		t.Errorf("group=%v, want AdvisoryManualReview", adv.Group)
	}
	if !strings.Contains(adv.Reason, "AI flagged") {
		t.Errorf("reason should mention AI flag, got %q", adv.Reason)
	}
	if !strings.Contains(adv.Reason, "audit pipeline") {
		t.Errorf("reason should include AI explanation, got %q", adv.Reason)
	}
}

func TestClassify_AISelfAssessment_HighBlastRadiusPromotes(t *testing.T) {
	c := NewClassifier(nil)
	pf := mkPending(`resource "aws_s3_bucket" "foo" {}`, "", "high")

	adv := c.Classify(pf)
	if adv == nil {
		t.Fatal("expected promotion when blast_radius is high")
	}
	if adv.Group != AdvisoryCrossResource {
		t.Errorf("group=%v, want AdvisoryCrossResource", adv.Group)
	}
}

func TestClassify_AISelfAssessment_LowBlastRadiusDoesNotPromote(t *testing.T) {
	c := NewClassifier(nil)
	pf := mkPending(`resource "aws_s3_bucket" "foo" {}`, "", "low")

	if adv := c.Classify(pf); adv != nil {
		t.Errorf("expected NO promotion, got %+v", adv)
	}
}

func TestClassify_AISelfAssessment_EmptyBlastRadiusDoesNotPromote(t *testing.T) {
	// Defensive: providers may omit the field entirely.
	c := NewClassifier(nil)
	pf := mkPending(`resource "aws_s3_bucket" "foo" {}`, "", "")

	if adv := c.Classify(pf); adv != nil {
		t.Errorf("expected NO promotion when both fields empty, got %+v", adv)
	}
}

func TestClassify_AISelfAssessment_ReasonTrimmedAndTruncated(t *testing.T) {
	c := NewClassifier(nil)
	long := strings.Repeat("a very long reason ", 30)
	pf := mkPending(`resource "aws_s3_bucket" "foo" {}`, long, "low")

	adv := c.Classify(pf)
	if adv == nil {
		t.Fatal("expected promotion")
	}
	if len(adv.Reason) > 200 {
		t.Errorf("reason should be truncated, got len=%d", len(adv.Reason))
	}
}

func TestNormalizeBlastRadius(t *testing.T) {
	cases := map[string]string{
		"none":     "none",
		"low":      "low",
		"medium":   "medium",
		"high":     "high",
		"":         "low",
		"unknown":  "low",
		"HIGH":     "low", // case-sensitive — providers must use lowercase
		"critical": "low", // not in our spec
	}
	for in, want := range cases {
		if got := normalizeBlastRadius(in); got != want {
			t.Errorf("normalizeBlastRadius(%q)=%q, want %q", in, got, want)
		}
	}
}
