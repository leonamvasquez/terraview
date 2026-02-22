package normalizer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ── IsEquivalent tests ─────────────────────────────────────────────

func TestIsEquivalent_ExactMatch(t *testing.T) {
	s := rules.Finding{Resource: "aws_instance.web", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_instance.web", Category: "security", Severity: "HIGH"}
	if !IsEquivalent(s, a) {
		t.Error("identical resource+category+severity should be equivalent")
	}
}

func TestIsEquivalent_CaseInsensitive(t *testing.T) {
	s := rules.Finding{Resource: "AWS_Instance.Web", Category: "Security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_instance.web", Category: "security", Severity: "HIGH"}
	if !IsEquivalent(s, a) {
		t.Error("case-insensitive resource+category should be equivalent")
	}
}

func TestIsEquivalent_SeverityWithinOneRank(t *testing.T) {
	s := rules.Finding{Resource: "aws_sg.test", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_sg.test", Category: "security", Severity: "MEDIUM"}
	if !IsEquivalent(s, a) {
		t.Error("HIGH and MEDIUM (1 rank apart) should be equivalent")
	}
}

func TestIsEquivalent_SeverityIgnored(t *testing.T) {
	s := rules.Finding{Resource: "aws_sg.test", Category: "security", Severity: "CRITICAL"}
	a := rules.Finding{Resource: "aws_sg.test", Category: "security", Severity: "LOW"}
	if !IsEquivalent(s, a) {
		t.Error("severity must NOT block equivalence (same resource+category)")
	}
}

func TestIsEquivalent_DifferentResource(t *testing.T) {
	s := rules.Finding{Resource: "aws_instance.alpha", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_instance.beta", Category: "security", Severity: "HIGH"}
	if IsEquivalent(s, a) {
		t.Error("different resources should NOT be equivalent")
	}
}

func TestIsEquivalent_DifferentCategory(t *testing.T) {
	s := rules.Finding{Resource: "aws_instance.web", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_instance.web", Category: "best-practice", Severity: "HIGH"}
	if IsEquivalent(s, a) {
		t.Error("different categories should NOT be equivalent")
	}
}

func TestIsEquivalent_EmptyCategoryDefaultsSecurity(t *testing.T) {
	s := rules.Finding{Resource: "aws_instance.web", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_instance.web", Category: "", Severity: "HIGH"}
	if !IsEquivalent(s, a) {
		t.Error("empty category defaults to security, should match security")
	}
}

// ── Deduplicate tests ──────────────────────────────────────────────

func TestDeduplicate_BothEmpty(t *testing.T) {
	r := Deduplicate(nil, nil)
	if len(r.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(r.Findings))
	}
	if r.Summary != "No findings to deduplicate." {
		t.Errorf("unexpected summary: %s", r.Summary)
	}
}

func TestDeduplicate_ScannerOnly(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov"},
		{RuleID: "CKV_2", Resource: "aws_rds.db", Severity: "MEDIUM", Category: "security", Source: "checkov"},
	}
	r := Deduplicate(scannerFindings, nil)
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(r.Findings))
	}
	if r.ScannerKept != 2 {
		t.Errorf("expected 2 scanner kept, got %d", r.ScannerKept)
	}
	if r.AIDiscarded != 0 || r.AIUniqueKept != 0 {
		t.Error("no AI stats expected when no AI findings")
	}
}

func TestDeduplicate_AIOnly(t *testing.T) {
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_s3.data", Severity: "MEDIUM", Category: "security", Source: "llm"},
	}
	r := Deduplicate(nil, aiFindings)
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1, got %d", len(r.Findings))
	}
	if r.AIUniqueKept != 1 {
		t.Errorf("expected 1 AI unique kept, got %d", r.AIUniqueKept)
	}
}

func TestDeduplicate_EquivalentAIDiscarded(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_instance.web", Severity: "HIGH", Category: "security", Source: "checkov", Message: "Public access"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_SEC_1", Resource: "aws_instance.web", Severity: "HIGH", Category: "security", Source: "llm", Message: "Instance publicly accessible"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 (AI duplicate discarded), got %d", len(r.Findings))
	}
	if r.AIDiscarded != 1 {
		t.Errorf("expected 1 AI discarded, got %d", r.AIDiscarded)
	}
	if r.Findings[0].Source != "checkov" {
		t.Errorf("expected scanner finding preserved, got source %q", r.Findings[0].Source)
	}
}

func TestDeduplicate_AIEnrichment(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov", Remediation: ""},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "llm", Remediation: "Restrict ingress to specific CIDRs"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1, got %d", len(r.Findings))
	}
	if r.AIEnriched != 1 {
		t.Errorf("expected 1 enrichment, got %d", r.AIEnriched)
	}
	if r.Findings[0].Remediation != "Restrict ingress to specific CIDRs" {
		t.Errorf("expected AI remediation attached, got %q", r.Findings[0].Remediation)
	}
}

func TestDeduplicate_EnrichmentWhenScannerHasRemediation(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov", Remediation: "Scanner fix"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "llm", Remediation: "AI fix"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if r.AIEnriched != 1 {
		t.Errorf("should enrich when AI has remediation, got %d", r.AIEnriched)
	}
	want := "Scanner fix\n\nAI Suggestions:\nAI fix"
	if r.Findings[0].Remediation != want {
		t.Errorf("expected appended remediation:\n%s\ngot:\n%s", want, r.Findings[0].Remediation)
	}
}

func TestDeduplicate_DistinctAIKept(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_lambda.func", Severity: "MEDIUM", Category: "best-practice", Source: "llm"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != 2 {
		t.Fatalf("expected 2 (scanner + unique AI), got %d", len(r.Findings))
	}
	if r.AIUniqueKept != 1 {
		t.Errorf("expected 1 AI unique kept, got %d", r.AIUniqueKept)
	}
}

func TestDeduplicate_SameResourceDifferentCategory(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_instance.web", Severity: "HIGH", Category: "security", Source: "checkov"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_BP_1", Resource: "aws_instance.web", Severity: "LOW", Category: "best-practice", Source: "llm"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != 2 {
		t.Fatalf("same resource but different category → both kept, got %d", len(r.Findings))
	}
	if r.AIDiscarded != 0 {
		t.Errorf("should not discard different-category AI finding, got %d discarded", r.AIDiscarded)
	}
}

func TestDeduplicate_SameResourceSameCategoryAnySeverity(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "CRITICAL", Category: "security", Source: "checkov"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "INFO", Category: "security", Source: "llm"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != 1 {
		t.Fatalf("same resource+category should merge regardless of severity, got %d", len(r.Findings))
	}
	if r.Findings[0].Severity != "CRITICAL" {
		t.Errorf("scanner severity must be preserved, got %q", r.Findings[0].Severity)
	}
}

func TestDeduplicate_MultipleAIMatchesSameResource(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov"},
		{RuleID: "CKV_2", Resource: "aws_sg.test", Severity: "MEDIUM", Category: "compliance", Source: "checkov"},
	}
	aiFindings := []rules.Finding{
		// Equivalent to CKV_1 (same resource, same category, close severity)
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "llm"},
		// Different category → unique
		{RuleID: "AI_2", Resource: "aws_sg.test", Severity: "LOW", Category: "best-practice", Source: "llm"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	// 2 scanner + 1 unique AI = 3 (AI_1 discarded as equivalent to CKV_1)
	if len(r.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(r.Findings))
	}
	if r.AIDiscarded != 1 {
		t.Errorf("expected 1 AI discarded, got %d", r.AIDiscarded)
	}
	if r.AIUniqueKept != 1 {
		t.Errorf("expected 1 AI unique, got %d", r.AIUniqueKept)
	}
}

func TestDeduplicate_ScannerFindingsUnmodified(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov", Message: "original message"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "llm", Message: "AI message"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	// Scanner message should not be overwritten
	if r.Findings[0].Message != "original message" {
		t.Errorf("scanner message should be preserved, got %q", r.Findings[0].Message)
	}
	if r.Findings[0].Source != "checkov" {
		t.Errorf("scanner source should be preserved, got %q", r.Findings[0].Source)
	}
}

// ── Performance test ───────────────────────────────────────────────

func TestDeduplicate_Performance10K(t *testing.T) {
	const n = 10000
	scannerFindings := make([]rules.Finding, n/2)
	aiFindings := make([]rules.Finding, n/2)

	categories := []string{"security", "compliance", "best-practice", "reliability"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

	for i := 0; i < n/2; i++ {
		resource := fmt.Sprintf("aws_instance.r%d", i)
		scannerFindings[i] = rules.Finding{
			RuleID:   fmt.Sprintf("CKV_%d", i),
			Resource: resource,
			Severity: severities[i%len(severities)],
			Category: categories[i%len(categories)],
			Source:   "checkov",
		}
		aiFindings[i] = rules.Finding{
			RuleID:   fmt.Sprintf("AI_%d", i),
			Resource: resource,
			Severity: severities[i%len(severities)],
			Category: categories[i%len(categories)],
			Source:   "llm",
		}
	}

	r := Deduplicate(scannerFindings, aiFindings)
	if len(r.Findings) != n/2 {
		t.Errorf("expected %d (all AI discarded as equivalent), got %d", n/2, len(r.Findings))
	}
	if r.AIDiscarded != n/2 {
		t.Errorf("expected %d AI discarded, got %d", n/2, r.AIDiscarded)
	}
}

// ── Helper tests ───────────────────────────────────────────────────

func TestIsEquivalent_CanonicalCategoryVariation(t *testing.T) {
	s := rules.Finding{Resource: "aws_sg.test", Category: "security", Severity: "HIGH"}
	a := rules.Finding{Resource: "aws_sg.test", Category: "iam-security", Severity: "LOW"}
	if !IsEquivalent(s, a) {
		t.Error("iam-security should canonicalize to security")
	}
}

func TestCanonicalRiskCategory(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"security", "security"},
		{"Security", "security"},
		{"SECURITY", "security"},
		{"iam-security", "security"},
		{"network", "security"},
		{"encryption", "security"},
		{"compliance", "compliance"},
		{"regulatory", "compliance"},
		{"best-practice", "best-practice"},
		{"best_practice", "best-practice"},
		{"naming", "best-practice"},
		{"tagging", "best-practice"},
		{"convention", "best-practice"},
		{"maintainability", "maintainability"},
		{"readability", "maintainability"},
		{"complexity", "maintainability"},
		{"reliability", "reliability"},
		{"availability", "reliability"},
		{"disaster", "reliability"},
		{"backup", "reliability"},
		{"", "security"},
		{"unknown", "security"},
		{"cost", "cost"},
	}
	for _, tc := range tests {
		got := canonicalRiskCategory(tc.input)
		if got != tc.want {
			t.Errorf("canonicalRiskCategory(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestEnrichRemediation_ScannerEmpty(t *testing.T) {
	got := enrichRemediation("", "AI fix here")
	if got != "AI fix here" {
		t.Errorf("expected AI text, got %q", got)
	}
}

func TestEnrichRemediation_AIEmpty(t *testing.T) {
	got := enrichRemediation("Scanner fix", "")
	if got != "Scanner fix" {
		t.Errorf("expected scanner text, got %q", got)
	}
}

func TestEnrichRemediation_BothPresent(t *testing.T) {
	got := enrichRemediation("Scanner fix", "Additional AI advice")
	want := "Scanner fix\n\nAI Suggestions:\nAdditional AI advice"
	if got != want {
		t.Errorf("expected appended text:\n%s\ngot:\n%s", want, got)
	}
}

func TestEnrichRemediation_IdenticalText(t *testing.T) {
	got := enrichRemediation("Restrict ingress", "Restrict ingress")
	if got != "Restrict ingress" {
		t.Errorf("identical text should not duplicate, got %q", got)
	}
}

func TestEnrichRemediation_IdenticalCaseInsensitive(t *testing.T) {
	got := enrichRemediation("Restrict Ingress", "restrict ingress")
	if got != "Restrict Ingress" {
		t.Errorf("case-insensitive duplicate should not duplicate, got %q", got)
	}
}

func TestEnrichRemediation_SubstringAlreadyPresent(t *testing.T) {
	got := enrichRemediation("Restrict ingress to specific CIDRs. Use security groups.", "restrict ingress to specific cidrs")
	if strings.Contains(got, "AI Suggestions:") {
		t.Error("should not append when AI text is already a substring")
	}
}

func TestDeduplicate_EquivalentDifferentSeverity(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "CRITICAL", Category: "security", Source: "llm"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if r.Findings[0].Severity != "HIGH" {
		t.Errorf("scanner severity should be preserved, got %q", r.Findings[0].Severity)
	}
	if r.Findings[0].RuleID != "CKV_1" {
		t.Errorf("scanner rule ID should be preserved, got %q", r.Findings[0].RuleID)
	}
}

func TestDeduplicate_EnrichmentNoDuplicateText(t *testing.T) {
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "checkov", Remediation: "Restrict ingress"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Resource: "aws_sg.test", Severity: "HIGH", Category: "security", Source: "llm", Remediation: "restrict ingress"},
	}
	r := Deduplicate(scannerFindings, aiFindings)
	if strings.Contains(r.Findings[0].Remediation, "AI Suggestions:") {
		t.Error("identical text should not be duplicated in remediation")
	}
}

func TestNormalizeResource(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"aws_instance.web", "aws_instance.web"},
		{"  AWS_Instance.Web  ", "aws_instance.web"},
		{"", ""},
	}
	for _, tc := range tests {
		got := normalizeResource(tc.input)
		if got != tc.want {
			t.Errorf("normalizeResource(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
