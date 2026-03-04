package resolver

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestResolveEmpty(t *testing.T) {
	r := New()
	result := r.Resolve(nil, nil)
	if len(result.Resolved) != 0 {
		t.Errorf("expected 0 resolved, got %d", len(result.Resolved))
	}
	if result.Summary != "No findings to resolve." {
		t.Errorf("unexpected summary: %s", result.Summary)
	}
}

func TestResolveScannerOnly(t *testing.T) {
	r := New()
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Source: "checkov", Resource: "aws_instance.web", Severity: "HIGH", Category: "security"},
	}
	result := r.Resolve(scannerFindings, nil)
	if result.ScannerOnly != 1 {
		t.Errorf("expected 1 scanner-only, got %d", result.ScannerOnly)
	}
	if result.Resolved[0].Resolution.Action != "scanner-only" {
		t.Errorf("expected scanner-only action, got %s", result.Resolved[0].Resolution.Action)
	}
}

func TestResolveAIOnly(t *testing.T) {
	r := New()
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Source: "llm", Resource: "aws_s3_bucket.data", Severity: "MEDIUM", Category: "security"},
	}
	result := r.Resolve(nil, aiFindings)
	if result.AIOnly != 1 {
		t.Errorf("expected 1 ai-only, got %d", result.AIOnly)
	}
	if result.Resolved[0].Resolution.Action != "ai-only" {
		t.Errorf("expected ai-only action, got %s", result.Resolved[0].Resolution.Action)
	}
	if result.Resolved[0].Resolution.Confidence >= 1.0 {
		t.Errorf("ai-only confidence should be < 1.0, got %.2f", result.Resolved[0].Resolution.Confidence)
	}
}

func TestResolveConfirmed(t *testing.T) {
	r := New()
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Source: "checkov", Resource: "aws_instance.web", Severity: "HIGH", Category: "security", Message: "Public access enabled"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_SEC_1", Source: "llm", Resource: "aws_instance.web", Severity: "HIGH", Category: "security", Message: "Instance has public access"},
	}
	result := r.Resolve(scannerFindings, aiFindings)
	if result.Confirmed != 1 {
		t.Errorf("expected 1 confirmed, got %d", result.Confirmed)
	}
	if result.Resolved[0].Resolution.Confidence != 1.0 {
		t.Errorf("confirmed confidence should be 1.0, got %.2f", result.Resolved[0].Resolution.Confidence)
	}
	if !strings.Contains(result.Resolved[0].Source, "checkov") {
		t.Errorf("source should contain checkov, got %s", result.Resolved[0].Source)
	}
}

func TestResolveSeverityConflict(t *testing.T) {
	r := New()
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Source: "checkov", Resource: "aws_instance.web", Severity: "CRITICAL", Category: "security"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Source: "llm", Resource: "aws_instance.web", Severity: "LOW", Category: "security"},
	}
	result := r.Resolve(scannerFindings, aiFindings)
	if result.ScannerPriority != 1 {
		t.Errorf("expected 1 scanner-priority, got %d", result.ScannerPriority)
	}
	// Scanner severity should win
	if result.Resolved[0].Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL severity (scanner wins), got %s", result.Resolved[0].Severity)
	}
}

func TestResolveMixed(t *testing.T) {
	r := New()
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Source: "checkov", Resource: "aws_instance.web", Severity: "HIGH", Category: "security"},
		{RuleID: "CKV_2", Source: "checkov", Resource: "aws_rds.db", Severity: "MEDIUM", Category: "security"},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Source: "llm", Resource: "aws_instance.web", Severity: "HIGH", Category: "security"},
		{RuleID: "AI_2", Source: "llm", Resource: "aws_lambda.func", Severity: "LOW", Category: "best-practice"},
	}
	result := r.Resolve(scannerFindings, aiFindings)

	total := result.Confirmed + result.ScannerPriority + result.ScannerOnly + result.AIOnly
	if total != len(result.Resolved) {
		t.Errorf("counts don't add up: %d != %d", total, len(result.Resolved))
	}
	if result.Confirmed != 1 {
		t.Errorf("expected 1 confirmed, got %d", result.Confirmed)
	}
	if result.ScannerOnly != 1 {
		t.Errorf("expected 1 scanner-only, got %d", result.ScannerOnly)
	}
	if result.AIOnly != 1 {
		t.Errorf("expected 1 ai-only, got %d", result.AIOnly)
	}
}

func TestToFindings(t *testing.T) {
	resolved := []ResolvedFinding{
		{Finding: rules.Finding{RuleID: "A"}, Resolution: Resolution{Action: "confirmed"}},
		{Finding: rules.Finding{RuleID: "B"}, Resolution: Resolution{Action: "ai-only"}},
	}
	findings := ToFindings(resolved)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].RuleID != "A" || findings[1].RuleID != "B" {
		t.Errorf("unexpected finding order: %s, %s", findings[0].RuleID, findings[1].RuleID)
	}
}

func TestSeveritiesAgree(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"HIGH", "HIGH", true},
		{"HIGH", "MEDIUM", true},   // one level apart
		{"CRITICAL", "HIGH", true}, // one level apart
		{"CRITICAL", "LOW", false}, // too far apart
		{"HIGH", "INFO", false},    // too far apart
		{"MEDIUM", "LOW", true},    // one level apart
	}
	for _, tc := range tests {
		got := severitiesAgree(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("severitiesAgree(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestIsRelatedByCategory(t *testing.T) {
	a := rules.Finding{Resource: "r1", Category: "security"}
	b := rules.Finding{Resource: "r1", Category: "Security"}
	if !isRelated(a, b) {
		t.Error("same category should be related")
	}
}

func TestIsRelatedByRuleID(t *testing.T) {
	a := rules.Finding{Resource: "r1", RuleID: "CKV_1"}
	b := rules.Finding{Resource: "r1", RuleID: "ckv_1"}
	if !isRelated(a, b) {
		t.Error("same ruleID should be related")
	}
}

func TestIsRelatedByMessage(t *testing.T) {
	a := rules.Finding{Resource: "r1", Message: "Public access enabled on S3 bucket without encryption"}
	b := rules.Finding{Resource: "r1", Message: "S3 bucket has public access and missing encryption settings"}
	if !isRelated(a, b) {
		t.Error("overlapping keywords should be related")
	}
}

func TestIsRelatedUnrelated(t *testing.T) {
	a := rules.Finding{Resource: "r1", Category: "security", Message: "SSH port open"}
	b := rules.Finding{Resource: "r1", Category: "best-practice", Message: "Missing tags on resources"}
	if isRelated(a, b) {
		t.Error("different category and message should not be related")
	}
}

func TestFormatResolution(t *testing.T) {
	r := New()
	result := r.Resolve(
		[]rules.Finding{{RuleID: "X", Source: "checkov", Resource: "r1", Severity: "HIGH", Category: "security"}},
		nil,
	)
	out := FormatResolution(result)
	if !strings.Contains(out, "Conflict Resolution") {
		t.Errorf("expected header, got: %s", out)
	}
}

func TestFormatResolutionBR(t *testing.T) {
	r := New()
	result := r.Resolve(
		[]rules.Finding{{RuleID: "X", Source: "checkov", Resource: "r1", Severity: "HIGH", Category: "security"}},
		nil,
	)
	out := FormatResolutionBR(result)
	if !strings.Contains(out, "Resolução de Conflitos") {
		t.Errorf("expected pt-BR header, got: %s", out)
	}
}

func TestFormatResolutionEmpty(t *testing.T) {
	out := FormatResolution(ConflictResult{})
	if out != "" {
		t.Errorf("expected empty, got: %s", out)
	}
}

func TestSignificantWords(t *testing.T) {
	words := significantWords("The quick brown fox jumps over the lazy dog!")
	if !words["quick"] || !words["brown"] || !words["jumps"] || !words["lazy"] {
		t.Errorf("missing expected words: %v", words)
	}
	if words["the"] || words["fox"] || words["dog"] {
		t.Error("short words should be excluded")
	}
}

func TestRemediationMerge(t *testing.T) {
	r := New()
	scannerFindings := []rules.Finding{
		{RuleID: "CKV_1", Source: "checkov", Resource: "r1", Severity: "HIGH", Category: "security", Remediation: ""},
	}
	aiFindings := []rules.Finding{
		{RuleID: "AI_1", Source: "llm", Resource: "r1", Severity: "HIGH", Category: "security", Remediation: "Add encryption"},
	}
	result := r.Resolve(scannerFindings, aiFindings)
	if result.Resolved[0].Remediation != "Add encryption" {
		t.Errorf("expected remediation merge, got %q", result.Resolved[0].Remediation)
	}
}

// ---------------------------------------------------------------------------
// FormatResolutionBR — all branches
// ---------------------------------------------------------------------------

func TestFormatResolutionBR_Empty(t *testing.T) {
	result := FormatResolutionBR(ConflictResult{})
	if result != "" {
		t.Errorf("expected empty string for no resolved findings, got %q", result)
	}
}

func TestFormatResolutionBR_AllBranches(t *testing.T) {
	cr := ConflictResult{
		Resolved: []ResolvedFinding{
			{Finding: rules.Finding{Resource: "r1"}},
			{Finding: rules.Finding{Resource: "r2"}},
			{Finding: rules.Finding{Resource: "r3"}},
			{Finding: rules.Finding{Resource: "r4"}},
		},
		Confirmed:       1,
		ScannerPriority: 1,
		ScannerOnly:     1,
		AIOnly:          1,
	}
	result := FormatResolutionBR(cr)
	if result == "" {
		t.Error("expected non-empty output")
	}
	wants := []string{
		"Resolução de Conflitos",
		"confirmados",
		"prioridade-scanner",
		"apenas-scanner",
		"apenas-IA",
	}
	for _, w := range wants {
		if !strings.Contains(result, w) {
			t.Errorf("missing %q in output: %s", w, result)
		}
	}
}

func TestFormatResolutionBR_OnlyConfirmed(t *testing.T) {
	cr := ConflictResult{
		Resolved:  []ResolvedFinding{{Finding: rules.Finding{Resource: "r1"}}},
		Confirmed: 1,
	}
	result := FormatResolutionBR(cr)
	if !strings.Contains(result, "confirmados") {
		t.Errorf("expected 'confirmados' in output: %s", result)
	}
	if strings.Contains(result, "apenas-scanner") {
		t.Error("should not contain 'apenas-scanner'")
	}
}

func TestFormatResolutionBR_OnlyAI(t *testing.T) {
	cr := ConflictResult{
		Resolved: []ResolvedFinding{{Finding: rules.Finding{Resource: "r1"}}},
		AIOnly:   1,
	}
	result := FormatResolutionBR(cr)
	if !strings.Contains(result, "apenas-IA") {
		t.Errorf("expected 'apenas-IA' in output: %s", result)
	}
}
