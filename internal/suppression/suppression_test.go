package suppression

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// helpers

func finding(ruleID, resource, source string) rules.Finding {
	return rules.Finding{RuleID: ruleID, Resource: resource, Source: source, Severity: "HIGH"}
}

func writeIgnoreFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".terraview-ignore")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// Load tests

func TestLoad_FileNotExist(t *testing.T) {
	f, err := Load("/nonexistent/.terraview-ignore")
	if err != nil {
		t.Fatalf("expected no error for missing file, got: %v", err)
	}
	if len(f.Suppressions) != 0 {
		t.Errorf("expected empty suppressions, got %d", len(f.Suppressions))
	}
}

func TestLoad_ValidFile(t *testing.T) {
	path := writeIgnoreFile(t, `
version: 1
suppressions:
  - rule_id: CKV_AWS_130
    reason: "public subnets required"
  - resource: aws_subnet.public[0]
    reason: "legacy"
`)
	f, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(f.Suppressions) != 2 {
		t.Errorf("expected 2 suppressions, got %d", len(f.Suppressions))
	}
	if f.Suppressions[0].RuleID != "CKV_AWS_130" {
		t.Errorf("unexpected rule_id: %s", f.Suppressions[0].RuleID)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	// Tabs in YAML indentation are not allowed and cause a parse error.
	path := writeIgnoreFile(t, "suppressions:\n\t- rule_id: bad")
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid YAML, got nil")
	}
}

// Entry.matches tests

func TestEntry_MatchesRuleIDOnly(t *testing.T) {
	e := Entry{RuleID: "CKV_AWS_130"}
	if !e.matches(finding("CKV_AWS_130", "aws_subnet.pub", "checkov")) {
		t.Error("should match by rule_id")
	}
	if e.matches(finding("CKV_AWS_131", "aws_subnet.pub", "checkov")) {
		t.Error("should not match different rule_id")
	}
}

func TestEntry_MatchesResourceOnly(t *testing.T) {
	e := Entry{Resource: "aws_subnet.public[0]"}
	if !e.matches(finding("CKV_AWS_130", "aws_subnet.public[0]", "checkov")) {
		t.Error("should match by resource")
	}
	if e.matches(finding("CKV_AWS_130", "aws_subnet.public[1]", "checkov")) {
		t.Error("should not match different resource")
	}
}

func TestEntry_MatchesSourceOnly(t *testing.T) {
	e := Entry{Source: "llm"}
	if !e.matches(finding("AI-CLA-SEC", "aws_lambda.fn", "llm")) {
		t.Error("should match by source")
	}
	if e.matches(finding("CKV_AWS_130", "aws_subnet.pub", "checkov")) {
		t.Error("should not match different source")
	}
}

func TestEntry_MatchesRuleAndResource(t *testing.T) {
	e := Entry{RuleID: "CKV_AWS_260", Resource: "aws_sg.alb_http"}
	if !e.matches(finding("CKV_AWS_260", "aws_sg.alb_http", "checkov")) {
		t.Error("should match both rule+resource")
	}
	// same rule, different resource → no match
	if e.matches(finding("CKV_AWS_260", "aws_sg.other", "checkov")) {
		t.Error("should not match different resource")
	}
	// same resource, different rule → no match
	if e.matches(finding("CKV_AWS_130", "aws_sg.alb_http", "checkov")) {
		t.Error("should not match different rule")
	}
}

func TestEntry_EmptyEntryNeverMatches(t *testing.T) {
	e := Entry{} // no fields set — wildcard guard
	if e.matches(finding("CKV_AWS_130", "aws_subnet.pub", "checkov")) {
		t.Error("empty entry should never match")
	}
}

// Apply tests

func TestApply_NilFile(t *testing.T) {
	findings := []rules.Finding{
		finding("CKV_AWS_130", "aws_subnet.pub", "checkov"),
	}
	filtered, suppressed := Apply(findings, nil)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
}

func TestApply_NoSuppressionsFile(t *testing.T) {
	findings := []rules.Finding{
		finding("CKV_AWS_130", "aws_subnet.pub", "checkov"),
	}
	filtered, suppressed := Apply(findings, &File{})
	if len(filtered) != 1 || len(suppressed) != 0 {
		t.Errorf("empty file should suppress nothing")
	}
}

func TestApply_GlobalRuleID(t *testing.T) {
	f := &File{Suppressions: []Entry{{RuleID: "CKV_AWS_130", Reason: "accepted"}}}
	findings := []rules.Finding{
		finding("CKV_AWS_130", "aws_subnet.pub[0]", "checkov"),
		finding("CKV_AWS_130", "aws_subnet.pub[1]", "checkov"),
		finding("CKV_AWS_260", "aws_sg.web", "checkov"),
	}
	filtered, suppressed := Apply(findings, f)
	if len(filtered) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered))
	}
	if filtered[0].RuleID != "CKV_AWS_260" {
		t.Errorf("wrong finding left: %s", filtered[0].RuleID)
	}
	if len(suppressed) != 2 {
		t.Errorf("expected 2 suppressed, got %d", len(suppressed))
	}
	if suppressed[0].Reason != "accepted" {
		t.Errorf("expected reason to be preserved, got: %s", suppressed[0].Reason)
	}
}

func TestApply_ResourceScoped(t *testing.T) {
	f := &File{Suppressions: []Entry{{Resource: "aws_subnet.public[0]"}}}
	findings := []rules.Finding{
		finding("CKV_AWS_130", "aws_subnet.public[0]", "checkov"),
		finding("CKV_AWS_130", "aws_subnet.public[1]", "checkov"),
	}
	filtered, suppressed := Apply(findings, f)
	if len(filtered) != 1 || filtered[0].Resource != "aws_subnet.public[1]" {
		t.Errorf("unexpected filtered results: %+v", filtered)
	}
	if len(suppressed) != 1 || suppressed[0].Finding.Resource != "aws_subnet.public[0]" {
		t.Errorf("unexpected suppressed results: %+v", suppressed)
	}
}

func TestApply_SourceScoped(t *testing.T) {
	f := &File{Suppressions: []Entry{{Source: "llm"}}}
	findings := []rules.Finding{
		finding("AI-CLA-REL", "aws_nat_gateway.this", "llm"),
		finding("CKV_AWS_130", "aws_subnet.pub", "checkov"),
	}
	filtered, suppressed := Apply(findings, f)
	if len(filtered) != 1 || filtered[0].Source != "checkov" {
		t.Errorf("expected only checkov finding, got: %+v", filtered)
	}
	if len(suppressed) != 1 || suppressed[0].Finding.Source != "llm" {
		t.Errorf("expected llm finding suppressed, got: %+v", suppressed)
	}
}

func TestApply_PreservesUnsuppressedFindings(t *testing.T) {
	f := &File{Suppressions: []Entry{{RuleID: "CKV_AWS_999"}}}
	findings := []rules.Finding{
		finding("CKV_AWS_130", "aws_subnet.pub", "checkov"),
		finding("CKV_AWS_260", "aws_sg.web", "checkov"),
	}
	filtered, suppressed := Apply(findings, f)
	if len(filtered) != 2 {
		t.Errorf("expected all findings preserved, got %d", len(filtered))
	}
	if len(suppressed) != 0 {
		t.Errorf("expected 0 suppressed, got %d", len(suppressed))
	}
}
