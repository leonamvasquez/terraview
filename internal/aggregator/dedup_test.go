package aggregator

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

// Tests below cover deduplication semantics (severity upgrade, case-insensitivity,
// multi-source merge) that are distinct from the broader verdict/exit-code tests
// already in aggregator_test.go. Previously lived in the dead internal/regression
// package.

func TestDedup_SeverityMerge(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "checkov", Remediation: "restrict CIDR"},
	}
	llm := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL (highest), got %s", f.Severity)
	}
	if f.Remediation != "restrict CIDR" {
		t.Errorf("expected remediation from scanner, got %q", f.Remediation)
	}
	if !strings.Contains(f.Source, "checkov") || !strings.Contains(f.Source, "llm") {
		t.Errorf("expected merged sources, got %q", f.Source)
	}
}

func TestDedup_CaseInsensitive(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.Test", Source: "scanner"},
	}
	llm := []rules.Finding{
		{RuleID: "sec001", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
			Resource: "AWS_SG.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding after case-insensitive dedup, got %d", len(result.Findings))
	}
}

func TestDedup_DifferentResourcesKept(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.alpha", Source: "scanner"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.beta", Source: "scanner"},
	}
	result := agg.Aggregate("test.json", 3, findings, nil, "", false)
	if len(result.Findings) != 2 {
		t.Errorf("same RuleID on different resources must NOT be collapsed, got %d", len(result.Findings))
	}
}

func TestDedup_SameRuleDifferentMessages(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Message: "Port 22 open", Source: "scanner"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Message: "SG allows all", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, findings, nil, "", false)
	if len(result.Findings) != 1 {
		t.Errorf("same resource + ruleID should dedup regardless of message, got %d", len(result.Findings))
	}
}

func TestDedup_ThreeSourcesMerge(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)
	hard := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "tfsec"},
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "checkov"},
	}
	llm := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
			Resource: "aws_sg.test", Source: "llm"},
	}
	result := agg.Aggregate("test.json", 3, hard, llm, "", false)

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding from 3 sources, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.Severity != rules.SeverityCritical {
		t.Errorf("expected CRITICAL, got %s", f.Severity)
	}
	for _, src := range []string{"tfsec", "checkov", "llm"} {
		if !strings.Contains(f.Source, src) {
			t.Errorf("missing %q in source: %q", src, f.Source)
		}
	}
}
