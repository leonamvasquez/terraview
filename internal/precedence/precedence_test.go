package precedence

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestRank(t *testing.T) {
	tests := []struct {
		source string
		want   int
	}{
		{"checkov", 1},
		{"tfsec", 2},
		{"trivy", 2},
		{"terrascan", 3},
		{"hard-rule", 4},
		{"deterministic", 4},
		{"llm", 5},
		{"ai", 5},
		{"unknown", 99},
	}
	for _, tc := range tests {
		got := Rank(tc.source)
		if got != tc.want {
			t.Errorf("Rank(%q) = %d, want %d", tc.source, got, tc.want)
		}
	}
}

func TestSortByPrecedence(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Source: "llm", Severity: "HIGH"},
		{RuleID: "R2", Source: "checkov", Severity: "MEDIUM"},
		{RuleID: "R3", Source: "tfsec", Severity: "CRITICAL"},
		{RuleID: "R4", Source: "checkov", Severity: "HIGH"},
	}
	SortByPrecedence(findings)

	if findings[0].Source != "checkov" || findings[0].Severity != "HIGH" {
		t.Errorf("expected checkov HIGH first, got %s %s", findings[0].Source, findings[0].Severity)
	}
	if findings[1].Source != "checkov" || findings[1].Severity != "MEDIUM" {
		t.Errorf("expected checkov MEDIUM second, got %s %s", findings[1].Source, findings[1].Severity)
	}
	if findings[2].Source != "tfsec" {
		t.Errorf("expected tfsec third, got %s", findings[2].Source)
	}
	if findings[3].Source != "llm" {
		t.Errorf("expected llm last, got %s", findings[3].Source)
	}
}

func TestHighestPrecedenceSource(t *testing.T) {
	findings := []rules.Finding{
		{Source: "llm"},
		{Source: "tfsec"},
		{Source: "checkov"},
	}
	got := HighestPrecedenceSource(findings)
	if got != "checkov" {
		t.Errorf("expected checkov, got %s", got)
	}
}

func TestHighestPrecedenceSourceEmpty(t *testing.T) {
	got := HighestPrecedenceSource(nil)
	if got != "" {
		t.Errorf("expected empty, got %s", got)
	}
}

func TestClassifyTier(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"checkov", "Tier 1 (scanner)"},
		{"tfsec", "Tier 1 (scanner)"},
		{"terrascan", "Tier 2 (scanner)"},
		{"hard-rule", "Tier 3 (deterministic)"},
		{"llm", "Tier 4 (AI)"},
		{"unknown", "Tier 5 (unknown)"},
	}
	for _, tc := range tests {
		got := ClassifyTier(tc.source)
		if got != tc.want {
			t.Errorf("ClassifyTier(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestConfidenceWeight(t *testing.T) {
	w1 := ConfidenceWeight("checkov")
	w2 := ConfidenceWeight("tfsec")
	w3 := ConfidenceWeight("llm")
	wU := ConfidenceWeight("unknown")

	if w1 <= w2 {
		t.Errorf("checkov weight %.2f should > tfsec %.2f", w1, w2)
	}
	if w2 <= w3 {
		t.Errorf("tfsec weight %.2f should > llm %.2f", w2, w3)
	}
	if w3 <= wU {
		t.Errorf("llm weight %.2f should > unknown %.2f", w3, wU)
	}
}
