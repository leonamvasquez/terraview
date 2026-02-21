package meta

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestAnalyzer_MultipleSources(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "hard-rule"},
		{RuleID: "CKV_001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "external:checkov"},
		{RuleID: "BP001", Severity: "MEDIUM", Category: "best-practice", Resource: "aws_s3_bucket.data", Source: "hard-rule"},
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(findings)

	if len(result.Sources) != 2 {
		t.Errorf("expected 2 sources, got %d", len(result.Sources))
	}
	if len(result.Correlations) != 1 {
		t.Errorf("expected 1 correlation, got %d", len(result.Correlations))
	}
	if result.Correlations[0].Resource != "aws_instance.web" {
		t.Errorf("expected correlation on aws_instance.web, got %s", result.Correlations[0].Resource)
	}
	if result.UnifiedScore >= 10.0 {
		t.Errorf("expected score < 10.0, got %.1f", result.UnifiedScore)
	}
}

func TestAnalyzer_SingleSource(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "hard-rule"},
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(findings)

	if len(result.CoverageGaps) == 0 {
		t.Error("expected coverage gaps for single source")
	}
	if len(result.Correlations) != 0 {
		t.Errorf("expected 0 correlations, got %d", len(result.Correlations))
	}
}

func TestAnalyzer_NoFindings(t *testing.T) {
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(nil)

	if result.UnifiedScore != 10.0 {
		t.Errorf("expected score 10.0, got %.1f", result.UnifiedScore)
	}
}

func TestNormalizeSource(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"hard-rule", "hard-rule"},
		{"external:checkov", "checkov"},
		{"external:tfsec", "tfsec"},
		{"", "unknown"},
		{"ai-review", "ai-review"},
	}
	for _, tt := range tests {
		got := normalizeSource(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeSource(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestComputeUnifiedScore_PerfectScore(t *testing.T) {
	score := computeUnifiedScore(nil, nil)
	if score != 10.0 {
		t.Errorf("expected 10.0, got %.1f", score)
	}
}
