package meta

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// severityRank — pure function with 6 branches
// ---------------------------------------------------------------------------

func TestSeverityRank_AllValues(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"CRITICAL", 0},
		{"HIGH", 1},
		{"MEDIUM", 2},
		{"LOW", 3},
		{"INFO", 4},
		{"UNKNOWN", 5},
		{"", 5},
		{"critical", 5}, // case-sensitive
	}
	for _, tc := range tests {
		got := severityRank(tc.input)
		if got != tc.want {
			t.Errorf("severityRank(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// detectCoverageGaps — pure function
// ---------------------------------------------------------------------------

func TestDetectCoverageGaps_SingleSource(t *testing.T) {
	sourceMap := map[string][]rules.Finding{
		"checkov": {{RuleID: "SEC001", Category: "security", Severity: "HIGH"}},
	}
	gaps := detectCoverageGaps(sourceMap)
	if len(gaps) == 0 {
		t.Error("expected at least one gap for single source")
	}
	found := false
	for _, g := range gaps {
		if len(g) > 0 {
			found = true
		}
	}
	if !found {
		t.Error("expected non-empty gap messages")
	}
}

func TestDetectCoverageGaps_MultipleSources(t *testing.T) {
	sourceMap := map[string][]rules.Finding{
		"checkov":   {{RuleID: "SEC001", Category: "security", Severity: "HIGH"}},
		"terraview": {{RuleID: "AI001", Category: "networking", Severity: "MEDIUM"}},
	}
	gaps := detectCoverageGaps(sourceMap)
	// With 2 sources and 2 categories, should have no single-source gap
	for _, g := range gaps {
		if g == "" {
			t.Error("gap should be non-empty")
		}
	}
}

func TestAnalyzer_MultipleSources(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "checkov"},
		{RuleID: "CKV_001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "tfsec"},
		{RuleID: "BP001", Severity: "MEDIUM", Category: "best-practice", Resource: "aws_s3_bucket.data", Source: "terrascan"},
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(findings)

	if len(result.Sources) != 3 {
		t.Errorf("expected 3 sources, got %d", len(result.Sources))
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
		{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "checkov"},
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
		{"checkov", "checkov"},
		{"external:checkov", "checkov"},
		{"external:tfsec", "tfsec"},
		{"", "unknown"},
		{"llm", "llm"},
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
