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

func TestComputeUnifiedScore_Gradacao(t *testing.T) {
	// Validates that the score is non-zero and produces meaningful gradation
	// across realistic finding volumes. Values mirror the godoc reference points.
	makeFinding := func(sev string) rules.Finding {
		return rules.Finding{Severity: sev, Category: "security", Resource: "aws_instance.web"}
	}
	repeat := func(sev string, n int) []rules.Finding {
		out := make([]rules.Finding, n)
		for i := range out {
			out[i] = makeFinding(sev)
		}
		return out
	}

	tests := []struct {
		name     string
		findings []rules.Finding
		wantMin  float64
		wantMax  float64
	}{
		{"single CRITICAL", repeat("CRITICAL", 1), 7.0, 9.5},
		{"3 CRITICAL + 5 HIGH", append(repeat("CRITICAL", 3), repeat("HIGH", 5)...), 4.0, 8.0},
		{"25 HIGH", repeat("HIGH", 25), 1.5, 4.0},
		// Large volumes should floor at 0, not produce negative or NaN
		{"173 HIGH (EKS-like)", repeat("HIGH", 173), 0.0, 1.0},
		{"5 CRITICAL + 167 HIGH (multi-VPC-like)", append(repeat("CRITICAL", 5), repeat("HIGH", 167)...), 0.0, 1.0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score := computeUnifiedScore(tc.findings, nil)
			if score < tc.wantMin || score > tc.wantMax {
				t.Errorf("computeUnifiedScore(%s) = %.1f, want [%.1f, %.1f]",
					tc.name, score, tc.wantMin, tc.wantMax)
			}
			if score < 0 {
				t.Errorf("score must not be negative, got %.2f", score)
			}
		})
	}
}

func TestComputeUnifiedScore_MonotonicDecay(t *testing.T) {
	// More findings of the same severity must always yield a lower or equal score.
	makeFinding := func() rules.Finding {
		return rules.Finding{Severity: "HIGH", Category: "security", Resource: "aws_instance.web"}
	}

	prev := 10.0
	for n := 1; n <= 50; n++ {
		findings := make([]rules.Finding, n)
		for i := range findings {
			findings[i] = makeFinding()
		}
		score := computeUnifiedScore(findings, nil)
		if score > prev {
			t.Errorf("score increased from %.2f to %.2f when going from %d to %d HIGH findings",
				prev, score, n-1, n)
		}
		prev = score
	}
}

func TestComputeUnifiedScore_NaoZeraComPoucosFindings(t *testing.T) {
	// A handful of findings must not produce 0.0 — that would make the score
	// indistinguishable from catastrophic infrastructure.
	findings := []rules.Finding{
		{Severity: "HIGH", Category: "security", Resource: "aws_s3_bucket.data"},
		{Severity: "HIGH", Category: "security", Resource: "aws_instance.web"},
		{Severity: "MEDIUM", Category: "compliance", Resource: "aws_vpc.main"},
	}
	score := computeUnifiedScore(findings, nil)
	if score == 0.0 {
		t.Errorf("expected non-zero score for 2 HIGH + 1 MEDIUM, got 0.0")
	}
	if score < 5.0 {
		t.Errorf("expected score >= 5.0 for a small finding set, got %.1f", score)
	}
}

func TestComputeUnifiedScore_CorrelacaoAumentaPenalidade(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "checkov"},
		{Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Source: "tfsec"},
	}
	correlations := []Correlation{
		{Resource: "aws_instance.web", Sources: []string{"checkov", "tfsec"}, MaxSeverity: "HIGH"},
	}

	scoreWithout := computeUnifiedScore(findings, nil)
	scoreWith := computeUnifiedScore(findings, correlations)

	if scoreWith >= scoreWithout {
		t.Errorf("correlated findings should produce lower score: with=%.2f, without=%.2f",
			scoreWith, scoreWithout)
	}
}
