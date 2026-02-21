package aggregator

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

func TestAggregate_ExitCodes(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)

	tests := []struct {
		name             string
		findings         []rules.Finding
		expectedExitCode int
		expectedMaxSev   string
	}{
		{
			name:             "no findings",
			findings:         nil,
			expectedExitCode: 0,
			expectedMaxSev:   "NONE",
		},
		{
			name: "critical finding",
			findings: []rules.Finding{
				{RuleID: "TEST", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "test"},
			},
			expectedExitCode: 2,
			expectedMaxSev:   rules.SeverityCritical,
		},
		{
			name: "high finding",
			findings: []rules.Finding{
				{RuleID: "TEST", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "test"},
			},
			expectedExitCode: 1,
			expectedMaxSev:   rules.SeverityHigh,
		},
		{
			name: "medium finding",
			findings: []rules.Finding{
				{RuleID: "TEST", Severity: rules.SeverityMedium, Category: rules.CategoryCompliance, Resource: "test"},
			},
			expectedExitCode: 0,
			expectedMaxSev:   rules.SeverityMedium,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := agg.Aggregate("test.json", 5, tt.findings, nil, "", false)
			if result.ExitCode != tt.expectedExitCode {
				t.Errorf("expected exit code %d, got %d", tt.expectedExitCode, result.ExitCode)
			}
			if result.MaxSeverity != tt.expectedMaxSev {
				t.Errorf("expected max severity %s, got %s", tt.expectedMaxSev, result.MaxSeverity)
			}
		})
	}
}

func TestAggregate_Deduplication(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)

	hardFindings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "aws_sg.test", Source: "hard-rule"},
	}
	llmFindings := []rules.Finding{
		{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "aws_sg.test", Source: "llm"},
	}

	result := agg.Aggregate("test.json", 3, hardFindings, llmFindings, "summary", false)

	if len(result.Findings) != 1 {
		t.Errorf("expected 1 deduplicated finding, got %d", len(result.Findings))
	}
}

func TestAggregate_SortBySeverity(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)

	findings := []rules.Finding{
		{RuleID: "LOW", Severity: rules.SeverityLow, Category: rules.CategoryCompliance, Resource: "r1"},
		{RuleID: "CRIT", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "r2"},
		{RuleID: "HIGH", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "r3"},
	}

	result := agg.Aggregate("test.json", 5, findings, nil, "", false)

	if result.Findings[0].Severity != rules.SeverityCritical {
		t.Errorf("expected first finding to be CRITICAL, got %s", result.Findings[0].Severity)
	}
	if result.Findings[1].Severity != rules.SeverityHigh {
		t.Errorf("expected second finding to be HIGH, got %s", result.Findings[1].Severity)
	}
}

func TestAggregate_Verdict(t *testing.T) {
	scorer := scoring.NewScorerWithWeights(5, 3, 1, 0.5)
	agg := NewAggregator(scorer)

	tests := []struct {
		name      string
		findings  []rules.Finding
		strict    bool
		wantSafe  bool
		wantLabel string
	}{
		{
			name:      "no findings is SAFE",
			findings:  nil,
			strict:    false,
			wantSafe:  true,
			wantLabel: "SAFE",
		},
		{
			name: "critical makes NOT SAFE",
			findings: []rules.Finding{
				{RuleID: "SEC003", Severity: rules.SeverityCritical, Category: rules.CategorySecurity, Resource: "aws_iam.test"},
			},
			strict:    false,
			wantSafe:  false,
			wantLabel: "NOT SAFE",
		},
		{
			name: "high in non-strict is SAFE",
			findings: []rules.Finding{
				{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "aws_sg.test"},
			},
			strict:    false,
			wantSafe:  true,
			wantLabel: "SAFE",
		},
		{
			name: "high in strict is NOT SAFE",
			findings: []rules.Finding{
				{RuleID: "SEC001", Severity: rules.SeverityHigh, Category: rules.CategorySecurity, Resource: "aws_sg.test"},
			},
			strict:    true,
			wantSafe:  false,
			wantLabel: "NOT SAFE",
		},
		{
			name: "medium and low only is SAFE",
			findings: []rules.Finding{
				{RuleID: "REL001", Severity: rules.SeverityMedium, Category: rules.CategoryReliability, Resource: "aws_db.test"},
				{RuleID: "COMP001", Severity: rules.SeverityLow, Category: rules.CategoryCompliance, Resource: "aws_cw.test"},
			},
			strict:    false,
			wantSafe:  true,
			wantLabel: "SAFE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := agg.Aggregate("test.json", 5, tt.findings, nil, "", tt.strict)
			if result.Verdict.Safe != tt.wantSafe {
				t.Errorf("verdict safe: got %v, want %v", result.Verdict.Safe, tt.wantSafe)
			}
			if result.Verdict.Label != tt.wantLabel {
				t.Errorf("verdict label: got %q, want %q", result.Verdict.Label, tt.wantLabel)
			}
			if len(result.Verdict.Reasons) == 0 {
				t.Error("verdict should have at least one reason")
			}
		})
	}
}
