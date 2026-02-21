package drift

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestClassifyDrift_SuspiciousDelete(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_db_instance.main", Type: "aws_db_instance", Action: "delete"},
	}
	criticals := []string{"aws_db_instance"}
	result := ClassifyDrift(resources, criticals)

	if len(result.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result.Items))
	}
	if result.Items[0].Classification != ClassSuspicious {
		t.Errorf("expected suspicious, got %s", result.Items[0].Classification)
	}
	if result.SuspiciousCount != 1 {
		t.Errorf("expected 1 suspicious, got %d", result.SuspiciousCount)
	}
}

func TestClassifyDrift_IntentionalCreate(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.new", Type: "aws_instance", Action: "create"},
	}
	result := ClassifyDrift(resources, nil)

	if len(result.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", len(result.Items))
	}
	if result.Items[0].Classification != ClassIntentional {
		t.Errorf("expected intentional, got %s", result.Items[0].Classification)
	}
}

func TestClassifyDrift_SecurityUpdate(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_iam_role.admin", Type: "aws_iam_role", Action: "update"},
	}
	result := ClassifyDrift(resources, nil)

	if result.Items[0].Classification != ClassSuspicious {
		t.Errorf("expected suspicious for IAM update, got %s", result.Items[0].Classification)
	}
	if result.Items[0].RiskScore < 3.0 {
		t.Errorf("expected risk >= 3.0, got %.1f", result.Items[0].RiskScore)
	}
}

func TestClassifyDrift_NoChanges(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "no-op"},
	}
	result := ClassifyDrift(resources, nil)

	if len(result.Items) != 0 {
		t.Errorf("expected 0 items, got %d", len(result.Items))
	}
	if result.OverallRisk != 0 {
		t.Errorf("expected 0 risk, got %.1f", result.OverallRisk)
	}
}

func TestComputeOverallRisk(t *testing.T) {
	items := []DriftItem{
		{RiskScore: 8.0},
		{RiskScore: 2.0},
	}
	risk := computeOverallRisk(items)
	// 60% of max(8) + 40% of avg(5) = 4.8 + 2.0 = 6.8
	if risk < 6.5 || risk > 7.0 {
		t.Errorf("expected risk ~6.8, got %.1f", risk)
	}
}

func TestFormatNarrative_Empty(t *testing.T) {
	result := &IntelligenceResult{}
	narrative := FormatNarrative(result)
	if narrative == "" {
		t.Error("expected non-empty narrative for empty result")
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		field    string
		expected bool
	}{
		{"policy", true},
		{"bucket_policy", true},
		{"tags", false},
		{"ingress", true},
		{"name", false},
	}
	for _, tt := range tests {
		got := isSensitiveField(tt.field)
		if got != tt.expected {
			t.Errorf("isSensitiveField(%q) = %v, want %v", tt.field, got, tt.expected)
		}
	}
}
