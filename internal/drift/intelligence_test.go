package drift

import (
	"strings"
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

// ---------------------------------------------------------------------------
// allFieldsAreCosmetic
// ---------------------------------------------------------------------------

func TestAllFieldsAreCosmetic_AllCosmetic(t *testing.T) {
	if !allFieldsAreCosmetic([]string{"tags", "description"}) {
		t.Error("expected true for all cosmetic fields")
	}
}

func TestAllFieldsAreCosmetic_MixedFields(t *testing.T) {
	if allFieldsAreCosmetic([]string{"tags", "cidr_blocks"}) {
		t.Error("expected false for mixed fields")
	}
}

func TestAllFieldsAreCosmetic_Empty(t *testing.T) {
	if allFieldsAreCosmetic(nil) {
		t.Error("expected false for nil fields")
	}
	if allFieldsAreCosmetic([]string{}) {
		t.Error("expected false for empty fields")
	}
}

func TestAllFieldsAreCosmetic_AllKnown(t *testing.T) {
	fields := []string{"tags", "tags_all", "description", "name_prefix"}
	if !allFieldsAreCosmetic(fields) {
		t.Error("expected true for all known cosmetic fields")
	}
}

// ---------------------------------------------------------------------------
// riskLevelLabel
// ---------------------------------------------------------------------------

func TestRiskLevelLabel(t *testing.T) {
	tests := []struct {
		risk float64
		want string
	}{
		{8.0, "CRITICAL"},
		{7.0, "CRITICAL"},
		{6.0, "HIGH"},
		{5.0, "HIGH"},
		{4.0, "MEDIUM"},
		{3.0, "MEDIUM"},
		{2.0, "LOW"},
		{1.0, "LOW"},
		{0.5, "NONE"},
		{0.0, "NONE"},
	}
	for _, tt := range tests {
		if got := riskLevelLabel(tt.risk); got != tt.want {
			t.Errorf("riskLevelLabel(%.1f) = %q, want %q", tt.risk, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// FormatNarrative — with actual data
// ---------------------------------------------------------------------------

func TestFormatNarrative_WithItems(t *testing.T) {
	result := &IntelligenceResult{
		Items: []DriftItem{
			{Resource: "aws_instance.web", Action: "delete", Classification: ClassSuspicious, RiskScore: 8.0, RiskFactors: []string{"critical-resource"}},
			{Resource: "aws_s3_bucket.logs", Action: "update", Classification: ClassIntentional, RiskScore: 2.0},
			{Resource: "aws_lb.main", Action: "create", Classification: ClassUnknown, RiskScore: 4.0, RiskFactors: []string{"new-resource"}},
		},
		OverallRisk:      5.5,
		RiskLevel:        "HIGH",
		SuspiciousCount:  1,
		IntentionalCount: 1,
		Recommendations:  []string{"Investigate suspicious changes"},
	}
	narrative := FormatNarrative(result)

	if !strings.Contains(narrative, "3 changes detected") {
		t.Error("expected item count in narrative")
	}
	if !strings.Contains(narrative, "SUSPICIOUS CHANGES:") {
		t.Error("expected suspicious section")
	}
	if !strings.Contains(narrative, "INTENTIONAL CHANGES:") {
		t.Error("expected intentional section")
	}
	if !strings.Contains(narrative, "UNCLASSIFIED CHANGES:") {
		t.Error("expected unclassified section")
	}
	if !strings.Contains(narrative, "RECOMMENDATIONS:") {
		t.Error("expected recommendations section")
	}
	if !strings.Contains(narrative, "aws_instance.web") {
		t.Error("expected resource name")
	}
	if !strings.Contains(narrative, "WARNING") {
		t.Error("expected warning for suspicious changes")
	}
}

func TestFormatNarrative_OnlySuspicious(t *testing.T) {
	result := &IntelligenceResult{
		Items: []DriftItem{
			{Resource: "aws_db.main", Action: "delete", Classification: ClassSuspicious, RiskScore: 9.0, RiskFactors: []string{"data-loss"}},
		},
		OverallRisk:     9.0,
		RiskLevel:       "CRITICAL",
		SuspiciousCount: 1,
		Recommendations: []string{"Stop and investigate"},
	}
	narrative := FormatNarrative(result)

	if !strings.Contains(narrative, "SUSPICIOUS CHANGES:") {
		t.Error("expected suspicious section")
	}
	// Should NOT contain INTENTIONAL section
	if strings.Contains(narrative, "INTENTIONAL CHANGES:") {
		t.Error("expected no intentional section when there are none")
	}
}
