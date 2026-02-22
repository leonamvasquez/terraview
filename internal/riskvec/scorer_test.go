package riskvec

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/feature"
)

func TestScore_ZeroRisk(t *testing.T) {
	features := []feature.ResourceFeatures{
		{
			ResourceID:   "null_resource.test",
			Provider:     "null",
			ResourceType: "null_resource",
		},
	}

	scorer := NewScorer()
	scored := scorer.Score(features)

	if len(scored) != 1 {
		t.Fatalf("expected 1 scored resource, got %d", len(scored))
	}
	rv := scored[0].RiskVector
	if rv.Total != 0 {
		t.Errorf("expected total risk 0, got %d", rv.Total)
	}
}

func TestScore_HighRisk(t *testing.T) {
	features := []feature.ResourceFeatures{
		{
			ResourceID:      "aws_security_group.open",
			Provider:        "aws",
			ResourceType:    "aws_security_group",
			NetworkExposure: 3,
			EncryptionRisk:  0,
			IdentityRisk:    0,
			GovernanceRisk:  1,
			ObservabilityRisk: 0,
			Flags:           []string{"no-tags", "wildcard-cidr"},
		},
	}

	scorer := NewScorer()
	scored := scorer.Score(features)
	rv := scored[0].RiskVector

	if rv.Network != 3 {
		t.Errorf("expected Network 3, got %d", rv.Network)
	}
	if rv.Governance != 1 {
		t.Errorf("expected Governance 1, got %d", rv.Governance)
	}
	if rv.Total != 4 {
		t.Errorf("expected total 4, got %d", rv.Total)
	}
}

func TestScore_Clamping(t *testing.T) {
	features := []feature.ResourceFeatures{
		{
			ResourceID:        "test.resource",
			Provider:          "aws",
			ResourceType:      "aws_instance",
			NetworkExposure:   5, // exceeds max
			EncryptionRisk:    -1, // below min
			IdentityRisk:      3,
			GovernanceRisk:    3,
			ObservabilityRisk: 3,
		},
	}

	scorer := NewScorer()
	scored := scorer.Score(features)
	rv := scored[0].RiskVector

	if rv.Network != 3 {
		t.Errorf("expected Network clamped to 3, got %d", rv.Network)
	}
	if rv.Encryption != 0 {
		t.Errorf("expected Encryption clamped to 0, got %d", rv.Encryption)
	}
	if rv.Total != 12 {
		t.Errorf("expected total 12 (clamp(5)=3+clamp(-1)=0+3+3+3), got %d", rv.Total)
	}
}

func TestScore_Multiple(t *testing.T) {
	features := []feature.ResourceFeatures{
		{ResourceID: "a", Provider: "aws", ResourceType: "aws_instance", NetworkExposure: 1},
		{ResourceID: "b", Provider: "aws", ResourceType: "aws_s3_bucket", EncryptionRisk: 2},
		{ResourceID: "c", Provider: "azure", ResourceType: "azurerm_vm", GovernanceRisk: 1},
	}

	scorer := NewScorer()
	scored := scorer.Score(features)

	if len(scored) != 3 {
		t.Fatalf("expected 3 scored resources, got %d", len(scored))
	}
	if scored[0].RiskVector.Total != 1 {
		t.Errorf("resource a: expected total 1, got %d", scored[0].RiskVector.Total)
	}
	if scored[1].RiskVector.Total != 2 {
		t.Errorf("resource b: expected total 2, got %d", scored[1].RiskVector.Total)
	}
	if scored[2].RiskVector.Total != 1 {
		t.Errorf("resource c: expected total 1, got %d", scored[2].RiskVector.Total)
	}
}

func TestHighestAxis(t *testing.T) {
	rv := RiskVector{
		Network:       1,
		Encryption:    3,
		Identity:      2,
		Governance:    0,
		Observability: 1,
	}

	if got := rv.HighestAxis(); got != 3 {
		t.Errorf("HighestAxis() = %d, want 3", got)
	}
}

func TestDominantCategory(t *testing.T) {
	tests := []struct {
		name string
		rv   RiskVector
		want string
	}{
		{"network dominant", RiskVector{Network: 3}, "security"},
		{"encryption dominant", RiskVector{Encryption: 3}, "security"},
		{"identity dominant", RiskVector{Identity: 3}, "security"},
		{"governance dominant", RiskVector{Governance: 3}, "compliance"},
		{"observability dominant", RiskVector{Observability: 3}, "reliability"},
		{"all zero", RiskVector{}, "best-practice"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rv.DominantCategory()
			if got != tt.want {
				t.Errorf("DominantCategory() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		v, min, max, want int
	}{
		{5, 0, 3, 3},
		{-1, 0, 3, 0},
		{2, 0, 3, 2},
		{0, 0, 3, 0},
		{3, 0, 3, 3},
	}

	for _, tt := range tests {
		got := clamp(tt.v, tt.min, tt.max)
		if got != tt.want {
			t.Errorf("clamp(%d, %d, %d) = %d, want %d", tt.v, tt.min, tt.max, got, tt.want)
		}
	}
}
