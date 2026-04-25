package feature

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestLookupProfile_KnownTypes(t *testing.T) {
	tests := []struct {
		resType string
		wantNet int
		wantEnc int
		wantId  int
		wantGov int
		wantObs int
	}{
		{"aws_eks_cluster", 3, 2, 2, 2, 2},
		{"aws_s3_bucket", 2, 2, 2, 2, 2},
		{"aws_iam_role", 0, 0, 3, 1, 0},
	}

	for _, tc := range tests {
		t.Run(tc.resType, func(t *testing.T) {
			p, ok := lookupProfile(tc.resType)
			if !ok {
				t.Fatalf("lookupProfile(%q) returned ok=false, want true", tc.resType)
			}
			if p.network != tc.wantNet {
				t.Errorf("network: got %d, want %d", p.network, tc.wantNet)
			}
			if p.encryption != tc.wantEnc {
				t.Errorf("encryption: got %d, want %d", p.encryption, tc.wantEnc)
			}
			if p.identity != tc.wantId {
				t.Errorf("identity: got %d, want %d", p.identity, tc.wantId)
			}
			if p.governance != tc.wantGov {
				t.Errorf("governance: got %d, want %d", p.governance, tc.wantGov)
			}
			if p.observability != tc.wantObs {
				t.Errorf("observability: got %d, want %d", p.observability, tc.wantObs)
			}
		})
	}
}

func TestLookupProfile_UnknownType(t *testing.T) {
	_, ok := lookupProfile("custom_resource")
	if ok {
		t.Fatal("lookupProfile(\"custom_resource\") returned ok=true, want false")
	}
}

func TestExtract_KinesisStreamHasEncryptionRisk(t *testing.T) {
	e := NewExtractor()
	resources := []parser.NormalizedResource{
		{
			Address: "aws_kinesis_stream.example",
			Type:    "aws_kinesis_stream",
			Values:  map[string]interface{}{},
		},
	}

	features := e.Extract(resources)
	if len(features) != 1 {
		t.Fatalf("expected 1 feature, got %d", len(features))
	}

	f := features[0]
	if f.EncryptionRisk < 2 {
		t.Errorf("EncryptionRisk: got %d, want >= 2", f.EncryptionRisk)
	}
}

func TestExtract_EKSClusterHighNetworkExposure(t *testing.T) {
	e := NewExtractor()
	resources := []parser.NormalizedResource{
		{
			Address: "aws_eks_cluster.main",
			Type:    "aws_eks_cluster",
			Values:  map[string]interface{}{},
		},
	}

	features := e.Extract(resources)
	if len(features) != 1 {
		t.Fatalf("expected 1 feature, got %d", len(features))
	}

	f := features[0]
	if f.NetworkExposure < 3 {
		t.Errorf("NetworkExposure: got %d, want >= 3", f.NetworkExposure)
	}
}

func TestExtract_IAMRoleIdentityRisk(t *testing.T) {
	e := NewExtractor()
	resources := []parser.NormalizedResource{
		{
			Address: "aws_iam_role.service",
			Type:    "aws_iam_role",
			Values:  map[string]interface{}{},
		},
	}

	features := e.Extract(resources)
	if len(features) != 1 {
		t.Fatalf("expected 1 feature, got %d", len(features))
	}

	f := features[0]
	if f.IdentityRisk < 3 {
		t.Errorf("IdentityRisk: got %d, want >= 3", f.IdentityRisk)
	}
}

func TestTypeRegistry_MinimumCoverage(t *testing.T) {
	if len(typeRegistry) < 60 {
		t.Errorf("typeRegistry has %d entries, want >= 60", len(typeRegistry))
	}
}
