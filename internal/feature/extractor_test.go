package feature

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestExtract_AWSSecurityGroup(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_security_group.wide_open",
			Type:     "aws_security_group",
			Name:     "wide_open",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"ingress": []interface{}{
					map[string]interface{}{
						"cidr_blocks": []interface{}{"0.0.0.0/0"},
					},
				},
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	if len(features) != 1 {
		t.Fatalf("expected 1 feature, got %d", len(features))
	}

	f := features[0]
	if f.Provider != "aws" {
		t.Errorf("expected provider 'aws', got %q", f.Provider)
	}
	if f.NetworkExposure != 3 {
		t.Errorf("expected NetworkExposure 3 (wildcard CIDR), got %d", f.NetworkExposure)
	}
	if !containsFlag(f.Flags, "wildcard-cidr") {
		t.Errorf("expected 'wildcard-cidr' flag, got %v", f.Flags)
	}
}

func TestExtract_AWSS3BucketPublicACL(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_s3_bucket.insecure",
			Type:     "aws_s3_bucket",
			Name:     "insecure",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"acl": "public-read",
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.NetworkExposure != 3 {
		t.Errorf("expected NetworkExposure 3 (public ACL), got %d", f.NetworkExposure)
	}
	if f.EncryptionRisk < 1 {
		t.Errorf("expected EncryptionRisk >= 1 for S3 bucket, got %d", f.EncryptionRisk)
	}
	if !containsFlag(f.Flags, "public-access") {
		t.Errorf("expected 'public-access' flag, got %v", f.Flags)
	}
}

func TestExtract_AWSIAMWildcard(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_iam_policy.overly_permissive",
			Type:     "aws_iam_policy",
			Name:     "overly_permissive",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"policy": `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`,
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.IdentityRisk != 3 {
		t.Errorf("expected IdentityRisk 3 (wildcard policy), got %d", f.IdentityRisk)
	}
	if !containsFlag(f.Flags, "wildcard-policy") {
		t.Errorf("expected 'wildcard-policy' flag, got %v", f.Flags)
	}
}

func TestExtract_AzureVM(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "azurerm_virtual_machine.web",
			Type:     "azurerm_virtual_machine",
			Name:     "web",
			Provider: "registry.terraform.io/hashicorp/azurerm",
			Values: map[string]interface{}{
				"tags": map[string]interface{}{
					"env": "prod",
				},
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.Provider != "azure" {
		t.Errorf("expected provider 'azure', got %q", f.Provider)
	}
	if containsFlag(f.Flags, "no-tags") {
		t.Error("should NOT have 'no-tags' flag when tags are present")
	}
}

func TestExtract_GCPComputeInstance(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "google_compute_instance.default",
			Type:     "google_compute_instance",
			Name:     "default",
			Provider: "registry.terraform.io/hashicorp/google",
			Values: map[string]interface{}{
				"labels": map[string]interface{}{
					"team": "platform",
				},
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.Provider != "gcp" {
		t.Errorf("expected provider 'gcp', got %q", f.Provider)
	}
	if containsFlag(f.Flags, "no-tags") {
		t.Error("should NOT have 'no-tags' flag when labels are present")
	}
}

func TestExtract_NoValues(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "null_resource.test",
			Type:     "null_resource",
			Name:     "test",
			Provider: "registry.terraform.io/hashicorp/null",
			Values:   nil,
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.TotalRisk() < 0 {
		t.Errorf("total risk should be non-negative, got %d", f.TotalRisk())
	}
}

func TestExtract_DBInstanceMultipleRisks(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_db_instance.insecure",
			Type:     "aws_db_instance",
			Name:     "insecure",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"publicly_accessible": true,
				"storage_encrypted":   false,
				"skip_final_snapshot": true,
				"deletion_protection": false,
				"multi_az":            false,
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.NetworkExposure < 2 {
		t.Errorf("expected NetworkExposure >= 2 (publicly accessible), got %d", f.NetworkExposure)
	}
	if f.EncryptionRisk < 2 {
		t.Errorf("expected EncryptionRisk >= 2 (storage not encrypted), got %d", f.EncryptionRisk)
	}
	if f.GovernanceRisk < 2 {
		t.Errorf("expected GovernanceRisk >= 2 (skip final snapshot), got %d", f.GovernanceRisk)
	}
	if !containsFlag(f.Flags, "skip-final-snapshot") {
		t.Errorf("expected 'skip-final-snapshot' flag, got %v", f.Flags)
	}
	if !containsFlag(f.Flags, "single-az") {
		t.Errorf("expected 'single-az' flag, got %v", f.Flags)
	}
}

func TestExtract_FlagsSorted(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_db_instance.test",
			Type:     "aws_db_instance",
			Name:     "test",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"publicly_accessible": true,
				"skip_final_snapshot": true,
				"storage_encrypted":   false,
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	flags := features[0].Flags
	for i := 1; i < len(flags); i++ {
		if flags[i-1] > flags[i] {
			t.Errorf("flags not sorted: %v", flags)
			break
		}
	}
}

func TestExtract_CloudWatchLogGroup(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_cloudwatch_log_group.no_retention",
			Type:     "aws_cloudwatch_log_group",
			Name:     "no_retention",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values:   map[string]interface{}{},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.ObservabilityRisk < 1 {
		t.Errorf("expected ObservabilityRisk >= 1 for log group, got %d", f.ObservabilityRisk)
	}
	if !containsFlag(f.Flags, "no-retention") {
		t.Errorf("expected 'no-retention' flag, got %v", f.Flags)
	}
}

func TestExtract_EBSVolumeUnencrypted(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_ebs_volume.unencrypted",
			Type:     "aws_ebs_volume",
			Name:     "unencrypted",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"encrypted": false,
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if f.EncryptionRisk < 2 {
		t.Errorf("expected EncryptionRisk >= 2 for unencrypted EBS, got %d", f.EncryptionRisk)
	}
	if !containsFlag(f.Flags, "unencrypted") {
		t.Errorf("expected 'unencrypted' flag, got %v", f.Flags)
	}
}

func TestExtract_EC2InstancePublicIP(t *testing.T) {
	resources := []parser.NormalizedResource{
		{
			Address:  "aws_instance.web",
			Type:     "aws_instance",
			Name:     "web",
			Provider: "registry.terraform.io/hashicorp/aws",
			Values: map[string]interface{}{
				"associate_public_ip_address": true,
			},
		},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	f := features[0]
	if !containsFlag(f.Flags, "public-ip") {
		t.Errorf("expected 'public-ip' flag, got %v", f.Flags)
	}
}

func TestExtract_MultipleResources(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.a", Type: "aws_instance", Provider: "aws", Values: map[string]interface{}{}},
		{Address: "aws_instance.b", Type: "aws_instance", Provider: "aws", Values: map[string]interface{}{}},
		{Address: "aws_s3_bucket.c", Type: "aws_s3_bucket", Provider: "aws", Values: map[string]interface{}{}},
	}

	ext := NewExtractor()
	features := ext.Extract(resources)

	if len(features) != 3 {
		t.Fatalf("expected 3 features, got %d", len(features))
	}

	for i, f := range features {
		if f.ResourceID != resources[i].Address {
			t.Errorf("feature %d: expected ResourceID %q, got %q", i, resources[i].Address, f.ResourceID)
		}
	}
}

func TestDetectProvider(t *testing.T) {
	tests := []struct {
		provider string
		resType  string
		want     string
	}{
		{"registry.terraform.io/hashicorp/aws", "aws_instance", "aws"},
		{"registry.terraform.io/hashicorp/azurerm", "azurerm_virtual_machine", "azure"},
		{"registry.terraform.io/hashicorp/google", "google_compute_instance", "gcp"},
		{"", "aws_s3_bucket", "aws"},
		{"", "azurerm_storage_account", "azure"},
		{"", "google_storage_bucket", "gcp"},
		{"", "unknown_resource", "unknown"},
	}

	for _, tt := range tests {
		got := detectProvider(tt.provider, tt.resType)
		if got != tt.want {
			t.Errorf("detectProvider(%q, %q) = %q, want %q", tt.provider, tt.resType, got, tt.want)
		}
	}
}

func TestTotalRisk(t *testing.T) {
	rf := ResourceFeatures{
		NetworkExposure:   3,
		EncryptionRisk:    2,
		IdentityRisk:      1,
		GovernanceRisk:    2,
		ObservabilityRisk: 1,
	}

	want := 9
	if got := rf.TotalRisk(); got != want {
		t.Errorf("TotalRisk() = %d, want %d", got, want)
	}
}

func containsFlag(flags []string, target string) bool {
	for _, f := range flags {
		if f == target {
			return true
		}
	}
	return false
}
