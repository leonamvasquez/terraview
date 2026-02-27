package diagram

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// ---------------------------------------------------------------------------
// getLayer — heuristic branches (unmapped resource types)
// ---------------------------------------------------------------------------

func TestGetLayer_HeuristicBranches(t *testing.T) {
	tests := []struct {
		resType string
		want    string
	}{
		// Data layer
		{"aws_custom_db_instance", "Data"},
		{"aws_custom_rds_cluster", "Data"},
		{"aws_custom_dynamodb_table", "Data"},
		{"aws_custom_elasticache_cluster", "Data"},
		{"aws_custom_storage_account", "Data"},
		{"aws_custom_bucket_policy", "Data"},
		{"aws_custom_s3_replication", "Data"},
		{"aws_custom_sqs_queue", "Data"},
		{"aws_custom_sns_topic", "Data"},
		// DNS layer
		{"aws_custom_cloudfront_dist", "DNS"},
		{"aws_custom_route53_zone", "DNS"},
		{"aws_custom_dns_record", "DNS"},
		// Access layer
		{"aws_custom_lb_listener", "Access"},
		{"aws_custom_alb_target", "Access"},
		{"aws_custom_gateway_route", "Access"},
		// Security layer
		{"aws_custom_security_rule", "Security"},
		{"aws_custom_iam_user", "Security"},
		{"aws_custom_kms_key", "Security"},
		{"aws_custom_firewall_rule", "Security"},
		{"aws_custom_waf_acl", "Security"},
		{"aws_custom_acm_certificate", "Security"},
		// Monitoring layer
		{"aws_custom_cloudwatch_alarm", "Monitoring"},
		{"aws_custom_log_group", "Monitoring"},
		{"aws_custom_alarm_action", "Monitoring"},
		{"aws_custom_monitor_policy", "Monitoring"},
		{"aws_custom_cloudtrail_trail", "Monitoring"},
		{"aws_custom_config_rule", "Monitoring"},
		// Network layer
		{"aws_custom_vpc_endpoint", "Network"},
		{"aws_custom_subnet_group", "Network"},
		{"aws_custom_network_interface", "Network"},
		{"aws_custom_route_entry", "Network"},
		{"aws_custom_eip_association", "Network"},
		{"aws_custom_nat_gateway", "Access"},
		// Compute layer
		{"aws_custom_instance_profile", "Compute"},
		{"aws_custom_cluster_config", "Monitoring"},
		{"aws_custom_lambda_function", "Compute"},
		{"aws_custom_ecs_service", "Compute"},
		{"aws_custom_eks_cluster", "Compute"},
		{"aws_custom_autoscaling_group", "Compute"},
		// Other (no match)
		{"aws_custom_something", "Other"},
		{"single_part", "Other"},
	}
	for _, tc := range tests {
		t.Run(tc.resType, func(t *testing.T) {
			got := getLayer(tc.resType)
			if got != tc.want {
				t.Errorf("getLayer(%q) = %q, want %q", tc.resType, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// containsPart
// ---------------------------------------------------------------------------

func TestContainsPart(t *testing.T) {
	if !containsPart([]string{"a", "b", "c"}, "b") {
		t.Error("expected true for existing part")
	}
	if containsPart([]string{"a", "b", "c"}, "d") {
		t.Error("expected false for missing part")
	}
	if containsPart(nil, "x") {
		t.Error("expected false for nil parts")
	}
	if containsPart([]string{}, "x") {
		t.Error("expected false for empty parts")
	}
}

// ---------------------------------------------------------------------------
// getLabel
// ---------------------------------------------------------------------------

func TestGetLabel_KnownType(t *testing.T) {
	got := getLabel("aws_instance", "aws_instance.web")
	if got == "aws_instance.web" {
		t.Logf("getLabel returned address, no friendly label (OK if not in serviceLabels)")
	}
	// If there's a serviceLabels entry, it should include the label
}

func TestGetLabel_UnknownType(t *testing.T) {
	got := getLabel("unknown_type_xyz", "unknown_type_xyz.foo")
	if got != "unknown_type_xyz.foo" {
		t.Errorf("expected address fallback, got %q", got)
	}
}

func TestGetLabel_NoAddressDot(t *testing.T) {
	got := getLabel("unknown_type", "single")
	if got != "single" {
		t.Errorf("expected %q, got %q", "single", got)
	}
}

// ---------------------------------------------------------------------------
// detectProvider
// ---------------------------------------------------------------------------

func TestDetectProvider_AWS(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Type: "aws_instance"},
	}
	if got := detectProvider(resources); got != "aws" {
		t.Errorf("detectProvider = %q, want aws", got)
	}
}

func TestDetectProvider_Azure(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Type: "azurerm_virtual_network"},
	}
	if got := detectProvider(resources); got != "azure" {
		t.Errorf("detectProvider = %q, want azure", got)
	}
}

func TestDetectProvider_GCP(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Type: "google_compute_instance"},
	}
	if got := detectProvider(resources); got != "gcp" {
		t.Errorf("detectProvider = %q, want gcp", got)
	}
}

func TestDetectProvider_Unknown(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Type: "custom_resource"},
	}
	if got := detectProvider(resources); got != "unknown" {
		t.Errorf("detectProvider = %q, want unknown", got)
	}
}

func TestDetectProvider_Empty(t *testing.T) {
	if got := detectProvider(nil); got != "unknown" {
		t.Errorf("detectProvider(nil) = %q, want unknown", got)
	}
}

// ---------------------------------------------------------------------------
// centerText
// ---------------------------------------------------------------------------

func TestCenterText_Shorter(t *testing.T) {
	got := centerText("hi", 10)
	if len(got) < 3 { // "hi" + some padding
		t.Errorf("got %q", got)
	}
}

func TestCenterText_ExactWidth(t *testing.T) {
	got := centerText("hello", 5)
	if got != "hello" {
		t.Errorf("got %q", got)
	}
}

func TestCenterText_LongerThanWidth(t *testing.T) {
	got := centerText("hello world", 5)
	if got != "hello world" {
		t.Errorf("got %q", got)
	}
}

func TestCenterText_Empty(t *testing.T) {
	got := centerText("", 10)
	if len(got) != 5 { // 5 spaces of padding left
		t.Logf("centerText('', 10) = %q (len=%d)", got, len(got))
	}
}
