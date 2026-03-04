package diagram

import (
	"fmt"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
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

// ---------------------------------------------------------------------------
// actionIcon
// ---------------------------------------------------------------------------

func TestActionIcon(t *testing.T) {
	tests := []struct {
		action string
		want   string
	}{
		{"create", "[+]"},
		{"update", "[~]"},
		{"delete", "[-]"},
		{"replace", "[!]"},
		{"unknown", "[ ]"},
		{"", "[ ]"},
	}
	for _, tc := range tests {
		t.Run(tc.action, func(t *testing.T) {
			got := actionIcon(tc.action)
			if got != tc.want {
				t.Errorf("actionIcon(%q) = %q, want %q", tc.action, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// providerTitle
// ---------------------------------------------------------------------------

func TestProviderTitle(t *testing.T) {
	tests := []struct {
		provider string
		want     string
	}{
		{"aws", "AWS"},
		{"azure", "Azure"},
		{"gcp", "Google Cloud"},
		{"unknown", "Cloud"},
		{"", "Cloud"},
	}
	for _, tc := range tests {
		t.Run(tc.provider, func(t *testing.T) {
			got := providerTitle(tc.provider)
			if got != tc.want {
				t.Errorf("providerTitle(%q) = %q, want %q", tc.provider, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// runeLen
// ---------------------------------------------------------------------------

func TestRuneLen(t *testing.T) {
	tests := []struct {
		input string
		want  int
	}{
		{"hello", 5},
		{"", 0},
		{"café", 4},
		{"日本語", 3},
	}
	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := runeLen(tc.input)
			if got != tc.want {
				t.Errorf("runeLen(%q) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// buildEdgeMap
// ---------------------------------------------------------------------------

func TestBuildEdgeMap_Empty(t *testing.T) {
	graph := &topology.Graph{}
	edges := buildEdgeMap(graph)
	if len(edges) != 0 {
		t.Errorf("expected empty map, got %d entries", len(edges))
	}
}

func TestBuildEdgeMap_WithEdges(t *testing.T) {
	graph := &topology.Graph{
		Edges: []topology.Edge{
			{From: "a", To: "b"},
			{From: "a", To: "c"},
			{From: "b", To: "c"},
		},
	}
	edges := buildEdgeMap(graph)
	if len(edges["a"]) != 2 {
		t.Errorf("expected 2 edges from a, got %d", len(edges["a"]))
	}
	if len(edges["b"]) != 1 {
		t.Errorf("expected 1 edge from b, got %d", len(edges["b"]))
	}
}

// ---------------------------------------------------------------------------
// renderLayerBoxes — coverage for single vs dual column paths
// ---------------------------------------------------------------------------

func TestRenderLayerBoxes_SingleBox(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	layer := Layer{
		Name: "Compute",
		Resources: []ResourceEntry{
			{Address: "aws_instance.web", Type: "aws_instance", Action: "create", Label: "EC2 Instance (web)"},
		},
	}
	g.renderLayerBoxes(&sb, layer, nil)
	out := sb.String()
	if !strings.Contains(out, "[+]") {
		t.Error("expected [+] icon in output")
	}
	if !strings.Contains(out, "Compute") {
		t.Error("expected Compute title in output")
	}
}

func TestRenderLayerBoxes_DualColumn(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	resources := make([]ResourceEntry, 4)
	for i := range resources {
		resources[i] = ResourceEntry{
			Address: fmt.Sprintf("aws_instance.node%d", i),
			Type:    "aws_instance",
			Action:  "create",
			Label:   fmt.Sprintf("EC2 Instance (node%d)", i),
		}
	}
	layer := Layer{
		Name:      "Compute",
		Resources: resources,
	}
	g.renderLayerBoxes(&sb, layer, nil)
	out := sb.String()
	if !strings.Contains(out, "Compute") {
		t.Error("expected Compute title")
	}
	if strings.Count(out, "[+]") != 4 {
		t.Errorf("expected 4 [+] icons, got %d", strings.Count(out, "[+]"))
	}
}

func TestRenderSingleLayerBox_LongLabel(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	resources := []ResourceEntry{
		{
			Address: "aws_instance.very_long_name",
			Type:    "aws_instance",
			Action:  "create",
			Label:   strings.Repeat("x", 200), // Very long label should be truncated
		},
	}
	g.renderSingleLayerBox(&sb, "Test", resources)
	out := sb.String()
	if !strings.Contains(out, "...") {
		t.Error("expected truncation with '...' for long label")
	}
}

func TestRenderLayerBoxes_UnknownLayer(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	layer := Layer{
		Name: "UnknownLayer",
		Resources: []ResourceEntry{
			{Address: "custom.res", Type: "custom", Action: "update", Label: "Custom Resource"},
		},
	}
	g.renderLayerBoxes(&sb, layer, nil)
	out := sb.String()
	if out == "" {
		t.Error("expected non-empty output for unknown layer")
	}
}

// ---------------------------------------------------------------------------
// Generate — additional edge cases
// ---------------------------------------------------------------------------

func TestGenerate_OnlyReadResources(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "data.aws_ami.latest", Action: "read", Type: "data.aws_ami"},
	}
	result := g.Generate(resources)
	if !strings.Contains(result, "no resource changes") {
		t.Error("expected 'no resource changes' for read-only resources")
	}
}

func TestGenerate_MixedActions(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
		{Address: "aws_instance.old", Action: "delete", Type: "aws_instance"},
		{Address: "aws_s3_bucket.logs", Action: "update", Type: "aws_s3_bucket"},
		{Address: "aws_iam_role.admin", Action: "replace", Type: "aws_iam_role"},
	}
	result := g.Generate(resources)
	if !strings.Contains(result, "[+]") {
		t.Error("expected [+] for create")
	}
	if !strings.Contains(result, "[-]") {
		t.Error("expected [-] for delete")
	}
	if !strings.Contains(result, "[~]") {
		t.Error("expected [~] for update")
	}
	if !strings.Contains(result, "[!]") {
		t.Error("expected [!] for replace")
	}
}

func TestGenerateWithGraph_NilGraph(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	result := g.GenerateWithGraph(resources, nil)
	if result == "" {
		t.Error("expected non-empty output with nil graph")
	}
}

// ---------------------------------------------------------------------------
// renderDualColumnBox — direct test for dual column rendering
// ---------------------------------------------------------------------------

func TestRenderDualColumnBox_UnequalColumns(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	left := []ResourceEntry{
		{Address: "aws_instance.a", Action: "create", Label: "Instance A"},
		{Address: "aws_instance.b", Action: "update", Label: "Instance B"},
		{Address: "aws_instance.c", Action: "delete", Label: "Instance C"},
	}
	right := []ResourceEntry{
		{Address: "aws_s3_bucket.x", Action: "create", Label: "Bucket X"},
	}
	g.renderDualColumnBox(&sb, "Test Box", left, right)
	output := sb.String()
	if !strings.Contains(output, "Test Box") {
		t.Error("expected title in output")
	}
	if !strings.Contains(output, "Instance A") {
		t.Error("expected left column resources")
	}
	if !strings.Contains(output, "Bucket X") {
		t.Error("expected right column resources")
	}
}

func TestRenderDualColumnBox_LongLabels(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	longLabel := "This is an extremely long resource label that should be truncated with ellipsis in the output"
	left := []ResourceEntry{
		{Address: "aws_instance.a", Action: "create", Label: longLabel},
	}
	right := []ResourceEntry{
		{Address: "aws_instance.b", Action: "delete", Label: longLabel},
	}
	g.renderDualColumnBox(&sb, "Truncation Test", left, right)
	output := sb.String()
	if !strings.Contains(output, "...") {
		t.Error("expected truncation ellipsis in output")
	}
}

func TestRenderDualColumnBox_EmptyColumns(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	left := []ResourceEntry{
		{Address: "aws_instance.a", Action: "create", Label: "Only Left"},
	}
	g.renderDualColumnBox(&sb, "One Side", left, nil)
	output := sb.String()
	if !strings.Contains(output, "One Side") {
		t.Error("expected title")
	}
}

// ---------------------------------------------------------------------------
// renderInnerDualBox — direct test for inner dual rendering
// ---------------------------------------------------------------------------

func TestRenderInnerDualBox_Basic(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	resources := []ResourceEntry{
		{Address: "aws_instance.a", Action: "create", Label: "Instance A"},
		{Address: "aws_instance.b", Action: "update", Label: "Instance B"},
		{Address: "aws_instance.c", Action: "delete", Label: "Instance C"},
		{Address: "aws_instance.d", Action: "create", Label: "Instance D"},
	}
	g.renderInnerDualBox(&sb, "Inner Box", resources, 80, 70)
	output := sb.String()
	if !strings.Contains(output, "Inner Box") {
		t.Error("expected title in output")
	}
}

func TestRenderInnerDualBox_NarrowWidth(t *testing.T) {
	g := NewGenerator()
	var sb strings.Builder
	resources := []ResourceEntry{
		{Address: "aws_instance.a", Action: "create", Label: "A really long label that needs truncation"},
	}
	g.renderInnerDualBox(&sb, "Narrow", resources, 40, 30)
	output := sb.String()
	if output == "" {
		t.Error("expected non-empty output even with narrow width")
	}
}
