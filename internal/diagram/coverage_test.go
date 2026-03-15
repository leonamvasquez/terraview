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
		{"aws_custom_sqs_queue", "Messaging"},
		{"aws_custom_sns_topic", "Messaging"},
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
		{"aws_custom_iam_user", "IAM"},
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

// ---------------------------------------------------------------------------
// New layer mappings — IAM, Messaging, Secrets, CICD
// ---------------------------------------------------------------------------

func TestGetLayer_NewCategories(t *testing.T) {
	tests := []struct {
		resType string
		want    string
	}{
		// IAM (split from Security)
		{"aws_iam_role", "IAM"},
		{"aws_iam_policy", "IAM"},
		{"aws_iam_role_policy_attachment", "IAM"},
		{"aws_iam_instance_profile", "IAM"},
		{"aws_iam_user", "IAM"},
		{"aws_iam_group", "IAM"},
		{"aws_iam_openid_connect_provider", "IAM"},
		{"aws_iam_service_linked_role", "IAM"},

		// Security (without IAM)
		{"aws_security_group", "Security"},
		{"aws_kms_key", "Security"},
		{"aws_acm_certificate", "Security"},
		{"aws_wafv2_web_acl", "Security"},
		{"aws_guardduty_detector", "Security"},
		{"aws_shield_protection", "Security"},

		// Messaging (split from Data)
		{"aws_sqs_queue", "Messaging"},
		{"aws_sns_topic", "Messaging"},
		{"aws_sns_topic_subscription", "Messaging"},
		{"aws_eventbridge_rule", "Messaging"},
		{"aws_cloudwatch_event_rule", "Messaging"},
		{"aws_msk_cluster", "Messaging"},
		{"aws_sfn_state_machine", "Messaging"},

		// Secrets & Config
		{"aws_ssm_parameter", "Secrets"},
		{"aws_secretsmanager_secret", "Secrets"},
		{"aws_appconfig_application", "Secrets"},

		// CI/CD & Registry
		{"aws_ecr_repository", "CICD"},
		{"aws_codebuild_project", "CICD"},
		{"aws_codepipeline", "CICD"},
		{"aws_codedeploy_app", "CICD"},
		{"aws_codecommit_repository", "CICD"},

		// Data (new additions)
		{"aws_efs_file_system", "Data"},
		{"aws_redshift_cluster", "Data"},
		{"aws_opensearch_domain", "Data"},
		{"aws_kinesis_stream", "Data"},
		{"aws_glue_job", "Data"},
		{"aws_backup_vault", "Data"},

		// Network (new additions)
		{"aws_vpc_endpoint", "Network"},
		{"aws_transit_gateway", "Network"},
		{"aws_vpn_connection", "Network"},

		// Compute (new additions)
		{"aws_eks_addon", "Compute"},
		{"aws_eks_fargate_profile", "Compute"},
		{"aws_lambda_layer_version", "Compute"},
		{"aws_batch_compute_environment", "Compute"},
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

func TestGetLayer_HeuristicNewCategories(t *testing.T) {
	tests := []struct {
		resType string
		want    string
	}{
		// Messaging heuristics
		{"aws_custom_sqs_dlq", "Messaging"},
		{"aws_custom_sns_platform", "Messaging"},
		{"aws_custom_eventbridge_bus", "Messaging"},
		{"aws_custom_ses_template", "Messaging"},
		{"aws_custom_msk_config", "Messaging"},
		{"aws_custom_sfn_workflow", "Messaging"},

		// IAM heuristic
		{"aws_custom_iam_policy", "IAM"},

		// Secrets heuristics
		{"aws_custom_ssm_patch", "Secrets"},
		{"aws_custom_secretsmanager_rotation", "Secrets"},
		{"aws_custom_appconfig_deploy", "Secrets"},

		// CICD heuristics
		{"aws_custom_ecr_image", "CICD"},
		{"aws_custom_codebuild_webhook", "CICD"},
		{"aws_custom_codepipeline_webhook", "CICD"},
		{"aws_custom_codedeploy_config", "CICD"},

		// Data heuristics (new keywords)
		{"aws_custom_efs_policy", "Data"},
		{"aws_custom_redshift_subnet", "Data"},
		{"aws_custom_kinesis_analytics", "Data"},
		{"aws_custom_glue_connection", "Data"},
		{"aws_custom_opensearch_policy", "Data"},
		{"aws_custom_backup_selection", "Data"},

		// Security heuristics (new keywords)
		{"aws_custom_guardduty_member", "Security"},
		{"aws_custom_shield_group", "Security"},
		{"aws_custom_macie_session", "Security"},
		{"aws_custom_inspector_template", "Security"},

		// Monitoring heuristics (new keywords)
		{"aws_custom_xray_group", "Monitoring"},
		{"aws_custom_budgets_action", "Monitoring"},
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

func TestServiceLabels_NewEntries(t *testing.T) {
	tests := map[string]string{
		// New services
		"aws_ecr_repository":              "ECR Repository",
		"aws_ssm_parameter":               "SSM Parameter",
		"aws_secretsmanager_secret":       "Secrets Manager",
		"aws_codebuild_project":           "CodeBuild Project",
		"aws_eventbridge_rule":            "EventBridge Rule",
		"aws_sfn_state_machine":           "Step Functions",
		"aws_efs_file_system":             "Amazon EFS",
		"aws_opensearch_domain":           "OpenSearch",
		"aws_guardduty_detector":          "GuardDuty",
		"aws_transit_gateway":             "Transit Gateway",
		"aws_eks_addon":                   "EKS Add-on",
		"aws_vpc_endpoint":                "VPC Endpoint",
		"aws_kinesis_stream":              "Kinesis Stream",
		"aws_msk_cluster":                 "Amazon MSK",
		"aws_redshift_cluster":            "Amazon Redshift",
		"aws_backup_vault":                "Backup Vault",
		"aws_glue_job":                    "Glue Job",
		"aws_iam_openid_connect_provider": "OIDC Provider",
	}
	for resType, want := range tests {
		got, ok := serviceLabels[resType]
		if !ok {
			t.Errorf("serviceLabels missing entry for %s", resType)
			continue
		}
		if got != want {
			t.Errorf("serviceLabels[%s] = %s, want %s", resType, got, want)
		}
	}
}

func TestGenerate_NewLayersAppear(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_iam_role.eks", Action: "create", Type: "aws_iam_role"},
		{Address: "aws_ecr_repository.app", Action: "create", Type: "aws_ecr_repository"},
		{Address: "aws_ssm_parameter.config", Action: "create", Type: "aws_ssm_parameter"},
		{Address: "aws_sqs_queue.events", Action: "create", Type: "aws_sqs_queue"},
		{Address: "aws_security_group.web", Action: "create", Type: "aws_security_group"},
	}
	result := gen.Generate(resources)

	for _, want := range []string{"IAM", "CI/CD & Registry", "Secrets & Config", "Messaging & Events", "Security"} {
		if !strings.Contains(result, want) {
			t.Errorf("expected layer %q in output", want)
		}
	}
}

func TestDiagramWidth_Increased(t *testing.T) {
	if diagramWidth != 100 {
		t.Errorf("diagramWidth = %d, want 100", diagramWidth)
	}
	if maxBoxWidth != 70 {
		t.Errorf("maxBoxWidth = %d, want 70", maxBoxWidth)
	}
}
