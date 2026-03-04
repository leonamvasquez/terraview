package topology

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestBuildGraph_BasicResources(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Provider: "aws"},
		{Address: "aws_subnet.public", Type: "aws_subnet", Name: "public", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.public"}},
	}

	g := BuildGraph(resources)

	if len(g.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(g.Nodes))
	}

	if len(g.Edges) < 2 {
		t.Errorf("expected at least 2 edges, got %d", len(g.Edges))
	}
}

func TestBuildGraph_NoResources(t *testing.T) {
	g := BuildGraph(nil)
	if len(g.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(g.Nodes))
	}
}

func TestGraph_Layers(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create"},
		{Address: "aws_security_group.web", Type: "aws_security_group", Name: "web", Action: "create"},
		{Address: "aws_instance.app", Type: "aws_instance", Name: "app", Action: "create"},
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Name: "data", Action: "create"},
		{Address: "aws_db_instance.db", Type: "aws_db_instance", Name: "db", Action: "create"},
	}

	g := BuildGraph(resources)
	layers := g.Layers()

	if len(layers["network"]) != 1 {
		t.Errorf("expected 1 network resource, got %d", len(layers["network"]))
	}
	if len(layers["security"]) != 1 {
		t.Errorf("expected 1 security resource, got %d", len(layers["security"]))
	}
	if len(layers["compute"]) != 1 {
		t.Errorf("expected 1 compute resource, got %d", len(layers["compute"]))
	}
	if len(layers["storage"]) != 1 {
		t.Errorf("expected 1 storage resource, got %d", len(layers["storage"]))
	}
	if len(layers["database"]) != 1 {
		t.Errorf("expected 1 database resource, got %d", len(layers["database"]))
	}
}

func TestGraph_FormatContext(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create"},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
	}

	g := BuildGraph(resources)
	ctx := g.FormatContext()

	if !strings.Contains(ctx, "Infrastructure Topology") {
		t.Error("FormatContext should contain topology header")
	}
	if !strings.Contains(ctx, "NETWORK") {
		t.Error("FormatContext should contain NETWORK layer")
	}
	if !strings.Contains(ctx, "COMPUTE") {
		t.Error("FormatContext should contain COMPUTE layer")
	}
	if !strings.Contains(ctx, "Dependencies") {
		t.Error("FormatContext should contain dependencies section")
	}
}

func TestGraph_ImpactChains(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "update"},
		{Address: "aws_subnet.pub", Type: "aws_subnet", Name: "pub", Action: "no-op",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "no-op",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub"}},
	}

	g := BuildGraph(resources)
	ctx := g.FormatContext()

	if !strings.Contains(ctx, "Impact Chains") {
		t.Error("FormatContext should include impact chains when resources are changed")
	}
}

// ---------------------------------------------------------------------------
// inferTypeFromField
// ---------------------------------------------------------------------------

func TestInferTypeFromField(t *testing.T) {
	tests := []struct {
		field string
		want  string
	}{
		{"vpc_id", "aws_vpc"},
		{"subnet_id", "aws_subnet"},
		{"subnet_ids", "aws_subnet"},
		{"security_groups", "aws_security_group"},
		{"security_group_ids", "aws_security_group"},
		{"role_arn", "aws_iam_role"},
		{"iam_role", "aws_iam_role"},
		{"policy_arn", "aws_iam_policy"},
		{"kms_key_id", "aws_kms_key"},
		{"kms_key_arn", "aws_kms_key"},
		{"target_group_arn", "aws_lb_target_group"},
		{"load_balancer_arn", "aws_lb"},
		{"listener_arn", "aws_lb_listener"},
		{"certificate_arn", "aws_acm_certificate"},
		{"route_table_id", "aws_route_table"},
		{"internet_gateway_id", "aws_internet_gateway"},
		{"nat_gateway_id", "aws_nat_gateway"},
		{"instance_id", "aws_instance"},
		{"cluster_id", "aws_ecs_cluster"},
		{"log_group_name", "aws_cloudwatch_log_group"},
		{"bucket", "aws_s3_bucket"},
		{"queue_url", "aws_sqs_queue"},
		{"topic_arn", "aws_sns_topic"},
		{"function_name", "aws_lambda_function"},
		{"lambda_function_arn", "aws_lambda_function"},
		{"table_name", "aws_dynamodb_table"},
		{"stream_arn", "aws_kinesis_stream"},
		{"db_subnet_group_name", "aws_db_subnet_group"},
		{"key_id", "aws_kms_key"},
		// Unknown field should return empty
		{"unknown_field", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.field, func(t *testing.T) {
			got := inferTypeFromField(tc.field)
			if got != tc.want {
				t.Errorf("inferTypeFromField(%q) = %q, want %q", tc.field, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Layers — additional coverage
// ---------------------------------------------------------------------------

func TestGraph_Layers_Categories(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create"},
		{Address: "aws_security_group.sg", Type: "aws_security_group", Name: "sg", Action: "create"},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
		{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Name: "logs", Action: "create"},
		{Address: "aws_db_instance.db", Type: "aws_db_instance", Name: "db", Action: "create"},
		{Address: "custom_resource.x", Type: "custom_resource", Name: "x", Action: "create"},
	}
	g := BuildGraph(resources)
	layers := g.Layers()

	if len(layers["network"]) == 0 {
		t.Error("expected network layer to have resources")
	}
	if len(layers["security"]) == 0 {
		t.Error("expected security layer to have resources")
	}
	if len(layers["compute"]) == 0 {
		t.Error("expected compute layer to have resources")
	}
}

// ---------------------------------------------------------------------------
// resolveReference — covers string exact match, inferred type, array, default
// ---------------------------------------------------------------------------

func TestResolveReference_ExactMatch(t *testing.T) {
	addrIndex := map[string]*Node{
		"aws_subnet.main": {Address: "aws_subnet.main"},
	}
	typeIndex := map[string][]string{}
	results := resolveReference("aws_subnet.main", "subnet_id", typeIndex, addrIndex)
	if len(results) != 1 || results[0] != "aws_subnet.main" {
		t.Errorf("expected exact match, got %v", results)
	}
}

func TestResolveReference_InferredType(t *testing.T) {
	addrIndex := map[string]*Node{}
	typeIndex := map[string][]string{
		"aws_subnet": {"aws_subnet.a", "aws_subnet.b"},
	}
	results := resolveReference("subnet-12345", "subnet_id", typeIndex, addrIndex)
	if len(results) != 2 {
		t.Errorf("expected 2 inferred results, got %d", len(results))
	}
}

func TestResolveReference_NoMatch(t *testing.T) {
	addrIndex := map[string]*Node{}
	typeIndex := map[string][]string{}
	results := resolveReference("some-id", "unknown_field", typeIndex, addrIndex)
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestResolveReference_Array(t *testing.T) {
	addrIndex := map[string]*Node{
		"aws_subnet.a": {Address: "aws_subnet.a"},
	}
	typeIndex := map[string][]string{}
	input := []interface{}{"aws_subnet.a", "unknown"}
	results := resolveReference(input, "subnet_ids", typeIndex, addrIndex)
	if len(results) != 1 || results[0] != "aws_subnet.a" {
		t.Errorf("expected [aws_subnet.a], got %v", results)
	}
}

func TestResolveReference_NonStringType(t *testing.T) {
	addrIndex := map[string]*Node{}
	typeIndex := map[string][]string{}
	// int value should return nil (switch default)
	results := resolveReference(42, "some_field", typeIndex, addrIndex)
	if len(results) != 0 {
		t.Errorf("expected 0 results for non-string, got %d", len(results))
	}
}
