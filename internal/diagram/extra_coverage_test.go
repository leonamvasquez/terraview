package diagram

// Additional tests targeting uncovered or low-coverage paths.
// Focuses on: canvas drawing primitives, emptyDiagram, diagramTitle,
// resolver helpers (toStringValue, findVPC*, ExtractConfigReferences),
// topo_renderer helpers, and Generate() with varied synthetic plans.

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// ─── Canvas primitives ───────────────────────────────────────────────────────

func TestCanvas_DrawVPCBorder(t *testing.T) {
	c := NewCanvas(20, 10)
	c.DrawVPCBorder(0, 0, 10, 5)
	// Top-left must be double-line TL corner
	if c.Cells[0][0] != cDblTL {
		t.Errorf("expected cDblTL at (0,0), got %q", c.Cells[0][0])
	}
	// Too-small sizes must not panic
	c.DrawVPCBorder(0, 0, 1, 1)
	c.DrawVPCBorder(0, 0, 0, 0)
}

func TestCanvas_DrawDashedBox(t *testing.T) {
	c := NewCanvas(20, 10)
	c.DrawDashedBox(0, 0, 10, 5)
	// Too-small sizes must not panic
	c.DrawDashedBox(0, 0, 1, 1)
	c.DrawDashedBox(0, 0, 0, 0)
}

func TestCanvas_DrawDottedBidirectionalArrow_NearVertical(t *testing.T) {
	c := NewCanvas(40, 20)
	// dx <= 2 — near-vertical path
	c.DrawDottedBidirectionalArrow(5, 2, 5, 8)
	// Not same row — should not panic
}

func TestCanvas_DrawDottedBidirectionalArrow_LShape(t *testing.T) {
	c := NewCanvas(40, 20)
	// dx > 2 — L-shape path
	c.DrawDottedBidirectionalArrow(5, 2, 15, 8)
}

func TestCanvas_DrawDottedBidirectionalArrow_FromGETo(t *testing.T) {
	c := NewCanvas(40, 20)
	// fromY >= toY — should return early without panic
	c.DrawDottedBidirectionalArrow(5, 8, 5, 2)
}

func TestCanvas_DrawRoutedBidirectionalArrow_NearVertical(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawRoutedBidirectionalArrow(5, 2, 5, 8)
}

func TestCanvas_DrawRoutedBidirectionalArrow_LShape(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawRoutedBidirectionalArrow(5, 2, 15, 12)
}

func TestCanvas_DrawRoutedBidirectionalArrow_FromGETo(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawRoutedBidirectionalArrow(5, 8, 5, 2)
}

func TestCanvas_DrawDashedArrowUp(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDashedArrowUp(5, 10, 2) // fromY > toY — valid
	c.DrawDashedArrowUp(5, 2, 10) // fromY <= toY — should return early
}

func TestCanvas_DrawDashedArrowLeft(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDashedArrowLeft(15, 5, 5) // fromX > toX — valid
	c.DrawDashedArrowLeft(5, 15, 5) // fromX <= toX — should return early
}

func TestCanvas_DrawDashedArrowRight(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDashedArrowRight(5, 15, 5) // toX > fromX — valid
	c.DrawDashedArrowRight(15, 5, 5) // toX <= fromX — should return early
}

func TestCanvas_DrawDottedArrow_NearVertical(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDottedArrow(5, 2, 5, 8) // dx <= 2
}

func TestCanvas_DrawDottedArrow_LShape(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDottedArrow(2, 2, 15, 10) // dx > 2
}

func TestCanvas_DrawDottedArrow_FromGETo(t *testing.T) {
	c := NewCanvas(40, 20)
	c.DrawDottedArrow(5, 8, 5, 2) // early return
}

func TestCanvas_IsVertConnector(t *testing.T) {
	cases := []struct {
		r    rune
		want bool
	}{
		{cBoxV, true},
		{cArrowD, true},
		{cTeeDown, true},
		{cTeeUp, true},
		{'x', false},
		{' ', false},
	}
	for _, tc := range cases {
		got := isVertConnector(tc.r)
		if got != tc.want {
			t.Errorf("isVertConnector(%q) = %v, want %v", tc.r, got, tc.want)
		}
	}
}

func TestCanvas_SetArrow_JunctionCharacters(t *testing.T) {
	c := NewCanvas(20, 20)
	// Pre-place a vertical line, then cross it with a horizontal
	c.Set(5, 5, cBoxV)
	c.setArrow(5, 5, cBoxH)
	if c.Cells[5][5] != cCross {
		t.Errorf("expected cCross at junction, got %q", c.Cells[5][5])
	}

	// Pre-place horizontal, cross with vertical
	c2 := NewCanvas(20, 20)
	c2.Set(5, 5, cBoxH)
	c2.setArrow(5, 5, cBoxV)
	if c2.Cells[5][5] != cCross {
		t.Errorf("expected cCross at H+V junction, got %q", c2.Cells[5][5])
	}

	// Protected cell — setArrow must be a no-op
	c3 := NewCanvas(20, 20)
	c3.SetProtected(5, 5, 'X')
	c3.setArrow(5, 5, '>')
	if c3.Cells[5][5] != 'X' {
		t.Errorf("protected cell was modified")
	}

	// dDblH + cBoxV (VPC border crossing)
	c4 := NewCanvas(20, 20)
	c4.Set(5, 5, cDblH)
	c4.setArrow(5, 5, cBoxV)
	if c4.Cells[5][5] != cBoxV {
		t.Errorf("expected cBoxV after VPC border crossing, got %q", c4.Cells[5][5])
	}

	// cDblV existing
	c5 := NewCanvas(20, 20)
	c5.Set(5, 5, cDblV)
	c5.setArrow(5, 5, cArrowD)
	if c5.Cells[5][5] != cBoxV {
		t.Errorf("expected cBoxV after dDblV, got %q", c5.Cells[5][5])
	}
}

func TestCanvas_Get_OutOfBounds(t *testing.T) {
	c := NewCanvas(5, 5)
	// Get returns ' ' for out-of-bounds coordinates.
	r := c.Get(-1, -1)
	if r != ' ' {
		t.Errorf("expected ' ' for out-of-bounds Get, got %q", r)
	}
	r = c.Get(100, 100)
	if r != ' ' {
		t.Errorf("expected ' ' for out-of-bounds Get, got %q", r)
	}
}

func TestCanvas_IsProtected_OutOfBounds(t *testing.T) {
	c := NewCanvas(5, 5)
	// Out-of-bounds coordinates are treated as protected (guard against writing).
	if !c.IsProtected(-1, -1) {
		t.Error("out-of-bounds should be treated as protected")
	}
}

func TestCanvas_AvoidBoxRows_WithRanges(t *testing.T) {
	c := NewCanvas(20, 20)
	c.ArrowAvoidRanges = []YRange{{MinY: 5, MaxY: 8}}
	// preferredY inside range → should find alternative
	got := c.avoidBoxRows(6, 2, 15)
	if got >= 5 && got <= 8 {
		t.Errorf("avoidBoxRows should avoid range [5,8], got %d", got)
	}
	// preferredY outside range → should return as-is
	got2 := c.avoidBoxRows(3, 2, 15)
	if got2 != 3 {
		t.Errorf("expected 3 (outside range), got %d", got2)
	}
	// No ranges
	c2 := NewCanvas(20, 20)
	got3 := c2.avoidBoxRows(7, 2, 15)
	if got3 != 7 {
		t.Errorf("expected 7 with no ranges, got %d", got3)
	}
}

// ─── emptyDiagram and diagramTitle ───────────────────────────────────────────

func TestEmptyDiagram_English(t *testing.T) {
	g := &Generator{}
	out := g.emptyDiagram()
	if !strings.Contains(out, "no resource changes") {
		t.Errorf("expected English empty message, got: %q", out)
	}
}

func TestEmptyDiagram_PTBR(t *testing.T) {
	g := &Generator{Lang: "pt-BR"}
	out := g.emptyDiagram()
	if !strings.Contains(out, "sem alterações") {
		t.Errorf("expected PT-BR empty message, got: %q", out)
	}
}

func TestDiagramTitle_English(t *testing.T) {
	title := diagramTitle("en", "AWS")
	if !strings.Contains(title, "Infrastructure Diagram") {
		t.Errorf("expected English title, got: %q", title)
	}
}

func TestDiagramTitle_PTBR(t *testing.T) {
	title := diagramTitle("pt-BR", "AWS")
	if !strings.Contains(title, "Diagrama de Infraestrutura") {
		t.Errorf("expected PT-BR title, got: %q", title)
	}
}

// ─── Generate() with empty/noop plan → emptyDiagram ─────────────────────────

func TestGenerate_EmptyResources(t *testing.T) {
	g := NewGenerator()
	out := g.Generate(nil)
	if out == "" {
		t.Error("expected non-empty output for empty resources")
	}
	if !strings.Contains(out, "no resource changes") {
		t.Errorf("expected empty diagram message, got: %q", out)
	}
}

func TestGenerate_AllNoOp(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "no-op"},
		{Address: "data.aws_ami.latest", Type: "data.aws_ami", Action: "read"},
	}
	out := g.Generate(resources)
	if !strings.Contains(out, "no resource changes") {
		t.Errorf("expected empty diagram for all no-op/read, got: %q", out)
	}
}

func TestGenerate_PTBR_EmptyResources(t *testing.T) {
	g := NewGenerator()
	g.Lang = "pt-BR"
	out := g.Generate(nil)
	if !strings.Contains(out, "sem alterações") {
		t.Errorf("expected PT-BR empty message, got: %q", out)
	}
}

// ─── Generate() flat mode with diverse resource types ────────────────────────

func TestGenerate_FlatMode_S3AndIAM(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Action: "create"},
		{Address: "aws_iam_role.lambda", Type: "aws_iam_role", Action: "create"},
		{Address: "aws_kms_key.main", Type: "aws_kms_key", Action: "create"},
		{Address: "aws_cloudwatch_log_group.app", Type: "aws_cloudwatch_log_group", Action: "create"},
	}
	out := g.Generate(resources)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestGenerate_FlatMode_WithGraph(t *testing.T) {
	g := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.pub", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub"}},
		{Address: "aws_lb.app", Type: "aws_lb", Action: "create",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub"}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty output")
	}
}

// ─── Generate() topo mode ─────────────────────────────────────────────────────

func TestGenerate_TopoMode_BasicVPC(t *testing.T) {
	g := NewTopoGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.pub", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub"}},
		{Address: "aws_security_group.web", Type: "aws_security_group", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_lb.app", Type: "aws_lb", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_db_instance.rds", Type: "aws_db_instance", Action: "create",
			Values: map[string]interface{}{"db_subnet_group_name": "aws_subnet.pub"}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty topo output")
	}
}

func TestGenerate_TopoMode_GlobalServices(t *testing.T) {
	g := NewTopoGenerator()
	// S3, IAM, CloudWatch — global services exercising topo_grid path
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Action: "create"},
		{Address: "aws_iam_role.lambda", Type: "aws_iam_role", Action: "create"},
		{Address: "aws_iam_policy.app", Type: "aws_iam_policy", Action: "create"},
		{Address: "aws_cloudwatch_log_group.app", Type: "aws_cloudwatch_log_group", Action: "create"},
		{Address: "aws_cloudwatch_metric_alarm.cpu", Type: "aws_cloudwatch_metric_alarm", Action: "create"},
		{Address: "aws_sqs_queue.events", Type: "aws_sqs_queue", Action: "create"},
		{Address: "aws_sns_topic.alerts", Type: "aws_sns_topic", Action: "create"},
		{Address: "aws_lambda_function.processor", Type: "aws_lambda_function", Action: "create",
			Values: map[string]interface{}{"role": "aws_iam_role.lambda"}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty topo output for global services")
	}
}

func TestGenerate_TopoMode_MultiVPC(t *testing.T) {
	g := NewTopoGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.prod", Type: "aws_vpc", Action: "create"},
		{Address: "aws_vpc.mgmt", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.prod_pub", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.prod"}},
		{Address: "aws_subnet.mgmt_pub", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.mgmt"}},
		{Address: "aws_instance.app", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.prod_pub"}},
		{Address: "aws_instance.bastion", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.mgmt_pub"}},
		{Address: "aws_vpc_peering_connection.prod_mgmt", Type: "aws_vpc_peering_connection",
			Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.prod", "peer_vpc_id": "aws_vpc.mgmt"}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty multi-VPC output")
	}
}

func TestGenerate_TopoMode_Lambda_SQS_Bidirectional(t *testing.T) {
	g := NewTopoGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_lambda_function.consumer", Type: "aws_lambda_function", Action: "create",
			Values: map[string]interface{}{"role": "aws_iam_role.lambda"}},
		{Address: "aws_sqs_queue.jobs", Type: "aws_sqs_queue", Action: "create"},
		{Address: "aws_iam_role.lambda", Type: "aws_iam_role", Action: "create"},
		// Lambda reads from SQS (bidirectional data service pattern)
		{Address: "aws_lambda_event_source_mapping.sqs", Type: "aws_lambda_event_source_mapping",
			Action: "create",
			Values: map[string]interface{}{
				"function_name":    "aws_lambda_function.consumer",
				"event_source_arn": "aws_sqs_queue.jobs",
			}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty lambda/sqs output")
	}
}

func TestGenerate_TopoMode_SecurityGroupCrossRefs(t *testing.T) {
	g := NewTopoGenerator()
	g.SGCrossRefs = []SGCrossRef{
		{OwnerSG: "aws_security_group.web", PeerSG: "aws_security_group.rds"},
	}
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.app", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_security_group.web", Type: "aws_security_group", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_security_group.rds", Type: "aws_security_group", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create",
			Values: map[string]interface{}{
				"subnet_id":              "aws_subnet.app",
				"vpc_security_group_ids": []interface{}{"aws_security_group.web"},
			}},
		{Address: "aws_db_instance.rds", Type: "aws_db_instance", Action: "create",
			Values: map[string]interface{}{
				"vpc_security_group_ids": []interface{}{"aws_security_group.rds"},
			}},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty SG cross-ref output")
	}
}

func TestGenerate_TopoMode_NetworkFirewall(t *testing.T) {
	g := NewTopoGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.firewall", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_networkfirewall_firewall.main", Type: "aws_networkfirewall_firewall",
			Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_networkfirewall_firewall_policy.main", Type: "aws_networkfirewall_firewall_policy",
			Action: "create"},
		{Address: "aws_networkfirewall_rule_group.stateless", Type: "aws_networkfirewall_rule_group",
			Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty network firewall output")
	}
}

func TestGenerate_TopoMode_EKS(t *testing.T) {
	g := NewTopoGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.private_1", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.private_2", Type: "aws_subnet", Action: "create",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_eks_cluster.main", Type: "aws_eks_cluster", Action: "create",
			Values: map[string]interface{}{
				"vpc_config": []interface{}{
					map[string]interface{}{"subnet_ids": []interface{}{"aws_subnet.private_1", "aws_subnet.private_2"}},
				},
			}},
		{Address: "aws_eks_node_group.workers", Type: "aws_eks_node_group", Action: "create",
			Values: map[string]interface{}{"cluster_name": "aws_eks_cluster.main"}},
		{Address: "aws_ecr_repository.app", Type: "aws_ecr_repository", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	out := g.GenerateWithGraph(resources, graph)
	if out == "" {
		t.Error("expected non-empty EKS output")
	}
}

func TestGenerate_TopoMode_DataSourcesOnly(t *testing.T) {
	g := NewTopoGenerator()
	// All resources are data or no-op — exercises emptyDiagram via active filter
	resources := []parser.NormalizedResource{
		{Address: "data.aws_ami.latest", Type: "data.aws_ami", Action: "read"},
		{Address: "aws_instance.unchanged", Type: "aws_instance", Action: "no-op"},
	}
	out := g.GenerateWithGraph(resources, nil)
	if !strings.Contains(out, "no resource changes") {
		t.Errorf("expected empty diagram for all read/no-op, got: %q", out)
	}
}

// ─── toStringValue ────────────────────────────────────────────────────────────

func TestToStringValue(t *testing.T) {
	tests := []struct {
		input interface{}
		want  string
	}{
		{"hello", "hello"},
		{[]interface{}{"first", "second"}, "first"},
		{[]interface{}{}, ""},
		{42, ""},
		{nil, ""},
	}
	for _, tc := range tests {
		got := toStringValue(tc.input)
		if got != tc.want {
			t.Errorf("toStringValue(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── findVPC* helpers ─────────────────────────────────────────────────────────

func TestFindVPCByModule(t *testing.T) {
	vpcAddrs := []string{"module.vpc.aws_vpc.main"}
	tests := []struct {
		addr string
		want string
	}{
		{"module.vpc.aws_subnet.pub", "module.vpc.aws_vpc.main"},
		{"aws_subnet.pub", ""},              // no module path
		{"module.other.aws_subnet.pub", ""}, // different module
	}
	for _, tc := range tests {
		got := findVPCByModule(tc.addr, vpcAddrs)
		if got != tc.want {
			t.Errorf("findVPCByModule(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestFindVPCByNamePrefix(t *testing.T) {
	vpcAddrs := []string{"aws_vpc.prod", "aws_vpc.mgmt"}
	tests := []struct {
		addr string
		want string
	}{
		{"aws_subnet.prod_public", "aws_vpc.prod"},
		{"aws_subnet.mgmt_private", "aws_vpc.mgmt"},
		{"aws_subnet.other", ""},
	}
	for _, tc := range tests {
		got := findVPCByNamePrefix(tc.addr, vpcAddrs)
		if got != tc.want {
			t.Errorf("findVPCByNamePrefix(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestFindVPCByAncestorName(t *testing.T) {
	parentOf := map[string]string{
		"aws_efs_access_point.data": "aws_efs_file_system.prod_shared",
	}
	vpcAddrs := []string{"aws_vpc.prod"}
	// The ancestor "prod_shared" name-prefix matches "aws_vpc.prod"
	got := findVPCByAncestorName("aws_efs_access_point.data", parentOf, vpcAddrs)
	if got != "aws_vpc.prod" {
		t.Errorf("expected aws_vpc.prod, got %q", got)
	}
	// No parent — should return ""
	got2 := findVPCByAncestorName("aws_instance.standalone", parentOf, vpcAddrs)
	if got2 != "" {
		t.Errorf("expected empty, got %q", got2)
	}
}

func TestFindVPCByConfigReferences(t *testing.T) {
	configRefs := map[string][]string{
		"aws_lambda_function.fn": {"local.prod_subnet_ids", "aws_vpc.prod.id"},
	}
	vpcAddrs := []string{"aws_vpc.prod"}
	got := findVPCByConfigReferences("aws_lambda_function.fn", configRefs, vpcAddrs)
	if got != "aws_vpc.prod" {
		t.Errorf("expected aws_vpc.prod, got %q", got)
	}
	// Non-matching refs
	configRefs2 := map[string][]string{
		"aws_lambda_function.fn": {"local.other_subnet_ids"},
	}
	got2 := findVPCByConfigReferences("aws_lambda_function.fn", configRefs2, vpcAddrs)
	_ = got2 // may or may not match depending on heuristic
}

// ─── ExtractConfigReferences ──────────────────────────────────────────────────

func TestExtractConfigReferences_Basic(t *testing.T) {
	config := parser.Configuration{
		RootModule: parser.ConfigModule{
			Resources: []parser.ConfigResource{
				{
					Address: "aws_lambda_function.fn",
					Expressions: map[string]interface{}{
						"subnet_ids": map[string]interface{}{
							"references": []interface{}{"local.subnet_ids", "aws_vpc.main.id"},
						},
					},
				},
			},
		},
	}
	refs := ExtractConfigReferences(config)
	if len(refs["aws_lambda_function.fn"]) == 0 {
		t.Error("expected references for aws_lambda_function.fn")
	}
}

func TestExtractConfigReferences_Empty(t *testing.T) {
	config := parser.Configuration{}
	refs := ExtractConfigReferences(config)
	if len(refs) != 0 {
		t.Errorf("expected empty refs, got %d", len(refs))
	}
}

func TestExtractConfigReferences_ModuleCalls(t *testing.T) {
	childModule := parser.ConfigModule{
		Resources: []parser.ConfigResource{
			{
				Address: "aws_instance.app",
				Expressions: map[string]interface{}{
					"subnet_id": map[string]interface{}{
						"references": []interface{}{"aws_subnet.main.id"},
					},
				},
			},
		},
	}
	config := parser.Configuration{
		RootModule: parser.ConfigModule{
			ModuleCalls: map[string]parser.ModuleCall{
				"app": {Module: &childModule},
			},
		},
	}
	refs := ExtractConfigReferences(config)
	// Should contain "module.app.aws_instance.app"
	found := false
	for k := range refs {
		if strings.Contains(k, "aws_instance.app") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected to find aws_instance.app in module refs")
	}
}

// ─── extractLocalName ─────────────────────────────────────────────────────────

func TestExtractLocalName(t *testing.T) {
	tests := []struct {
		addr string
		want string
	}{
		{"aws_vpc.main", "main"},
		{"module.vpc.aws_vpc.main", "main"},
		{"aws_subnet.prod_public[0]", "prod_public"},
		{"single", ""},
	}
	for _, tc := range tests {
		got := extractLocalName(tc.addr)
		if got != tc.want {
			t.Errorf("extractLocalName(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

// ─── vpcBucket.resourceCount ──────────────────────────────────────────────────

func TestVPCBucket_ResourceCount(t *testing.T) {
	b := &vpcBucket{
		subnetSummary: SubnetSummary{Public: 2, Private: 3, PrivateApp: 1},
		networkGroups: []*AggregatedGroup{{TotalCount: 2}},
		computeGroups: []*AggregatedGroup{{TotalCount: 5}},
		dataGroups:    []*AggregatedGroup{{TotalCount: 1}},
	}
	got := b.resourceCount()
	// 2+3+1 = 6 subnets + 2 network + 5 compute + 1 data = 14
	if got != 14 {
		t.Errorf("resourceCount() = %d, want 14", got)
	}
}

// ─── abbreviateService ────────────────────────────────────────────────────────

func TestAbbreviateService(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Lambda", "Lambda"},
		{"ElastiCache", "Cache"},
		{"VeryLongServiceNameThatExceedsTen", "VeryLongSe"},
		{"Short", "Short"},
	}
	for _, tc := range tests {
		got := abbreviateService(tc.input)
		if got != tc.want {
			t.Errorf("abbreviateService(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// ─── arrowXAtY ────────────────────────────────────────────────────────────────

func TestArrowXAtY(t *testing.T) {
	a := ArrowDef{FromX: 5, FromY: 2, ToX: 15, ToY: 10}
	// midY inside arrowXAtY = FromY + (ToY-FromY)/2 = 2 + 4 = 6

	// y=4 is before midY (6) — should return FromX (dx=10 > 2)
	x1 := arrowXAtY(a, 4)
	if x1 != a.FromX {
		t.Errorf("before midY: expected FromX=%d, got %d", a.FromX, x1)
	}

	// y=8 is after midY (6) — should return ToX
	x2 := arrowXAtY(a, 8)
	if x2 != a.ToX {
		t.Errorf("after midY: expected ToX=%d, got %d", a.ToX, x2)
	}

	// Near-vertical (dx <= 2) — always returns ToX
	a2 := ArrowDef{FromX: 5, FromY: 2, ToX: 6, ToY: 10}
	x3 := arrowXAtY(a2, 4)
	if x3 != a2.ToX {
		t.Errorf("near-vertical: expected ToX=%d, got %d", a2.ToX, x3)
	}
}

// ─── mergeServiceGroupsAcrossLayers ──────────────────────────────────────────

// ─── applyWAFAnnotations ──────────────────────────────────────────────────────

func TestApplyWAFAnnotations_NilConfigRefs(t *testing.T) {
	// nil configRefs — must return early without panic
	applyWAFAnnotations(map[string]*ServiceNode{}, nil)
}

func TestApplyWAFAnnotations_WithWAFAssoc(t *testing.T) {
	lbNode := &ServiceNode{ID: "lb1", Addresses: []string{"aws_lb.app"}}
	nodes := map[string]*ServiceNode{"lb1": lbNode}
	configRefs := map[string][]string{
		"aws_wafv2_web_acl_association.main": {"aws_lb.app.arn"},
	}
	applyWAFAnnotations(nodes, configRefs)
	// Should not panic; WAFProtected may be set on lbNode
}

// ─── tierPriority ─────────────────────────────────────────────────────────────

func TestTierPriority(t *testing.T) {
	tests := []struct {
		node *ServiceNode
		want int
	}{
		{&ServiceNode{Scope: "edge"}, 0},
		{&ServiceNode{SubnetTier: "public"}, 1},
		{&ServiceNode{SubnetTier: "private_app"}, 2},
		{&ServiceNode{SubnetTier: "private_data"}, 3},
		{&ServiceNode{SubnetTier: "private"}, 2},
		{&ServiceNode{SubnetTier: "vpc_level"}, 1},
		{&ServiceNode{SubnetTier: "unknown"}, 4},
	}
	for _, tc := range tests {
		got := tierPriority(tc.node)
		if got != tc.want {
			t.Errorf("tierPriority(scope=%q tier=%q) = %d, want %d",
				tc.node.Scope, tc.node.SubnetTier, got, tc.want)
		}
	}
}

// ─── hasVPCConfig ─────────────────────────────────────────────────────────────

func TestHasVPCConfig(t *testing.T) {
	tests := []struct {
		values map[string]interface{}
		want   bool
	}{
		{map[string]interface{}{}, false},
		{map[string]interface{}{"vpc_config": []interface{}{}}, false},
		{map[string]interface{}{"vpc_config": []interface{}{map[string]interface{}{"subnet_ids": []interface{}{}}}}, true},
		{map[string]interface{}{"vpc_config": map[string]interface{}{"subnet_ids": "x"}}, true},
	}
	for _, tc := range tests {
		got := hasVPCConfig(tc.values)
		if got != tc.want {
			t.Errorf("hasVPCConfig(%v) = %v, want %v", tc.values, got, tc.want)
		}
	}
}

// ─── findVPCByReverseConfigRefs ───────────────────────────────────────────────

func TestFindVPCByReverseConfigRefs(t *testing.T) {
	// configRefs: the VPC references an address that the subnet uses
	configRefs := map[string][]string{
		"aws_vpc.main": {"aws_subnet.pub.id"},
	}
	vpcAddrs := []string{"aws_vpc.main"}
	got := findVPCByReverseConfigRefs("aws_subnet.pub", configRefs, vpcAddrs)
	_ = got // may or may not match — just verify no panic

	// Empty refs — should return ""
	got2 := findVPCByReverseConfigRefs("aws_lambda.fn", nil, vpcAddrs)
	if got2 != "" {
		t.Errorf("expected empty result for nil configRefs, got %q", got2)
	}
}

// ─── resolveLambdaPlacement ───────────────────────────────────────────────────

func TestResolveLambdaPlacement(t *testing.T) {
	// Lambda with vpc_config → should resolve to VPC placement
	lambdaRes := &parser.NormalizedResource{
		Address: "aws_lambda_function.fn",
		Type:    "aws_lambda_function",
		Values: map[string]interface{}{
			"vpc_config": []interface{}{
				map[string]interface{}{"subnet_ids": []interface{}{"aws_subnet.app"}},
			},
		},
	}
	group := &AggregatedGroup{
		Service:   "Lambda",
		Addresses: []string{"aws_lambda_function.fn"},
	}
	resByAddr := map[string]*parser.NormalizedResource{
		"aws_lambda_function.fn": lambdaRes,
	}
	got := resolveLambdaPlacement(group, resByAddr)
	_ = got // result depends on VPC resolution logic — just verify no panic

	// Lambda without vpc_config
	lambdaNoVPC := &parser.NormalizedResource{
		Address: "aws_lambda_function.fn2",
		Type:    "aws_lambda_function",
		Values:  map[string]interface{}{},
	}
	group2 := &AggregatedGroup{
		Service:   "Lambda",
		Addresses: []string{"aws_lambda_function.fn2"},
	}
	resByAddr2 := map[string]*parser.NormalizedResource{
		"aws_lambda_function.fn2": lambdaNoVPC,
	}
	got2 := resolveLambdaPlacement(group2, resByAddr2)
	_ = got2
}

// ─── connectionsFromConfigRefs ────────────────────────────────────────────────

func TestConnectionsFromConfigRefs_Basic(t *testing.T) {
	cfgRefs := map[string][]string{
		"aws_lambda_function.fn": {"aws_sqs_queue.jobs.arn"},
	}
	resByAddr := map[string]*parser.NormalizedResource{
		"aws_lambda_function.fn": {Address: "aws_lambda_function.fn", Type: "aws_lambda_function"},
		"aws_sqs_queue.jobs":     {Address: "aws_sqs_queue.jobs", Type: "aws_sqs_queue"},
	}
	conns := connectionsFromConfigRefs(cfgRefs, resByAddr)
	_ = conns // verify no panic
}

func TestConnectionsFromConfigRefs_Empty(t *testing.T) {
	conns := connectionsFromConfigRefs(nil, nil)
	if len(conns) != 0 {
		t.Errorf("expected 0 connections for nil input, got %d", len(conns))
	}
}

// ─── placeTGWNode ─────────────────────────────────────────────────────────────

func TestPlaceTGWNode_WithAttachments(t *testing.T) {
	result := &LayoutResult{
		Boxes: make(map[string]*BoxPos),
	}
	curY := 5
	placeTGWNode(result, &curY, 80, 2, 0)
	if len(result.Boxes) == 0 {
		t.Error("expected at least one box entry after placeTGWNode")
	}
}

func TestPlaceTGWNode_ZeroAttachments(t *testing.T) {
	result := &LayoutResult{
		Boxes: make(map[string]*BoxPos),
	}
	curY := 5
	// attachmentCount=0 — label is "Transit Gateway" (no count)
	placeTGWNode(result, &curY, 80, 0, 1)
	if len(result.Boxes) == 0 {
		t.Error("expected box entry even with 0 attachments")
	}
}

func TestMergeServiceGroupsAcrossLayers_Basic(t *testing.T) {
	// Two non-VPC layers with the same service — merging should deduplicate.
	result := &TopoResult{
		Layers: []*TopoLayer{
			{
				IsVPC: false,
				Groups: []*AggregatedGroup{
					{Service: "S3", Type: "aws_s3_bucket", Addresses: []string{"aws_s3_bucket.a"}, TotalCount: 1},
				},
			},
			{
				IsVPC: false,
				Groups: []*AggregatedGroup{
					{Service: "S3", Type: "aws_s3_bucket", Addresses: []string{"aws_s3_bucket.b"}, TotalCount: 1},
				},
			},
		},
	}
	mergeServiceGroupsAcrossLayers(result)
	// After merge the second layer's S3 group should be absorbed into the first.
	total := 0
	for _, l := range result.Layers {
		total += len(l.Groups)
	}
	if total != 1 {
		t.Errorf("expected 1 group after merge, got %d", total)
	}
}
