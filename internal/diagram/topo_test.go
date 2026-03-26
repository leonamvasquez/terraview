package diagram

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// --- Resolver Tests ---

func TestResolveTopology_BasicVPC(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.pub", Action: "create", Type: "aws_subnet",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub"}},
	}

	graph := topology.BuildGraph(resources)
	result := ResolveTopology(resources, graph)

	if result.Provider != "aws" {
		t.Errorf("expected provider aws, got %s", result.Provider)
	}

	var vpcLayer *TopoLayer
	for _, l := range result.Layers {
		if l.IsVPC {
			vpcLayer = l
			break
		}
	}
	if vpcLayer == nil {
		t.Fatal("expected a VPC layer")
	}

	// Subnet should be in subnet summary, not individual boxes
	if vpcLayer.SubnetSummary == nil {
		t.Error("expected subnet summary inside VPC layer")
	}

	// Instance should be in Compute groups inside VPC
	if len(vpcLayer.ComputeGroups) == 0 {
		t.Error("expected compute groups inside VPC")
	}
}

func TestResolveTopology_TypeHierarchyAutoAssign(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.pub", Action: "create", Type: "aws_subnet"},
		{Address: "aws_security_group.web", Action: "create", Type: "aws_security_group"},
		{Address: "aws_internet_gateway.gw", Action: "create", Type: "aws_internet_gateway"},
	}

	result := ResolveTopology(resources, nil)

	var vpcLayer *TopoLayer
	for _, l := range result.Layers {
		if l.IsVPC {
			vpcLayer = l
			break
		}
	}
	if vpcLayer == nil {
		t.Fatal("expected VPC layer even without explicit references")
	}

	// Subnet should be in summary
	if vpcLayer.SubnetSummary == nil {
		t.Error("expected subnet summary")
	}
	// SG and IGW should be in Network groups
	if len(vpcLayer.NetworkGroups) < 2 {
		t.Errorf("expected SG and IGW in VPC network groups, got %d groups", len(vpcLayer.NetworkGroups))
	}
}

func TestResolveTopology_EKSClusterInCompute(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_eks_cluster.main", Action: "create", Type: "aws_eks_cluster"},
		{Address: "aws_eks_node_group.workers", Action: "create", Type: "aws_eks_node_group"},
		{Address: "aws_eks_addon.cni", Action: "create", Type: "aws_eks_addon"},
	}

	result := ResolveTopology(resources, nil)

	var vpcLayer *TopoLayer
	for _, l := range result.Layers {
		if l.IsVPC {
			vpcLayer = l
			break
		}
	}
	if vpcLayer == nil {
		t.Fatal("expected VPC layer")
	}

	if len(vpcLayer.ComputeGroups) == 0 {
		t.Error("expected EKS resources in Compute groups inside VPC")
	}

	// Check that EKS Cluster, Node Group, and Addon are all in Compute
	serviceSet := make(map[string]bool)
	for _, g := range vpcLayer.ComputeGroups {
		serviceSet[g.Service] = true
	}
	if !serviceSet["EKS Cluster"] {
		t.Error("expected EKS Cluster in Compute groups")
	}
	if !serviceSet["EKS Node Group"] {
		t.Error("expected EKS Node Group in Compute groups")
	}
	if !serviceSet["EKS Addon"] {
		t.Error("expected EKS Addon in Compute groups")
	}
}

func TestResolveTopology_DataInVPC(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_rds_cluster.main", Action: "create", Type: "aws_rds_cluster"},
		{Address: "aws_dynamodb_table.sessions", Action: "create", Type: "aws_dynamodb_table"},
		{Address: "aws_elasticache_replication_group.redis", Action: "create", Type: "aws_elasticache_replication_group"},
	}

	result := ResolveTopology(resources, nil)

	var vpcLayer *TopoLayer
	for _, l := range result.Layers {
		if l.IsVPC {
			vpcLayer = l
			break
		}
	}
	if vpcLayer == nil {
		t.Fatal("expected VPC layer")
	}

	if len(vpcLayer.DataGroups) == 0 {
		t.Error("expected data resources in Data groups inside VPC")
	}
}

func TestResolveTopology_ConnectionEdges(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance",
			Values: map[string]interface{}{"role_arn": "aws_iam_role.web"}},
		{Address: "aws_iam_role.web", Action: "create", Type: "aws_iam_role"},
	}

	graph := topology.BuildGraph(resources)
	result := ResolveTopology(resources, graph)

	if len(result.Connections) == 0 {
		t.Error("expected connection edges for role_arn dependency")
	}
}

func TestResolveTopology_InferredConnections(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_route53_record.app", Action: "create", Type: "aws_route53_record"},
		{Address: "aws_lb.main", Action: "create", Type: "aws_lb"},
	}

	result := ResolveTopology(resources, nil)

	found := false
	for _, c := range result.Connections {
		if c.Via == "alias" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected inferred connection Route53→LB via 'alias'")
	}
}

func TestResolveTopology_NoGraph(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.logs", Action: "create", Type: "aws_s3_bucket"},
	}

	result := ResolveTopology(resources, nil)

	if result.Provider != "aws" {
		t.Errorf("expected provider aws, got %s", result.Provider)
	}
	if len(result.Layers) == 0 {
		t.Error("expected at least one layer")
	}
}

func TestResolveTopology_SubnetSummaryTiers(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.public_a", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.public_b", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.private_app_a", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.private_app_b", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.private_data_a", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.private_data_b", Action: "create", Type: "aws_subnet"},
	}

	result := ResolveTopology(resources, nil)

	var vpcLayer *TopoLayer
	for _, l := range result.Layers {
		if l.IsVPC {
			vpcLayer = l
			break
		}
	}
	if vpcLayer == nil {
		t.Fatal("expected VPC layer")
	}
	if vpcLayer.SubnetSummary == nil {
		t.Fatal("expected subnet summary")
	}

	s := vpcLayer.SubnetSummary
	if s.Public != 2 {
		t.Errorf("expected 2 public subnets, got %d", s.Public)
	}
	if s.PrivateApp != 2 {
		t.Errorf("expected 2 private_app subnets, got %d", s.PrivateApp)
	}
	if s.PrivateData != 2 {
		t.Errorf("expected 2 private_data subnets, got %d", s.PrivateData)
	}
}

func TestResolveTopology_NoVPCServerless(t *testing.T) {
	// Serverless infra without VPC — Compute/Data should go to Supporting
	resources := []parser.NormalizedResource{
		{Address: "aws_lambda_function.api", Action: "create", Type: "aws_lambda_function"},
		{Address: "aws_dynamodb_table.users", Action: "create", Type: "aws_dynamodb_table"},
		{Address: "aws_s3_bucket.data", Action: "create", Type: "aws_s3_bucket"},
	}

	result := ResolveTopology(resources, nil)

	// No VPC layer
	for _, l := range result.Layers {
		if l.IsVPC {
			t.Error("should not have VPC layer for serverless infra")
		}
	}

	// All resources should land in Supporting
	if len(result.Layers) == 0 {
		t.Error("expected at least one layer")
	}
}

func TestIsContainmentEdge(t *testing.T) {
	tests := map[string]bool{
		"vpc_id":           true,
		"subnet_id":        true,
		"subnet_ids":       true,
		"role_arn":         false,
		"target_group_arn": false,
		"security_groups":  false,
	}
	for field, want := range tests {
		got := isContainmentEdge(field)
		if got != want {
			t.Errorf("isContainmentEdge(%q) = %v, want %v", field, got, want)
		}
	}
}

func TestExtractModulePath(t *testing.T) {
	tests := map[string]string{
		"aws_vpc.main":                         "",
		"module.vpc.aws_vpc.main":              "module.vpc",
		"module.infra.module.vpc.aws_vpc.main": "module.infra.module.vpc",
	}
	for addr, want := range tests {
		got := extractModulePath(addr)
		if got != want {
			t.Errorf("extractModulePath(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestExtractTypeFromAddress(t *testing.T) {
	tests := map[string]string{
		"aws_vpc.main":                       "aws_vpc",
		"module.vpc.aws_subnet.pub":          "aws_subnet",
		"module.a.module.b.aws_instance.web": "aws_instance",
	}
	for addr, want := range tests {
		got := extractTypeFromAddress(addr)
		if got != want {
			t.Errorf("extractTypeFromAddress(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestClassifySubnetTier(t *testing.T) {
	tests := map[string]string{
		"aws_subnet.public_a":       "public",
		"aws_subnet.private_app_a":  "private_app",
		"aws_subnet.private_data_a": "private_data",
		"aws_subnet.internal":       "private",
	}
	for addr, want := range tests {
		got := classifySubnetTier(addr)
		if got != want {
			t.Errorf("classifySubnetTier(%q) = %q, want %q", addr, got, want)
		}
	}
}

// --- Aggregator Tests ---

func TestAggregateTopoResult_ServiceLabels(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "Supporting",
				Order: 3,
				Groups: []*AggregatedGroup{
					{Service: "S3", Type: "aws_s3_bucket", Label: "S3",
						PrimaryCount: 8, TotalCount: 35, Addresses: []string{"a", "b", "c", "d", "e", "f", "g", "h"}},
					{Service: "IAM", Type: "aws_iam_role", Label: "IAM",
						PrimaryCount: 1, TotalCount: 1, Addresses: []string{"x"}},
				},
			},
		},
	}

	AggregateTopoResult(result)

	g := result.Layers[0].Groups[0]
	if !strings.Contains(g.Label, "8") || !strings.Contains(g.Label, "35") {
		t.Errorf("expected S3 label with counts 8 and 35, got %q", g.Label)
	}

	g2 := result.Layers[0].Groups[1]
	if g2.Label != "IAM (1)" {
		t.Errorf("expected 'IAM (1)' (always show count), got %q", g2.Label)
	}
}

func TestAggregateTopoResult_VPCInnerGroups(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Layers: []*TopoLayer{
			{
				Name:  "VPC",
				IsVPC: true,
				NetworkGroups: []*AggregatedGroup{
					{Service: "Security Group", Label: "Security Group", PrimaryCount: 11, TotalCount: 14},
				},
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Node Group", Label: "EKS Node Group", PrimaryCount: 3, TotalCount: 3},
				},
				DataGroups: []*AggregatedGroup{
					{Service: "Aurora RDS", Label: "Aurora RDS", PrimaryCount: 2, TotalCount: 5},
				},
			},
		},
	}

	AggregateTopoResult(result)

	ng := result.Layers[0].NetworkGroups[0]
	if !strings.Contains(ng.Label, "11") {
		t.Errorf("expected Security Group label with count 11, got %q", ng.Label)
	}

	cg := result.Layers[0].ComputeGroups[0]
	if !strings.Contains(cg.Label, "3") {
		t.Errorf("expected EKS Node Group label with count 3, got %q", cg.Label)
	}

	dg := result.Layers[0].DataGroups[0]
	if !strings.Contains(dg.Label, "2") && !strings.Contains(dg.Label, "5") {
		t.Errorf("expected Aurora RDS label with counts, got %q", dg.Label)
	}
}

func TestAggregateTopoResult_DeduplicateConnections(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Layers: []*TopoLayer{
			{
				Name:  "VPC",
				IsVPC: true,
				ComputeGroups: []*AggregatedGroup{
					{Service: "EC2 Instance", Label: "EC2 Instance (2)",
						PrimaryCount: 2, TotalCount: 2,
						Addresses: []string{"aws_instance.a", "aws_instance.b"}},
				},
			},
			{
				Name: "Supporting",
				Groups: []*AggregatedGroup{
					{Service: "IAM", Label: "IAM",
						PrimaryCount: 1, TotalCount: 1,
						Addresses: []string{"aws_iam_role.web"}},
				},
			},
		},
		Connections: []*Connection{
			{From: "aws_instance.a", To: "aws_iam_role.web", Via: "role_arn"},
			{From: "aws_instance.b", To: "aws_iam_role.web", Via: "role_arn"},
		},
	}

	AggregateTopoResult(result)

	if len(result.Connections) != 1 {
		t.Errorf("expected 1 deduplicated connection, got %d", len(result.Connections))
	}
}

func TestAggregateTopoResult_SkipSelfConnections(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Layers: []*TopoLayer{
			{
				Name: "Supporting",
				Groups: []*AggregatedGroup{
					{Service: "IAM", Label: "IAM",
						PrimaryCount: 2, TotalCount: 5,
						Addresses: []string{"aws_iam_role.a", "aws_iam_role.b",
							"aws_iam_role_policy_attachment.a", "aws_iam_role_policy_attachment.b",
							"aws_iam_instance_profile.a"}},
				},
			},
		},
		Connections: []*Connection{
			{From: "aws_iam_role_policy_attachment.a", To: "aws_iam_role.a", Via: "role"},
		},
	}

	AggregateTopoResult(result)

	if len(result.Connections) != 0 {
		t.Errorf("expected 0 connections (self-connection), got %d", len(result.Connections))
	}
}

// --- Renderer Tests ---

func TestRenderTopoResult_BasicOutput(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "Ingress",
				Order: 1,
				Groups: []*AggregatedGroup{
					{Service: "Load Balancer", Label: "Load Balancer", PrimaryCount: 1, TotalCount: 1, Action: "create"},
				},
			},
		},
	}

	output := RenderTopoResult(result)

	if !strings.Contains(output, "Infrastructure Diagram") {
		t.Error("expected 'Infrastructure Diagram' in title")
	}
	if !strings.Contains(output, "Internet") {
		t.Error("expected Internet entry point")
	}
	if !strings.Contains(output, "[+]") {
		t.Error("expected [+] icon for create action")
	}
	if !strings.Contains(output, "Load Balancer") {
		t.Error("expected 'Load Balancer' label")
	}
	// DAG mode: arrows connect boxes visually (│ and ▼)
	if !strings.Contains(output, "│") {
		t.Error("expected vertical connector in DAG output")
	}
	if !strings.Contains(output, "▼") {
		t.Error("expected arrow head in DAG output")
	}
	// No text-only Dependencies section
	if strings.Contains(output, "Dependencies") {
		t.Error("DAG mode should NOT have a text Dependencies section")
	}
}

func TestRenderTopoResult_VPCWithBoxes(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "VPC",
				Order: 2,
				IsVPC: true,
				Groups: []*AggregatedGroup{
					{Service: "VPC", Label: "VPC", PrimaryCount: 1, TotalCount: 1, Action: "create",
						Addresses: []string{"aws_vpc.main"}},
				},
				SubnetSummary: &SubnetSummary{Public: 2, PrivateApp: 2, PrivateData: 2},
				NetworkGroups: []*AggregatedGroup{
					{Service: "Security Group", Label: "Security Group (11)", PrimaryCount: 11, TotalCount: 14, Action: "create"},
					{Service: "Route Table", Label: "Route Table (4)", PrimaryCount: 4, TotalCount: 10, Action: "create"},
					{Service: "VPC Endpoint", Label: "VPC Endpoint (11)", PrimaryCount: 11, TotalCount: 11, Action: "create"},
				},
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Cluster", Label: "EKS Cluster", PrimaryCount: 1, TotalCount: 1, Action: "create"},
					{Service: "EKS Node Group", Label: "EKS Node Group (3)", PrimaryCount: 3, TotalCount: 3, Action: "create"},
				},
				DataGroups: []*AggregatedGroup{
					{Service: "Aurora RDS", Label: "Aurora RDS (2, 5 total)", PrimaryCount: 2, TotalCount: 5, Action: "create"},
				},
			},
		},
	}

	output := RenderTopoResult(result)

	// VPC double border
	if !strings.Contains(output, "╔") {
		t.Error("expected double-line VPC border (╔)")
	}
	// Network groups as summary text inside VPC
	if !strings.Contains(output, "Security Group") {
		t.Error("expected network group labels in VPC summary")
	}
	// Subnet info rendered as boxes (e.g., "Public Subnets (2)")
	if !strings.Contains(output, "Public Subnets") {
		t.Error("expected Public Subnets box in VPC")
	}
	// Compute and Data services as boxes inside VPC
	if !strings.Contains(output, "EKS Cluster") {
		t.Error("expected EKS Cluster box inside VPC")
	}
	if !strings.Contains(output, "EKS Node Group") {
		t.Error("expected EKS Node Group box inside VPC")
	}
	if !strings.Contains(output, "Aurora RDS") {
		t.Error("expected Aurora RDS box inside VPC")
	}
	// Network groups joined with · in summary
	if !strings.Contains(output, "·") {
		t.Error("expected compact format with '·' separator for network groups")
	}
	// No Dependencies text section
	if strings.Contains(output, "Dependencies") {
		t.Error("should not have text Dependencies section")
	}
}

func TestRenderTopoResult_ConnectionsAsArrows(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "Ingress",
				Order: 1,
				Groups: []*AggregatedGroup{
					{Service: "Load Balancer", Label: "Load Balancer", PrimaryCount: 1, TotalCount: 1, Action: "create"},
				},
			},
			{
				Name:  "VPC",
				Order: 2,
				IsVPC: true,
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Node Group", Label: "EKS Node Group", PrimaryCount: 1, TotalCount: 1, Action: "create"},
				},
			},
		},
		Connections: []*Connection{
			{From: "Load Balancer", To: "EKS Node Group", Via: "targets"},
		},
	}

	output := RenderTopoResult(result)

	// DAG mode: arrows are visual, no text Dependencies section
	if strings.Contains(output, "Dependencies") {
		t.Error("DAG mode should NOT have text Dependencies section")
	}
	// Both services should appear as boxes
	if !strings.Contains(output, "Load Balancer") {
		t.Error("expected Load Balancer box")
	}
	if !strings.Contains(output, "EKS Node Group") {
		t.Error("expected EKS Node Group box")
	}
	// LB should be above EKS (dependency drives layout)
	if !strings.Contains(output, "▼") {
		t.Error("expected visual arrow (▼) connecting boxes")
	}
}

func TestRenderSubnetSummary(t *testing.T) {
	s := &SubnetSummary{Public: 2, PrivateApp: 3, PrivateData: 2}
	result := formatSubnetSummary(s)

	if !strings.Contains(result, "2 public") {
		t.Errorf("expected '2 public' in %q", result)
	}
	if !strings.Contains(result, "3 private_app") {
		t.Errorf("expected '3 private_app' in %q", result)
	}
	if !strings.Contains(result, "Subnets:") {
		t.Errorf("expected 'Subnets:' prefix in %q", result)
	}
}

func TestBuildCompactLines(t *testing.T) {
	groups := []*AggregatedGroup{
		{Label: "EKS Cluster"},
		{Label: "Node Groups (3)"},
		{Label: "Addons (6)"},
		{Label: "Fargate"},
		{Label: "Lambda (4)"},
		{Label: "Auto Scaling (3)"},
	}

	lines := buildCompactLines(groups, 60)

	if len(lines) == 0 {
		t.Fatal("expected at least one compact line")
	}

	// All labels should appear somewhere in the output
	joined := strings.Join(lines, "\n")
	for _, g := range groups {
		if !strings.Contains(joined, g.Label) {
			t.Errorf("expected %q in compact output", g.Label)
		}
	}

	// Lines should use · separator
	if !strings.Contains(joined, "·") {
		t.Error("expected '·' separator in compact lines")
	}
}

// --- Integration Test: Full Pipeline ---

func TestTopoGenerator_FullPipeline(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.pub_a", Action: "create", Type: "aws_subnet",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.pub_b", Action: "create", Type: "aws_subnet",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web1", Action: "create", Type: "aws_instance",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub_a"}},
		{Address: "aws_instance.web2", Action: "create", Type: "aws_instance",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub_a"}},
		{Address: "aws_instance.web3", Action: "update", Type: "aws_instance",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub_b"}},
		{Address: "aws_db_instance.primary", Action: "create", Type: "aws_db_instance",
			Values: map[string]interface{}{"subnet_id": "aws_subnet.pub_b"}},
		{Address: "aws_lb.alb", Action: "create", Type: "aws_lb",
			Values: map[string]interface{}{"security_groups": []interface{}{"aws_security_group.web"}}},
		{Address: "aws_security_group.web", Action: "create", Type: "aws_security_group",
			Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_iam_role.web", Action: "create", Type: "aws_iam_role"},
		{Address: "aws_iam_role_policy_attachment.web", Action: "create", Type: "aws_iam_role_policy_attachment"},
		{Address: "aws_s3_bucket.logs", Action: "create", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket.assets", Action: "create", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket.backups", Action: "delete", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket_versioning.logs", Action: "create", Type: "aws_s3_bucket_versioning"},
		{Address: "aws_s3_bucket_versioning.assets", Action: "create", Type: "aws_s3_bucket_versioning"},
		{Address: "aws_s3_bucket_policy.logs", Action: "create", Type: "aws_s3_bucket_policy"},
	}

	graph := topology.BuildGraph(resources)
	gen := NewTopoGenerator()
	output := gen.GenerateWithGraph(resources, graph)

	if !strings.Contains(output, "Infrastructure Diagram") {
		t.Error("expected 'Infrastructure Diagram' in topo mode output")
	}
	if !strings.Contains(output, "╔") {
		t.Error("expected VPC double-border")
	}
	if !strings.Contains(output, "AWS") {
		t.Error("expected AWS in title")
	}
	if !strings.Contains(output, "Internet") {
		t.Error("expected Internet entry point")
	}
	// Subnet info rendered as boxes or fallback text
	if !strings.Contains(output, "Subnets") {
		t.Error("expected subnet info inside VPC")
	}

	// Should NOT list individual resource addresses in topo mode
	if strings.Contains(output, "aws_s3_bucket.logs") {
		t.Error("topo mode should aggregate S3 buckets, not list individual addresses")
	}

	// Sub-resources should be collapsed
	if strings.Contains(output, "aws_s3_bucket_versioning") {
		t.Error("versioning resources should be collapsed into S3 service group")
	}
	if strings.Contains(output, "aws_iam_role_policy_attachment") {
		t.Error("policy attachments should be collapsed into IAM service group")
	}

	// EC2 Instance should be inside VPC border
	if !strings.Contains(output, "EC2 Instance") {
		t.Error("expected EC2 Instance box inside VPC")
	}

	// RDS should be inside VPC border
	if !strings.Contains(output, "RDS Instance") {
		t.Error("expected RDS Instance box inside VPC")
	}

	// No text Dependencies section — arrows are visual
	if strings.Contains(output, "Dependencies") {
		t.Error("DAG mode should NOT have text Dependencies section")
	}
}

func TestTopoGenerator_ServiceAggregation(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.a", Action: "create", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket.b", Action: "create", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket.c", Action: "create", Type: "aws_s3_bucket"},
		{Address: "aws_s3_bucket_versioning.a", Action: "create", Type: "aws_s3_bucket_versioning"},
		{Address: "aws_s3_bucket_versioning.b", Action: "create", Type: "aws_s3_bucket_versioning"},
		{Address: "aws_s3_bucket_versioning.c", Action: "create", Type: "aws_s3_bucket_versioning"},
		{Address: "aws_s3_bucket_public_access_block.a", Action: "create", Type: "aws_s3_bucket_public_access_block"},
		{Address: "aws_s3_bucket_public_access_block.b", Action: "create", Type: "aws_s3_bucket_public_access_block"},
		{Address: "aws_s3_bucket_public_access_block.c", Action: "create", Type: "aws_s3_bucket_public_access_block"},
		{Address: "aws_s3_bucket_policy.a", Action: "create", Type: "aws_s3_bucket_policy"},
		{Address: "aws_s3_bucket_policy.b", Action: "create", Type: "aws_s3_bucket_policy"},
		{Address: "aws_s3_bucket_policy.c", Action: "create", Type: "aws_s3_bucket_policy"},
	}

	gen := NewTopoGenerator()
	output := gen.GenerateWithGraph(resources, nil)

	// Should NOT show individual sub-resource type names
	if strings.Contains(output, "aws_s3_bucket_versioning") {
		t.Error("should not show individual sub-resource types")
	}
	if strings.Contains(output, "aws_s3_bucket_public_access_block") {
		t.Error("should not show individual sub-resource types")
	}

	// Should show a single S3 service group with primary count 3 and total 12
	if !strings.Contains(output, "S3 (3") {
		t.Error("expected aggregated S3 label with primary count 3")
	}
}

func TestTopoGenerator_APIGatewayAggregation(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_api_gateway_rest_api.main", Action: "create", Type: "aws_api_gateway_rest_api"},
		{Address: "aws_api_gateway_resource.proxy", Action: "create", Type: "aws_api_gateway_resource"},
		{Address: "aws_api_gateway_method.any", Action: "create", Type: "aws_api_gateway_method"},
		{Address: "aws_api_gateway_integration.lambda", Action: "create", Type: "aws_api_gateway_integration"},
		{Address: "aws_api_gateway_deployment.main", Action: "create", Type: "aws_api_gateway_deployment"},
		{Address: "aws_api_gateway_stage.prod", Action: "create", Type: "aws_api_gateway_stage"},
	}

	gen := NewTopoGenerator()
	output := gen.GenerateWithGraph(resources, nil)

	// All should collapse into "API Gateway"
	if strings.Contains(output, "aws_api_gateway_resource") {
		t.Error("should not show individual API Gateway sub-resources")
	}
	if !strings.Contains(output, "API Gateway") {
		t.Error("expected 'API Gateway' service group")
	}
}

func TestTopoGenerator_FlatModeBackwardCompat(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}

	graph := topology.BuildGraph(resources)
	gen := NewGenerator()
	result := gen.GenerateWithGraph(resources, graph)

	if !strings.Contains(result, "AWS") {
		t.Error("expected AWS in flat mode title")
	}
}

func TestTopoGenerator_EmptyResources(t *testing.T) {
	gen := NewTopoGenerator()
	result := gen.GenerateWithGraph(nil, nil)

	if !strings.Contains(result, "no resource changes") {
		t.Error("expected 'no resource changes' for empty input")
	}
}

func TestTopoGenerator_AllNoOp(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "no-op", Type: "aws_instance"},
	}
	graph := topology.BuildGraph(resources)
	gen := NewTopoGenerator()
	result := gen.GenerateWithGraph(resources, graph)

	if !strings.Contains(result, "no resource changes") {
		t.Error("expected 'no resource changes' when all resources are no-op")
	}
}

// --- Helper function tests ---

func TestGetServiceGroup(t *testing.T) {
	tests := map[string]string{
		"aws_s3_bucket":                  "S3",
		"aws_s3_bucket_versioning":       "S3",
		"aws_s3_bucket_policy":           "S3",
		"aws_iam_role":                   "IAM",
		"aws_iam_role_policy_attachment": "IAM",
		"aws_eks_cluster":                "EKS Cluster",
		"aws_eks_node_group":             "EKS Node Group",
		"aws_lb":                         "Load Balancer",
		"aws_lb_listener":                "Load Balancer",
		"aws_security_group":             "Security Group",
		"aws_cloudwatch_log_group":       "CloudWatch",
		"aws_api_gateway_rest_api":       "API Gateway",
		"aws_api_gateway_method":         "API Gateway",
		"aws_networkfirewall_firewall":   "Network Firewall",
		"aws_launch_template":            "Auto Scaling",
	}
	for resType, want := range tests {
		got := getServiceGroup(resType)
		if got != want {
			t.Errorf("getServiceGroup(%q) = %q, want %q", resType, got, want)
		}
	}
}

func TestIsPrimaryType(t *testing.T) {
	if !isPrimaryType("aws_s3_bucket") {
		t.Error("aws_s3_bucket should be primary")
	}
	if isPrimaryType("aws_s3_bucket_versioning") {
		t.Error("aws_s3_bucket_versioning should NOT be primary")
	}
	if !isPrimaryType("aws_iam_role") {
		t.Error("aws_iam_role should be primary")
	}
	if isPrimaryType("aws_iam_role_policy_attachment") {
		t.Error("aws_iam_role_policy_attachment should NOT be primary")
	}
	if !isPrimaryType("aws_api_gateway_rest_api") {
		t.Error("aws_api_gateway_rest_api should be primary")
	}
}

func TestGetTopoVPCLayer(t *testing.T) {
	tests := map[string]string{
		"aws_security_group":  "Network",
		"aws_subnet":          "Network",
		"aws_eks_cluster":     "Compute",
		"aws_lambda_function": "Compute",
		"aws_rds_cluster":     "Data",
		"aws_dynamodb_table":  "Data",
		"aws_s3_bucket":       "", // not in VPC
		"aws_iam_role":        "", // not in VPC
	}
	for resType, want := range tests {
		got := getTopoVPCLayer(resType)
		if got != want {
			t.Errorf("getTopoVPCLayer(%q) = %q, want %q", resType, got, want)
		}
	}
}

// --- DAG and Canvas Tests ---

func TestTopoSortLevels_Basic(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"A": {ID: "A", Label: "A", DepsOut: []string{"B", "C"}},
		"B": {ID: "B", Label: "B", DepsIn: []string{"A"}, DepsOut: []string{"D"}},
		"C": {ID: "C", Label: "C", DepsIn: []string{"A"}, DepsOut: []string{"D"}},
		"D": {ID: "D", Label: "D", DepsIn: []string{"B", "C"}},
	}

	levels := topoSortLevels(nodes)

	if len(levels) != 3 {
		t.Fatalf("expected 3 levels, got %d", len(levels))
	}
	if len(levels[0]) != 1 || levels[0][0] != "A" {
		t.Errorf("expected level 0 = [A], got %v", levels[0])
	}
	if len(levels[1]) != 2 {
		t.Errorf("expected level 1 = [B, C], got %v", levels[1])
	}
	if len(levels[2]) != 1 || levels[2][0] != "D" {
		t.Errorf("expected level 2 = [D], got %v", levels[2])
	}
}

func TestTopoSortLevels_GlobalExcludedFromDAG(t *testing.T) {
	// Global nodes should not be in DAG levels (they go to the grid)
	dagNodes := map[string]*ServiceNode{
		"LB":  {ID: "LB", Label: "LB", Scope: "vpc", DepsOut: []string{"EKS"}},
		"EKS": {ID: "EKS", Label: "EKS", Scope: "vpc", DepsIn: []string{"LB"}},
	}

	levels := topoSortLevels(dagNodes)
	if len(levels) < 2 {
		t.Fatalf("expected at least 2 levels, got %d", len(levels))
	}
}

func TestTopoSortLevels_DisconnectedVPCPlacement(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"Route 53": {ID: "Route 53", Label: "Route 53", Scope: "edge", DepsOut: []string{"LB"}},
		"LB":       {ID: "LB", Label: "LB", Scope: "vpc", DepsIn: []string{"Route 53"}},
		"EKS":      {ID: "EKS", Label: "EKS", Scope: "vpc"},
		"RDS":      {ID: "RDS", Label: "RDS", Scope: "vpc"},
	}

	levels := topoSortLevels(nodes)
	eksLevel, lbLevel := -1, -1
	for li, level := range levels {
		for _, id := range level {
			switch id {
			case "EKS":
				eksLevel = li
			case "LB":
				lbLevel = li
			}
		}
	}
	if eksLevel <= lbLevel {
		t.Errorf("EKS (level %d) should be after LB (level %d)", eksLevel, lbLevel)
	}
}

func TestCanvas_WriteText(t *testing.T) {
	c := NewCanvas(20, 3)
	c.WriteText(2, 1, "Hello")
	if c.Get(2, 1) != 'H' {
		t.Errorf("expected 'H' at (2,1), got '%c'", c.Get(2, 1))
	}
	if c.Get(6, 1) != 'o' {
		t.Errorf("expected 'o' at (6,1), got '%c'", c.Get(6, 1))
	}
}

func TestCanvas_WriteTextUnicode(t *testing.T) {
	c := NewCanvas(30, 3)
	c.WriteText(5, 1, "══════")
	if c.Get(5, 1) != '═' {
		t.Errorf("expected '═' at (5,1), got '%c'", c.Get(5, 1))
	}
	if c.Get(6, 1) != '═' {
		t.Errorf("expected '═' at (6,1), got '%c'", c.Get(6, 1))
	}
}

func TestCanvas_DrawBox(t *testing.T) {
	c := NewCanvas(20, 5)
	c.DrawBox(2, 1, 10, 3, []string{"Test"})
	if c.Get(2, 1) != cBoxTL {
		t.Errorf("expected ┌ at (2,1), got '%c'", c.Get(2, 1))
	}
	if c.Get(11, 1) != cBoxTR {
		t.Errorf("expected ┐ at (11,1), got '%c'", c.Get(11, 1))
	}
	output := c.String()
	if !strings.Contains(output, "Test") {
		t.Error("expected 'Test' in canvas output")
	}
	if !c.IsProtected(2, 1) {
		t.Error("box cells should be protected")
	}
}

func TestCanvas_DrawRoutedArrow_Vertical(t *testing.T) {
	c := NewCanvas(20, 10)
	c.DrawRoutedArrow(10, 2, 10, 7)
	if c.Get(10, 3) != cBoxV {
		t.Errorf("expected │ at (10,3), got '%c'", c.Get(10, 3))
	}
	if c.Get(10, 7) != cArrowD {
		t.Errorf("expected ▼ at (10,7), got '%c'", c.Get(10, 7))
	}
}

func TestCanvas_ArrowRespectsProtectedCells(t *testing.T) {
	c := NewCanvas(20, 10)
	c.DrawBox(5, 4, 10, 3, []string{"Box"})
	c.DrawRoutedArrow(9, 1, 9, 8)
	output := c.String()
	if !strings.Contains(output, "Box") {
		t.Error("box content should be preserved when arrow crosses")
	}
}

func TestBuildServiceDAG_SkipsVPCAndNetwork(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Layers: []*TopoLayer{
			{
				Name: "VPC", IsVPC: true,
				Groups:        []*AggregatedGroup{{Service: "VPC", Label: "VPC"}},
				NetworkGroups: []*AggregatedGroup{{Service: "Security Group", Label: "SG (11)"}},
				ComputeGroups: []*AggregatedGroup{{Service: "EKS Cluster", Label: "EKS Cluster"}},
				DataGroups:    []*AggregatedGroup{{Service: "Aurora RDS", Label: "Aurora RDS"}},
			},
		},
	}

	nodes := buildServiceDAG(result)
	if _, ok := nodes["VPC"]; ok {
		t.Error("VPC should not be a DAG node")
	}
	if _, ok := nodes["SG (11)"]; ok {
		t.Error("Security Group should not be a DAG node")
	}
	if _, ok := nodes["EKS Cluster"]; !ok {
		t.Error("EKS Cluster should be a DAG node")
	}
	if _, ok := nodes["Aurora RDS"]; !ok {
		t.Error("Aurora RDS should be a DAG node")
	}
}

func TestIsComputeService(t *testing.T) {
	tests := []struct {
		service  string
		expected bool
	}{
		{"ECS Cluster", true},
		{"EKS Cluster", true},
		{"Lambda", true},
		{"Auto Scaling", true},
		{"EC2", true},
		{"Bastion Host", true},
		{"Aurora RDS", false},
		{"DynamoDB", false},
		{"Route 53", false},
		{"ALB", false},
	}
	for _, tt := range tests {
		n := &ServiceNode{Service: tt.service}
		if got := isComputeService(n); got != tt.expected {
			t.Errorf("isComputeService(%q) = %v, want %v", tt.service, got, tt.expected)
		}
	}
	if isComputeService(nil) {
		t.Error("isComputeService(nil) should return false")
	}
}

// --- Legacy Helper Tests ---

func TestMakeBox(t *testing.T) {
	box := makeBox([]string{"Hello"}, 0)

	// Box should have 3 lines: top border, content, bottom border
	if len(box.lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(box.lines))
	}

	// Top and bottom borders
	if !strings.Contains(box.lines[0], "┌") || !strings.Contains(box.lines[0], "┐") {
		t.Error("expected top border with ┌ and ┐")
	}
	if !strings.Contains(box.lines[2], "└") || !strings.Contains(box.lines[2], "┘") {
		t.Error("expected bottom border with └ and ┘")
	}

	// Content line
	if !strings.Contains(box.lines[1], "Hello") {
		t.Error("expected content 'Hello' in box")
	}
	if !strings.Contains(box.lines[1], "│") {
		t.Error("expected │ borders on content line")
	}
}

func TestMakeBox_MinWidth(t *testing.T) {
	box := makeBox([]string{"Hi"}, 20)

	if box.width < 20 {
		t.Errorf("expected width >= 20, got %d", box.width)
	}
}

func TestPackIntoRows_SingleRow(t *testing.T) {
	boxes := []renderedBox{
		{lines: []string{"a"}, width: 10},
		{lines: []string{"b"}, width: 10},
	}
	rows := packIntoRows(boxes, 30, 2)

	if len(rows) != 1 {
		t.Errorf("expected 1 row (10+2+10=22 < 30), got %d", len(rows))
	}
}

func TestPackIntoRows_Wrapping(t *testing.T) {
	boxes := []renderedBox{
		{lines: []string{"a"}, width: 15},
		{lines: []string{"b"}, width: 15},
		{lines: []string{"c"}, width: 15},
	}
	rows := packIntoRows(boxes, 35, 2)

	// 15+2+15=32 fits, 32+2+15=49 doesn't → 2 rows
	if len(rows) != 2 {
		t.Errorf("expected 2 rows, got %d", len(rows))
	}
	if len(rows[0]) != 2 {
		t.Errorf("expected 2 boxes in first row, got %d", len(rows[0]))
	}
	if len(rows[1]) != 1 {
		t.Errorf("expected 1 box in second row, got %d", len(rows[1]))
	}
}

func TestBoxRowToLines_CenteredOutput(t *testing.T) {
	box1 := makeBox([]string{"A"}, 14)
	box2 := makeBox([]string{"B"}, 14)
	row := []renderedBox{box1, box2}

	lines := boxRowToLines(row, 80, 2)

	if len(lines) == 0 {
		t.Fatal("expected output lines")
	}

	// Each line should contain both box borders
	for _, line := range lines {
		// Boxes are side by side — line should have content from both
		if len(line) == 0 {
			t.Error("empty line in box row output")
		}
	}

	// Content lines should have both A and B
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "A") || !strings.Contains(joined, "B") {
		t.Error("expected both box labels in output")
	}
}

func TestRenderDAG_MultipleServices(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "Supporting",
				Order: 3,
				Groups: []*AggregatedGroup{
					{Service: "S3", Label: "S3 (3, 12 total)", Action: "create"},
					{Service: "CloudWatch", Label: "CloudWatch", Action: "create"},
				},
			},
		},
	}

	output := RenderTopoResult(result)

	// Non-cross-cutting services should appear as boxes
	if !strings.Contains(output, "S3 (3, 12 total)") {
		t.Error("expected S3 label in output")
	}
	if !strings.Contains(output, "CloudWatch") {
		t.Error("expected CloudWatch label in output")
	}
	// Box borders
	if !strings.Contains(output, "┌") {
		t.Error("expected box borders (┌)")
	}
	// Internet entry point
	if !strings.Contains(output, "Internet") {
		t.Error("expected Internet entry point")
	}
}

func TestRenderDAG_VPCWithBoxes(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS",
		Layers: []*TopoLayer{
			{
				Name:  "VPC",
				Order: 2,
				IsVPC: true,
				Groups: []*AggregatedGroup{
					{Service: "VPC", Label: "VPC", Action: "create",
						Addresses: []string{"aws_vpc.main"}},
				},
				SubnetSummary: &SubnetSummary{Public: 2, PrivateApp: 2},
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Cluster", Label: "EKS Cluster", Action: "create"},
					{Service: "Lambda", Label: "Lambda (4)", Action: "create"},
				},
				DataGroups: []*AggregatedGroup{
					{Service: "Aurora RDS", Label: "Aurora RDS", Action: "create"},
				},
			},
		},
	}

	output := RenderTopoResult(result)

	// VPC double border
	if !strings.Contains(output, "╔") {
		t.Error("expected VPC double border")
	}
	// Compute boxes inside VPC
	if !strings.Contains(output, "EKS Cluster") {
		t.Error("expected EKS Cluster box inside VPC")
	}
	if !strings.Contains(output, "Lambda (4)") {
		t.Error("expected Lambda box inside VPC")
	}
	// Data box inside VPC
	if !strings.Contains(output, "Aurora RDS") {
		t.Error("expected Aurora RDS box inside VPC")
	}
	// Subnet info rendered as boxes (e.g., "Public Subnets (2)")
	if !strings.Contains(output, "Public Subnets") {
		t.Error("expected Public Subnets box in VPC")
	}
	// Individual box borders inside VPC
	if !strings.Contains(output, "┌") {
		t.Error("expected box borders inside VPC")
	}
}

// --- Tests for Refinement features ---

func TestBuildCompoundNodes_EKS(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"EKS Cluster (1)": {
			ID: "EKS Cluster (1)", Service: "EKS Cluster", Label: "EKS Cluster (1)",
			Action: "create", Scope: "vpc",
			DepsOut: []string{"Aurora RDS (2)"},
			DepsIn:  []string{"Load Balancer (1)"},
		},
		"EKS Node Group (2)": {
			ID: "EKS Node Group (2)", Service: "EKS Node Group", Label: "EKS Node Group (2)",
			Action: "create", Scope: "vpc",
		},
		"EKS Addon (3)": {
			ID: "EKS Addon (3)", Service: "EKS Addon", Label: "EKS Addon (3)",
			Action: "create", Scope: "vpc",
		},
		"Aurora RDS (2)": {
			ID: "Aurora RDS (2)", Service: "Aurora RDS", Label: "Aurora RDS (2)",
			Action: "create", Scope: "vpc",
			DepsIn: []string{"EKS Cluster (1)"},
		},
		"Load Balancer (1)": {
			ID: "Load Balancer (1)", Service: "Load Balancer", Label: "Load Balancer (1)",
			Action: "create", Scope: "vpc",
			DepsOut: []string{"EKS Cluster (1)"},
		},
	}

	compounds := buildCompoundNodes(nodes)

	// EKS should be a compound node
	cn, ok := compounds["EKS Cluster (1)"]
	if !ok {
		t.Fatal("expected EKS Cluster to be a compound node")
	}
	if len(cn.Children) != 2 {
		t.Errorf("expected 2 children (Node Group + Addon), got %d", len(cn.Children))
	}

	// Children should be removed from nodes map
	if _, exists := nodes["EKS Node Group (2)"]; exists {
		t.Error("EKS Node Group should be removed from nodes after compound merge")
	}
	if _, exists := nodes["EKS Addon (3)"]; exists {
		t.Error("EKS Addon should be removed from nodes after compound merge")
	}

	// Parent should still exist
	if _, exists := nodes["EKS Cluster (1)"]; !exists {
		t.Error("EKS Cluster parent should remain in nodes")
	}

	// External connections should be preserved on parent
	parent := nodes["EKS Cluster (1)"]
	if !containsStr(parent.DepsOut, "Aurora RDS (2)") {
		t.Error("parent should retain DepsOut to Aurora RDS")
	}
	if !containsStr(parent.DepsIn, "Load Balancer (1)") {
		t.Error("parent should retain DepsIn from Load Balancer")
	}
}

func TestIsDistributionBar(t *testing.T) {
	tests := []struct {
		name     string
		node     *ServiceNode
		expected bool
	}{
		{
			name: "LB vpc scope with 2+ outbound — not dist bar",
			node: &ServiceNode{
				Service: "Load Balancer",
				Scope:   "vpc",
				DepsOut: []string{"a", "b"},
			},
			expected: false,
		},
		{
			name: "LB edge with 1 outbound",
			node: &ServiceNode{
				Service: "Load Balancer",
				Scope:   "edge",
				DepsOut: []string{"a"},
			},
			expected: false,
		},
		{
			name: "Route 53 edge with 3 outbound",
			node: &ServiceNode{
				Service: "Route 53",
				Scope:   "edge",
				DepsOut: []string{"a", "b", "c"},
			},
			expected: true,
		},
		{
			name: "non-hub service with 2+ outbound",
			node: &ServiceNode{
				Service: "EC2 Instance",
				Scope:   "vpc",
				DepsOut: []string{"a", "b"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isDistributionBar(tt.node)
			if got != tt.expected {
				t.Errorf("isDistributionBar() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestCalcCompoundSize(t *testing.T) {
	children := []*CompoundChild{
		{W: 20, H: 5, Lines: []string{"Child A"}},
		{W: 18, H: 5, Lines: []string{"Child B"}},
	}
	w, h := calcCompoundSize("EKS Cluster (1, 3 total)", children)

	// Width = 20 + 2 + 18 + 4 = 44
	if w < 44 {
		t.Errorf("expected compound width >= 44, got %d", w)
	}
	// Height = 5 + 5 = 10
	if h < 10 {
		t.Errorf("expected compound height >= 10, got %d", h)
	}
}

func TestCanvas_DrawDistributionBar(t *testing.T) {
	c := NewCanvas(40, 3)
	c.DrawDistributionBar(2, 1, 36, "ALB (2)")

	line := string(c.Cells[1])
	if !strings.Contains(line, "ALB (2)") {
		t.Error("expected distribution bar to contain label")
	}
	// Endpoints
	if c.Cells[1][2] != '╶' {
		t.Error("expected left endpoint ╶")
	}
	if c.Cells[1][37] != '╴' {
		t.Error("expected right endpoint ╴")
	}
	// Bar should be protected
	if !c.IsProtected(2, 1) {
		t.Error("distribution bar cells should be protected")
	}
}

func TestCanvas_DrawCompoundBox(t *testing.T) {
	c := NewCanvas(50, 12)
	children := []*CompoundChild{
		{W: 16, H: 3, Lines: []string{"Node Group"}},
		{W: 14, H: 3, Lines: []string{"Addon (3)"}},
	}
	c.DrawCompoundBox(2, 1, 40, 9, "EKS Cluster (1)", children)

	output := c.String()
	if !strings.Contains(output, "EKS Cluster (1)") {
		t.Error("expected compound box to contain parent title")
	}
	if !strings.Contains(output, "Node Group") {
		t.Error("expected compound box to contain child 'Node Group'")
	}
	if !strings.Contains(output, "Addon (3)") {
		t.Error("expected compound box to contain child 'Addon (3)'")
	}
	// Outer box borders
	if c.Cells[1][2] != cBoxTL {
		t.Error("expected top-left corner of compound box")
	}
}

func TestCanvas_DrawBoxAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		tl     rune // expected top-left corner
		tr     rune // expected top-right corner
		bl     rune // expected bottom-left corner
		br     rune // expected bottom-right corner
		hFill  rune // expected horizontal fill character on top border
		marker rune // special character at position (x+1, y) for replace
	}{
		{"create", "create", cBoxTL, cBoxTR, cBoxBL, cBoxBR, cBoxH, 0},
		{"update", "update", cBoxTL, cBoxTR, cBoxBL, cBoxBR, cDashH, 0},
		{"replace", "replace", cBoxTL, cBoxTR, cBoxBL, cBoxBR, cBoxH, '!'},
		{"mixed", "mixed", cDblTL, cDblTR, cDblBL, cDblBR, cDblH, 0},
		{"default_empty", "", cBoxTL, cBoxTR, cBoxBL, cBoxBR, cBoxH, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewCanvas(20, 5)
			c.DrawBoxAction(2, 1, 10, 3, []string{"Test"}, tt.action)

			if got := c.Get(2, 1); got != tt.tl {
				t.Errorf("top-left: expected %c, got %c", tt.tl, got)
			}
			if got := c.Get(11, 1); got != tt.tr {
				t.Errorf("top-right: expected %c, got %c", tt.tr, got)
			}
			if got := c.Get(2, 3); got != tt.bl {
				t.Errorf("bottom-left: expected %c, got %c", tt.bl, got)
			}
			if got := c.Get(11, 3); got != tt.br {
				t.Errorf("bottom-right: expected %c, got %c", tt.br, got)
			}
			// Check horizontal fill (position x+2 on top row, skipping marker)
			fillCol := 4
			if tt.marker != 0 {
				fillCol = 5 // skip the ! marker at position 3
			}
			if got := c.Get(fillCol, 1); got != tt.hFill {
				t.Errorf("horiz fill at col %d: expected %c, got %c", fillCol, tt.hFill, got)
			}
			// Check replace marker
			if tt.marker != 0 {
				if got := c.Get(3, 1); got != tt.marker {
					t.Errorf("replace marker: expected %c, got %c", tt.marker, got)
				}
			}
			// Content should be present
			output := c.String()
			if !strings.Contains(output, "Test") {
				t.Error("expected 'Test' in canvas output")
			}
			// All cells should be protected
			if !c.IsProtected(2, 1) {
				t.Error("box cells should be protected")
			}
		})
	}
}

func TestCanvas_DrawCompoundBoxAction(t *testing.T) {
	children := []*CompoundChild{
		{W: 12, H: 3, Lines: []string{"Child"}, Action: "update"},
	}
	c := NewCanvas(40, 10)
	c.DrawCompoundBoxAction(2, 1, 30, 8, "Parent (1)", children, "mixed")

	// Outer box should be double-border (mixed)
	if got := c.Get(2, 1); got != cDblTL {
		t.Errorf("outer TL: expected ╔, got %c", got)
	}
	// Inner child box should be dashed (update)
	innerX := 4 // x+2
	innerY := 4 // y+3
	if got := c.Get(innerX+2, innerY); got != cDashH {
		t.Errorf("inner child top fill: expected ╌, got %c", got)
	}
	output := c.String()
	if !strings.Contains(output, "Parent (1)") {
		t.Error("expected parent title")
	}
	if !strings.Contains(output, "Child") {
		t.Error("expected child label")
	}
}

func TestCanvas_DrawVPCBorderWithLabel(t *testing.T) {
	c := NewCanvas(50, 10)
	c.DrawVPCBorderWithLabel(5, 2, 40, 6, "VPC (10.0.0.0/16)")

	output := c.String()
	if !strings.Contains(output, "VPC (10.0.0.0/16)") {
		t.Error("expected VPC label on border line")
	}
	// Double-line corners
	if c.Cells[2][5] != cDblTL {
		t.Error("expected double-line top-left corner")
	}
	if c.Cells[2][44] != cDblTR {
		t.Error("expected double-line top-right corner")
	}
	// VPC border is NOT protected (arrows can pass through)
	if c.IsProtected(5, 2) {
		t.Error("VPC border should NOT be protected")
	}
}

func TestCanvas_DrawSubnetBox(t *testing.T) {
	c := NewCanvas(50, 10)
	c.DrawSubnetBox(2, 1, 30, 6, "Public Subnets (3)", []string{"IGW", "NAT (2)"})

	output := c.String()
	if !strings.Contains(output, "Public Subnets (3)") {
		t.Error("expected subnet box title")
	}
	if !strings.Contains(output, "IGW") {
		t.Error("expected inner IGW component")
	}
	if !strings.Contains(output, "NAT (2)") {
		t.Error("expected inner NAT component")
	}
	// Subnet box is protected
	if !c.IsProtected(2, 1) {
		t.Error("subnet box should be protected")
	}
}

func TestSubnetTierTitle(t *testing.T) {
	tests := []struct {
		tier     string
		count    int
		expected string
	}{
		{"public", 3, "Public Subnets (3)"},
		{"private_app", 2, "Private App Subnets (2)"},
		{"private_data", 1, "Private Data Subnets (1)"},
		{"private", 4, "Private Subnets (4)"},
	}
	for _, tt := range tests {
		got := subnetTierTitle(tt.tier, tt.count)
		if got != tt.expected {
			t.Errorf("subnetTierTitle(%q, %d) = %q, want %q", tt.tier, tt.count, got, tt.expected)
		}
	}
}

func TestBuildNetworkSection_WithSubnets(t *testing.T) {
	ss := &SubnetSummary{Public: 3, PrivateApp: 2}
	groups := []*AggregatedGroup{
		{Service: "Internet Gateway", Label: "IGW", PrimaryCount: 1},
		{Service: "NAT Gateway", Label: "NAT GW (2)", PrimaryCount: 2},
		{Service: "Security Group", Label: "SG (5)", PrimaryCount: 5},
	}
	ns := buildNetworkSection(ss, groups, 80, 4)
	if ns == nil {
		t.Fatal("expected non-nil NetworkSection")
	}
	if len(ns.SubnetBoxes) < 2 {
		t.Errorf("expected at least 2 subnet boxes (public + private_app), got %d", len(ns.SubnetBoxes))
	}

	// Check public subnet has inner labels
	pub := ns.SubnetBoxes[0]
	if pub.Tier != "public" {
		t.Errorf("expected first box to be 'public', got %q", pub.Tier)
	}
	if len(pub.InnerLabels) == 0 {
		t.Error("expected public subnet to have inner labels (IGW, NAT)")
	}

	// Utility bar for SG
	if ns.UtilBar == nil {
		t.Error("expected utility bar for Security Group")
	}
}

func TestBuildNetworkSection_NilSubnetSummary(t *testing.T) {
	ns := buildNetworkSection(nil, nil, 80, 4)
	if ns != nil {
		t.Error("expected nil NetworkSection when SubnetSummary is nil")
	}
}

func TestRenderTopoResult_CompoundAndDistBar(t *testing.T) {
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS Test",
		Layers: []*TopoLayer{
			{
				Name:  "Distribution",
				Order: 1,
				Groups: []*AggregatedGroup{
					{Service: "Load Balancer", Label: "ALB (2)", PrimaryCount: 2, Action: "create"},
				},
			},
			{
				Name:          "VPC",
				Order:         2,
				IsVPC:         true,
				SubnetSummary: &SubnetSummary{Public: 2, PrivateApp: 3},
				Groups: []*AggregatedGroup{
					{Service: "VPC", Label: "VPC", PrimaryCount: 1, Action: "create"},
				},
				NetworkGroups: []*AggregatedGroup{
					{Service: "Internet Gateway", Label: "IGW", PrimaryCount: 1},
					{Service: "Security Group", Label: "SG (4)", PrimaryCount: 4},
				},
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Cluster", Label: "EKS Cluster (1, 3 total)", PrimaryCount: 1, TotalCount: 3, Action: "create"},
					{Service: "EKS Node Group", Label: "EKS Node Group (2)", PrimaryCount: 2, Action: "create"},
				},
				DataGroups: []*AggregatedGroup{
					{Service: "Aurora RDS", Label: "Aurora RDS (1)", PrimaryCount: 1, Action: "create"},
				},
			},
		},
		Connections: []*Connection{
			{From: "ALB (2)", To: "EKS Cluster (1, 3 total)", Via: "target_group"},
			{From: "ALB (2)", To: "Aurora RDS (1)", Via: "ref"},
		},
	}

	output := RenderTopoResult(result)

	// VPC with label on border
	if !strings.Contains(output, "╔") {
		t.Error("expected VPC double border")
	}

	// EKS should appear (as compound or regular box)
	if !strings.Contains(output, "EKS Cluster") {
		t.Error("expected EKS Cluster in output")
	}

	// Distribution bar: ALB with 2+ outbound should render as bar
	if !strings.Contains(output, "ALB") {
		t.Error("expected ALB label in output")
	}

	// Subnet boxes
	if !strings.Contains(output, "Public Subnets") {
		t.Error("expected Public Subnets box")
	}

	// Legend
	if !strings.Contains(output, "[+] create") {
		t.Error("expected legend line")
	}
}

func TestGetServiceScope(t *testing.T) {
	tests := []struct {
		service string
		want    string
	}{
		{"Route 53", "edge"},
		{"CloudFront", "edge"},
		{"WAF", "global"}, // annotation service — not a DAG node
		{"ACM", "global"}, // annotation service — not a DAG node
		{"EKS Cluster", "vpc"},
		{"Load Balancer", "vpc"},
		{"Lambda", "vpc"},
		{"Aurora RDS", "vpc"},
		{"DynamoDB", "vpc"},
		{"CloudWatch", "global"},
		{"IAM", "global"},
		{"S3", "global"},
		{"ECR", "global"},
		{"SNS", "global"},
		{"UnknownService", "global"}, // default
	}
	for _, tt := range tests {
		got := getServiceScope(tt.service)
		if got != tt.want {
			t.Errorf("getServiceScope(%q) = %q, want %q", tt.service, got, tt.want)
		}
	}
}

func TestSeparateByScope(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"R53": {ID: "R53", Service: "Route 53", Scope: "edge"},
		"EKS": {ID: "EKS", Service: "EKS Cluster", Scope: "vpc"},
		"IAM": {ID: "IAM", Service: "IAM", Scope: "global"},
		"S3":  {ID: "S3", Service: "S3", Scope: "global"},
	}

	dagNodes, globalNodes := separateByScope(nodes)

	if len(dagNodes) != 2 {
		t.Errorf("expected 2 DAG nodes (edge+vpc), got %d", len(dagNodes))
	}
	if _, ok := dagNodes["R53"]; !ok {
		t.Error("edge node R53 should be in dagNodes")
	}
	if _, ok := dagNodes["EKS"]; !ok {
		t.Error("vpc node EKS should be in dagNodes")
	}
	if len(globalNodes) != 2 {
		t.Errorf("expected 2 global nodes, got %d", len(globalNodes))
	}
}

func TestBuildGlobalGrid(t *testing.T) {
	nodes := []*ServiceNode{
		{ID: "CloudWatch", Service: "CloudWatch", Label: "CloudWatch (5)", Action: "create"},
		{ID: "IAM (3)", Service: "IAM", Label: "IAM (3)", Action: "create"},
		{ID: "S3 (2)", Service: "S3", Label: "S3 (2)", Action: "create"},
		{ID: "ECR", Service: "ECR", Label: "ECR", Action: "create"},
		{ID: "SNS (4)", Service: "SNS", Label: "SNS (4)", Action: "create"},
	}

	grid := buildGlobalGrid(nodes, 120)
	if grid == nil {
		t.Fatal("expected non-nil grid")
	}
	if len(grid.Rows) == 0 {
		t.Error("expected at least 1 row in grid")
	}
	if grid.Title != "Global / Regional Services" {
		t.Errorf("unexpected grid title: %q", grid.Title)
	}
	if grid.H < 5 {
		t.Errorf("expected grid height >= 5, got %d", grid.H)
	}
}

func TestBuildGlobalGrid_Empty(t *testing.T) {
	grid := buildGlobalGrid(nil, 120)
	if grid != nil {
		t.Error("expected nil grid for empty nodes")
	}
}

func TestRenderTopoResult_ThreeZones(t *testing.T) {
	// Test with edge, VPC, and global services
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS Zones",
		Layers: []*TopoLayer{
			{
				Name:  "Edge",
				Order: 0,
				Groups: []*AggregatedGroup{
					{Service: "Route 53", Label: "Route 53 (3)", PrimaryCount: 3, Action: "create"},
					{Service: "CloudFront", Label: "CloudFront (2)", PrimaryCount: 2, Action: "create"},
				},
			},
			{
				Name:          "VPC",
				Order:         2,
				IsVPC:         true,
				SubnetSummary: &SubnetSummary{Public: 2},
				Groups: []*AggregatedGroup{
					{Service: "VPC", Label: "VPC", PrimaryCount: 1, Action: "create"},
				},
				NetworkGroups: []*AggregatedGroup{
					{Service: "Internet Gateway", Label: "IGW", PrimaryCount: 1},
				},
				ComputeGroups: []*AggregatedGroup{
					{Service: "EKS Cluster", Label: "EKS Cluster (1)", PrimaryCount: 1, Action: "create"},
				},
			},
			{
				Name:  "Supporting",
				Order: 4,
				Groups: []*AggregatedGroup{
					{Service: "CloudWatch", Label: "CloudWatch (5)", PrimaryCount: 5, Action: "create"},
					{Service: "IAM", Label: "IAM (3)", PrimaryCount: 3, Action: "create"},
					{Service: "S3", Label: "S3 (2)", PrimaryCount: 2, Action: "create"},
				},
			},
		},
		Connections: []*Connection{
			{From: "Route 53 (3)", To: "CloudFront (2)", Via: "alias"},
			{From: "Route 53 (3)", To: "EKS Cluster (1)", Via: "ref"},
		},
	}

	output := RenderTopoResult(result)

	// Edge services should be ABOVE VPC
	if !strings.Contains(output, "Route 53") {
		t.Error("expected Route 53 in output (edge zone)")
	}
	if !strings.Contains(output, "CloudFront") {
		t.Error("expected CloudFront in output (edge zone)")
	}

	// VPC services
	if !strings.Contains(output, "╔") {
		t.Error("expected VPC double border")
	}
	if !strings.Contains(output, "EKS Cluster") {
		t.Error("expected EKS Cluster inside VPC")
	}

	// Global services should be in grid
	if !strings.Contains(output, "Global / Regional Services") {
		t.Error("expected Global Services grid title")
	}
	if !strings.Contains(output, "CloudWatch") {
		t.Error("expected CloudWatch in global grid")
	}
	if !strings.Contains(output, "IAM") {
		t.Error("expected IAM in global grid")
	}

	// Global services should NOT be inside VPC
	// Find VPC end and check CloudWatch is after it
	vpcEnd := strings.Index(output, "╚")
	cwPos := strings.Index(output, "CloudWatch")
	if vpcEnd >= 0 && cwPos >= 0 && cwPos < vpcEnd {
		t.Error("CloudWatch should be BELOW VPC, not inside it")
	}
}

func TestRenderTopoResult_NoEdgeZone(t *testing.T) {
	// ECS project: no edge services → Internet goes directly to VPC
	result := &TopoResult{
		Provider: "aws",
		Title:    "AWS ECS",
		Layers: []*TopoLayer{
			{
				Name:          "VPC",
				Order:         2,
				IsVPC:         true,
				SubnetSummary: &SubnetSummary{Public: 2, Private: 2},
				Groups: []*AggregatedGroup{
					{Service: "VPC", Label: "VPC", PrimaryCount: 1, Action: "create"},
				},
				NetworkGroups: []*AggregatedGroup{
					{Service: "Internet Gateway", Label: "IGW", PrimaryCount: 1},
					{Service: "Security Group", Label: "SG (2)", PrimaryCount: 2},
				},
				ComputeGroups: []*AggregatedGroup{
					{Service: "ECS Cluster", Label: "ECS Cluster", PrimaryCount: 1, Action: "create"},
					{Service: "ECS", Label: "ECS (2)", PrimaryCount: 2, Action: "create"},
				},
			},
			{
				Name:  "Supporting",
				Order: 4,
				Groups: []*AggregatedGroup{
					{Service: "CloudWatch", Label: "CloudWatch", PrimaryCount: 1, Action: "create"},
					{Service: "IAM", Label: "IAM (2)", PrimaryCount: 2, Action: "create"},
				},
			},
		},
	}

	output := RenderTopoResult(result)

	// No edge services
	if strings.Contains(output, "Route 53") {
		t.Error("should NOT have Route 53 in no-edge scenario")
	}
	if strings.Contains(output, "CloudFront") {
		t.Error("should NOT have CloudFront in no-edge scenario")
	}

	// VPC should be present
	if !strings.Contains(output, "╔") {
		t.Error("expected VPC border")
	}
	if !strings.Contains(output, "ECS Cluster") {
		t.Error("expected ECS Cluster inside VPC")
	}

	// Global grid
	if !strings.Contains(output, "Global / Regional Services") {
		t.Error("expected global grid")
	}
	if !strings.Contains(output, "CloudWatch") {
		t.Error("expected CloudWatch in global grid")
	}
}

func TestExtractSGCrossRefs(t *testing.T) {
	config := parser.Configuration{
		RootModule: parser.ConfigModule{
			Resources: []parser.ConfigResource{
				{
					Address: "aws_vpc_security_group_ingress_rule.alb_from_eks",
					Type:    "aws_vpc_security_group_ingress_rule",
					Expressions: map[string]interface{}{
						"security_group_id": map[string]interface{}{
							"references": []interface{}{
								"aws_security_group.alb.id",
								"aws_security_group.alb",
							},
						},
						"referenced_security_group_id": map[string]interface{}{
							"references": []interface{}{
								"aws_security_group.eks_nodes.id",
								"aws_security_group.eks_nodes",
							},
						},
						"from_port": map[string]interface{}{"constant_value": 8080},
					},
				},
				{
					Address: "aws_vpc_security_group_ingress_rule.alb_https",
					Type:    "aws_vpc_security_group_ingress_rule",
					Expressions: map[string]interface{}{
						"security_group_id": map[string]interface{}{
							"references": []interface{}{
								"aws_security_group.alb.id",
								"aws_security_group.alb",
							},
						},
						"cidr_ipv4": map[string]interface{}{"constant_value": "0.0.0.0/0"},
					},
				},
				{
					Address: "aws_security_group_rule.old_style",
					Type:    "aws_security_group_rule",
					Expressions: map[string]interface{}{
						"security_group_id": map[string]interface{}{
							"references": []interface{}{
								"aws_security_group.rds.id",
								"aws_security_group.rds",
							},
						},
						"source_security_group_id": map[string]interface{}{
							"references": []interface{}{
								"aws_security_group.eks_nodes.id",
								"aws_security_group.eks_nodes",
							},
						},
					},
				},
			},
		},
	}

	refs := ExtractSGCrossRefs(config)

	if len(refs) != 2 {
		t.Fatalf("expected 2 SG cross-refs, got %d", len(refs))
	}
	// First: ALB SG → EKS nodes SG
	if refs[0].OwnerSG != "aws_security_group.alb" || refs[0].PeerSG != "aws_security_group.eks_nodes" {
		t.Errorf("unexpected first ref: %+v", refs[0])
	}
	// Second: RDS SG → EKS nodes SG (old-style rule)
	if refs[1].OwnerSG != "aws_security_group.rds" || refs[1].PeerSG != "aws_security_group.eks_nodes" {
		t.Errorf("unexpected second ref: %+v", refs[1])
	}
}

func TestWireSGRefEdges(t *testing.T) {
	// Create nodes with addresses that reference SGs
	nodes := map[string]*ServiceNode{
		"ALB": {
			ID:        "ALB",
			Service:   "ALB",
			Label:     "ALB",
			Scope:     "vpc",
			Addresses: []string{"aws_lb.main"},
		},
		"EKS Cluster": {
			ID:        "EKS Cluster",
			Service:   "EKS Cluster",
			Label:     "EKS Cluster",
			Scope:     "vpc",
			Addresses: []string{"aws_eks_cluster.main"},
		},
		"RDS": {
			ID:        "RDS",
			Service:   "Aurora RDS",
			Label:     "RDS",
			Scope:     "vpc",
			Addresses: []string{"aws_rds_cluster.main"},
		},
	}

	cfgRefs := map[string][]string{
		"aws_lb.main":          {"aws_security_group.alb.id", "aws_security_group.alb"},
		"aws_eks_cluster.main": {"aws_security_group.eks_cluster.id", "aws_security_group.eks_cluster"},
		"aws_rds_cluster.main": {"aws_security_group.rds.id", "aws_security_group.rds"},
		// SG own refs (for VPC lookup in fallback)
		"aws_security_group.alb":         {"aws_vpc.main.id", "aws_vpc.main"},
		"aws_security_group.eks_cluster": {"aws_vpc.main.id", "aws_vpc.main"},
		"aws_security_group.rds":         {"aws_vpc.main.id", "aws_vpc.main"},
	}

	crossRefs := []SGCrossRef{
		{OwnerSG: "aws_security_group.alb", PeerSG: "aws_security_group.rds"},
	}

	wireSGRefEdges(nodes, crossRefs, cfgRefs)

	// ALB should have SGRefDeps pointing to RDS
	if len(nodes["ALB"].SGRefDeps) != 1 || nodes["ALB"].SGRefDeps[0] != "RDS" {
		t.Errorf("expected ALB SGRefDeps=[RDS], got %v", nodes["ALB"].SGRefDeps)
	}
}

func TestCanvas_DrawDottedArrow(t *testing.T) {
	c := NewCanvas(20, 15)

	// Vertical dotted arrow (near-vertical, dx<=2)
	c.DrawDottedArrow(10, 2, 10, 8)
	out := c.String()

	// Should have dotted characters
	if !strings.Contains(out, "·") {
		t.Error("expected dotted characters in arrow")
	}
	// Should have arrowhead
	if !strings.Contains(out, "▼") {
		t.Error("expected ▼ arrowhead")
	}
}

func TestBuildSGRefArrows(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"A": {ID: "A", SGRefDeps: []string{"B"}},
		"B": {ID: "B"},
	}
	boxes := map[string]*BoxPos{
		"A": {X: 10, Y: 2, W: 10, H: 3, CenterX: 15},
		"B": {X: 30, Y: 10, W: 10, H: 3, CenterX: 35},
	}
	solidArrows := []ArrowDef{} // no solid arrows

	arrows := buildSGRefArrows(nodes, boxes, solidArrows)

	if len(arrows) != 1 {
		t.Fatalf("expected 1 dotted arrow, got %d", len(arrows))
	}
	a := arrows[0]
	// Should go from A (higher) to B (lower)
	if a.FromY != 5 || a.ToY != 9 {
		t.Errorf("unexpected Y coords: from=%d to=%d", a.FromY, a.ToY)
	}
}

func TestWireSGRefEdges_Bidirectional(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"ALB": {
			ID:        "ALB",
			Service:   "ALB",
			Label:     "ALB",
			Scope:     "vpc",
			Addresses: []string{"aws_lb.main"},
		},
		"ECS": {
			ID:        "ECS",
			Service:   "ECS",
			Label:     "ECS",
			Scope:     "vpc",
			Addresses: []string{"aws_ecs_service.api"},
		},
	}

	cfgRefs := map[string][]string{
		"aws_lb.main":            {"aws_security_group.alb.id", "aws_security_group.alb"},
		"aws_ecs_service.api":    {"aws_security_group.ecs.id", "aws_security_group.ecs"},
		"aws_security_group.alb": {"aws_vpc.main.id"},
		"aws_security_group.ecs": {"aws_vpc.main.id"},
	}

	// Both directions: ALB SG refs ECS SG, and ECS SG refs ALB SG
	crossRefs := []SGCrossRef{
		{OwnerSG: "aws_security_group.alb", PeerSG: "aws_security_group.ecs"},
		{OwnerSG: "aws_security_group.ecs", PeerSG: "aws_security_group.alb"},
	}

	wireSGRefEdges(nodes, crossRefs, cfgRefs)

	// Both should have BiDeps
	if !nodes["ALB"].BiDeps["ECS"] {
		t.Errorf("expected ALB.BiDeps to contain ECS, got %v", nodes["ALB"].BiDeps)
	}
	if !nodes["ECS"].BiDeps["ALB"] {
		t.Errorf("expected ECS.BiDeps to contain ALB, got %v", nodes["ECS"].BiDeps)
	}
}

func TestBuildSGRefArrows_SkipDuplicate(t *testing.T) {
	// Both A→B and B→A exist in SGRefDeps — should produce only 1 arrow
	nodes := map[string]*ServiceNode{
		"A": {ID: "A", SGRefDeps: []string{"B"}},
		"B": {ID: "B", SGRefDeps: []string{"A"}},
	}
	boxes := map[string]*BoxPos{
		"A": {X: 10, Y: 2, W: 10, H: 3, CenterX: 15},
		"B": {X: 30, Y: 10, W: 10, H: 3, CenterX: 35},
	}

	arrows := buildSGRefArrows(nodes, boxes, nil)

	if len(arrows) != 1 {
		t.Fatalf("expected 1 arrow (deduped), got %d", len(arrows))
	}
}

func TestBuildArrows_BidirectionalFromBiDeps(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"ALB": {ID: "ALB", Service: "ALB", DepsOut: []string{"EKS"}, BiDeps: map[string]bool{"EKS": true}},
		"EKS": {ID: "EKS", Service: "EKS Cluster", DepsOut: nil, BiDeps: map[string]bool{"ALB": true}},
	}
	boxes := map[string]*BoxPos{
		"ALB": {X: 10, Y: 2, W: 10, H: 3, CenterX: 15},
		"EKS": {X: 10, Y: 10, W: 10, H: 3, CenterX: 15},
	}
	levels := [][]string{{"ALB"}, {"EKS"}}

	arrows := buildArrows(levels, nodes, boxes)

	found := false
	for _, a := range arrows {
		if a.FromID == "ALB" && a.ToID == "EKS" {
			if !a.Bidirectional {
				t.Error("expected ALB->EKS arrow to be bidirectional via BiDeps")
			}
			found = true
		}
	}
	if !found {
		t.Error("ALB->EKS arrow not found")
	}
}

func TestBuildArrows_BidirectionalFromDataService(t *testing.T) {
	nodes := map[string]*ServiceNode{
		"ECS": {ID: "ECS", Service: "ECS Cluster", DepsOut: []string{"RDS"}},
		"RDS": {ID: "RDS", Service: "Aurora RDS"},
	}
	boxes := map[string]*BoxPos{
		"ECS": {X: 10, Y: 2, W: 10, H: 3, CenterX: 15},
		"RDS": {X: 10, Y: 10, W: 10, H: 3, CenterX: 15},
	}
	levels := [][]string{{"ECS"}, {"RDS"}}

	arrows := buildArrows(levels, nodes, boxes)

	found := false
	for _, a := range arrows {
		if a.FromID == "ECS" && a.ToID == "RDS" {
			if !a.Bidirectional {
				t.Error("expected ECS->RDS arrow to be bidirectional (data service)")
			}
			found = true
		}
	}
	if !found {
		t.Error("ECS->RDS arrow not found")
	}
}
