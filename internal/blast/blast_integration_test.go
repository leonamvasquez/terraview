package blast

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// The tests below exercise Analyze (value-based dep inference) rather than
// AnalyzeWithGraph (pre-built graph). They were previously in the dead
// internal/regression package that had no production code of its own.

func TestBlast_DirectDependencies(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.b", Type: "aws_subnet", Name: "b", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
	}
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(resources)

	var vpcImpact *Impact
	for i := range result.Impacts {
		if result.Impacts[i].Resource == "aws_vpc.main" {
			vpcImpact = &result.Impacts[i]
			break
		}
	}
	if vpcImpact == nil {
		t.Fatal("expected impact for aws_vpc.main")
	}
	if vpcImpact.TotalAffected < 2 {
		t.Errorf("VPC change should affect >= 2 subnets, got %d", vpcImpact.TotalAffected)
	}
	directStr := strings.Join(vpcImpact.DirectDeps, ",")
	if !strings.Contains(directStr, "aws_subnet.a") || !strings.Contains(directStr, "aws_subnet.b") {
		t.Errorf("expected both subnets in direct deps, got %v", vpcImpact.DirectDeps)
	}
}

func TestBlast_IndirectDependenciesBFS(t *testing.T) {
	// Chain: VPC <- subnet (vpc_id) <- eni (subnet_id) <- instance (network_interface_id)
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_network_interface.eni", Type: "aws_network_interface", Name: "eni", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"network_interface_id": "aws_network_interface.eni"}},
	}
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(resources)

	var vpcImpact *Impact
	for i := range result.Impacts {
		if result.Impacts[i].Resource == "aws_vpc.main" {
			vpcImpact = &result.Impacts[i]
			break
		}
	}
	if vpcImpact == nil {
		t.Fatal("expected impact for aws_vpc.main")
	}
	if vpcImpact.TotalAffected < 3 {
		t.Errorf("VPC should transitively affect >= 3 resources, got %d (direct: %v, indirect: %v)",
			vpcImpact.TotalAffected, vpcImpact.DirectDeps, vpcImpact.IndirectDeps)
	}
}

func TestBlast_DeleteHigherRiskThanCreate(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_vpc.del", Type: "aws_vpc", Name: "del", Action: "delete", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a1", Type: "aws_subnet", Name: "a1", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.a2", Type: "aws_subnet", Name: "a2", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.a3", Type: "aws_subnet", Name: "a3", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_subnet.b1", Type: "aws_subnet", Name: "b1", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
		{Address: "aws_subnet.b2", Type: "aws_subnet", Name: "b2", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
		{Address: "aws_subnet.b3", Type: "aws_subnet", Name: "b3", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.del"}},
	}
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(resources)

	var createRisk, deleteRisk string
	for _, imp := range result.Impacts {
		if imp.Resource == "aws_vpc.main" {
			createRisk = imp.RiskLevel
		}
		if imp.Resource == "aws_vpc.del" {
			deleteRisk = imp.RiskLevel
		}
	}
	if createRisk == "" || deleteRisk == "" {
		t.Fatal("expected impacts for both VPCs")
	}
	if createRisk == deleteRisk {
		t.Errorf("delete should have higher risk than create with same deps: create=%s, delete=%s", createRisk, deleteRisk)
	}
}

func TestBlast_Consistency(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_sg.sg", Type: "aws_security_group", Name: "sg", Action: "update", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a", "vpc_security_group_ids": "aws_sg.sg"}},
	}
	analyzer := NewAnalyzer()
	r1 := analyzer.Analyze(resources)
	r2 := analyzer.Analyze(resources)
	r3 := analyzer.Analyze(resources)
	if r1.MaxRadius != r2.MaxRadius || r2.MaxRadius != r3.MaxRadius {
		t.Errorf("max radius inconsistent: %d, %d, %d", r1.MaxRadius, r2.MaxRadius, r3.MaxRadius)
	}
}

func TestBlast_AnalyzeVsAnalyzeWithGraph(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Values: map[string]interface{}{}},
		{Address: "aws_subnet.a", Type: "aws_subnet", Name: "a", Action: "create", Values: map[string]interface{}{"vpc_id": "aws_vpc.main"}},
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Values: map[string]interface{}{"subnet_id": "aws_subnet.a"}},
	}
	analyzer := NewAnalyzer()
	r1 := analyzer.Analyze(resources)
	g := topology.BuildGraph(resources)
	r2 := analyzer.AnalyzeWithGraph(resources, g)

	if r1.MaxRadius != r2.MaxRadius {
		t.Errorf("Analyze vs AnalyzeWithGraph MaxRadius differ: %d vs %d", r1.MaxRadius, r2.MaxRadius)
	}
	if len(r1.Impacts) != len(r2.Impacts) {
		t.Fatalf("impact count differs: %d vs %d", len(r1.Impacts), len(r2.Impacts))
	}
	for i := range r1.Impacts {
		if r1.Impacts[i].TotalAffected != r2.Impacts[i].TotalAffected {
			t.Errorf("TotalAffected differs for %s: %d vs %d",
				r1.Impacts[i].Resource, r1.Impacts[i].TotalAffected, r2.Impacts[i].TotalAffected)
		}
	}
}
