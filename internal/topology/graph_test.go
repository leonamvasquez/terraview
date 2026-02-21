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
