package diagram

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func TestGenerator_EmptyResources(t *testing.T) {
	gen := NewGenerator()
	result := gen.Generate(nil)
	if result == "" {
		t.Error("expected non-empty output for nil resources")
	}
}

func TestGenerator_NoOpSkipped(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.a", Action: "no-op", Type: "aws_instance"},
	}
	result := gen.Generate(resources)
	if strings.Contains(result, "aws_instance.a") {
		t.Error("no-op resources should not appear in diagram")
	}
}

func TestGenerator_CreateShowsPlus(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	result := gen.Generate(resources)
	if !strings.Contains(result, "[+]") {
		t.Error("expected [+] icon for create action")
	}
	if !strings.Contains(result, "EC2 Instance") {
		t.Error("expected friendly label in output")
	}
}

func TestGenerator_DeleteShowsMinus(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "delete", Type: "aws_instance"},
	}
	result := gen.Generate(resources)
	if !strings.Contains(result, "[-]") {
		t.Error("expected [-] icon for delete action")
	}
}

func TestGetLayer(t *testing.T) {
	tests := map[string]string{
		"aws_vpc":            "Network",
		"aws_subnet":         "Network",
		"aws_instance":       "Compute",
		"aws_s3_bucket":      "Data",
		"aws_iam_role":       "Security",
		"aws_security_group": "Security",
		"aws_unknown_thing":  "Other",
	}
	for resType, want := range tests {
		got := getLayer(resType)
		if got != want {
			t.Errorf("getLayer(%s) = %s, want %s", resType, got, want)
		}
	}
}

func TestGenerateWithGraph_VPCNesting(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.pub", Action: "create", Type: "aws_subnet"},
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
		{Address: "aws_db_instance.db", Action: "create", Type: "aws_db_instance"},
	}

	graph := topology.BuildGraph(resources)
	result := gen.GenerateWithGraph(resources, graph)

	// Should have VPC boundary
	if !strings.Contains(result, "VPC") {
		t.Error("expected VPC boundary in diagram")
	}
	// Should have Internet entry point
	if !strings.Contains(result, "Internet") {
		t.Error("expected Internet entry point")
	}
	// Should use Unicode box-drawing characters
	if !strings.Contains(result, "┌") {
		t.Error("expected Unicode box-drawing characters")
	}
	// Should have double-line VPC border
	if !strings.Contains(result, "╔") {
		t.Error("expected double-line VPC border")
	}
	// Should have AWS title
	if !strings.Contains(result, "AWS") {
		t.Error("expected AWS provider in title")
	}
}

func TestGenerateWithGraph_NoVPC(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_iam_role.admin", Action: "create", Type: "aws_iam_role"},
		{Address: "aws_s3_bucket.logs", Action: "create", Type: "aws_s3_bucket"},
	}

	graph := topology.BuildGraph(resources)
	result := gen.GenerateWithGraph(resources, graph)

	// Without aws_vpc, S3 and IAM should render outside VPC
	if strings.Contains(result, "╔") {
		t.Error("should NOT have VPC border when no VPC resource exists")
	}
	if !strings.Contains(result, "Amazon S3") {
		t.Error("expected friendly S3 label")
	}
}

func TestGenerateWithGraph_MultipleResources(t *testing.T) {
	gen := NewGenerator()
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.a", Action: "create", Type: "aws_subnet"},
		{Address: "aws_subnet.b", Action: "create", Type: "aws_subnet"},
		{Address: "aws_instance.web1", Action: "create", Type: "aws_instance"},
		{Address: "aws_instance.web2", Action: "create", Type: "aws_instance"},
		{Address: "aws_instance.web3", Action: "create", Type: "aws_instance"},
		{Address: "aws_db_instance.primary", Action: "create", Type: "aws_db_instance"},
		{Address: "aws_security_group.web", Action: "create", Type: "aws_security_group"},
		{Address: "aws_lb.alb", Action: "create", Type: "aws_lb"},
	}

	graph := topology.BuildGraph(resources)
	result := gen.GenerateWithGraph(resources, graph)

	// Should contain layers for all resource types
	if !strings.Contains(result, "Network") {
		t.Error("expected Network layer")
	}
	if !strings.Contains(result, "Compute") {
		t.Error("expected Compute layer")
	}
	if !strings.Contains(result, "Data") {
		t.Error("expected Data layer")
	}
	// Security/IAM is outside VPC
	if !strings.Contains(result, "Security") {
		t.Error("expected Security layer")
	}
}

func TestServiceLabels(t *testing.T) {
	tests := map[string]string{
		"aws_instance":        "EC2 Instance",
		"aws_s3_bucket":       "Amazon S3",
		"aws_db_instance":     "Amazon RDS",
		"aws_lambda_function": "Lambda Function",
		"aws_vpc":             "Amazon VPC",
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
