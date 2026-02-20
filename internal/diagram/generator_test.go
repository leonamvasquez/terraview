package diagram

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
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
	if !strings.Contains(result, "aws_instance.web") {
		t.Error("expected resource address in output")
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
