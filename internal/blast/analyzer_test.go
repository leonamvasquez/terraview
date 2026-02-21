package blast

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestAnalyzer_NoResources(t *testing.T) {
	analyzer := NewAnalyzer()
	result := analyzer.Analyze(nil)
	if result.MaxRadius != 0 {
		t.Errorf("expected max radius 0, got %d", result.MaxRadius)
	}
	if len(result.Impacts) != 0 {
		t.Errorf("expected 0 impacts, got %d", len(result.Impacts))
	}
}

func TestAnalyzer_NoOpSkipped(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.a", Action: "no-op", Type: "aws_instance"},
		{Address: "aws_instance.b", Action: "read", Type: "aws_instance"},
	}
	result := analyzer.Analyze(resources)
	if len(result.Impacts) != 0 {
		t.Errorf("expected 0 impacts for no-op/read, got %d", len(result.Impacts))
	}
}

func TestAnalyzer_SingleCreate(t *testing.T) {
	analyzer := NewAnalyzer()
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	result := analyzer.Analyze(resources)
	if len(result.Impacts) != 1 {
		t.Fatalf("expected 1 impact, got %d", len(result.Impacts))
	}
	if result.Impacts[0].Resource != "aws_instance.web" {
		t.Errorf("expected resource aws_instance.web, got %s", result.Impacts[0].Resource)
	}
}

func TestComputeRisk(t *testing.T) {
	tests := []struct {
		action   string
		affected int
		want     string
	}{
		{"create", 0, "low"},
		{"create", 3, "medium"},
		{"create", 6, "high"},
		{"create", 10, "critical"},
		{"delete", 0, "low"},
		{"delete", 2, "medium"},
		{"delete", 3, "high"},
		{"delete", 5, "critical"},
	}
	for _, tt := range tests {
		got := computeRisk(tt.action, tt.affected)
		if got != tt.want {
			t.Errorf("computeRisk(%s, %d) = %s, want %s", tt.action, tt.affected, got, tt.want)
		}
	}
}

func TestBlastResult_FormatPretty_Empty(t *testing.T) {
	br := &BlastResult{}
	out := br.FormatPretty()
	if out == "" {
		t.Error("expected non-empty output")
	}
}

func TestActionIcon(t *testing.T) {
	if actionIcon("create") != "[+]" {
		t.Error("create should be [+]")
	}
	if actionIcon("delete") != "[-]" {
		t.Error("delete should be [-]")
	}
	if actionIcon("update") != "[~]" {
		t.Error("update should be [~]")
	}
	if actionIcon("replace") != "[!]" {
		t.Error("replace should be [!]")
	}
}
