package contextanalysis

import (
	"context"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func TestExtractRelevantAttributes_SelectsSecurityKeys(t *testing.T) {
	values := map[string]interface{}{
		"cidr_block":           "10.0.0.0/16",
		"encrypted":            true,
		"instance_type":        "t3.micro",
		"tags":                 map[string]interface{}{"Name": "test"},
		"irrelevant_field":     "should be ignored",
		"another_random_field": 42,
	}

	got := extractRelevantAttributes(values)

	if _, ok := got["cidr_block"]; !ok {
		t.Error("expected cidr_block to be extracted")
	}
	if _, ok := got["encrypted"]; !ok {
		t.Error("expected encrypted to be extracted")
	}
	if _, ok := got["instance_type"]; !ok {
		t.Error("expected instance_type to be extracted")
	}
	if _, ok := got["tags"]; !ok {
		t.Error("expected tags to be extracted")
	}
	if _, ok := got["irrelevant_field"]; ok {
		t.Error("irrelevant_field should NOT be extracted")
	}
	if _, ok := got["another_random_field"]; ok {
		t.Error("another_random_field should NOT be extracted")
	}
}

func TestExtractRelevantAttributes_EmptyValues(t *testing.T) {
	got := extractRelevantAttributes(map[string]interface{}{})
	if len(got) != 0 {
		t.Errorf("expected 0 attributes, got %d", len(got))
	}
}

func TestNewAnalyzer(t *testing.T) {
	a := NewAnalyzer(nil, "pt-BR", "")
	if a == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if a.lang != "pt-BR" {
		t.Errorf("expected lang pt-BR, got %s", a.lang)
	}
}

func TestBuildSystemPrompt_Default(t *testing.T) {
	a := NewAnalyzer(nil, "", "")
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "cross-resource") {
		t.Error("system prompt should mention cross-resource risks")
	}
	if contains(prompt, "pt-BR") {
		t.Error("should NOT contain pt-BR instruction when lang is empty")
	}
}

func TestBuildSystemPrompt_PtBR(t *testing.T) {
	a := NewAnalyzer(nil, "pt-BR", "")
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "pt-BR") {
		t.Error("should contain pt-BR instruction")
	}
}

func TestBuildPrompt_Structure(t *testing.T) {
	a := NewAnalyzer(nil, "", "")

	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"cidr_block": "10.0.0.0/16"}},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"instance_type": "t3.micro", "ami": "ami-123"}},
	}
	graph := topology.BuildGraph(resources)

	prompt := a.buildPrompt(resources, graph)

	analysis, ok := prompt["analysis"].(string)
	if !ok {
		t.Fatal("prompt should contain 'analysis' string")
	}
	if !contains(analysis, "aws_vpc.main") {
		t.Error("prompt should contain vpc resource address")
	}
	if !contains(analysis, "aws_instance.web") {
		t.Error("prompt should contain instance resource address")
	}
	if !contains(analysis, "Topology") {
		t.Error("prompt should contain topology section")
	}
	if prompt["context_analysis"] != true {
		t.Error("prompt should have context_analysis=true")
	}
}

func TestBuildSystemPrompt_LoadedFromFile(t *testing.T) {
	customPrompt := "You are a custom context analyzer. Focus on cross-resource dependencies."
	a := NewAnalyzer(nil, "", customPrompt)
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "custom context analyzer") {
		t.Error("should use loaded prompt when contextAnalysisPrompt is non-empty")
	}
	if contains(prompt, "senior cloud infrastructure architect") {
		t.Error("should NOT use inline fallback when loaded prompt is available")
	}
}

func TestBuildSystemPrompt_FallbackWhenEmpty(t *testing.T) {
	a := NewAnalyzer(nil, "", "")
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "senior cloud infrastructure architect") {
		t.Error("should use inline fallback when contextAnalysisPrompt is empty")
	}
}

func TestAnalyze_NoResources(t *testing.T) {
	a := NewAnalyzer(nil, "", "")
	result, err := a.Analyze(context.TODO(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "No resources to analyze." {
		t.Errorf("expected no-resources summary, got %q", result.Summary)
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 && len(s) >= len(substr) &&
		(s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
