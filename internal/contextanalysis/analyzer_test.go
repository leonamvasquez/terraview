package contextanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
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
	a := NewAnalyzer(nil, "pt-BR", "", 0)
	if a == nil {
		t.Fatal("expected non-nil analyzer")
	}
	if a.lang != "pt-BR" {
		t.Errorf("expected lang pt-BR, got %s", a.lang)
	}
}

func TestBuildSystemPrompt_Default(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "cross-resource") {
		t.Error("system prompt should mention cross-resource risks")
	}
	if contains(prompt, "pt-BR") {
		t.Error("should NOT contain pt-BR instruction when lang is empty")
	}
}

func TestBuildSystemPrompt_PtBR(t *testing.T) {
	a := NewAnalyzer(nil, "pt-BR", "", 0)
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "pt-BR") {
		t.Error("should contain pt-BR instruction")
	}
}

func TestBuildPrompt_Structure(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)

	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"cidr_block": "10.0.0.0/16"}},
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create", Provider: "aws",
			Values: map[string]interface{}{"instance_type": "t3.micro", "ami": "ami-123"}},
	}
	graph := topology.BuildGraph(resources)

	prompt := a.buildPrompt(resources, graph, 0, 0, 0)

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
	a := NewAnalyzer(nil, "", customPrompt, 0)
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "custom context analyzer") {
		t.Error("should use loaded prompt when contextAnalysisPrompt is non-empty")
	}
	if contains(prompt, "senior cloud infrastructure architect") {
		t.Error("should NOT use inline fallback when loaded prompt is available")
	}
}

func TestBuildSystemPrompt_FallbackWhenEmpty(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	prompt := a.buildSystemPrompt()

	if !contains(prompt, "senior cloud infrastructure architect") {
		t.Error("should use inline fallback when contextAnalysisPrompt is empty")
	}
}

func TestAnalyze_NoResources(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	result, err := a.Analyze(context.TODO(), nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Summary != "No resources to analyze." {
		t.Errorf("expected no-resources summary, got %q", result.Summary)
	}
}

// ---------------------------------------------------------------------------
// filterActive
// ---------------------------------------------------------------------------

func TestFilterActive_RemovesNoOpAndRead(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create"},
		{Address: "aws_subnet.a", Action: "no-op"},
		{Address: "aws_subnet.b", Action: "read"},
		{Address: "aws_instance.web", Action: "update"},
		{Address: "aws_sg.old", Action: "delete"},
		{Address: "aws_rds.db", Action: "replace"},
	}

	active, excluded := filterActive(resources)

	if excluded != 2 {
		t.Errorf("expected 2 excluded, got %d", excluded)
	}
	if len(active) != 4 {
		t.Errorf("expected 4 active resources, got %d", len(active))
	}
	for _, r := range active {
		if r.Action == "no-op" || r.Action == "read" {
			t.Errorf("filtered slice should not contain action %q (resource %s)", r.Action, r.Address)
		}
	}
}

func TestFilterActive_AllNoOp(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "no-op"},
		{Address: "aws_subnet.a", Action: "no-op"},
		{Address: "aws_s3_bucket.data", Action: "read"},
	}

	active, excluded := filterActive(resources)

	if excluded != 3 {
		t.Errorf("expected 3 excluded, got %d", excluded)
	}
	if len(active) != 0 {
		t.Errorf("expected 0 active resources, got %d", len(active))
	}
}

func TestFilterActive_NoneExcluded(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create"},
		{Address: "aws_instance.web", Action: "update"},
	}

	active, excluded := filterActive(resources)

	if excluded != 0 {
		t.Errorf("expected 0 excluded, got %d", excluded)
	}
	if len(active) != 2 {
		t.Errorf("expected 2 active resources, got %d", len(active))
	}
}

func TestFilterActive_EmptySlice(t *testing.T) {
	active, excluded := filterActive(nil)
	if excluded != 0 || len(active) != 0 {
		t.Errorf("expected 0/0, got %d/%d", excluded, len(active))
	}
}

func TestAnalyze_AllNoOpReturnsEarlyWithCount(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "no-op"},
		{Address: "aws_subnet.a", Action: "no-op"},
		{Address: "aws_s3_bucket.data", Action: "read"},
	}

	result, err := a.Analyze(context.TODO(), resources, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExcludedNoOp != 3 {
		t.Errorf("expected ExcludedNoOp=3, got %d", result.ExcludedNoOp)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for all-no-op plan, got %d", len(result.Findings))
	}
}

// ---------------------------------------------------------------------------
// effectiveBatchSize
// ---------------------------------------------------------------------------

func TestEffectiveBatchSize_Default(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	if got := a.effectiveBatchSize(); got != defaultContextBatchSize {
		t.Errorf("expected %d, got %d", defaultContextBatchSize, got)
	}
}

func TestEffectiveBatchSize_Custom(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 50)
	if got := a.effectiveBatchSize(); got != 50 {
		t.Errorf("expected 50, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// deduplicateFindings
// ---------------------------------------------------------------------------

func TestDeduplicateFindings_RemovesDuplicates(t *testing.T) {
	findings := []rules.Finding{
		{Resource: "aws_sg.a", Message: "port 22 open to 0.0.0.0/0", Severity: "HIGH"},
		{Resource: "aws_sg.a", Message: "port 22 open to 0.0.0.0/0", Severity: "HIGH"},
		{Resource: "aws_sg.b", Message: "port 22 open to 0.0.0.0/0", Severity: "HIGH"},
	}
	got := deduplicateFindings(findings)
	if len(got) != 2 {
		t.Errorf("expected 2 after dedup, got %d", len(got))
	}
}

func TestDeduplicateFindings_PreservesOrder(t *testing.T) {
	findings := []rules.Finding{
		{Resource: "r1", Message: "issue A"},
		{Resource: "r2", Message: "issue B"},
		{Resource: "r1", Message: "issue A"},
	}
	got := deduplicateFindings(findings)
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
	if got[0].Resource != "r1" || got[1].Resource != "r2" {
		t.Errorf("order not preserved: %v", got)
	}
}

func TestDeduplicateFindings_TruncatesMessageKey(t *testing.T) {
	long := strings.Repeat("x", 100)
	// Same first 60 chars → duplicate
	findings := []rules.Finding{
		{Resource: "r1", Message: long},
		{Resource: "r1", Message: long + "different_suffix"},
	}
	got := deduplicateFindings(findings)
	if len(got) != 1 {
		t.Errorf("expected 1 after dedup on 60-char prefix, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// resourcePriorityTier
// ---------------------------------------------------------------------------

func TestResourcePriorityTier_IAMIsHighest(t *testing.T) {
	if resourcePriorityTier("aws_iam_role") != 1 {
		t.Error("expected tier 1 for aws_iam_role")
	}
}

func TestResourcePriorityTier_EKSIsMedium(t *testing.T) {
	if resourcePriorityTier("aws_eks_cluster") != 2 {
		t.Error("expected tier 2 for aws_eks_cluster")
	}
}

func TestResourcePriorityTier_UnknownIsLow(t *testing.T) {
	if resourcePriorityTier("aws_cloudwatch_metric_alarm") != 3 {
		t.Error("expected tier 3 for unknown type")
	}
}

// ---------------------------------------------------------------------------
// buildPrompt — batch note
// ---------------------------------------------------------------------------

func TestBuildPrompt_BatchNote(t *testing.T) {
	a := NewAnalyzer(nil, "", "", 0)
	resources := []parser.NormalizedResource{
		{Address: "aws_iam_role.r", Type: "aws_iam_role", Action: "create"},
	}
	prompt := a.buildPrompt(resources, nil, 2, 3, 100)
	analysis, _ := prompt["analysis"].(string)
	if !contains(analysis, "Batch 2 of 3") {
		t.Errorf("expected batch note, got: %s", analysis)
	}
	if !contains(analysis, "100") {
		t.Error("expected total resource count in batch note")
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
