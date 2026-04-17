package pipeline

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// writePlan drops a minimal Terraform plan JSON in a tempdir and returns the
// path, so we can exercise the Runner without touching the repo-level fixture
// files.
func writePlan(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	planPath := filepath.Join(dir, "plan.json")
	content := `{
		"format_version": "1.2",
		"terraform_version": "1.6.0",
		"resource_changes": [
			{
				"address": "aws_s3_bucket.logs",
				"type": "aws_s3_bucket",
				"name": "logs",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": {
					"actions": ["create"],
					"before": null,
					"after": {"bucket": "logs"},
					"after_unknown": {}
				}
			}
		]
	}`
	if err := os.WriteFile(planPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write plan: %v", err)
	}
	return planPath
}

func baseConfig(planPath string) Config {
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{
		Critical: 10, High: 7, Medium: 4, Low: 1,
	}
	return Config{
		Cfg:             cfg,
		PlanPath:        planPath,
		WorkDir:         filepath.Dir(planPath),
		EffectiveAI:     false,
		EffectiveFormat: "json",
		ShowSpinner:     false,
		Stderr:          io.Discard,
	}
}

func TestParsePlan_OK(t *testing.T) {
	planPath := writePlan(t)

	_, resources, graph, err := ParsePlan(planPath, nil)
	if err != nil {
		t.Fatalf("ParsePlan: %v", err)
	}
	if len(resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(resources))
	}
	if resources[0].Address != "aws_s3_bucket.logs" {
		t.Errorf("unexpected address: %q", resources[0].Address)
	}
	if graph == nil {
		t.Error("expected non-nil topology graph")
	}
}

func TestParsePlan_Error(t *testing.T) {
	if _, _, _, err := ParsePlan("/nonexistent/plan.json", nil); err == nil {
		t.Fatal("expected error for missing plan")
	}
}

func TestRunner_Run_NoScannerNoAI(t *testing.T) {
	planPath := writePlan(t)
	cfg := baseConfig(planPath)

	runner := NewRunner(cfg)
	result, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Review.PipelineStatus == nil {
		t.Fatal("expected pipeline status")
	}
	if result.Review.PipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("want complete, got %q", result.Review.PipelineStatus.ResultCompleteness)
	}
	if len(result.Resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(result.Resources))
	}
}

func TestRunScanPhase_NoScannerNoAI(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err != nil {
		t.Fatalf("RunScanPhase: %v", err)
	}
	if sr.PipelineStatus == nil {
		t.Fatal("expected pipeline status")
	}
	if sr.PipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("want complete, got %q", sr.PipelineStatus.ResultCompleteness)
	}
	if sr.PipelineStatus.Scanner != nil {
		t.Error("expected nil scanner status when no scanner specified")
	}
	if sr.PipelineStatus.AI != nil {
		t.Error("expected nil AI status when AI disabled")
	}
}

func TestRunScanPhase_InvalidScanner(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.ScannerName = "definitely_not_a_scanner_123"
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	sr, err := RunScanPhase(context.Background(), cfg, resources, graph)
	if err == nil {
		// Scanner fails but without AI this is fatal (both failed path)
		if sr.PipelineStatus == nil || sr.PipelineStatus.Scanner == nil {
			t.Fatal("expected scanner status to be populated")
		}
	}
}

func TestMergeAndScore_EmptyFindings(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := ScanPhaseResult{}

	result := MergeAndScore(cfg, resources, graph, sr)
	if result.Score.OverallScore < 0 || result.Score.OverallScore > 10 {
		t.Errorf("score out of range: %f", result.Score.OverallScore)
	}
}

func TestMergeAndScore_WithFindings(t *testing.T) {
	cfg := baseConfig("plan.json")
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "test"},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)
	if len(result.Findings) == 0 {
		t.Error("expected findings in result")
	}
}

func TestMergeAndScore_DisabledRules(t *testing.T) {
	cfg := baseConfig("plan.json")
	cfg.Cfg.Rules.DisabledRules = []string{"CKV_AWS_1"}
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := ScanPhaseResult{
		HardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "disabled"},
			{RuleID: "CKV_AWS_2", Severity: "LOW", Resource: "aws_instance.web", Message: "kept"},
		},
	}

	result := MergeAndScore(cfg, resources, graph, sr)
	for _, f := range result.Findings {
		if f.RuleID == "CKV_AWS_1" {
			t.Errorf("disabled rule %q was not filtered", f.RuleID)
		}
	}
}

func TestFilterDisabledRules(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001"},
		{RuleID: "SEC002"},
		{RuleID: "TAG001"},
	}

	t.Run("nil disables nothing", func(t *testing.T) {
		got := FilterDisabledRules(findings, nil)
		if len(got) != 3 {
			t.Errorf("got %d, want 3", len(got))
		}
	})

	t.Run("exact match", func(t *testing.T) {
		got := FilterDisabledRules(findings, []string{"SEC001"})
		if len(got) != 2 {
			t.Errorf("got %d, want 2", len(got))
		}
	})

	t.Run("prefix match", func(t *testing.T) {
		got := FilterDisabledRules(findings, []string{"SEC"})
		if len(got) != 1 {
			t.Errorf("got %d, want 1", len(got))
		}
		if got[0].RuleID != "TAG001" {
			t.Errorf("unexpected kept rule: %s", got[0].RuleID)
		}
	})
}

func TestBuildResourceLimits(t *testing.T) {
	safe := BuildResourceLimits(config.Config{}, true)
	def := BuildResourceLimits(config.Config{}, false)
	if safe.MaxThreads == 0 || def.MaxThreads == 0 {
		t.Error("expected non-zero default thread limits")
	}
}
