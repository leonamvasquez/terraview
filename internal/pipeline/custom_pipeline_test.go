package pipeline

import (
	"io"
	"testing"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func TestMergeAndScore_WithCustomRules(t *testing.T) {
	// Rule fires when aws_s3_bucket is missing the "bucket" field.
	customRule := config.CustomRuleConfig{
		ID:           "CUSTOM_001",
		Severity:     rules.SeverityHigh,
		Category:     rules.CategoryBestPractice,
		Message:      "S3 bucket name must be set",
		Remediation:  "Set the bucket attribute",
		ResourceType: "aws_s3_bucket",
		Condition: config.CustomRuleCondition{
			Field: "bucket",
			Op:    "is_null",
		},
	}

	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{
		Critical: 10, High: 7, Medium: 4, Low: 1,
	}
	cfg.Rules.Custom = []config.CustomRuleConfig{customRule}

	pipelineCfg := Config{
		Cfg:             cfg,
		PlanPath:        "testdata/plan.json",
		WorkDir:         "testdata",
		EffectiveAI:     false,
		EffectiveFormat: "json",
		ShowSpinner:     false,
		Stderr:          io.Discard,
	}

	// Resource with no "bucket" field — the rule should fire.
	resources := []parser.NormalizedResource{
		{
			Address: "aws_s3_bucket.logs",
			Type:    "aws_s3_bucket",
			Name:    "logs",
			Action:  "create",
			Values:  map[string]interface{}{},
		},
	}

	topoGraph := topology.BuildGraph(resources)
	sr := ScanPhaseResult{
		HardFindings: nil,
	}

	result := MergeAndScore(pipelineCfg, resources, topoGraph, sr)

	found := false
	for _, f := range result.Findings {
		if f.RuleID == "CUSTOM_001" && f.Resource == "aws_s3_bucket.logs" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected CUSTOM_001 finding for aws_s3_bucket.logs, got findings: %+v", result.Findings)
	}
}
