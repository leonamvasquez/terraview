package modules

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestFormatPretty_EmptyResult(t *testing.T) {
	result := &AnalysisResult{
		Summary: ResultSummary{TotalModules: 0},
	}

	out := FormatPretty(result)
	if !strings.Contains(out, "No module calls found") {
		t.Errorf("expected empty message, got:\n%s", out)
	}
}

func TestFormatPretty_EmptyResult_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("en")

	result := &AnalysisResult{
		Summary: ResultSummary{TotalModules: 0},
	}

	out := FormatPretty(result)
	if !strings.Contains(out, "Nenhuma chamada de módulo") {
		t.Errorf("expected BR empty message, got:\n%s", out)
	}
}

func TestFormatPretty_WithModules(t *testing.T) {
	result := &AnalysisResult{
		Modules: []ModuleInfo{
			{Name: "vpc", Source: "terraform-aws-modules/vpc/aws", SourceType: "registry", VersionConstraint: "~> 5.0", Depth: 1, ResourceCount: 12},
			{Name: "rds", Source: "terraform-aws-modules/rds/aws", SourceType: "registry", Depth: 1},
		},
		Findings: []ModuleFinding{
			{
				RuleID:      RuleUnpinnedRegistry,
				Severity:    rules.SeverityHigh,
				Module:      "module.rds",
				Source:      "terraform-aws-modules/rds/aws",
				Message:     "Registry module has no version constraint",
				Remediation: "Add version constraint",
			},
		},
		Summary: ResultSummary{
			TotalModules:    2,
			BySourceType:    map[string]int{"registry": 2},
			FindingsBySev:   map[string]int{rules.SeverityHigh: 1},
			MaxNestingDepth: 1,
		},
	}

	out := FormatPretty(result)

	checks := []string{
		"Modules found",
		"module.vpc",
		"module.rds",
		"registry",
		"Findings (1)",
		"MOD_001",
		"no version constraint",
	}

	for _, check := range checks {
		if !strings.Contains(out, check) {
			t.Errorf("expected output to contain %q, got:\n%s", check, out)
		}
	}
}

func TestFormatPretty_NoFindings(t *testing.T) {
	result := &AnalysisResult{
		Modules: []ModuleInfo{
			{Name: "vpc", Source: "./modules/vpc", SourceType: "local", Depth: 1},
		},
		Summary: ResultSummary{
			TotalModules: 1,
			BySourceType: map[string]int{"local": 1},
		},
	}

	out := FormatPretty(result)
	if !strings.Contains(out, "No module issues found") {
		t.Errorf("expected clean verdict, got:\n%s", out)
	}
}

func TestFormatJSON(t *testing.T) {
	result := &AnalysisResult{
		Modules: []ModuleInfo{
			{Name: "vpc", Source: "terraform-aws-modules/vpc/aws", SourceType: "registry", VersionConstraint: "~> 5.0", Depth: 1},
		},
		Summary: ResultSummary{
			TotalModules: 1,
			BySourceType: map[string]int{"registry": 1},
		},
	}

	out, err := FormatJSON(result)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(out, `"name": "vpc"`) {
		t.Errorf("expected JSON to contain module name, got:\n%s", out)
	}
	if !strings.Contains(out, `"source_type": "registry"`) {
		t.Errorf("expected JSON to contain source_type, got:\n%s", out)
	}
}
