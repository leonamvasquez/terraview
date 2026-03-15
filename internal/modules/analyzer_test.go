package modules

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// --- classifySource ---

func TestClassifySource(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"local relative dot", "./modules/vpc", "local"},
		{"local relative parent", "../shared/rds", "local"},
		{"local empty", "", "local"},
		{"registry standard", "hashicorp/consul/aws", "registry"},
		{"registry with prefix", "registry.terraform.io/hashicorp/consul/aws", "registry"},
		{"git ssh", "git@github.com:org/module.git", "git"},
		{"git https", "git::https://github.com/org/module.git", "git"},
		{"github shorthand", "github.com/org/terraform-aws-vpc", "git"},
		{"bitbucket", "bitbucket.org/org/terraform-module", "git"},
		{"http plain", "http://example.com/module.zip", "http"},
		{"https", "https://example.com/module.zip", "http"},
		{"s3 source", "s3::https://bucket/module.zip", "http"},
		{"gcs source", "gcs::https://bucket/module.zip", "http"},
		{"unknown two parts", "foo/bar", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySource(tt.source)
			if got != tt.want {
				t.Errorf("classifySource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

// --- extractGitRef ---

func TestExtractGitRef(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"no ref", "git::https://github.com/org/mod.git", ""},
		{"with ref", "git::https://github.com/org/mod.git?ref=v1.0.0", "v1.0.0"},
		{"ref with ampersand before", "git::https://github.com/org/mod.git?depth=1&ref=main", "main"},
		{"ref with ampersand after", "git::https://github.com/org/mod.git?ref=develop&depth=1", "develop"},
		{"ref tag", "git::https://github.com/org/mod.git?ref=v2.3.1", "v2.3.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractGitRef(tt.source)
			if got != tt.want {
				t.Errorf("extractGitRef(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

// --- isBranchRef ---

func TestIsBranchRef(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want bool
	}{
		{"main branch", "main", true},
		{"master branch", "master", true},
		{"develop branch", "develop", true},
		{"dev branch", "dev", true},
		{"staging branch", "staging", true},
		{"production branch", "production", true},
		{"release branch", "release", true},
		{"semver tag", "v1.2.3", false},
		{"semver no prefix", "1.2.3", false},
		{"full sha", "abc123def456abc123def456abc123def456abcd", false},
		{"short sha", "abc123d", false},
		{"custom branch", "feature-foo", true},
		{"tag-like with v", "v0.1.0-beta", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBranchRef(tt.ref)
			if got != tt.want {
				t.Errorf("isBranchRef(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

// --- isHex ---

func TestIsHex(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"abc123", true},
		{"ABCDEF", true},
		{"0123456789abcdef", true},
		{"xyz", false},
		{"abc123g", false},
		{"", true},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := isHex(tt.s)
			if got != tt.want {
				t.Errorf("isHex(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// --- parseRegistrySource ---

func TestParseRegistrySource(t *testing.T) {
	tests := []struct {
		name                       string
		source                     string
		wantNS, wantName, wantProv string
	}{
		{"standard", "hashicorp/consul/aws", "hashicorp", "consul", "aws"},
		{"with prefix", "registry.terraform.io/hashicorp/consul/aws", "hashicorp", "consul", "aws"},
		{"two parts", "hashicorp/consul", "", "", ""},
		{"empty", "", "", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ns, name, prov := parseRegistrySource(tt.source)
			if ns != tt.wantNS || name != tt.wantName || prov != tt.wantProv {
				t.Errorf("parseRegistrySource(%q) = (%q,%q,%q), want (%q,%q,%q)",
					tt.source, ns, name, prov, tt.wantNS, tt.wantName, tt.wantProv)
			}
		})
	}
}

// --- constraintAllows ---

func TestConstraintAllows(t *testing.T) {
	tests := []struct {
		name       string
		constraint string
		latest     string
		want       bool
	}{
		{"exact match", "5.0.0", "5.0.0", true},
		{"tilde same major", "~> 5.0", "5.7.0", true},
		{"different major", "~> 4.0", "5.0.0", false},
		{"contains latest", ">= 3.0.0, < 4.0.0", "3.5.0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := constraintAllows(tt.constraint, tt.latest)
			if got != tt.want {
				t.Errorf("constraintAllows(%q, %q) = %v, want %v",
					tt.constraint, tt.latest, got, tt.want)
			}
		})
	}
}

// --- Analyzer.Analyze (integration) ---

func TestAnalyze_EmptyPlan(t *testing.T) {
	plan := &parser.TerraformPlan{}
	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	if result.Summary.TotalModules != 0 {
		t.Errorf("expected 0 modules, got %d", result.Summary.TotalModules)
	}
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(result.Findings))
	}
}

func TestAnalyze_RegistryUnpinned(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"vpc": {
			Source:            "terraform-aws-modules/vpc/aws",
			VersionConstraint: "",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	assertFinding(t, result, RuleUnpinnedRegistry, rules.SeverityHigh, "module.vpc")
}

func TestAnalyze_RegistryPinned(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"vpc": {
			Source:            "terraform-aws-modules/vpc/aws",
			VersionConstraint: "~> 5.0",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	for _, f := range result.Findings {
		if f.RuleID == RuleUnpinnedRegistry {
			t.Errorf("should not flag pinned registry module, got %+v", f)
		}
	}
}

func TestAnalyze_GitNoRef(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"custom": {
			Source: "git::https://github.com/org/terraform-module.git",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	assertFinding(t, result, RuleGitNoRef, rules.SeverityHigh, "module.custom")
}

func TestAnalyze_GitBranchRef(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"custom": {
			Source: "git::https://github.com/org/terraform-module.git?ref=main",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	assertFinding(t, result, RuleGitNoBranch, rules.SeverityHigh, "module.custom")
}

func TestAnalyze_GitTagRef(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"custom": {
			Source: "git::https://github.com/org/terraform-module.git?ref=v1.2.3",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	for _, f := range result.Findings {
		if f.RuleID == RuleGitNoBranch || f.RuleID == RuleGitNoRef {
			t.Errorf("should not flag tag ref, got %+v", f)
		}
	}
}

func TestAnalyze_HTTPSource(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"insecure": {
			Source: "http://example.com/module.zip",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	assertFinding(t, result, RuleHTTPSource, rules.SeverityHigh, "module.insecure")
}

func TestAnalyze_HTTPSSource_NoFinding(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"secure": {
			Source: "https://example.com/module.zip",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	for _, f := range result.Findings {
		if f.RuleID == RuleHTTPSource {
			t.Errorf("should not flag HTTPS source, got %+v", f)
		}
	}
}

func TestAnalyze_DeepNesting(t *testing.T) {
	// Build 4-level nesting: root -> l1 -> l2 -> l3 -> l4
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{
				ModuleCalls: map[string]parser.ModuleCall{
					"l1": {
						Source:            "terraform-aws-modules/vpc/aws",
						VersionConstraint: "~> 5.0",
						Module: &parser.ConfigModule{
							ModuleCalls: map[string]parser.ModuleCall{
								"l2": {
									Source: "./inner",
									Module: &parser.ConfigModule{
										ModuleCalls: map[string]parser.ModuleCall{
											"l3": {
												Source: "./deeper",
												Module: &parser.ConfigModule{
													ModuleCalls: map[string]parser.ModuleCall{
														"l4": {Source: "./deepest"},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	// l4 is at depth 4, should be flagged
	assertFinding(t, result, RuleDeepNesting, rules.SeverityMedium, "module.l1.module.l2.module.l3.module.l4")

	if result.Summary.MaxNestingDepth != 4 {
		t.Errorf("expected max nesting depth 4, got %d", result.Summary.MaxNestingDepth)
	}
}

func TestAnalyze_LocalModule_NoFindings(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"local": {Source: "./modules/vpc"},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings for local module, got %d: %+v", len(result.Findings), result.Findings)
	}
}

func TestAnalyze_MultipleModules(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"vpc": {
			Source:            "terraform-aws-modules/vpc/aws",
			VersionConstraint: "~> 5.0",
		},
		"unpinned": {
			Source: "terraform-aws-modules/rds/aws",
		},
		"git_bad": {
			Source: "git::https://github.com/org/mod.git?ref=develop",
		},
		"local_ok": {
			Source: "./modules/local",
		},
	})

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	if result.Summary.TotalModules != 4 {
		t.Errorf("expected 4 modules, got %d", result.Summary.TotalModules)
	}

	// Should have findings for unpinned registry and git branch
	findingRules := make(map[string]bool)
	for _, f := range result.Findings {
		findingRules[f.RuleID] = true
	}
	if !findingRules[RuleUnpinnedRegistry] {
		t.Error("expected MOD_001 finding for unpinned registry module")
	}
	if !findingRules[RuleGitNoBranch] {
		t.Error("expected MOD_002 finding for git branch ref")
	}
}

func TestAnalyze_RegistryOutdated_WithMock(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"vpc": {
			Source:            "terraform-aws-modules/vpc/aws",
			VersionConstraint: "~> 4.0",
		},
	})

	mock := &mockRegistry{version: "5.0.0"}
	a := NewAnalyzer(mock)
	result := a.Analyze(plan)

	assertFinding(t, result, RuleRegistryOutdated, rules.SeverityMedium, "module.vpc")
}

func TestAnalyze_RegistryUpToDate_WithMock(t *testing.T) {
	plan := buildPlanWithModules(map[string]parser.ModuleCall{
		"vpc": {
			Source:            "terraform-aws-modules/vpc/aws",
			VersionConstraint: "~> 5.0",
		},
	})

	mock := &mockRegistry{version: "5.7.0"}
	a := NewAnalyzer(mock)
	result := a.Analyze(plan)

	for _, f := range result.Findings {
		if f.RuleID == RuleRegistryOutdated {
			t.Errorf("should not flag up-to-date module, got %+v", f)
		}
	}
}

func TestAnalyze_ResourceCount(t *testing.T) {
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{
				ModuleCalls: map[string]parser.ModuleCall{
					"vpc": {
						Source:            "terraform-aws-modules/vpc/aws",
						VersionConstraint: "~> 5.0",
					},
				},
			},
		},
		PlannedValues: parser.PlannedValues{
			RootModule: parser.Module{
				ChildModules: []parser.Module{
					{
						Address: "module.vpc",
						Resources: []parser.PlannedResource{
							{Address: "module.vpc.aws_vpc.this", Type: "aws_vpc"},
							{Address: "module.vpc.aws_subnet.public", Type: "aws_subnet"},
							{Address: "module.vpc.aws_subnet.private", Type: "aws_subnet"},
						},
					},
				},
			},
		},
	}

	a := NewAnalyzer(nil)
	result := a.Analyze(plan)

	for _, m := range result.Modules {
		if m.Name == "vpc" && m.ResourceCount != 3 {
			t.Errorf("expected vpc resource count 3, got %d", m.ResourceCount)
		}
	}
}

// --- ToFindings ---

func TestToFindings(t *testing.T) {
	mf := []ModuleFinding{
		{
			RuleID:      RuleUnpinnedRegistry,
			Severity:    rules.SeverityHigh,
			Module:      "module.vpc",
			Source:      "terraform-aws-modules/vpc/aws",
			Message:     "test message",
			Remediation: "test remediation",
		},
	}

	findings := ToFindings(mf)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Source != "module-analyzer" {
		t.Errorf("expected source 'module-analyzer', got %q", f.Source)
	}
	if f.Category != rules.CategoryBestPractice {
		t.Errorf("expected category %q, got %q", rules.CategoryBestPractice, f.Category)
	}
	if f.Resource != "module.vpc" {
		t.Errorf("expected resource 'module.vpc', got %q", f.Resource)
	}
}

// --- Summary ---

func TestBuildSummary(t *testing.T) {
	modules := []ModuleInfo{
		{Name: "a", SourceType: "registry", Depth: 1},
		{Name: "b", SourceType: "git", Depth: 1},
		{Name: "c", SourceType: "registry", Depth: 2},
		{Name: "d", SourceType: "local", Depth: 3},
	}
	findings := []ModuleFinding{
		{Severity: rules.SeverityHigh},
		{Severity: rules.SeverityHigh},
		{Severity: rules.SeverityMedium},
	}

	summary := buildSummary(modules, findings)

	if summary.TotalModules != 4 {
		t.Errorf("expected 4 total modules, got %d", summary.TotalModules)
	}
	if summary.BySourceType["registry"] != 2 {
		t.Errorf("expected 2 registry modules, got %d", summary.BySourceType["registry"])
	}
	if summary.FindingsBySev[rules.SeverityHigh] != 2 {
		t.Errorf("expected 2 HIGH findings, got %d", summary.FindingsBySev[rules.SeverityHigh])
	}
	if summary.MaxNestingDepth != 3 {
		t.Errorf("expected max depth 3, got %d", summary.MaxNestingDepth)
	}
}

// --- Helpers ---

func buildPlanWithModules(calls map[string]parser.ModuleCall) *parser.TerraformPlan {
	return &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{
				ModuleCalls: calls,
			},
		},
	}
}

func assertFinding(t *testing.T, result *AnalysisResult, ruleID, severity, module string) {
	t.Helper()
	for _, f := range result.Findings {
		if f.RuleID == ruleID && f.Severity == severity && f.Module == module {
			return
		}
	}
	t.Errorf("expected finding %s (%s) for %s, got findings: %+v", ruleID, severity, module, result.Findings)
}

type mockRegistry struct {
	version string
	err     error
}

func (m *mockRegistry) LatestVersion(_, _, _ string) (string, error) {
	return m.version, m.err
}
