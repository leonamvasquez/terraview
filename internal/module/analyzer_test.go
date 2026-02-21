package module

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

func TestExtractModuleAddress(t *testing.T) {
	tests := []struct {
		address string
		want    string
	}{
		{"aws_instance.web", "root"},
		{"module.vpc.aws_subnet.private", "module.vpc"},
		{"module.app.module.db.aws_rds_cluster.main", "module.app.module.db"},
		{"module.network.aws_vpc.main", "module.network"},
	}

	for _, tt := range tests {
		got := extractModuleAddress(tt.address)
		if got != tt.want {
			t.Errorf("extractModuleAddress(%q) = %q, want %q", tt.address, got, tt.want)
		}
	}
}

func TestClassifySource(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"./modules/vpc", "local"},
		{"../shared/networking", "local"},
		{"hashicorp/vpc/aws", "registry"},
		{"git::https://github.com/org/repo.git", "git"},
		{"github.com/org/terraform-module", "git"},
		{"s3::https://bucket/module.zip", "bucket"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		got := classifySource(tt.source)
		if got != tt.want {
			t.Errorf("classifySource(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestAnalyze_NoModules(t *testing.T) {
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{},
		},
	}

	// Create 25 root resources to trigger no-modules finding
	var resources []parser.NormalizedResource
	for i := 0; i < 25; i++ {
		resources = append(resources, parser.NormalizedResource{
			Address: "aws_instance.web_" + string(rune('a'+i)),
			Type:    "aws_instance",
			Action:  "create",
		})
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(plan, resources)

	if result.ModuleCount != 0 {
		t.Errorf("ModuleCount = %d, want 0", result.ModuleCount)
	}

	foundNoModules := false
	for _, f := range result.Findings {
		if f.Type == "no-modules" {
			foundNoModules = true
		}
	}
	if !foundNoModules {
		t.Error("expected 'no-modules' finding for 25 root resources")
	}
}

func TestAnalyze_RepeatedResources(t *testing.T) {
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{},
		},
	}

	resources := []parser.NormalizedResource{
		{Address: "aws_subnet.a", Type: "aws_subnet", Action: "create"},
		{Address: "aws_subnet.b", Type: "aws_subnet", Action: "create"},
		{Address: "aws_subnet.c", Type: "aws_subnet", Action: "create"},
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(plan, resources)

	foundRepeated := false
	for _, f := range result.Findings {
		if f.Type == "repeated-resources" {
			foundRepeated = true
		}
	}
	if !foundRepeated {
		t.Error("expected 'repeated-resources' finding for 3x aws_subnet in root")
	}
}

func TestAnalyze_VersionPinning(t *testing.T) {
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{
				ModuleCalls: map[string]parser.ModuleCall{
					"vpc": {
						Source:            "hashicorp/vpc/aws",
						VersionConstraint: "",
					},
				},
			},
		},
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(plan, nil)

	foundNoPin := false
	for _, f := range result.Findings {
		if f.Type == "no-version-pin" {
			foundNoPin = true
		}
	}
	if !foundNoPin {
		t.Error("expected 'no-version-pin' finding for registry module without version")
	}
}

func TestAnalyze_OversizedModule(t *testing.T) {
	plan := &parser.TerraformPlan{
		Configuration: parser.Configuration{RootModule: parser.ConfigModule{}},
	}

	var resources []parser.NormalizedResource
	for i := 0; i < 55; i++ {
		resources = append(resources, parser.NormalizedResource{
			Address: "module.big.aws_instance.web_" + string(rune('a'+i%26)),
			Type:    "aws_instance",
			Action:  "create",
		})
	}

	analyzer := NewAnalyzer()
	result := analyzer.Analyze(plan, resources)

	foundOversized := false
	for _, f := range result.Findings {
		if f.Type == "oversized-module" {
			foundOversized = true
		}
	}
	if !foundOversized {
		t.Error("expected 'oversized-module' finding for module with 55 resources")
	}
}

func TestComputeScore(t *testing.T) {
	// No findings = 10.0
	if got := computeScore(nil); got != 10.0 {
		t.Errorf("computeScore(nil) = %f, want 10.0", got)
	}

	// One HIGH finding = 10.0 - 2.0 = 8.0
	findings := []Finding{{Severity: "HIGH"}}
	if got := computeScore(findings); got != 8.0 {
		t.Errorf("computeScore(HIGH) = %f, want 8.0", got)
	}
}

func TestFormatModuleAnalysis(t *testing.T) {
	result := &AnalysisResult{
		Score:      8.0,
		ScoreLevel: "GOOD",
		Findings:   []Finding{{Type: "no-version-pin", Severity: "HIGH", Module: "vpc", Message: "test", Advice: "pin it"}},
		Summary:    "1 issue",
	}

	output := FormatModuleAnalysis(result)
	if output == "" {
		t.Error("FormatModuleAnalysis returned empty string")
	}
}
