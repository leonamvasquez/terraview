package module
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
		{"../shared/network", "local"},
		{"git::https://github.com/org/repo.git", "git"},
		{"hashicorp/consul/aws", "registry"},
		{"s3::https://bucket/module.zip", "bucket"},
		{"", "unknown"},
	}

	for _, tt := range tests {
		got := classifySource(tt.source)






















































































































































}	}		t.Error("FormatModuleAnalysis returned empty string")	if output == "" {	output := FormatModuleAnalysis(result)	}		Summary:    "1 issue",		Findings:   []Finding{{Type: "no-version-pin", Severity: "HIGH", Module: "vpc", Message: "test", Advice: "pin it"}},		ScoreLevel: "GOOD",		Score:      8.0,	result := &AnalysisResult{func TestFormatModuleAnalysis(t *testing.T) {}	}		t.Errorf("computeScore(HIGH) = %f, want 8.0", got)	if got := computeScore(findings); got != 8.0 {	findings := []Finding{{Severity: "HIGH"}}	// One HIGH finding = 10.0 - 2.0 = 8.0	}		t.Errorf("computeScore(nil) = %f, want 10.0", got)	if got := computeScore(nil); got != 10.0 {	// No findings = 10.0func TestComputeScore(t *testing.T) {}	}		t.Error("expected 'oversized-module' finding for module with 55 resources")	if !foundOversized {	}		}			foundOversized = true		if f.Type == "oversized-module" {	for _, f := range result.Findings {	foundOversized := false	result := analyzer.Analyze(plan, resources)	analyzer := NewAnalyzer()	}		})			Action:  "create",			Type:    "aws_instance",			Address: "module.big.aws_instance.web_" + string(rune('a'+i%26)),		resources = append(resources, parser.NormalizedResource{	for i := 0; i < 55; i++ {	var resources []parser.NormalizedResource	}		Configuration: parser.Configuration{RootModule: parser.ConfigModule{}},	plan := &parser.TerraformPlan{func TestAnalyze_OversizedModule(t *testing.T) {}	}		t.Error("expected 'no-version-pin' finding for registry module without version")	if !foundNoPin {	}		}			foundNoPin = true		if f.Type == "no-version-pin" {	for _, f := range result.Findings {	foundNoPin := false	result := analyzer.Analyze(plan, nil)	analyzer := NewAnalyzer()	}		},			},				},					},						VersionConstraint: "",						Source:            "hashicorp/vpc/aws",					"vpc": {				ModuleCalls: map[string]parser.ModuleCall{			RootModule: parser.ConfigModule{		Configuration: parser.Configuration{	plan := &parser.TerraformPlan{func TestAnalyze_VersionPinning(t *testing.T) {}	}		t.Error("expected 'repeated-resources' finding for 3x aws_subnet in root")	if !foundRepeated {	}		}			foundRepeated = true		if f.Type == "repeated-resources" {	for _, f := range result.Findings {	foundRepeated := false	result := analyzer.Analyze(plan, resources)	analyzer := NewAnalyzer()	}		{Address: "aws_subnet.c", Type: "aws_subnet", Action: "create"},		{Address: "aws_subnet.b", Type: "aws_subnet", Action: "create"},		{Address: "aws_subnet.a", Type: "aws_subnet", Action: "create"},	resources := []parser.NormalizedResource{	}		},			RootModule: parser.ConfigModule{},		Configuration: parser.Configuration{	plan := &parser.TerraformPlan{func TestAnalyze_RepeatedResources(t *testing.T) {}	}		t.Error("expected 'no-modules' finding for 25 root resources")	if !foundNoModules {	}		}			foundNoModules = true		if f.Type == "no-modules" {	for _, f := range result.Findings {	foundNoModules := false	}		t.Errorf("ModuleCount = %d, want 0", result.ModuleCount)	if result.ModuleCount != 0 {	result := analyzer.Analyze(plan, resources)	analyzer := NewAnalyzer()	}		})			Action:  "create",			Type:    "aws_instance",			Address: "aws_instance.web_" + string(rune('a'+i)),		resources = append(resources, parser.NormalizedResource{	for i := 0; i < 25; i++ {	var resources []parser.NormalizedResource	// Create 25 root resources to trigger no-modules finding	}		},			RootModule: parser.ConfigModule{},		Configuration: parser.Configuration{	plan := &parser.TerraformPlan{func TestAnalyze_NoModules(t *testing.T) {}	}		}			t.Errorf("classifySource(%q) = %q, want %q", tt.source, got, tt.want)		if got != tt.want {