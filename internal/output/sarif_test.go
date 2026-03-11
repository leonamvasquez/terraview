package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestWriteSARIF_CreatesValidJSON(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 3,
		Findings: []rules.Finding{
			{
				RuleID:   "SEC001",
				Severity: "CRITICAL",
				Category: "security",
				Resource: "aws_instance.web",
				Message:  "Public SSH access",
				Source:   "checkov",
			},
			{
				RuleID:   "TAG001",
				Severity: "MEDIUM",
				Category: "compliance",
				Resource: "aws_s3_bucket.data",
				Message:  "Missing required tags",
				Source:   "tfsec",
			},
		},
	}
	tmpDir := t.TempDir()
	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	err := w.WriteSARIF(result, sarifPath)
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed to read SARIF file: %v", err)
	}
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed to parse SARIF JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestWriteSARIF_EmptyFindings(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 0,
	}
	tmpDir := t.TempDir()
	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	err := w.WriteSARIF(result, sarifPath)
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed to read SARIF file: %v", err)
	}
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed to parse SARIF JSON: %v", err)
	}
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	if got := mapSeverityToSARIFLevel("CRITICAL"); got != "error" {
		t.Errorf("expected error, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("HIGH"); got != "error" {
		t.Errorf("expected error, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("MEDIUM"); got != "warning" {
		t.Errorf("expected warning, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("LOW"); got != "note" {
		t.Errorf("expected note, got %s", got)
	}
}

func TestSeverityToSARIFLevel_InfoAndUnknown(t *testing.T) {
	if got := mapSeverityToSARIFLevel("INFO"); got != "note" {
		t.Errorf("INFO: expected note, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("UNKNOWN"); got != "warning" {
		t.Errorf("UNKNOWN: expected warning, got %s", got)
	}
	if got := mapSeverityToSARIFLevel(""); got != "warning" {
		t.Errorf("empty: expected warning, got %s", got)
	}
}

func TestSeverityToSARIFLevel_Lowercase(t *testing.T) {
	cases := []struct{ input, want string }{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "note"},
	}
	for _, c := range cases {
		if got := mapSeverityToSARIFLevel(c.input); got != c.want {
			t.Errorf("mapSeverityToSARIFLevel(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

func TestBuildSARIF_SchemaAndToolInfo(t *testing.T) {
	result := aggregator.ReviewResult{}
	report := buildSARIF(result, "test")

	if report.Schema != "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json" {
		t.Errorf("unexpected schema: %s", report.Schema)
	}
	if report.Version != "2.1.0" {
		t.Errorf("unexpected version: %s", report.Version)
	}
	if len(report.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(report.Runs))
	}
	driver := report.Runs[0].Tool.Driver
	if driver.Name != "terraview" {
		t.Errorf("tool name = %q, want terraview", driver.Name)
	}
	if driver.InformationURI != "https://github.com/leonamvasquez/terraview" {
		t.Errorf("unexpected informationUri: %s", driver.InformationURI)
	}
	if driver.Version != "test" {
		t.Errorf("tool version = %q, want \"test\"", driver.Version)
	}
}

func TestBuildSARIF_EmptyVersionFallback(t *testing.T) {
	report := buildSARIF(aggregator.ReviewResult{}, "")
	driver := report.Runs[0].Tool.Driver
	if driver.Version != "dev" {
		t.Errorf("empty version should fallback to \"dev\", got %q", driver.Version)
	}
}

func TestBuildSARIF_RuleDeduplication(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.a", Message: "msg1", Source: "checkov"},
			{RuleID: "SEC001", Severity: "HIGH", Category: "security", Resource: "aws_instance.b", Message: "msg2", Source: "checkov"},
			{RuleID: "SEC002", Severity: "MEDIUM", Category: "security", Resource: "aws_instance.c", Message: "msg3", Source: "checkov"},
		},
	}
	report := buildSARIF(result, "test")
	run := report.Runs[0]

	// Two unique rules despite three findings
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("expected 3 results, got %d", len(run.Results))
	}

	// First two results share ruleIndex 0
	if run.Results[0].RuleIndex != 0 {
		t.Errorf("result[0] ruleIndex = %d, want 0", run.Results[0].RuleIndex)
	}
	if run.Results[1].RuleIndex != 0 {
		t.Errorf("result[1] ruleIndex = %d, want 0", run.Results[1].RuleIndex)
	}
	if run.Results[2].RuleIndex != 1 {
		t.Errorf("result[2] ruleIndex = %d, want 1", run.Results[2].RuleIndex)
	}
}

func TestBuildSARIF_WithRemediation(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{
				RuleID:      "SEC001",
				Severity:    "HIGH",
				Resource:    "aws_instance.web",
				Message:     "Public SSH",
				Remediation: "Restrict ingress to trusted CIDRs",
				Source:      "checkov",
			},
		},
	}
	report := buildSARIF(result, "test")
	rule := report.Runs[0].Tool.Driver.Rules[0]

	if rule.Help == nil {
		t.Fatalf("expected rule.Help to be set, got nil")
	}
	if rule.Help.Text != "Restrict ingress to trusted CIDRs" {
		t.Errorf("rule.Help.Text = %q, want %q", rule.Help.Text, "Restrict ingress to trusted CIDRs")
	}
}

func TestBuildSARIF_WithoutRemediation(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "HIGH", Resource: "aws_instance.web", Message: "msg", Source: "s"},
		},
	}
	report := buildSARIF(result, "test")
	rule := report.Runs[0].Tool.Driver.Rules[0]

	if rule.Help != nil {
		t.Errorf("expected rule.Help to be nil, got %q", rule.Help.Text)
	}
}

func TestBuildSARIF_EmptyResource(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "HIGH", Resource: "", Message: "global issue", Source: "lint"},
		},
	}
	report := buildSARIF(result, "test")
	res := report.Runs[0].Results[0]

	if len(res.Locations) != 0 {
		t.Errorf("expected 0 locations for empty resource, got %d", len(res.Locations))
	}
}

func TestBuildSARIF_LocationURI(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: "LOW", Resource: "module.vpc.aws_vpc.main", Message: "m", Source: "s"},
		},
	}
	report := buildSARIF(result, "test")
	res := report.Runs[0].Results[0]

	if len(res.Locations) != 1 {
		t.Fatalf("expected 1 location, got %d", len(res.Locations))
	}
	uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "module.vpc.aws_vpc.main" {
		t.Errorf("location URI = %q, want module.vpc.aws_vpc.main", uri)
	}
}

func TestBuildSARIF_ResultMessageFormat(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: "LOW", Resource: "aws_s3_bucket.b", Message: "no encryption", Source: "tfsec"},
		},
	}
	report := buildSARIF(result, "test")
	msg := report.Runs[0].Results[0].Message.Text

	want := "[tfsec] aws_s3_bucket.b: no encryption"
	if msg != want {
		t.Errorf("message = %q, want %q", msg, want)
	}
}

func TestBuildSARIF_RuleCategoryProperty(t *testing.T) {
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "R1", Severity: "LOW", Category: "cost", Resource: "r", Message: "m", Source: "s"},
		},
	}
	report := buildSARIF(result, "test")
	rule := report.Runs[0].Tool.Driver.Rules[0]

	if rule.Properties.Category != "cost" {
		t.Errorf("rule category = %q, want cost", rule.Properties.Category)
	}
	if rule.DefaultConfig.Level != "note" {
		t.Errorf("rule level = %q, want note", rule.DefaultConfig.Level)
	}
}

func TestWriteSARIF_InvalidPath(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{}
	err := w.WriteSARIF(result, "/nonexistent/dir/review.sarif.json")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}
