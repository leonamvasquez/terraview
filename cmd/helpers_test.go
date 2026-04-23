package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// fix.go — filterFixTargets
// ---------------------------------------------------------------------------

func TestFilterFixTargets_CriticalHighOnly(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "aws_s3_bucket.a"},
		{RuleID: "R2", Severity: "HIGH", Resource: "aws_s3_bucket.b"},
		{RuleID: "R3", Severity: "MEDIUM", Resource: "aws_s3_bucket.c"},
		{RuleID: "R4", Severity: "LOW", Resource: "aws_s3_bucket.d"},
	}
	got := filterFixTargets(findings, fixFilter{})
	if len(got) != 2 {
		t.Errorf("expected 2 findings (CRITICAL+HIGH), got %d", len(got))
	}
}

func TestFilterFixTargets_SeverityFilter(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "res.a"},
		{RuleID: "R2", Severity: "HIGH", Resource: "res.b"},
	}
	got := filterFixTargets(findings, fixFilter{severity: "HIGH"})
	if len(got) != 1 || got[0].RuleID != "R2" {
		t.Errorf("expected only HIGH finding, got %v", got)
	}
}

func TestFilterFixTargets_FindingIDFilter(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_1", Severity: "CRITICAL", Resource: "res.a"},
		{RuleID: "CKV_AWS_2", Severity: "HIGH", Resource: "res.b"},
	}
	got := filterFixTargets(findings, fixFilter{findingID: "ckv_aws_1"})
	if len(got) != 1 || got[0].RuleID != "CKV_AWS_1" {
		t.Errorf("expected only CKV_AWS_1, got %v", got)
	}
}

func TestFilterFixTargets_MaxLimit(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "res.a"},
		{RuleID: "R2", Severity: "CRITICAL", Resource: "res.b"},
		{RuleID: "R3", Severity: "HIGH", Resource: "res.c"},
	}
	got := filterFixTargets(findings, fixFilter{max: 2})
	if len(got) != 2 {
		t.Errorf("expected 2 findings (max=2), got %d", len(got))
	}
}

func TestFilterFixTargets_Deduplication(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "R1", Severity: "CRITICAL", Resource: "res.a"},
		{RuleID: "R1", Severity: "CRITICAL", Resource: "res.a"}, // duplicate
	}
	got := filterFixTargets(findings, fixFilter{})
	if len(got) != 1 {
		t.Errorf("expected 1 after dedup, got %d", len(got))
	}
}

func TestFilterFixTargets_EmptyInput(t *testing.T) {
	got := filterFixTargets(nil, fixFilter{})
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
}

// ---------------------------------------------------------------------------
// fix.go — locationMatchesFile
// ---------------------------------------------------------------------------

func TestLocationMatchesFile_NilLocation(t *testing.T) {
	if locationMatchesFile(nil, "main.tf", "/base") {
		t.Error("nil location should return false")
	}
}

func TestLocationMatchesFile_BasenameMatch(t *testing.T) {
	loc := &fix.Location{File: "/project/modules/vpc/main.tf"}
	if !locationMatchesFile(loc, "main.tf", "/project") {
		t.Error("basename match should return true")
	}
}

func TestLocationMatchesFile_SubstringMatch(t *testing.T) {
	loc := &fix.Location{File: "/project/modules/vpc/main.tf"}
	if !locationMatchesFile(loc, "modules/vpc/main.tf", "/project") {
		t.Error("substring match should return true")
	}
}

func TestLocationMatchesFile_NoMatch(t *testing.T) {
	loc := &fix.Location{File: "/project/main.tf"}
	if locationMatchesFile(loc, "variables.tf", "/project") {
		t.Error("non-matching file should return false")
	}
}

func TestLocationMatchesFile_RelPathError(t *testing.T) {
	// When filepath.Rel fails (different volume on Windows), falls back to raw path
	loc := &fix.Location{File: "main.tf"}
	// With an absolute base that doesn't match, Rel returns relative path or error
	result := locationMatchesFile(loc, "main.tf", "/some/base")
	// Should match by basename at minimum
	if !result {
		t.Error("should match by basename even when rel fails")
	}
}

// ---------------------------------------------------------------------------
// fix.go — extractType
// ---------------------------------------------------------------------------

func TestExtractType_WithDot(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"aws_instance.web", "aws_instance"},
		{"aws_s3_bucket.my_bucket", "aws_s3_bucket"},
		{"module.vpc.aws_vpc.main", "module"},
	}
	for _, tc := range cases {
		got := extractType(tc.addr)
		if got != tc.want {
			t.Errorf("extractType(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestExtractType_NoDot(t *testing.T) {
	got := extractType("notype")
	if got != "notype" {
		t.Errorf("extractType without dot should return full string, got %q", got)
	}
}

func TestExtractType_Empty(t *testing.T) {
	got := extractType("")
	if got != "" {
		t.Errorf("extractType empty should return empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// fix.go — resolveAPIKey
// ---------------------------------------------------------------------------

func TestResolveAPIKey_Claude(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-anthropic-key")
	got := resolveAPIKey("claude")
	if got != "test-anthropic-key" {
		t.Errorf("expected ANTHROPIC_API_KEY, got %q", got)
	}
}

func TestResolveAPIKey_ClaudeCode(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "claude-code-key")
	got := resolveAPIKey("claude-code")
	if got != "claude-code-key" {
		t.Errorf("expected ANTHROPIC_API_KEY for claude-code, got %q", got)
	}
}

func TestResolveAPIKey_Gemini(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "test-gemini-key")
	got := resolveAPIKey("gemini")
	if got != "test-gemini-key" {
		t.Errorf("expected GEMINI_API_KEY, got %q", got)
	}
}

func TestResolveAPIKey_OpenAI(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-openai-key")
	got := resolveAPIKey("openai")
	if got != "test-openai-key" {
		t.Errorf("expected OPENAI_API_KEY, got %q", got)
	}
}

func TestResolveAPIKey_DeepSeek(t *testing.T) {
	t.Setenv("DEEPSEEK_API_KEY", "test-deepseek-key")
	got := resolveAPIKey("deepseek")
	if got != "test-deepseek-key" {
		t.Errorf("expected DEEPSEEK_API_KEY, got %q", got)
	}
}

func TestResolveAPIKey_OpenRouter(t *testing.T) {
	t.Setenv("OPENROUTER_API_KEY", "test-openrouter-key")
	got := resolveAPIKey("openrouter")
	if got != "test-openrouter-key" {
		t.Errorf("expected OPENROUTER_API_KEY, got %q", got)
	}
}

func TestResolveAPIKey_Unknown(t *testing.T) {
	got := resolveAPIKey("ollama")
	if got != "" {
		t.Errorf("unknown provider should return empty, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// fix.go — isTimeoutErr
// ---------------------------------------------------------------------------

func TestIsTimeoutErr_TimeoutWord(t *testing.T) {
	err := errors.New("context timeout exceeded")
	if !isTimeoutErr(err) {
		t.Error("should detect 'timeout' in error message")
	}
}

func TestIsTimeoutErr_DeadlineWord(t *testing.T) {
	err := errors.New("context deadline exceeded")
	if !isTimeoutErr(err) {
		t.Error("should detect 'deadline' in error message")
	}
}

func TestIsTimeoutErr_UpperCase(t *testing.T) {
	err := errors.New("TIMEOUT: request took too long")
	if !isTimeoutErr(err) {
		t.Error("should detect uppercase 'TIMEOUT'")
	}
}

func TestIsTimeoutErr_UnrelatedError(t *testing.T) {
	err := errors.New("connection refused")
	if isTimeoutErr(err) {
		t.Error("unrelated error should not be a timeout error")
	}
}

// ---------------------------------------------------------------------------
// diagram.go — diagramFileExt
// ---------------------------------------------------------------------------

func TestDiagramFileExt_JSON(t *testing.T) {
	if got := diagramFileExt("json"); got != ".json" {
		t.Errorf("json → %q, want .json", got)
	}
}

func TestDiagramFileExt_Mermaid(t *testing.T) {
	if got := diagramFileExt("mermaid"); got != ".mmd" {
		t.Errorf("mermaid → %q, want .mmd", got)
	}
}

func TestDiagramFileExt_Default(t *testing.T) {
	if got := diagramFileExt("txt"); got != ".txt" {
		t.Errorf("txt → %q, want .txt", got)
	}
}

func TestDiagramFileExt_Empty(t *testing.T) {
	if got := diagramFileExt(""); got != ".txt" {
		t.Errorf("empty → %q, want .txt", got)
	}
}

// ---------------------------------------------------------------------------
// status.go — humanAge
// ---------------------------------------------------------------------------

func TestHumanAge_JustNow(t *testing.T) {
	got := humanAge(30 * time.Second)
	if got != "just now" {
		t.Errorf("< 1min should be 'just now', got %q", got)
	}
}

func TestHumanAge_Minutes(t *testing.T) {
	got := humanAge(5 * time.Minute)
	if got != "5m ago" {
		t.Errorf("5min should be '5m ago', got %q", got)
	}
}

func TestHumanAge_Hours(t *testing.T) {
	got := humanAge(3 * time.Hour)
	if got != "3h ago" {
		t.Errorf("3h should be '3h ago', got %q", got)
	}
}

func TestHumanAge_Days(t *testing.T) {
	got := humanAge(48 * time.Hour)
	if got != "2d ago" {
		t.Errorf("48h should be '2d ago', got %q", got)
	}
}

func TestHumanAge_ExactlyOneMinute(t *testing.T) {
	// exactly 1 minute falls in the < hour bucket
	got := humanAge(time.Minute)
	if got != "1m ago" {
		t.Errorf("1min should be '1m ago', got %q", got)
	}
}

// ---------------------------------------------------------------------------
// scan.go — toPipeline (brFlag branch)
// ---------------------------------------------------------------------------

func TestToPipeline_BRFlag(t *testing.T) {
	rc := reviewConfig{
		scannerName:     "checkov",
		resolvedPlan:    "/tmp/plan.json",
		effectiveAI:     false,
		effectiveFormat: "pretty",
	}

	// Test with brFlag = false
	brFlag = false
	p := rc.toPipeline()
	if p.Lang != "" {
		t.Errorf("expected empty lang when brFlag=false, got %q", p.Lang)
	}

	// Test with brFlag = true
	brFlag = true
	defer func() { brFlag = false }()
	p = rc.toPipeline()
	if p.Lang != "pt-BR" {
		t.Errorf("expected 'pt-BR' when brFlag=true, got %q", p.Lang)
	}
}

func TestToPipeline_FieldMapping(t *testing.T) {
	rc := reviewConfig{
		scannerName:     "tfsec",
		resolvedPlan:    "/tmp/plan.json",
		effectiveAI:     true,
		effectiveFormat: "json",
		aiProvider:      "claude",
		aiModel:         "claude-3-5-sonnet",
		aiTimeout:       60,
		aiMaxResources:  20,
	}
	brFlag = false
	p := rc.toPipeline()
	if p.ScannerName != "tfsec" {
		t.Errorf("ScannerName = %q, want tfsec", p.ScannerName)
	}
	if p.EffectiveAI != true {
		t.Error("EffectiveAI should be true")
	}
	if p.AIProvider != "claude" {
		t.Errorf("AIProvider = %q, want claude", p.AIProvider)
	}
	if p.AIMaxResources != 20 {
		t.Errorf("AIMaxResources = %d, want 20", p.AIMaxResources)
	}
}

// ---------------------------------------------------------------------------
// diagram.go — diagramFileExt used to name output file (integration smoke)
// ---------------------------------------------------------------------------

func TestDiagramFileExt_UsedForFilename(t *testing.T) {
	dir := t.TempDir()
	ext := diagramFileExt("json")
	name := filepath.Join(dir, fmt.Sprintf("diagram%s", ext))
	if err := os.WriteFile(name, []byte("{}"), 0644); err != nil {
		t.Fatalf("could not write file: %v", err)
	}
	if _, err := os.Stat(name); err != nil {
		t.Errorf("file %s should exist: %v", name, err)
	}
}
