package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/topology"
)

func captureStdout(fn func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		io.Copy(&buf, r)
		close(done)
	}()

	fn()

	w.Close()
	os.Stdout = old
	<-done
	return buf.String()
}

func TestLastN(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"abcdef", 3, "def"},
		{"ab", 5, "ab"},
		{"hello", 5, "hello"},
		{"", 3, ""},
		{"x", 1, "x"},
	}
	for _, c := range cases {
		if got := lastN(c.s, c.n); got != c.want {
			t.Errorf("lastN(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func TestExitError_Error(t *testing.T) {
	e := &ExitError{Code: 2}
	got := e.Error()
	if got != "exit code 2" {
		t.Errorf("Error() = %q, want %q", got, "exit code 2")
	}
}

func TestExitError_Code0(t *testing.T) {
	e := &ExitError{Code: 0}
	if !strings.Contains(e.Error(), "0") {
		t.Errorf("Error() = %q, expected to contain 0", e.Error())
	}
}

func TestFilterDisabledRules_Empty(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001"},
		{RuleID: "SEC002"},
	}
	got := filterDisabledRules(findings, nil)
	if len(got) != 2 {
		t.Errorf("expected 2, got %d", len(got))
	}
}

func TestFilterDisabledRules_ExactMatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001"},
		{RuleID: "SEC002"},
		{RuleID: "TAG001"},
	}
	got := filterDisabledRules(findings, []string{"SEC001", "TAG001"})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].RuleID != "SEC002" {
		t.Errorf("expected SEC002, got %s", got[0].RuleID)
	}
}

func TestFilterDisabledRules_PrefixMatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_001"},
		{RuleID: "CKV_AWS_002"},
		{RuleID: "CKV_GCP_001"},
		{RuleID: "TFSEC_001"},
	}
	// "CKV" as a prefix (no underscore) should disable all CKV_ rules
	got := filterDisabledRules(findings, []string{"CKV"})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got[0].RuleID != "TFSEC_001" {
		t.Errorf("expected TFSEC_001, got %s", got[0].RuleID)
	}
}

func TestFilterDisabledRules_CaseInsensitive(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "sec001"},
		{RuleID: "SEC002"},
	}
	got := filterDisabledRules(findings, []string{"SEC001"})
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestFilterDisabledRules_NoFindings(t *testing.T) {
	got := filterDisabledRules(nil, []string{"SEC001"})
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestBuildResourceLimits_SafeMode(t *testing.T) {
	cfg := config.Config{}
	limits := buildResourceLimits(cfg, true)
	// Safe mode should use SafeResourceLimits, which has MinFreeMemoryMB=1500
	if limits.MinFreeMemoryMB != 1500 {
		t.Errorf("MinFreeMemoryMB = %d, want 1500", limits.MinFreeMemoryMB)
	}
}

func TestBuildResourceLimits_DefaultMode(t *testing.T) {
	cfg := config.Config{}
	limits := buildResourceLimits(cfg, false)
	// Default mode should use DefaultResourceLimits, which has MinFreeMemoryMB=1024
	if limits.MinFreeMemoryMB != 1024 {
		t.Errorf("MinFreeMemoryMB = %d, want 1024", limits.MinFreeMemoryMB)
	}
}

func TestBuildResourceLimits_WithOllamaConfig(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Ollama.MaxThreads = 8
	cfg.LLM.Ollama.MaxMemoryMB = 4096
	cfg.LLM.Ollama.MinFreeMemoryMB = 2048

	limits := buildResourceLimits(cfg, false)
	if limits.MaxThreads != 8 {
		t.Errorf("MaxThreads = %d, want 8", limits.MaxThreads)
	}
	if limits.MaxMemoryMB != 4096 {
		t.Errorf("MaxMemoryMB = %d, want 4096", limits.MaxMemoryMB)
	}
	if limits.MinFreeMemoryMB != 2048 {
		t.Errorf("MinFreeMemoryMB = %d, want 2048", limits.MinFreeMemoryMB)
	}
}

func TestInfraToStringSlice_Normal(t *testing.T) {
	input := []interface{}{"a", "b", "c"}
	got := infraToStringSlice(input)
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Errorf("got %v", got)
	}
}

func TestInfraToStringSlice_MixedTypes(t *testing.T) {
	input := []interface{}{"a", 123, "b", true}
	got := infraToStringSlice(input)
	// Only strings should be kept
	if len(got) != 2 {
		t.Fatalf("expected 2, got %d", len(got))
	}
}

func TestInfraToStringSlice_Nil(t *testing.T) {
	got := infraToStringSlice(nil)
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestInfraToStringSlice_NotSlice(t *testing.T) {
	got := infraToStringSlice("not a slice")
	if got != nil {
		t.Errorf("expected nil, got %v", got)
	}
}

func TestInfraExplFromMap_FullMap(t *testing.T) {
	m := map[string]interface{}{
		"overview":     "An ECS platform",
		"architecture": "microservices",
		"components": []interface{}{
			map[string]interface{}{"resource": "aws_ecs_cluster.main", "purpose": "container orchestration", "role": "compute"},
		},
		"connections": []interface{}{"ECS → ALB", "ALB → VPC"},
		"patterns":    []interface{}{"HA", "auto-scaling"},
		"concerns":    []interface{}{"no DR"},
	}
	expl := infraExplFromMap(m)
	if expl.Overview != "An ECS platform" {
		t.Errorf("Overview = %q", expl.Overview)
	}
	if expl.Architecture != "microservices" {
		t.Errorf("Architecture = %q", expl.Architecture)
	}
	if len(expl.Components) != 1 {
		t.Fatalf("expected 1 component, got %d", len(expl.Components))
	}
	if expl.Components[0].Resource != "aws_ecs_cluster.main" {
		t.Errorf("component resource = %q", expl.Components[0].Resource)
	}
	if len(expl.Connections) != 2 {
		t.Errorf("expected 2 connections, got %d", len(expl.Connections))
	}
	if len(expl.Patterns) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(expl.Patterns))
	}
	if len(expl.Concerns) != 1 {
		t.Errorf("expected 1 concern, got %d", len(expl.Concerns))
	}
}

func TestInfraExplFromMap_OverviewAsMap(t *testing.T) {
	m := map[string]interface{}{
		"overview": map[string]interface{}{
			"overview": "nested overview",
		},
	}
	expl := infraExplFromMap(m)
	if expl.Overview != "nested overview" {
		t.Errorf("Overview = %q, want 'nested overview'", expl.Overview)
	}
}

func TestInfraExplFromMap_OverviewAsSummaryFallback(t *testing.T) {
	m := map[string]interface{}{
		"overview": map[string]interface{}{
			"summary": "via summary key",
		},
	}
	expl := infraExplFromMap(m)
	if expl.Overview != "via summary key" {
		t.Errorf("Overview = %q", expl.Overview)
	}
}

func TestInfraExplFromMap_EmptyMap(t *testing.T) {
	expl := infraExplFromMap(map[string]interface{}{})
	if expl.Overview != "Unable to parse structured response" {
		t.Errorf("Overview = %q, want fallback", expl.Overview)
	}
}

func TestParseInfraExplanation_DirectJSON(t *testing.T) {
	raw := `{"overview":"test overview","architecture":"monolith","components":[],"connections":[],"patterns":[]}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "test overview" {
		t.Errorf("Overview = %q", expl.Overview)
	}
	if expl.Architecture != "monolith" {
		t.Errorf("Architecture = %q", expl.Architecture)
	}
}

func TestParseInfraExplanation_CodeFence(t *testing.T) {
	raw := "Here's the analysis:\n```json\n{\"overview\":\"fenced\",\"architecture\":\"serverless\"}\n```\nEnd."
	expl := parseInfraExplanation(raw)
	if expl.Overview != "fenced" {
		t.Errorf("Overview = %q, want 'fenced'", expl.Overview)
	}
}

func TestParseInfraExplanation_FallbackPlainText(t *testing.T) {
	raw := "This is just plain text, not JSON at all."
	expl := parseInfraExplanation(raw)
	if expl.Overview != raw {
		t.Errorf("Overview should be raw text, got %q", expl.Overview)
	}
	if expl.Architecture != "Unable to parse structured response" {
		t.Errorf("Architecture = %q", expl.Architecture)
	}
}

func TestBuildInfraExplainPrompt(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Action: "create"},
	}
	graph := &topology.Graph{}

	got := buildInfraExplainPrompt(resources, graph)

	for _, want := range []string{
		"senior cloud architect",
		"aws_instance.web",
		"TOPOLOGY:",
		"RESOURCES:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in prompt", want)
		}
	}
}

func TestStrContainsFold(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"Hello World", "xyz", false},
		{"", "a", false},
		{"abc", "", true},
		{"ABC", "abc", true},
		{"fooBar", "oob", true},
	}
	for _, tt := range tests {
		if got := strContainsFold(tt.s, tt.sub); got != tt.want {
			t.Errorf("strContainsFold(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestPluralS(t *testing.T) {
	tests := []struct {
		n    int
		want string
	}{
		{0, "s"},
		{1, ""},
		{2, "s"},
		{10, "s"},
	}
	for _, tt := range tests {
		if got := pluralS(tt.n); got != tt.want {
			t.Errorf("pluralS(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

func TestCommandAvailable_True(t *testing.T) {
	old := execLookPath
	defer func() { execLookPath = old }()
	execLookPath = func(name string) (string, error) {
		return "/usr/bin/" + name, nil
	}
	if !commandAvailable("terraform") {
		t.Error("expected commandAvailable to return true")
	}
}

func TestCommandAvailable_False(t *testing.T) {
	old := execLookPath
	defer func() { execLookPath = old }()
	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}
	if commandAvailable("nonexistent") {
		t.Error("expected commandAvailable to return false")
	}
}

// stubScanner implements scanner.Scanner for testing.
type stubScanner struct{ name string }

func (s stubScanner) Name() string                                        { return s.name }
func (s stubScanner) Available() bool                                     { return false }
func (s stubScanner) Version() string                                     { return "" }
func (s stubScanner) SupportedModes() []scanner.ScanMode                  { return nil }
func (s stubScanner) Scan(_ scanner.ScanContext) ([]rules.Finding, error) { return nil, nil }
func (s stubScanner) EnsureInstalled() (bool, scanner.InstallHint) {
	return false, scanner.InstallHint{}
}
func (s stubScanner) Priority() int { return 0 }

func TestSortedScannerNames_Empty(t *testing.T) {
	got := sortedScannerNames(map[string]scanner.Scanner{})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestSortedScannerNames_Sorted(t *testing.T) {
	m := map[string]scanner.Scanner{
		"tfsec":   stubScanner{"tfsec"},
		"checkov": stubScanner{"checkov"},
		"trivy":   stubScanner{"trivy"},
		"atlas":   stubScanner{"atlas"},
	}
	got := sortedScannerNames(m)
	expected := []string{"atlas", "checkov", "tfsec", "trivy"}
	if len(got) != len(expected) {
		t.Fatalf("expected %d names, got %d", len(expected), len(got))
	}
	for i, want := range expected {
		if got[i] != want {
			t.Errorf("[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestSortedScannerNames_Single(t *testing.T) {
	m := map[string]scanner.Scanner{
		"checkov": stubScanner{"checkov"},
	}
	got := sortedScannerNames(m)
	if len(got) != 1 || got[0] != "checkov" {
		t.Errorf("expected [checkov], got %v", got)
	}
}

func TestParseInfraExplanation_OverviewAsMap(t *testing.T) {
	raw := `{"overview":{"summary":"nested summary"},"architecture":"monolith"}`
	expl := parseInfraExplanation(raw)
	if !strings.Contains(expl.Overview, "nested summary") {
		t.Errorf("overview = %q, should contain 'nested summary'", expl.Overview)
	}
}

func TestInfraExplFromMap_Full(t *testing.T) {
	m := map[string]interface{}{
		"overview":     "my overview",
		"architecture": "serverless",
		"components": []interface{}{
			map[string]interface{}{
				"resource": "lambda",
				"purpose":  "handler",
				"role":     "compute",
			},
		},
		"connections": []interface{}{"lambda->dynamo"},
		"patterns":    []interface{}{"event-driven"},
		"concerns":    []interface{}{"cold starts"},
	}
	expl := infraExplFromMap(m)
	if expl.Overview != "my overview" {
		t.Errorf("overview = %q", expl.Overview)
	}
	if expl.Architecture != "serverless" {
		t.Errorf("architecture = %q", expl.Architecture)
	}
	if len(expl.Components) != 1 || expl.Components[0].Resource != "lambda" {
		t.Errorf("components = %v", expl.Components)
	}
	if len(expl.Connections) != 1 || expl.Connections[0] != "lambda->dynamo" {
		t.Errorf("connections = %v", expl.Connections)
	}
}

func TestInfraExplFromMap_EmptyOverview(t *testing.T) {
	m := map[string]interface{}{}
	expl := infraExplFromMap(m)
	if expl.Overview != "Unable to parse structured response" {
		t.Errorf("expected fallback overview, got %q", expl.Overview)
	}
}

func TestInfraToStringSlice(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want int
	}{
		{"nil", nil, 0},
		{"string", "not an array", 0},
		{"empty array", []interface{}{}, 0},
		{"string array", []interface{}{"a", "b"}, 2},
		{"mixed types", []interface{}{"a", 42, "b"}, 2}, // only strings kept
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := infraToStringSlice(tc.in)
			if len(got) != tc.want {
				t.Errorf("len = %d, want %d", len(got), tc.want)
			}
		})
	}
}

func TestPrintInfraExplanation_EN(t *testing.T) {
	old := brFlag
	brFlag = false
	defer func() { brFlag = old }()

	expl := &InfraExplanation{
		Overview:     "Test overview",
		Architecture: "microservices",
		Components: []ComponentExpl{
			{Resource: "ecs", Purpose: "run tasks", Role: "compute"},
		},
		Connections: []string{"ecs -> rds"},
		Patterns:    []string{"HA"},
		Concerns:    []string{"no DR"},
	}
	out := captureStdout(func() { printInfraExplanation(expl) })
	checks := []string{
		"Explain My Infrastructure",
		"OVERVIEW:",
		"Test overview",
		"ARCHITECTURE:",
		"microservices",
		"COMPONENTS:",
		"- ecs",
		"Purpose: run tasks",
		"Role: compute",
		"CONNECTIONS:",
		"ecs -> rds",
		"PATTERNS:",
		"- HA",
		"CONCERNS:",
		"- no DR",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("missing %q in output", c)
		}
	}
}

func TestPrintInfraExplanation_BR(t *testing.T) {
	old := brFlag
	brFlag = true
	defer func() { brFlag = old }()

	expl := &InfraExplanation{
		Overview: "Visão geral da infra",
	}
	out := captureStdout(func() { printInfraExplanation(expl) })
	if !strings.Contains(out, "Explicação da Infraestrutura") {
		t.Errorf("missing BR title in output")
	}
	if !strings.Contains(out, "VISÃO GERAL:") {
		t.Errorf("missing BR label in output")
	}
}

func TestFilterDisabledRules_NoDisabled(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "TV001", Severity: "HIGH"},
		{RuleID: "TV002", Severity: "LOW"},
	}
	got := filterDisabledRules(findings, nil)
	if len(got) != 2 {
		t.Errorf("expected 2 findings, got %d", len(got))
	}
}

func TestFilterItems_EmptyQuery(t *testing.T) {
	items := []selectItem{{Label: "a"}, {Label: "b"}}
	got := filterItems(items, "")
	if len(got) != 2 {
		t.Errorf("expected all items with empty query, got %d", len(got))
	}
}

func TestFilterItems_MatchesCaseInsensitive(t *testing.T) {
	items := []selectItem{
		{Label: "OpenRouter"},
		{Label: "Ollama"},
		{Label: "Gemini"},
	}
	got := filterItems(items, "ol")
	if len(got) != 1 || got[0].Label != "Ollama" {
		t.Errorf("expected [Ollama], got %v", got)
	}
}

func TestFilterItems_NoMatch(t *testing.T) {
	items := []selectItem{{Label: "alpha"}, {Label: "beta"}}
	got := filterItems(items, "xyz")
	if len(got) != 0 {
		t.Errorf("expected 0, got %d", len(got))
	}
}

func TestExitError(t *testing.T) {
	e := &ExitError{Code: 2}
	if e.Error() != "exit code 2" {
		t.Errorf("Error() = %q", e.Error())
	}
}

// (buildInfraExplainPrompt already tested above)

func TestLogVerbose_Enabled(t *testing.T) {
	old := verbose
	defer func() { verbose = old }()
	verbose = true

	// logVerbose writes to os.Stderr, so capture it
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	logVerbose("test %s %d", "hello", 42)

	w.Close()
	os.Stderr = oldStderr
	out := <-done

	if !strings.Contains(out, "hello") || !strings.Contains(out, "42") {
		t.Errorf("expected formatted output, got %q", out)
	}
}

func TestLogVerbose_Disabled(t *testing.T) {
	old := verbose
	defer func() { verbose = old }()
	verbose = false

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	logVerbose("should not appear")

	w.Close()
	os.Stderr = oldStderr
	out := <-done

	if len(out) > 0 {
		t.Errorf("expected no output when verbose=false, got %q", out)
	}
}

func TestApplyBRTranslations(t *testing.T) {
	// Should not panic
	applyBRTranslations()

	// Verify root command help was translated
	usage := rootCmd.UsageTemplate()
	if usage == "" {
		t.Error("expected non-empty usage template after BR translation")
	}
}

func TestTranslateFlags(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("verbose", false, "original usage")

	translateFlags(cmd, map[string]string{
		"verbose":     "traduzido",
		"nonexistent": "should not panic",
	})

	f := cmd.Flags().Lookup("verbose")
	if f.Usage != "traduzido" {
		t.Errorf("expected translated usage, got %q", f.Usage)
	}
}

func TestRawPrint(t *testing.T) {
	out := captureStdout(func() {
		rawPrint("hello world")
	})
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world', got %q", out)
	}
}

func TestDefaultLookPath_Echo(t *testing.T) {
	path, err := defaultLookPath("echo")
	if err != nil {
		t.Skipf("echo not in PATH: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
}

func TestDefaultLookPath_Nonexistent(t *testing.T) {
	_, err := defaultLookPath("nonexistent-cmd-xyz-12345")
	if err == nil {
		t.Error("expected error for nonexistent command")
	}
}

func TestVersionVariable(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "test-v1.0.0"
	if Version != "test-v1.0.0" {
		t.Errorf("expected test version, got %q", Version)
	}
}

// ---------------------------------------------------------------------------
// formatBytes
// ---------------------------------------------------------------------------

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{1024*1024 + 512*1024, "1.5 MB"},
		{10 * 1024 * 1024, "10.0 MB"},
	}
	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			got := formatBytes(tc.input)
			if got != tc.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// detectCurrentPlanHash
// ---------------------------------------------------------------------------

func TestDetectCurrentPlanHash_WithPlanJSON(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	content := []byte(`{"format_version":"1.0","resource_changes":[]}`)
	os.WriteFile(filepath.Join(dir, "plan.json"), content, 0644)

	hash := detectCurrentPlanHash()
	if hash == "" {
		t.Error("expected non-empty hash for existing plan.json")
	}
	if len(hash) != 64 { // SHA-256 hex
		t.Errorf("expected 64-char hex hash, got len %d", len(hash))
	}
}

func TestDetectCurrentPlanHash_WithTfplan(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	content := []byte("binary plan data here")
	os.WriteFile(filepath.Join(dir, "tfplan"), content, 0644)

	hash := detectCurrentPlanHash()
	if hash == "" {
		t.Error("expected non-empty hash for existing tfplan")
	}
}

func TestDetectCurrentPlanHash_NoPlanFile(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	hash := detectCurrentPlanHash()
	if hash != "" {
		t.Errorf("expected empty hash when no plan file exists, got %q", hash)
	}
}

func TestDetectCurrentPlanHash_EmptyPlanJSON(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	os.WriteFile(filepath.Join(dir, "plan.json"), []byte{}, 0644)

	hash := detectCurrentPlanHash()
	if hash != "" {
		t.Errorf("expected empty hash for empty plan.json, got %q", hash)
	}
}

func TestDetectCurrentPlanHash_PlanJSONPreferredOverTfplan(t *testing.T) {
	dir := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	os.Chdir(dir)

	os.WriteFile(filepath.Join(dir, "plan.json"), []byte("json content"), 0644)
	os.WriteFile(filepath.Join(dir, "tfplan"), []byte("binary content"), 0644)

	hash := detectCurrentPlanHash()
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	// Verify it's the plan.json hash (not tfplan)
	os.Remove(filepath.Join(dir, "tfplan"))
	hashOnlyJSON := detectCurrentPlanHash()
	if hash != hashOnlyJSON {
		t.Error("plan.json should be preferred over tfplan")
	}
}
