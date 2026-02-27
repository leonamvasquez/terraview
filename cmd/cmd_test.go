package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/drift"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/spf13/cobra"
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

// discardStdout executes fn while discarding all stdout output.
func discardStdout(fn func()) {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, r)
		close(done)
	}()

	fn()

	w.Close()
	os.Stdout = old
	<-done
}

// ---------------------------------------------------------------------------
// lastN (ai.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ExitError (root.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// filterDisabledRules (scan.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// buildResourceLimits (scan.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// infraToStringSlice (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// infraExplFromMap (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// parseInfraExplanation (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// buildInfraExplainPrompt (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// strContainsFold (selector.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// pluralS (setup.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// commandAvailable (setup.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// sortedScannerNames (scanners.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// printDriftSummary (drift.go)
// ---------------------------------------------------------------------------

func TestPrintDriftSummary_Compact_NoChanges(t *testing.T) {
	result := drift.DriftResult{TotalChanges: 0}
	out := captureStdout(func() { printDriftSummary(result, "compact") })
	if !strings.Contains(out, "no changes detected") {
		t.Errorf("expected 'no changes detected', got %q", out)
	}
}

func TestPrintDriftSummary_Compact_WithChanges(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 3,
		MaxSeverity:  "HIGH",
		ExitCode:     2,
		Findings: []rules.Finding{
			{Severity: "HIGH", Message: "sg drift"},
		},
	}
	out := captureStdout(func() { printDriftSummary(result, "compact") })
	if !strings.Contains(out, "3 changes") {
		t.Errorf("expected '3 changes', got %q", out)
	}
	if !strings.Contains(out, "findings=1") {
		t.Errorf("expected 'findings=1', got %q", out)
	}
	if !strings.Contains(out, "max=HIGH") {
		t.Errorf("expected 'max=HIGH', got %q", out)
	}
}

func TestPrintDriftSummary_Full_NoChanges(t *testing.T) {
	result := drift.DriftResult{TotalChanges: 0}
	out := captureStdout(func() { printDriftSummary(result, "full") })
	if !strings.Contains(out, "No infrastructure drift detected") {
		t.Errorf("expected 'No infrastructure drift detected', got %q", out)
	}
	if !strings.Contains(out, "Drift Analysis") {
		t.Errorf("expected 'Drift Analysis' header, got %q", out)
	}
}

func TestPrintDriftSummary_Full_WithAllChangeTypes(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 10,
		Creates:      2,
		Updates:      3,
		Deletes:      4,
		Replaces:     1,
		MaxSeverity:  "CRITICAL",
		ExitCode:     3,
		Summary:      "Significant drift detected",
		Findings: []rules.Finding{
			{Severity: "CRITICAL", Message: "IAM policy changed"},
			{Severity: "HIGH", Message: "Security group modified"},
		},
	}
	out := captureStdout(func() { printDriftSummary(result, "full") })

	checks := []string{
		"Total changes:  10",
		"Creates:      2",
		"Updates:      3",
		"Deletes:      4",
		"Replaces:     1",
		"Drift findings: 2",
		"[CRITICAL] IAM policy changed",
		"[HIGH] Security group modified",
		"Max severity:   CRITICAL",
		"Exit code:      3",
		"Significant drift detected",
	}
	for _, c := range checks {
		if !strings.Contains(out, c) {
			t.Errorf("expected %q in output, got %q", c, out)
		}
	}
}

func TestPrintDriftSummary_Full_NoFindings(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 1,
		Updates:      1,
		MaxSeverity:  "LOW",
		ExitCode:     1,
		Summary:      "Minor update",
	}
	out := captureStdout(func() { printDriftSummary(result, "full") })
	if strings.Contains(out, "Drift findings") {
		t.Errorf("should not print 'Drift findings' with 0 findings")
	}
	if !strings.Contains(out, "Updates:") {
		t.Errorf("expected Updates line in output")
	}
}

func TestParseInfraExplanation_OverviewAsMap(t *testing.T) {
	raw := `{"overview":{"summary":"nested summary"},"architecture":"monolith"}`
	expl := parseInfraExplanation(raw)
	if !strings.Contains(expl.Overview, "nested summary") {
		t.Errorf("overview = %q, should contain 'nested summary'", expl.Overview)
	}
}

// ---------------------------------------------------------------------------
// infraExplFromMap (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// infraToStringSlice (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// printInfraExplanation (explain_cmd.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// filterDisabledRules (scan.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// filterItems (selector.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ExitError (root.go)
// ---------------------------------------------------------------------------

func TestExitError(t *testing.T) {
	e := &ExitError{Code: 2}
	if e.Error() != "exit code 2" {
		t.Errorf("Error() = %q", e.Error())
	}
}

// ---------------------------------------------------------------------------
// normalizeVersion, findAssetURL, getAssetsDir (update.go)
// ---------------------------------------------------------------------------

func TestNormalizeVersion(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"  v0.1.0  ", "0.1.0"},
		{"", ""},
	}
	for _, tc := range cases {
		got := normalizeVersion(tc.in)
		if got != tc.want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestFindAssetURL_Found(t *testing.T) {
	release := &githubRelease{
		TagName: "v1.0.0",
		Assets: []githubAsset{
			{Name: "terraview_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/mac"},
			{Name: "terraview_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
		},
	}
	got := findAssetURL(release, "terraview_linux_amd64.tar.gz")
	if got != "https://example.com/linux" {
		t.Errorf("got %q", got)
	}
}

func TestFindAssetURL_NotFound(t *testing.T) {
	release := &githubRelease{
		TagName: "v1.0.0",
		Assets:  []githubAsset{{Name: "other.tar.gz", BrowserDownloadURL: "x"}},
	}
	got := findAssetURL(release, "nonexistent")
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestGetAssetsDir(t *testing.T) {
	dir := getAssetsDir()
	if !strings.HasSuffix(dir, ".terraview") {
		t.Errorf("expected dir ending with .terraview, got %q", dir)
	}
}

// (buildInfraExplainPrompt already tested above)

// ---------------------------------------------------------------------------
// logVerbose
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// applyBRTranslations
// ---------------------------------------------------------------------------

func TestApplyBRTranslations(t *testing.T) {
	// Should not panic
	applyBRTranslations()

	// Verify root command help was translated
	usage := rootCmd.UsageTemplate()
	if usage == "" {
		t.Error("expected non-empty usage template after BR translation")
	}
}

// ---------------------------------------------------------------------------
// translateFlags
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// rawPrint (selector.go)
// ---------------------------------------------------------------------------

func TestRawPrint(t *testing.T) {
	out := captureStdout(func() {
		rawPrint("hello world")
	})
	if !strings.Contains(out, "hello world") {
		t.Errorf("expected 'hello world', got %q", out)
	}
}

// ---------------------------------------------------------------------------
// defaultLookPath (setup.go)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// extractBinaryFromTar (update.go)
// ---------------------------------------------------------------------------

func TestExtractBinaryFromTar_InvalidFile(t *testing.T) {
	_, err := extractBinaryFromTar("/nonexistent/file.tar.gz", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent tar file")
	}
}

func TestExtractTarGz_InvalidFile(t *testing.T) {
	err := extractTarGz("/nonexistent/file.tar.gz", t.TempDir())
	if err == nil {
		t.Error("expected error for nonexistent tar file")
	}
}

// ---------------------------------------------------------------------------
// replaceBinary (update.go)
// ---------------------------------------------------------------------------

func TestReplaceBinary(t *testing.T) {
	dir := t.TempDir()
	oldBin := filepath.Join(dir, "old")
	newBin := filepath.Join(dir, "new")

	os.WriteFile(oldBin, []byte("old-content"), 0755)
	os.WriteFile(newBin, []byte("new-content"), 0755)

	err := replaceBinary(newBin, oldBin)
	if err != nil {
		t.Fatalf("replaceBinary failed: %v", err)
	}

	data, _ := os.ReadFile(oldBin)
	if string(data) != "new-content" {
		t.Errorf("expected new-content, got %q", string(data))
	}

	// Backup should be removed
	if _, err := os.Stat(oldBin + ".bak"); !os.IsNotExist(err) {
		t.Error("expected backup file to be removed")
	}
}

func TestReplaceBinary_OldNotFound(t *testing.T) {
	dir := t.TempDir()
	newBin := filepath.Join(dir, "new")
	os.WriteFile(newBin, []byte("new-content"), 0755)

	err := replaceBinary(newBin, filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Error("expected error when old binary doesn't exist")
	}
}

// ---------------------------------------------------------------------------
// downloadFile (update.go)
// ---------------------------------------------------------------------------

func TestDownloadFile_InvalidURL(t *testing.T) {
	err := downloadFile("http://localhost:1/nonexistent", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

func TestVersionVariable(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	Version = "test-v1.0.0"
	if Version != "test-v1.0.0" {
		t.Errorf("expected test version, got %q", Version)
	}
}
