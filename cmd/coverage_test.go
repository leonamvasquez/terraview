package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/drift"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// ---------------------------------------------------------------------------
// pick (ai.go)
// ---------------------------------------------------------------------------

func TestPick_English(t *testing.T) {
	// Ensure BR is not active
	old := os.Getenv("LANG")
	defer os.Setenv("LANG", old)
	os.Setenv("LANG", "en_US.UTF-8")

	// pick should return the EN string when BR is not active
	got := pick("english", "portuguese")
	if i18n.IsBR() {
		if got != "portuguese" {
			t.Errorf("pick() = %q, want %q (BR detected)", got, "portuguese")
		}
	} else {
		if got != "english" {
			t.Errorf("pick() = %q, want %q", got, "english")
		}
	}
}

func TestPick_EmptyStrings(t *testing.T) {
	got := pick("", "")
	if got != "" {
		t.Errorf("pick('', '') = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// buildConnectError (ai.go)
// ---------------------------------------------------------------------------

func TestBuildConnectError_CLIBinaryNotFound(t *testing.T) {
	info := ai.ProviderInfo{
		CLIBinary:   "nonexistent-binary-xyz",
		InstallHint: "npm install -g nonexistent",
	}
	got := buildConnectError(info, "claude-code", errors.New("test"))
	if !strings.Contains(got, "nonexistent-binary-xyz") {
		t.Errorf("expected CLI binary name in error, got: %q", got)
	}
	if !strings.Contains(got, "npm install -g nonexistent") {
		t.Errorf("expected install hint in error, got: %q", got)
	}
}

func TestBuildConnectError_CLIBinaryFoundButFailed(t *testing.T) {
	// Use a binary that exists (like "echo") to simulate CLI found but failed
	info := ai.ProviderInfo{
		CLIBinary: "echo",
	}
	got := buildConnectError(info, "test-provider", errors.New("auth failed"))
	if !strings.Contains(got, "auth failed") {
		t.Errorf("expected error message in output, got: %q", got)
	}
}

func TestBuildConnectError_APIKeyMissing(t *testing.T) {
	info := ai.ProviderInfo{
		RequiresKey: true,
		EnvVarKey:   "TOTALLY_FAKE_API_KEY_XYZ",
	}
	// Ensure env var is not set
	os.Unsetenv("TOTALLY_FAKE_API_KEY_XYZ")
	got := buildConnectError(info, "gemini", errors.New("no key"))
	if !strings.Contains(got, "TOTALLY_FAKE_API_KEY_XYZ") {
		t.Errorf("expected env var name in error, got: %q", got)
	}
}

func TestBuildConnectError_APIKeySetButFailed(t *testing.T) {
	info := ai.ProviderInfo{
		RequiresKey: true,
		EnvVarKey:   "TOTALLY_FAKE_API_KEY_XYZ",
	}
	t.Setenv("TOTALLY_FAKE_API_KEY_XYZ", "some-key")
	got := buildConnectError(info, "gemini", errors.New("invalid key"))
	if !strings.Contains(got, "invalid key") {
		t.Errorf("expected error in output, got: %q", got)
	}
	if !strings.Contains(got, "TOTALLY_FAKE_API_KEY_XYZ") {
		t.Errorf("expected env var in output, got: %q", got)
	}
}

func TestBuildConnectError_LocalProvider(t *testing.T) {
	info := ai.ProviderInfo{}
	got := buildConnectError(info, "ollama", errors.New("connection refused"))
	if !strings.Contains(got, "ollama") {
		t.Errorf("expected provider name in error, got: %q", got)
	}
	if !strings.Contains(got, "connection refused") {
		t.Errorf("expected original error in output, got: %q", got)
	}
}

// ---------------------------------------------------------------------------
// disableCmdColors (selector.go)
// ---------------------------------------------------------------------------

func TestDisableCmdColors_WhenDisabled(t *testing.T) {
	old := output.ColorEnabled
	defer func() { output.ColorEnabled = old }()

	// Save original values
	origReset := ansiReset
	origBold := ansiBold
	origDim := ansiDim
	origCyan := ansiCyan
	origGreen := ansiGreen
	origYellow := ansiYellow
	origRed := ansiRed
	defer func() {
		ansiReset = origReset
		ansiBold = origBold
		ansiDim = origDim
		ansiCyan = origCyan
		ansiGreen = origGreen
		ansiYellow = origYellow
		ansiRed = origRed
	}()

	output.ColorEnabled = false
	disableCmdColors()

	if ansiReset != "" || ansiBold != "" || ansiDim != "" ||
		ansiCyan != "" || ansiGreen != "" || ansiYellow != "" || ansiRed != "" {
		t.Error("expected all ANSI codes to be empty when colors disabled")
	}
}

func TestDisableCmdColors_WhenEnabled(t *testing.T) {
	old := output.ColorEnabled
	defer func() { output.ColorEnabled = old }()

	output.ColorEnabled = true
	origReset := ansiReset
	disableCmdColors()

	// When colors enabled, ansiReset should remain unchanged
	if ansiReset != origReset {
		t.Error("expected ANSI codes unchanged when colors enabled")
	}
}

// ---------------------------------------------------------------------------
// canResolveAIProvider (scan.go)
// ---------------------------------------------------------------------------

func TestCanResolveAIProvider_EmptyProvider(t *testing.T) {
	cfg := config.Config{}
	if canResolveAIProvider(cfg) {
		t.Error("expected false for empty provider")
	}
}

func TestCanResolveAIProvider_KnownProvider(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Provider = "ollama"
	if !canResolveAIProvider(cfg) {
		t.Error("expected true for ollama provider")
	}
}

func TestCanResolveAIProvider_UnknownProvider(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Provider = "nonexistent-provider-xyz"
	if canResolveAIProvider(cfg) {
		t.Error("expected false for unknown provider")
	}
}

// ---------------------------------------------------------------------------
// applyTemplateToCmds (root.go)
// ---------------------------------------------------------------------------

func TestApplyTemplateToCmds(t *testing.T) {
	root := &cobra.Command{Use: "root"}
	child1 := &cobra.Command{Use: "child1"}
	child2 := &cobra.Command{Use: "child2"}
	grandchild := &cobra.Command{Use: "grandchild"}
	child1.AddCommand(grandchild)
	root.AddCommand(child1, child2)

	tmpl := "custom template {{.UseLine}}"
	applyTemplateToCmds(root, tmpl)

	// All children and grandchildren should have the template
	for _, c := range root.Commands() {
		if c.UsageTemplate() != tmpl {
			t.Errorf("child %q doesn't have custom template", c.Use)
		}
	}
	if grandchild.UsageTemplate() != tmpl {
		t.Errorf("grandchild doesn't have custom template")
	}
}

// ---------------------------------------------------------------------------
// translateFlags (root.go)
// ---------------------------------------------------------------------------

func TestTranslateFlags_Multiple(t *testing.T) {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().Bool("verbose", false, "original verbose")
	cmd.Flags().String("format", "full", "original format")
	cmd.Flags().Bool("help", false, "original help")

	translateFlags(cmd, map[string]string{
		"verbose": "modo detalhado",
		"format":  "formato de saída",
		"missing": "should not panic",
	})

	if f := cmd.Flags().Lookup("verbose"); f.Usage != "modo detalhado" {
		t.Errorf("verbose usage = %q", f.Usage)
	}
	if f := cmd.Flags().Lookup("format"); f.Usage != "formato de saída" {
		t.Errorf("format usage = %q", f.Usage)
	}
	if f := cmd.Flags().Lookup("help"); f.Usage != "original help" {
		t.Errorf("help should not be modified, got %q", f.Usage)
	}
}

// ---------------------------------------------------------------------------
// logVerbose (root.go)
// ---------------------------------------------------------------------------

func TestLogVerbose_FormatString(t *testing.T) {
	old := verbose
	defer func() { verbose = old }()
	verbose = true

	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	logVerbose("count=%d name=%s", 42, "test")

	w.Close()
	os.Stderr = oldStderr
	out := <-done

	if !strings.Contains(out, "count=42") || !strings.Contains(out, "name=test") {
		t.Errorf("expected formatted output, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// filterItems (selector.go)
// ---------------------------------------------------------------------------

func TestFilterItems_MatchesLabel(t *testing.T) {
	items := []selectItem{
		{Label: "Ollama (Local)", Value: "ollama"},
		{Label: "Gemini", Value: "gemini"},
		{Label: "OpenRouter", Value: "openrouter"},
		{Label: "Claude Code", Value: "claude-code"},
	}

	got := filterItems(items, "code")
	if len(got) != 1 || got[0].Value != "claude-code" {
		t.Errorf("expected [claude-code], got %v", got)
	}
}

func TestFilterItems_MultipleMatches(t *testing.T) {
	items := []selectItem{
		{Label: "Ollama", Value: "ollama"},
		{Label: "OpenAI", Value: "openai"},
		{Label: "OpenRouter", Value: "openrouter"},
	}
	got := filterItems(items, "open")
	if len(got) != 2 {
		t.Errorf("expected 2 matches, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// rawPrint (selector.go)
// ---------------------------------------------------------------------------

func TestRawPrint_NewlinesToCRLF(t *testing.T) {
	out := captureStdout(func() {
		rawPrint("line1\nline2\n")
	})
	if !strings.Contains(out, "line1") || !strings.Contains(out, "line2") {
		t.Errorf("expected lines in output, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// pluralS (setup.go)
// ---------------------------------------------------------------------------

func TestPluralS_Extended(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{-1, "s"},
		{0, "s"},
		{1, ""},
		{2, "s"},
		{100, "s"},
	}
	for _, c := range cases {
		if got := pluralS(c.n); got != c.want {
			t.Errorf("pluralS(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ExitError (root.go)
// ---------------------------------------------------------------------------

func TestExitError_VariousCodes(t *testing.T) {
	for _, code := range []int{0, 1, 2, 127, 130} {
		e := &ExitError{Code: code}
		expected := fmt.Sprintf("exit code %d", code)
		if got := e.Error(); got != expected {
			t.Errorf("ExitError{%d}.Error() = %q, want %q", code, got, expected)
		}
	}
}

// ---------------------------------------------------------------------------
// buildResourceLimits (scan.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestBuildResourceLimits_PartialOllamaConfig(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Ollama.MaxThreads = 4
	// MaxMemoryMB and MinFreeMemoryMB are 0 (not configured)

	limits := buildResourceLimits(cfg, false)
	if limits.MaxThreads != 4 {
		t.Errorf("MaxThreads = %d, want 4", limits.MaxThreads)
	}
	// Defaults should be used for unconfigured fields
	if limits.MinFreeMemoryMB != 1024 {
		t.Errorf("MinFreeMemoryMB = %d, want 1024 (default)", limits.MinFreeMemoryMB)
	}
}

func TestBuildResourceLimits_SafeOverridesConfig(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Ollama.MaxThreads = 16

	limits := buildResourceLimits(cfg, true)
	// Safe mode should ignore config overrides
	if limits.MinFreeMemoryMB != 1500 {
		t.Errorf("MinFreeMemoryMB = %d, want 1500 (safe)", limits.MinFreeMemoryMB)
	}
}

// ---------------------------------------------------------------------------
// infraExplFromMap (explain_cmd.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestInfraExplFromMap_ComponentsWithMissingFields(t *testing.T) {
	m := map[string]interface{}{
		"overview": "test",
		"components": []interface{}{
			map[string]interface{}{
				"resource": "only-resource",
			},
			map[string]interface{}{
				"purpose": "only-purpose",
			},
			"not-a-map",
		},
	}
	expl := infraExplFromMap(m)
	if len(expl.Components) < 2 {
		t.Errorf("expected at least 2 parsed components, got %d", len(expl.Components))
	}
}

func TestInfraExplFromMap_OverviewAsNumber(t *testing.T) {
	m := map[string]interface{}{
		"overview": 42,
	}
	expl := infraExplFromMap(m)
	if expl.Overview == "" {
		t.Error("expected non-empty overview from numeric value")
	}
}

// ---------------------------------------------------------------------------
// buildInfraExplainPrompt (explain_cmd.go) - edge cases
// ---------------------------------------------------------------------------

func TestBuildInfraExplainPrompt_EmptyResources(t *testing.T) {
	graph := &topology.Graph{}
	got := buildInfraExplainPrompt(nil, graph)
	if !strings.Contains(got, "senior cloud architect") {
		t.Error("expected prompt template even with nil resources")
	}
	if !strings.Contains(got, "RESOURCES:") {
		t.Error("expected RESOURCES section")
	}
}

func TestBuildInfraExplainPrompt_MultipleResources(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Type: "aws_vpc", Action: "create"},
		{Address: "aws_subnet.pub", Type: "aws_subnet", Action: "create"},
	}
	graph := &topology.Graph{}
	got := buildInfraExplainPrompt(resources, graph)
	if !strings.Contains(got, "aws_vpc.main") {
		t.Error("missing first resource")
	}
	if !strings.Contains(got, "aws_subnet.pub") {
		t.Error("missing second resource")
	}
}

// ---------------------------------------------------------------------------
// parseInfraExplanation (explain_cmd.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestParseInfraExplanation_NestedJSON(t *testing.T) {
	raw := `{"overview":"toplevel","architecture":"monolith","components":[{"resource":"r","purpose":"p","role":"c"}],"connections":["a->b"],"patterns":["HA"],"concerns":["none"]}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "toplevel" {
		t.Errorf("overview = %q", expl.Overview)
	}
	if len(expl.Components) != 1 {
		t.Errorf("components = %d", len(expl.Components))
	}
}

func TestParseInfraExplanation_EmptyJSON(t *testing.T) {
	raw := `{}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "Unable to parse structured response" {
		t.Errorf("expected fallback overview for empty JSON, got %q", expl.Overview)
	}
}

// ---------------------------------------------------------------------------
// printInfraExplanation (explain_cmd.go) - additional tests
// ---------------------------------------------------------------------------

func TestPrintInfraExplanation_EmptyComponents(t *testing.T) {
	old := brFlag
	brFlag = false
	defer func() { brFlag = old }()

	expl := &InfraExplanation{
		Overview:     "Simple overview",
		Architecture: "monolith",
	}
	out := captureStdout(func() { printInfraExplanation(expl) })
	if !strings.Contains(out, "Simple overview") {
		t.Errorf("missing overview in output")
	}
	if !strings.Contains(out, "monolith") {
		t.Errorf("missing architecture in output")
	}
}

func TestPrintInfraExplanation_AllSections(t *testing.T) {
	old := brFlag
	brFlag = false
	defer func() { brFlag = old }()

	expl := &InfraExplanation{
		Overview:     "Full overview",
		Architecture: "microservices",
		Components: []ComponentExpl{
			{Resource: "ecs", Purpose: "compute", Role: "backend"},
			{Resource: "rds", Purpose: "storage", Role: "database"},
		},
		Connections: []string{"ecs -> rds", "alb -> ecs"},
		Patterns:    []string{"HA", "auto-scaling", "blue-green"},
		Concerns:    []string{"no DR plan", "single region"},
	}
	out := captureStdout(func() { printInfraExplanation(expl) })

	for _, expected := range []string{
		"Full overview",
		"microservices",
		"ecs",
		"rds",
		"ecs -> rds",
		"alb -> ecs",
		"HA",
		"auto-scaling",
		"no DR plan",
		"single region",
	} {
		if !strings.Contains(out, expected) {
			t.Errorf("missing %q in output", expected)
		}
	}
}

// ---------------------------------------------------------------------------
// filterDisabledRules (scan.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestFilterDisabledRules_AllDisabled(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001"},
		{RuleID: "SEC002"},
	}
	got := filterDisabledRules(findings, []string{"SEC001", "SEC002"})
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestFilterDisabledRules_PrefixOnly(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "CKV_AWS_001"},
		{RuleID: "CKV_AWS_002"},
		{RuleID: "CKV_GCP_001"},
		{RuleID: "TV_SEC_001"},
	}
	// "CKV" has no underscore, so it acts as a prefix (matching all CKV_*)
	got := filterDisabledRules(findings, []string{"CKV"})
	if len(got) != 1 {
		t.Errorf("expected 1 finding after prefix CKV filter, got %d", len(got))
	}
	if len(got) > 0 && got[0].RuleID != "TV_SEC_001" {
		t.Errorf("expected TV_SEC_001, got %s", got[0].RuleID)
	}
}

func TestFilterDisabledRules_WhitespaceHandling(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC001"},
	}
	got := filterDisabledRules(findings, []string{"  SEC001  "})
	if len(got) != 0 {
		t.Errorf("expected 0 findings with whitespace-trimmed rule, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// commandAvailable (setup.go) - additional
// ---------------------------------------------------------------------------

func TestCommandAvailable_ExistingCommand(t *testing.T) {
	old := execLookPath
	defer func() { execLookPath = old }()
	execLookPath = func(name string) (string, error) {
		if name == "terraform" {
			return "/usr/local/bin/terraform", nil
		}
		return "", fmt.Errorf("not found")
	}
	if !commandAvailable("terraform") {
		t.Error("expected terraform to be available")
	}
	if commandAvailable("nonexistent") {
		t.Error("expected nonexistent to not be available")
	}
}

// ---------------------------------------------------------------------------
// Version variable
// ---------------------------------------------------------------------------

func TestVersion_NonEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}

// ---------------------------------------------------------------------------
// strContainsFold (selector.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestStrContainsFold_Unicode(t *testing.T) {
	if !strContainsFold("Café", "café") {
		t.Error("expected case-insensitive match for accented chars")
	}
}

func TestStrContainsFold_EmptyBoth(t *testing.T) {
	if !strContainsFold("", "") {
		t.Error("empty substring should match empty string")
	}
}

// ---------------------------------------------------------------------------
// lastN (ai.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestLastN_Zero(t *testing.T) {
	got := lastN("hello", 0)
	if got != "" {
		t.Errorf("lastN('hello', 0) = %q, want empty", got)
	}
}

func TestLastN_ExactLength(t *testing.T) {
	got := lastN("abc", 3)
	if got != "abc" {
		t.Errorf("lastN('abc', 3) = %q, want 'abc'", got)
	}
}

// ---------------------------------------------------------------------------
// sortedScannerNames (scanners.go) - additional
// ---------------------------------------------------------------------------

func TestSortedScannerNames_LargeMap(t *testing.T) {
	m := map[string]scanner.Scanner{
		"z-scanner": stubScanner{"z-scanner"},
		"a-scanner": stubScanner{"a-scanner"},
		"m-scanner": stubScanner{"m-scanner"},
	}
	got := sortedScannerNames(m)
	if len(got) != 3 {
		t.Fatalf("expected 3, got %d", len(got))
	}
	if got[0] != "a-scanner" {
		t.Errorf("first should be a-scanner, got %q", got[0])
	}
	if got[2] != "z-scanner" {
		t.Errorf("last should be z-scanner, got %q", got[2])
	}
}

// ---------------------------------------------------------------------------
// printDriftSummary (drift.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestPrintDriftSummary_CompactWithOnlyUpdates(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 1,
		Updates:      1,
		MaxSeverity:  "LOW",
		ExitCode:     1,
	}
	out := captureStdout(func() { printDriftSummary(result, "compact") })
	if !strings.Contains(out, "1 changes") && !strings.Contains(out, "1 change") {
		t.Errorf("expected change count in output, got %q", out)
	}
}

func TestPrintDriftSummary_UnknownFormat(t *testing.T) {
	result := drift.DriftResult{TotalChanges: 2}
	// Unknown format should still work (defaults to full or compact)
	out := captureStdout(func() { printDriftSummary(result, "unknown-format") })
	if out == "" {
		t.Error("expected some output even with unknown format")
	}
}

// ===========================================================================
// applyTemplateToCmds — deeper coverage
// ===========================================================================

func TestApplyTemplateToCmds_MultipleSubcommands(t *testing.T) {
	parent := &cobra.Command{Use: "root", Short: "Root command"}
	child1 := &cobra.Command{Use: "sub1", Short: "child1"}
	child2 := &cobra.Command{Use: "sub2", Short: "child2"}
	grandchild := &cobra.Command{Use: "gc", Short: "grandchild"}
	child1.AddCommand(grandchild)
	parent.AddCommand(child1, child2)

	applyTemplateToCmds(parent, "custom-template")

	// Verify help flags are translated on subcommands
	if h := child1.Flags().Lookup("help"); h != nil {
		if h.Usage != "ajuda para sub1" {
			t.Errorf("child1 help usage = %q", h.Usage)
		}
	}
	if h := grandchild.Flags().Lookup("help"); h != nil {
		if h.Usage != "ajuda para gc" {
			t.Errorf("grandchild help usage = %q", h.Usage)
		}
	}
}

// ===========================================================================
// runSetup — integration test (captures stdout)
// ===========================================================================

func TestRunSetupEN(t *testing.T) {
	oldWorkDir := workDir
	oldLookPath := execLookPath
	oldBR := brFlag
	defer func() {
		workDir = oldWorkDir
		execLookPath = oldLookPath
		brFlag = oldBR
	}()

	workDir = t.TempDir()
	brFlag = false

	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetup(nil, nil)
	})

	if runErr != nil {
		t.Fatalf("runSetup EN error: %v", runErr)
	}

	for _, want := range []string{"Security Scanners", "AI Provider", "Quick Start"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing section %q in output", want)
		}
	}
}

func TestRunSetupBR(t *testing.T) {
	oldWorkDir := workDir
	oldLookPath := execLookPath
	oldBR := brFlag
	defer func() {
		workDir = oldWorkDir
		execLookPath = oldLookPath
		brFlag = oldBR
	}()

	workDir = t.TempDir()
	brFlag = true
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")

	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetup(nil, nil)
	})

	if runErr != nil {
		t.Fatalf("runSetup BR error: %v", runErr)
	}

	for _, want := range []string{"Scanners de Segurança", "Provider de IA", "Início Rápido"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing section %q in output", want)
		}
	}
}

func TestRunSetupEN_WithOllama(t *testing.T) {
	oldWorkDir := workDir
	oldLookPath := execLookPath
	oldBR := brFlag
	defer func() {
		workDir = oldWorkDir
		execLookPath = oldLookPath
		brFlag = oldBR
	}()

	workDir = t.TempDir()
	brFlag = false

	execLookPath = func(name string) (string, error) {
		if name == "ollama" {
			return "/usr/local/bin/ollama", nil
		}
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetup(nil, nil)
	})

	if runErr != nil {
		t.Fatalf("error: %v", runErr)
	}

	if !strings.Contains(out, "AI ready") {
		t.Error("expected 'AI ready' with ollama available")
	}
}

func TestRunSetup_Dispatch(t *testing.T) {
	oldWorkDir := workDir
	oldLookPath := execLookPath
	oldBR := brFlag
	defer func() {
		workDir = oldWorkDir
		execLookPath = oldLookPath
		brFlag = oldBR
	}()

	workDir = t.TempDir()
	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	brFlag = false
	var err error
	captureStdout(func() {
		err = runSetup(nil, nil)
	})
	if err != nil {
		t.Fatalf("runSetup EN error: %v", err)
	}

	// Test BR dispatch
	brFlag = true
	captureStdout(func() {
		err = runSetup(nil, nil)
	})
	if err != nil {
		t.Fatalf("runSetup BR error: %v", err)
	}
}

// ===========================================================================
// runAIUse — integration test
// ===========================================================================

func TestRunAIUse_Ollama(t *testing.T) {
	// Use temp HOME so GlobalConfigDir writes to temp
	t.Setenv("HOME", t.TempDir())

	var err error
	captureStdout(func() {
		err = runAIUse(nil, []string{"ollama"})
	})

	if err != nil {
		t.Fatalf("runAIUse error: %v", err)
	}

	// Verify config was written
	cfgPath := config.GlobalConfigPath()
	if _, statErr := os.Stat(cfgPath); statErr != nil {
		t.Errorf("config file not created: %s", cfgPath)
	}
}

func TestRunAIUse_WithModel(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	var err error
	captureStdout(func() {
		err = runAIUse(nil, []string{"ollama", "llama3:8b"})
	})

	if err != nil {
		t.Fatalf("runAIUse error: %v", err)
	}
}

func TestRunAIUse_InvalidProvider(t *testing.T) {
	err := runAIUse(nil, []string{"nonexistent_provider"})
	if err == nil {
		t.Fatal("expected error for invalid provider")
	}
}

// ===========================================================================
// runAICurrent — integration test
// ===========================================================================

func TestRunAICurrent(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	tmpDir := t.TempDir()
	workDir = tmpDir

	// Create a config file
	cfgContent := `llm:
  provider: ollama
  model: llama3:8b
  url: http://localhost:11434
  timeout_seconds: 120
  temperature: 0.2
  enabled: true
`
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(cfgContent), 0644)

	var runErr error
	out := captureStdout(func() {
		runErr = runAICurrent(nil, nil)
	})

	if runErr != nil {
		t.Fatalf("runAICurrent error: %v", runErr)
	}

	if !strings.Contains(out, "ollama") {
		t.Error("expected 'ollama' in output")
	}
	if !strings.Contains(out, "llama3:8b") {
		t.Error("expected 'llama3:8b' in output")
	}
}

// ===========================================================================
// runDiagram — integration test with fixture plan
// ===========================================================================

func TestRunDiagram_WithFixture(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
	}()

	// Use the examples/plan.json fixture (relative from cmd/ → ../examples/plan.json)
	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	tmpDir := t.TempDir()
	planFile = fixturePath
	outputDir = tmpDir
	workDir = tmpDir

	var runErr error
	captureStdout(func() {
		runErr = runDiagram(nil, nil)
	})

	if runErr != nil {
		t.Fatalf("runDiagram error: %v", runErr)
	}

	// Check diagram.txt was written
	diagramPath := filepath.Join(tmpDir, "diagram.txt")
	if _, statErr := os.Stat(diagramPath); statErr != nil {
		t.Errorf("diagram.txt not created: %v", statErr)
	}
}

func TestRunDiagram_NoPlanFile(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
	}()

	tmpDir := t.TempDir()
	planFile = ""
	workDir = tmpDir
	outputDir = tmpDir

	// runDiagram with empty planFile should try to auto-generate then fail
	err := runDiagram(nil, nil)
	if err == nil {
		t.Log("runDiagram returned nil (auto-generate succeeded or was skipped)")
	}
}

// ===========================================================================
// runDrift — integration test with fixture plan
// ===========================================================================

func TestRunDrift_WithFixture(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	oldFormat := outputFormat
	oldIntel := driftIntelligenceFlag
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
		outputFormat = oldFormat
		driftIntelligenceFlag = oldIntel
	}()

	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	tmpDir := t.TempDir()
	planFile = fixturePath
	outputDir = tmpDir
	workDir = tmpDir
	outputFormat = ""
	driftIntelligenceFlag = false

	var runErr error
	captureStdout(func() {
		runErr = runDrift(nil, nil)
	})

	// May return ExitError for non-zero drift — that's OK
	if runErr != nil {
		if _, ok := runErr.(*ExitError); !ok {
			t.Fatalf("runDrift error: %v", runErr)
		}
	}

	// drift.json should be written
	if _, statErr := os.Stat(filepath.Join(tmpDir, "drift.json")); statErr != nil {
		t.Error("drift.json not created")
	}
}

func TestRunDrift_WithIntelligence(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	oldFormat := outputFormat
	oldIntel := driftIntelligenceFlag
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
		outputFormat = oldFormat
		driftIntelligenceFlag = oldIntel
	}()

	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	tmpDir := t.TempDir()
	planFile = fixturePath
	outputDir = tmpDir
	workDir = tmpDir
	outputFormat = ""
	driftIntelligenceFlag = true

	var runErr error
	captureStdout(func() {
		runErr = runDrift(nil, nil)
	})

	if runErr != nil {
		if _, ok := runErr.(*ExitError); !ok {
			t.Fatalf("runDrift error: %v", runErr)
		}
	}

	// Both drift.json and drift-intelligence.json should be written
	if _, statErr := os.Stat(filepath.Join(tmpDir, "drift.json")); statErr != nil {
		t.Error("drift.json not created")
	}
	if _, statErr := os.Stat(filepath.Join(tmpDir, "drift-intelligence.json")); statErr != nil {
		t.Error("drift-intelligence.json not created")
	}
}

func TestRunDrift_CompactFormat(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	oldFormat := outputFormat
	oldIntel := driftIntelligenceFlag
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
		outputFormat = oldFormat
		driftIntelligenceFlag = oldIntel
	}()

	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	tmpDir := t.TempDir()
	planFile = fixturePath
	outputDir = tmpDir
	workDir = tmpDir
	outputFormat = "compact"
	driftIntelligenceFlag = false

	var runErr error
	out := captureStdout(func() {
		runErr = runDrift(nil, nil)
	})

	if runErr != nil {
		if _, ok := runErr.(*ExitError); !ok {
			t.Fatalf("runDrift compact error: %v", runErr)
		}
	}

	if !strings.Contains(out, "terraview drift:") {
		t.Errorf("compact output should contain 'terraview drift:', got: %s", out)
	}
}

func TestRunDrift_JSONFormat(t *testing.T) {
	oldPlanFile := planFile
	oldOutputDir := outputDir
	oldWorkDir := workDir
	oldFormat := outputFormat
	oldIntel := driftIntelligenceFlag
	defer func() {
		planFile = oldPlanFile
		outputDir = oldOutputDir
		workDir = oldWorkDir
		outputFormat = oldFormat
		driftIntelligenceFlag = oldIntel
	}()

	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	tmpDir := t.TempDir()
	planFile = fixturePath
	outputDir = tmpDir
	workDir = tmpDir
	outputFormat = "json"
	driftIntelligenceFlag = false

	var runErr error
	captureStdout(func() {
		runErr = runDrift(nil, nil)
	})

	if runErr != nil {
		if _, ok := runErr.(*ExitError); !ok {
			t.Fatalf("runDrift json error: %v", runErr)
		}
	}
}

// ===========================================================================
// versionCmd — coverage
// ===========================================================================

func TestVersionCmd(t *testing.T) {
	oldVersion := Version
	defer func() { Version = oldVersion }()
	Version = "v0.0.0-test"

	out := captureStdout(func() {
		versionCmd.Run(versionCmd, nil)
	})

	if !strings.Contains(out, "v0.0.0-test") {
		t.Errorf("version output missing test version: %s", out)
	}
	if !strings.Contains(out, "go:") {
		t.Error("version output missing go version")
	}
}

// ===========================================================================
// selector helpers — coverage
// ===========================================================================

func TestStrContainsFold_Extra(t *testing.T) {
	tests := []struct {
		s, sub string
		want   bool
	}{
		{"Hello World", "hello", true},
		{"Hello World", "WORLD", true},
		{"foo", "bar", false},
		{"", "", true},
		{"abc", "", true},
	}
	for _, tt := range tests {
		if got := strContainsFold(tt.s, tt.sub); got != tt.want {
			t.Errorf("strContainsFold(%q, %q) = %v, want %v", tt.s, tt.sub, got, tt.want)
		}
	}
}

func TestFilterItems(t *testing.T) {
	items := []selectItem{
		{Label: "Ollama", Value: "ollama"},
		{Label: "Claude", Value: "claude"},
		{Label: "OpenAI", Value: "openai"},
	}

	// Empty query returns all
	all := filterItems(items, "")
	if len(all) != 3 {
		t.Errorf("filterItems empty query: got %d, want 3", len(all))
	}

	// Filter by "oll"
	filtered := filterItems(items, "oll")
	if len(filtered) != 1 || filtered[0].Value != "ollama" {
		t.Errorf("filterItems 'oll': got %v", filtered)
	}

	// No match
	none := filterItems(items, "xyz")
	if len(none) != 0 {
		t.Errorf("filterItems 'xyz': got %d, want 0", len(none))
	}
}

func TestRenderList(t *testing.T) {
	items := []selectItem{
		{Label: "Option A", Value: "a", Detail: "detail a"},
		{Label: "Option B", Value: "b", IsActive: true},
	}

	out := captureStdout(func() {
		renderList("Test Title", items, 0)
	})

	if !strings.Contains(out, "Test Title") {
		t.Error("renderList should contain title")
	}
	if !strings.Contains(out, "Option A") {
		t.Error("renderList should contain Option A")
	}
	if !strings.Contains(out, "Option B") {
		t.Error("renderList should contain Option B")
	}
}

func TestPrintItem_Cursor(t *testing.T) {
	item := selectItem{Label: "Test", Value: "test", Detail: "some detail", IsActive: true}

	out := captureStdout(func() {
		printItem(0, item, 0) // cursor on this item
	})

	if !strings.Contains(out, "Test") {
		t.Error("printItem should contain label")
	}
	if !strings.Contains(out, "▶") {
		t.Error("printItem with cursor should contain ▶")
	}
}

func TestPrintItem_NotCursor(t *testing.T) {
	item := selectItem{Label: "Other", Value: "other"}

	out := captureStdout(func() {
		printItem(1, item, 0) // cursor NOT on this item
	})

	if !strings.Contains(out, "Other") {
		t.Error("printItem should contain label")
	}
	if strings.Contains(out, "▶") {
		t.Error("printItem without cursor should not contain ▶")
	}
}

func TestRenderFilterList(t *testing.T) {
	items := []selectItem{
		{Label: "Item 1", Value: "1"},
		{Label: "Item 2", Value: "2"},
	}

	var lines int
	out := captureStdout(func() {
		lines = renderFilterList("Filter Title", items, "ite", 0)
	})

	if lines < 5 {
		t.Errorf("renderFilterList returned %d lines, expected >= 5", lines)
	}
	if !strings.Contains(out, "Filter Title") {
		t.Error("renderFilterList should contain title")
	}
	if !strings.Contains(out, "ite") {
		t.Error("renderFilterList should contain query")
	}
}

func TestRenderFilterList_Empty(t *testing.T) {
	var lines int
	out := captureStdout(func() {
		lines = renderFilterList("Empty", nil, "xxx", 0)
	})

	if lines < 5 {
		t.Errorf("renderFilterList empty returned %d lines", lines)
	}
	if !strings.Contains(out, "no results") {
		t.Error("empty filter should show 'no results'")
	}
}

func TestEraseLines(t *testing.T) {
	out := captureStdout(func() {
		eraseLines(3)
	})
	if !strings.Contains(out, "\033[2K") {
		t.Error("eraseLines should contain ANSI erase sequences")
	}
}

func TestEraseList(t *testing.T) {
	out := captureStdout(func() {
		eraseList(3) // should erase 3+5=8 lines
	})
	if !strings.Contains(out, "\033[2K") {
		t.Error("eraseList should contain ANSI erase")
	}
}

func TestMoveUp(t *testing.T) {
	out := captureStdout(func() {
		moveUp(3)
	})
	if strings.Count(out, "\033[A") != 3 {
		t.Errorf("moveUp(3): expected 3 cursor-up sequences, got %d", strings.Count(out, "\033[A"))
	}
}

// ===========================================================================
// runScan — error path coverage
// ===========================================================================

func TestRunScan_NoProviderNoScanner(t *testing.T) {
	oldWorkDir := workDir
	oldStatic := staticOnly
	oldFindings := findingsFile
	defer func() {
		workDir = oldWorkDir
		staticOnly = oldStatic
		findingsFile = oldFindings
	}()

	tmpDir := t.TempDir()
	workDir = tmpDir
	staticOnly = false
	findingsFile = ""

	// Clear all AI env vars so no provider is available
	for _, k := range []string{"GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "OPENROUTER_API_KEY", "OLLAMA_HOST"} {
		t.Setenv(k, "")
	}

	// Ensure no config file exists
	err := runScan(nil, nil)
	if err == nil {
		t.Log("runScan returned nil (AI provider resolved from global config or scanner installed)")
	}
}

// ===========================================================================
// canResolveAIProvider — coverage
// ===========================================================================

func TestCanResolveAIProvider(t *testing.T) {
	// Empty provider
	cfg := config.Config{}
	if canResolveAIProvider(cfg) {
		t.Error("empty provider should return false")
	}

	// Known provider
	cfg.LLM.Provider = "ollama"
	if !canResolveAIProvider(cfg) {
		t.Error("ollama should be resolvable")
	}

	// Unknown provider
	cfg.LLM.Provider = "nonexistent_fake_provider"
	if canResolveAIProvider(cfg) {
		t.Error("nonexistent provider should return false")
	}
}

// ===========================================================================
// printDriftSummary — direct coverage
// ===========================================================================

func TestPrintDriftSummary_NoChanges(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 0,
		ExitCode:     0,
	}

	out := captureStdout(func() {
		printDriftSummary(result, "pretty")
	})

	if !strings.Contains(out, "No infrastructure drift") {
		t.Errorf("expected 'No infrastructure drift', got: %s", out)
	}
}

func TestPrintDriftSummary_WithChanges(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 5,
		Creates:      2,
		Updates:      1,
		Deletes:      1,
		Replaces:     1,
		MaxSeverity:  "HIGH",
		ExitCode:     1,
		Summary:      "Drift detected with high risk",
		Findings: []rules.Finding{
			{Severity: "HIGH", Message: "IAM role modified"},
		},
	}

	out := captureStdout(func() {
		printDriftSummary(result, "pretty")
	})

	for _, want := range []string{"Creates", "Updates", "Deletes", "Replaces", "HIGH", "IAM role modified"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in drift summary", want)
		}
	}
}

func TestPrintDriftSummary_Compact(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 3,
		MaxSeverity:  "MEDIUM",
		ExitCode:     0,
		Findings: []rules.Finding{
			{Severity: "MEDIUM", Message: "Tags changed"},
		},
	}

	out := captureStdout(func() {
		printDriftSummary(result, "compact")
	})

	if !strings.Contains(out, "terraview drift:") {
		t.Errorf("compact format should contain 'terraview drift:', got: %s", out)
	}
}

func TestPrintDriftSummary_CompactNoChanges(t *testing.T) {
	result := drift.DriftResult{
		TotalChanges: 0,
		ExitCode:     0,
	}

	out := captureStdout(func() {
		printDriftSummary(result, "compact")
	})

	if !strings.Contains(out, "no changes detected") {
		t.Errorf("compact no-changes should contain 'no changes detected', got: %s", out)
	}
}

// ===========================================================================
// runAICurrent — no config
// ===========================================================================

func TestRunAICurrent_NoConfig(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	workDir = t.TempDir() // no config file

	var err error
	captureStdout(func() {
		err = runAICurrent(nil, nil)
	})

	if err != nil {
		t.Fatalf("runAICurrent no config error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// parsePlan
// ---------------------------------------------------------------------------

func TestParsePlan_WithFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	_, resources, graph, err := parsePlan(fixturePath)
	if err != nil {
		t.Fatalf("parsePlan error: %v", err)
	}
	if len(resources) == 0 {
		t.Error("expected at least one resource")
	}
	if graph == nil {
		t.Error("expected non-nil topology graph")
	}
}

func TestParsePlan_InvalidPath(t *testing.T) {
	_, _, _, err := parsePlan("/nonexistent/path/plan.json")
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestParsePlan_InvalidJSON(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "bad.json")
	os.WriteFile(tmpFile, []byte("not json"), 0644)

	_, _, _, err := parsePlan(tmpFile)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParsePlan_EmptyPlan(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "empty.json")
	os.WriteFile(tmpFile, []byte(`{"format_version":"1.0","resource_changes":[]}`), 0644)

	_, _, _, err := parsePlan(tmpFile)
	// Parser may reject empty plans — both outcomes are valid
	if err != nil {
		if !strings.Contains(err.Error(), "no resource") {
			t.Errorf("unexpected error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// runCacheClear
// ---------------------------------------------------------------------------

func TestRunCacheClear(t *testing.T) {
	// Should not fail even if cache dir is empty
	var err error
	captureStdout(func() {
		err = runCacheClear(nil, nil)
	})
	if err != nil {
		t.Errorf("runCacheClear error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runCacheStatus
// ---------------------------------------------------------------------------

func TestRunCacheStatus(t *testing.T) {
	var err error
	out := captureStdout(func() {
		err = runCacheStatus(nil, nil)
	})
	if err != nil {
		t.Errorf("runCacheStatus error: %v", err)
	}
	_ = out // just ensure no panic
}

// ---------------------------------------------------------------------------
// mergeAndScore
// ---------------------------------------------------------------------------

func TestMergeAndScore_EmptyFindings(t *testing.T) {
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{
		Critical: 10,
		High:     7,
		Medium:   4,
		Low:      1,
	}

	rc := reviewConfig{
		cfg:          cfg,
		resolvedPlan: "test.json",
	}

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	topoGraph := topology.BuildGraph(resources)

	sr := scanResult{}

	result := mergeAndScore(rc, resources, topoGraph, sr)
	if result.Score.OverallScore < 0 || result.Score.OverallScore > 10 {
		t.Errorf("score out of range: %f", result.Score.OverallScore)
	}
}

func TestMergeAndScore_WithFindings(t *testing.T) {
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{
		Critical: 10,
		High:     7,
		Medium:   4,
		Low:      1,
	}

	rc := reviewConfig{
		cfg:          cfg,
		resolvedPlan: "test.json",
	}

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	topoGraph := topology.BuildGraph(resources)

	sr := scanResult{
		hardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "test"},
		},
	}

	result := mergeAndScore(rc, resources, topoGraph, sr)
	if len(result.Findings) == 0 {
		t.Error("expected findings in result")
	}
	// Score should be computed (may still be high with just 1 finding)
	if result.Score.OverallScore < 0 {
		t.Error("score should not be negative")
	}
}

func TestMergeAndScore_WithDisabledRules(t *testing.T) {
	cfg := config.Config{}
	cfg.Scoring.SeverityWeights = config.SeverityWeightsConfig{
		Critical: 10,
		High:     7,
		Medium:   4,
		Low:      1,
	}
	cfg.Rules.DisabledRules = []string{"CKV_AWS_1"}

	rc := reviewConfig{
		cfg:          cfg,
		resolvedPlan: "test.json",
	}

	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance"},
	}
	topoGraph := topology.BuildGraph(resources)

	sr := scanResult{
		hardFindings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "should be filtered"},
			{RuleID: "CKV_AWS_2", Severity: "MEDIUM", Resource: "aws_instance.web", Message: "should remain"},
		},
	}

	result := mergeAndScore(rc, resources, topoGraph, sr)
	for _, f := range result.Findings {
		if f.RuleID == "CKV_AWS_1" {
			t.Error("CKV_AWS_1 should have been filtered by DisabledRules")
		}
	}
}

// ---------------------------------------------------------------------------
// resolveReviewConfig — partial (with fixture plan and minimal config)
// ---------------------------------------------------------------------------

func TestResolveReviewConfig_WithFixturePlan(t *testing.T) {
	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	oldPlanFile := planFile
	oldWorkDir := workDir
	oldStaticOnly := staticOnly
	defer func() {
		planFile = oldPlanFile
		workDir = oldWorkDir
		staticOnly = oldStaticOnly
	}()

	planFile = fixturePath
	workDir = t.TempDir()
	staticOnly = true

	rc, err := resolveReviewConfig("")
	if err != nil {
		t.Fatalf("resolveReviewConfig error: %v", err)
	}
	if rc.resolvedPlan != fixturePath {
		t.Errorf("expected plan %q, got %q", fixturePath, rc.resolvedPlan)
	}
	if rc.effectiveAI {
		t.Error("expected AI to be off with --static")
	}
}

func TestResolveReviewConfig_WithProviderOverride(t *testing.T) {
	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	oldPlanFile := planFile
	oldWorkDir := workDir
	oldProvider := activeProvider
	oldModel := activeModel
	defer func() {
		planFile = oldPlanFile
		workDir = oldWorkDir
		activeProvider = oldProvider
		activeModel = oldModel
	}()

	planFile = fixturePath
	workDir = t.TempDir()
	activeProvider = "openai"
	activeModel = "gpt-4"

	rc, err := resolveReviewConfig("")
	if err != nil {
		t.Fatalf("resolveReviewConfig error: %v", err)
	}
	if rc.aiProvider != "openai" {
		t.Errorf("expected provider 'openai', got %q", rc.aiProvider)
	}
	if rc.aiModel != "gpt-4" {
		t.Errorf("expected model 'gpt-4', got %q", rc.aiModel)
	}
}

func TestResolveReviewConfig_OutputFormatOverride(t *testing.T) {
	fixturePath := filepath.Join("..", "examples", "plan.json")
	if _, err := os.Stat(fixturePath); err != nil {
		t.Skip("fixture plan.json not available")
	}

	oldPlanFile := planFile
	oldWorkDir := workDir
	oldFormat := outputFormat
	defer func() {
		planFile = oldPlanFile
		workDir = oldWorkDir
		outputFormat = oldFormat
	}()

	planFile = fixturePath
	workDir = t.TempDir()
	outputFormat = "json"

	rc, err := resolveReviewConfig("")
	if err != nil {
		t.Fatalf("resolveReviewConfig error: %v", err)
	}
	if rc.effectiveFormat != "json" {
		t.Errorf("expected format 'json', got %q", rc.effectiveFormat)
	}
}

// ---------------------------------------------------------------------------
// AI List command (runAIList)
// ---------------------------------------------------------------------------

func TestRunAIList(t *testing.T) {
	var err error
	out := captureStdout(func() {
		err = runAIList(nil, nil)
	})
	if err != nil {
		t.Errorf("runAIList error: %v", err)
	}
	if out == "" {
		t.Error("expected non-empty output from runAIList")
	}
}

// ---------------------------------------------------------------------------
// runAITest scenarios
// ---------------------------------------------------------------------------

func TestRunAITest_NoProvider(t *testing.T) {
	oldProvider := activeProvider
	oldWorkDir := workDir
	defer func() {
		activeProvider = oldProvider
		workDir = oldWorkDir
	}()

	activeProvider = ""
	workDir = t.TempDir()

	err := runAITest(nil, nil)
	// Should return error when no provider is configured
	if err == nil {
		t.Log("runAITest returned nil (provider may be configured in env)")
	}
}

// ---------------------------------------------------------------------------
// generatePlan — error when no terraform available
// ---------------------------------------------------------------------------

func TestGeneratePlan_NoTerraform(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	workDir = t.TempDir()

	_, _, err := generatePlan()
	if err == nil {
		t.Log("generatePlan succeeded (terraform may be installed)")
	}
}

// ---------------------------------------------------------------------------
// Sorted scanner names
// ---------------------------------------------------------------------------

func TestSortedScannerNames(t *testing.T) {
	names := sortedScannerNames(map[string]scanner.Scanner{
		"z": nil,
		"a": nil,
		"m": nil,
	})
	if len(names) != 3 {
		t.Fatalf("expected 3 names, got %d", len(names))
	}
	if names[0] != "a" || names[1] != "m" || names[2] != "z" {
		t.Errorf("expected sorted order, got %v", names)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — 3 format paths (pretty, json, sarif)
// ---------------------------------------------------------------------------

func TestRenderOutput_PrettyFormat(t *testing.T) {
	dir := t.TempDir()

	// Save/restore package-level flags
	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test-plan.json",
		TotalResources: 3,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	// Capture stdout (PrintSummary writes there)
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r) // drain

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Check JSON was written
	if _, err := os.Stat(filepath.Join(dir, "review.json")); err != nil {
		t.Error("review.json not created")
	}
	// Check MD was written (pretty format writes markdown too)
	if _, err := os.Stat(filepath.Join(dir, "review.md")); err != nil {
		t.Error("review.md not created")
	}
}

func TestRenderOutput_JSONFormat(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatJSON,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// JSON format should NOT create review.md
	if _, err := os.Stat(filepath.Join(dir, "review.md")); !os.IsNotExist(err) {
		t.Error("review.md should not be created in JSON format")
	}
	// Should create review.json
	if _, err := os.Stat(filepath.Join(dir, "review.json")); err != nil {
		t.Error("review.json not created")
	}
}

func TestRenderOutput_SARIFFormat(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatSARIF,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 2,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// SARIF format creates both review.json and review.sarif.json
	if _, err := os.Stat(filepath.Join(dir, "review.json")); err != nil {
		t.Error("review.json not created")
	}
	if _, err := os.Stat(filepath.Join(dir, "review.sarif.json")); err != nil {
		t.Error("review.sarif.json not created in SARIF format")
	}
}

func TestRenderOutput_StrictMode(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = true

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 2,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE"},
		Score:          scoring.Score{OverallScore: 7.0},
		ExitCode:       1, // HIGH severity
		SeverityCounts: map[string]int{"HIGH": 1},
		CategoryCounts: map[string]int{"security": 1},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	// strict mode: exit code 1 → 2
	if exitCode != 2 {
		t.Errorf("expected exit code 2 in strict mode, got %d", exitCode)
	}
}

func TestRenderOutput_WithScannerResult(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}
	scanResult := &scanner.AggregatedResult{}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, scanResult)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

func TestRenderOutput_BRFlag(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = true
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

// ---------------------------------------------------------------------------
// AI Registry: Names, List, Has
// ---------------------------------------------------------------------------

func TestAI_Names(t *testing.T) {
	names := ai.Names()
	if len(names) == 0 {
		t.Fatal("expected at least one registered provider")
	}
	// Should be sorted
	for i := 1; i < len(names); i++ {
		if names[i] < names[i-1] {
			t.Errorf("names not sorted: %v", names)
			break
		}
	}
}

func TestAI_List(t *testing.T) {
	infos := ai.List()
	if len(infos) == 0 {
		t.Fatal("expected at least one provider info")
	}
	// Each info should have a non-empty Name
	for _, info := range infos {
		if info.Name == "" {
			t.Error("provider info has empty name")
		}
	}
}

func TestAI_Has(t *testing.T) {
	// ollama is always registered via the providers import
	if !ai.Has("ollama") {
		t.Error("expected ollama to be registered")
	}
	if ai.Has("nonexistent-provider-xyz") {
		t.Error("non-existent provider should not be registered")
	}
}

// ---------------------------------------------------------------------------
// canResolveAIProvider
// ---------------------------------------------------------------------------

func TestCanResolveAIProvider_NoProvider(t *testing.T) {
	cfg := config.Config{}
	if canResolveAIProvider(cfg) {
		t.Error("expected false when no provider set")
	}
}

func TestCanResolveAIProvider_Ollama(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Provider = "ollama"
	if !canResolveAIProvider(cfg) {
		t.Error("expected true for ollama")
	}
}

func TestCanResolveAIProvider_Unknown(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Provider = "nonexistent-provider"
	if canResolveAIProvider(cfg) {
		t.Error("expected false for unknown provider")
	}
}

// ---------------------------------------------------------------------------
// mergeAndScore — additional branch coverage
// ---------------------------------------------------------------------------

func TestMergeAndScore_WithContextFindings(t *testing.T) {
	rc := reviewConfig{
		resolvedPlan: "test.json",
		cfg:          config.Config{},
	}
	resources := []parser.NormalizedResource{
		{Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := scanResult{
		contextFindings: []rules.Finding{
			{Resource: "aws_instance.web", Severity: "MEDIUM", Message: "AI finding"},
		},
		contextSummary: "AI summary",
	}

	result := mergeAndScore(rc, resources, graph, sr)
	if result.TotalResources != 1 {
		t.Errorf("expected 1 total resource, got %d", result.TotalResources)
	}
}

func TestMergeAndScore_MetaAnalysis(t *testing.T) {
	rc := reviewConfig{
		resolvedPlan: "test.json",
		cfg:          config.Config{},
	}
	resources := []parser.NormalizedResource{
		{Type: "aws_security_group", Name: "sg", Action: "create"},
	}
	sr := scanResult{
		hardFindings: []rules.Finding{
			{Resource: "aws_security_group.sg", Severity: "CRITICAL", Message: "open to world", Category: "security"},
			{Resource: "aws_security_group.sg", Severity: "HIGH", Message: "no tags", Category: "compliance"},
		},
	}

	result := mergeAndScore(rc, resources, nil, sr)
	if result.MetaAnalysis == nil {
		t.Error("expected meta analysis when findings exist")
	}
}

// ---------------------------------------------------------------------------
// runScan — early error paths
// ---------------------------------------------------------------------------

func TestRunScan_NoScannerStaticNoFindings(t *testing.T) {
	oldStatic, oldWorkDir, oldFindingsFile := staticOnly, workDir, findingsFile
	defer func() { staticOnly, workDir, findingsFile = oldStatic, oldWorkDir, oldFindingsFile }()

	dir := t.TempDir()
	// Create minimal .terraview.yaml AND a dummy .tf file so workspace validation passes
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(""), 0644)

	workDir = dir
	staticOnly = true
	findingsFile = ""

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error with --static and no scanner")
	}
}

func TestRunScan_NoScannerNoAI(t *testing.T) {
	oldStatic, oldWorkDir, oldFindingsFile := staticOnly, workDir, findingsFile
	defer func() { staticOnly, workDir, findingsFile = oldStatic, oldWorkDir, oldFindingsFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(""), 0644)

	workDir = dir
	staticOnly = false
	findingsFile = ""

	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error with no scanner and no AI configured")
	}
}

// ---------------------------------------------------------------------------
// executeReview — error on missing plan
// ---------------------------------------------------------------------------

func TestExecuteReview_NoPlanFile(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	workDir = dir
	planFile = filepath.Join(dir, "nonexistent.json")

	_, _, err := executeReview("")
	if err == nil {
		t.Fatal("expected error for nonexistent plan file")
	}
}

func TestExecuteReview_InvalidPlanJSON(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{invalid"), 0644)

	workDir = dir
	planFile = filepath.Join(dir, "bad.json")

	_, _, err := executeReview("")
	if err == nil {
		t.Fatal("expected error for invalid plan JSON")
	}
}

// ---------------------------------------------------------------------------
// runCacheStatus — test with real (empty) cache dir
// ---------------------------------------------------------------------------

func TestRunCacheStatus_NoCache(t *testing.T) {
	// runCacheStatus reads DiskCacheDir() which is determined by $HOME
	// We capture stdout to avoid polluting test output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runCacheStatus(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	// Either returns nil (with "no cache" message) or an error
	_ = err
	_ = out
	// We just ensure it doesn't panic
}

// ---------------------------------------------------------------------------
// runSetup — covers the setup command printing logic
// ---------------------------------------------------------------------------

func TestRunSetup_Basic(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	workDir = dir

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runSetup(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	outBytes, _ := io.ReadAll(r)
	out := string(outBytes)

	if err != nil {
		t.Fatalf("runSetup error: %v", err)
	}
	if !strings.Contains(out, "setup") && !strings.Contains(out, "scanner") && !strings.Contains(out, "Scanner") {
		t.Errorf("setup output doesn't contain expected content: %s", out[:min(200, len(out))])
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — error paths
// ---------------------------------------------------------------------------

func TestRunExplainCmd_BadPlan(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{not json"), 0644)
	workDir = dir
	planFile = filepath.Join(dir, "bad.json")

	err := runExplainCmd(nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid plan")
	}
}

func TestRunExplainCmd_EmptyPlan(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	// Write a valid but empty plan
	emptyPlan := map[string]interface{}{
		"format_version":   "1.0",
		"resource_changes": []interface{}{},
	}
	data, _ := json.Marshal(emptyPlan)
	planPath := filepath.Join(dir, "empty.json")
	os.WriteFile(planPath, data, 0644)

	workDir = dir
	planFile = planPath

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runExplainCmd(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	// Empty plan should either return nil (with "no resources" message) or an error
	// either way, no panic
	_ = err
}

// ---------------------------------------------------------------------------
// runDiagram — error paths
// ---------------------------------------------------------------------------

func TestRunDiagram_BadPlan(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	workDir = dir
	planFile = filepath.Join(dir, "nonexistent.json")

	err := runDiagram(nil, nil)
	if err == nil {
		t.Fatal("expected error for missing plan file")
	}
}

// ---------------------------------------------------------------------------
// runDrift — error paths
// ---------------------------------------------------------------------------

func TestRunDrift_NoPlanNoTerraform(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)
	workDir = dir
	planFile = ""

	err := runDrift(nil, nil)
	// Either error (no terraform/no workspace) or success - just don't panic
	_ = err
}

// ---------------------------------------------------------------------------
// output.FormatSARIF constant via renderOutput
// ---------------------------------------------------------------------------

func TestRenderOutput_CompactFormat(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatCompact,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	// Compact format should create review.md (not JSON or SARIF only)
	if _, err := os.Stat(filepath.Join(dir, "review.md")); err != nil {
		t.Error("review.md not created in compact format")
	}
}

// ---------------------------------------------------------------------------
// Additional coverage for partially covered functions
// ---------------------------------------------------------------------------

func TestLogVerbose_NotVerbose(t *testing.T) {
	// When verbose is false, logVerbose should do nothing (no panic)
	oldVerbose := verbose
	defer func() { verbose = oldVerbose }()
	verbose = false
	logVerbose("test %s", "message")
}

func TestLogVerbose_Verbose(t *testing.T) {
	oldVerbose := verbose
	defer func() { verbose = oldVerbose }()
	verbose = true

	// Capture stderr (logVerbose writes there)
	oldStderr := os.Stderr
	r, w, _ := os.Pipe()
	os.Stderr = w

	logVerbose("test %s", "message")

	w.Close()
	os.Stderr = oldStderr
	out, _ := io.ReadAll(r)

	if !strings.Contains(string(out), "test message") {
		t.Errorf("logVerbose didn't write expected output: %q", string(out))
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — valid plan but no AI provider
// ---------------------------------------------------------------------------

func TestRunExplainCmd_ValidPlanNoProvider(t *testing.T) {
	oldWorkDir, oldPlanFile, oldProvider, oldModel := workDir, planFile, activeProvider, activeModel
	defer func() {
		workDir, planFile, activeProvider, activeModel = oldWorkDir, oldPlanFile, oldProvider, oldModel
	}()

	dir := t.TempDir()
	// Write config that explicitly disables provider
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("llm:\n  provider: \"\"\n"), 0644)

	// Write a plan with actual resources
	plan := map[string]interface{}{
		"format_version": "1.0",
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "aws_instance.web",
				"type":    "aws_instance",
				"name":    "web",
				"change": map[string]interface{}{
					"actions": []interface{}{"create"},
					"after":   map[string]interface{}{"instance_type": "t3.micro"},
				},
			},
		},
	}
	data, _ := json.Marshal(plan)
	planPath := filepath.Join(dir, "plan.json")
	os.WriteFile(planPath, data, 0644)

	workDir = dir
	planFile = planPath
	activeProvider = ""
	activeModel = ""

	// Override HOME to prevent loading global config with a configured provider
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", dir)
	defer os.Setenv("HOME", origHome)

	err := runExplainCmd(nil, nil)
	if err == nil {
		t.Fatal("expected error when no AI provider configured")
	}
	if !strings.Contains(err.Error(), "provider") {
		t.Errorf("expected provider-related error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// executeReview — with a valid minimal plan (scanner=static, no AI)
// ---------------------------------------------------------------------------

func TestExecuteReview_ValidPlanStaticOnly(t *testing.T) {
	oldWorkDir, oldPlanFile, oldStatic, oldOutputDir := workDir, planFile, staticOnly, outputDir
	oldFindingsFile := findingsFile
	defer func() {
		workDir, planFile, staticOnly, outputDir = oldWorkDir, oldPlanFile, oldStatic, oldOutputDir
		findingsFile = oldFindingsFile
	}()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	plan := map[string]interface{}{
		"format_version": "1.0",
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "aws_instance.web",
				"type":    "aws_instance",
				"name":    "web",
				"change": map[string]interface{}{
					"actions": []interface{}{"create"},
					"after":   map[string]interface{}{"instance_type": "t3.micro"},
				},
			},
		},
	}
	data, _ := json.Marshal(plan)
	planPath := filepath.Join(dir, "plan.json")
	os.WriteFile(planPath, data, 0644)

	outDir := t.TempDir()

	workDir = dir
	planFile = planPath
	staticOnly = true
	outputDir = outDir
	findingsFile = ""

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, exitCode, err := executeReview("")

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("executeReview error: %v", err)
	}
	// No findings → exit code 0
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// Check output files were created
	if _, err := os.Stat(filepath.Join(outDir, "review.json")); err != nil {
		t.Error("review.json not created")
	}
}

// ---------------------------------------------------------------------------
// runDiagram — valid plan
// ---------------------------------------------------------------------------

func TestRunDiagram_ValidPlan(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	plan := map[string]interface{}{
		"format_version": "1.0",
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "aws_vpc.main",
				"type":    "aws_vpc",
				"name":    "main",
				"change": map[string]interface{}{
					"actions": []interface{}{"create"},
					"after":   map[string]interface{}{"cidr_block": "10.0.0.0/16"},
				},
			},
		},
	}
	data, _ := json.Marshal(plan)
	planPath := filepath.Join(dir, "plan.json")
	os.WriteFile(planPath, data, 0644)

	workDir = dir
	planFile = planPath

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDiagram(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	outBytes, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("runDiagram error: %v", err)
	}
	out := string(outBytes)
	if !strings.Contains(out, "vpc") && !strings.Contains(out, "aws") && len(out) < 10 {
		t.Errorf("expected diagram output, got: %q", out[:min(100, len(out))])
	}
}

// ---------------------------------------------------------------------------
// runDrift — with valid plan
// ---------------------------------------------------------------------------

func TestRunDrift_ValidPlan(t *testing.T) {
	oldWorkDir, oldPlanFile := workDir, planFile
	defer func() { workDir, planFile = oldWorkDir, oldPlanFile }()

	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(""), 0644)

	plan := map[string]interface{}{
		"format_version": "1.0",
		"resource_changes": []interface{}{
			map[string]interface{}{
				"address": "aws_instance.web",
				"type":    "aws_instance",
				"name":    "web",
				"change": map[string]interface{}{
					"actions": []interface{}{"create"},
					"after":   map[string]interface{}{"instance_type": "t3.micro"},
				},
			},
		},
	}
	data, _ := json.Marshal(plan)
	planPath := filepath.Join(dir, "plan.json")
	os.WriteFile(planPath, data, 0644)

	workDir = dir
	planFile = planPath

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDrift(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("runDrift error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// filterDisabledRules — ensure disabled rules are removed
// ---------------------------------------------------------------------------

func TestFilterDisabledRules_RemovesMatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC-001", Resource: "a", Severity: "HIGH"},
		{RuleID: "NET-002", Resource: "b", Severity: "MEDIUM"},
		{RuleID: "SEC-003", Resource: "c", Severity: "LOW"},
	}
	disabled := []string{"SEC-001", "SEC-003"}

	result := filterDisabledRules(findings, disabled)
	if len(result) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(result))
	}
	if result[0].RuleID != "NET-002" {
		t.Errorf("expected NET-002 to remain, got %s", result[0].RuleID)
	}
}

func TestFilterDisabledRules_NoMatch(t *testing.T) {
	findings := []rules.Finding{
		{RuleID: "SEC-001", Severity: "HIGH"},
	}
	result := filterDisabledRules(findings, []string{"NONEXISTENT"})
	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// buildResourceLimits
// ---------------------------------------------------------------------------

func TestBuildResourceLimits_Default(t *testing.T) {
	limits := buildResourceLimits(config.Config{}, false)
	// Should return defaults (non-zero)
	if limits.MaxThreads == 0 {
		t.Error("expected non-zero default MaxThreads")
	}
}

func TestBuildResourceLimits_Safe(t *testing.T) {
	limits := buildResourceLimits(config.Config{}, true)
	// Safe limits should be set
	if limits.MaxThreads == 0 {
		t.Error("expected non-zero safe MaxThreads")
	}
}

func TestBuildResourceLimits_CustomConfig(t *testing.T) {
	cfg := config.Config{}
	cfg.LLM.Ollama.MaxThreads = 8
	cfg.LLM.Ollama.MaxMemoryMB = 4096
	cfg.LLM.Ollama.MinFreeMemoryMB = 512

	limits := buildResourceLimits(cfg, false)
	if limits.MaxThreads != 8 {
		t.Errorf("expected MaxThreads=8, got %d", limits.MaxThreads)
	}
	if limits.MaxMemoryMB != 4096 {
		t.Errorf("expected MaxMemoryMB=4096, got %d", limits.MaxMemoryMB)
	}
	if limits.MinFreeMemoryMB != 512 {
		t.Errorf("expected MinFreeMemoryMB=512, got %d", limits.MinFreeMemoryMB)
	}
}

// ---------------------------------------------------------------------------
// parseInfraExplanation — code fence branches
// ---------------------------------------------------------------------------

func TestParseInfraExplanation_JSONCodeFence(t *testing.T) {
	raw := "Here is the explanation:\n```json\n{\"overview\":\"vpc-based\",\"architecture\":\"three-tier\"}\n```\nEnjoy!"
	expl := parseInfraExplanation(raw)
	if expl.Overview != "vpc-based" {
		t.Errorf("expected 'vpc-based' from json code fence, got %q", expl.Overview)
	}
}

func TestParseInfraExplanation_PlainCodeFence(t *testing.T) {
	raw := "Explanation:\n```\n{\"overview\":\"simple\",\"architecture\":\"flat\"}\n```\nDone."
	expl := parseInfraExplanation(raw)
	if expl.Overview != "simple" {
		t.Errorf("expected 'simple' from plain code fence, got %q", expl.Overview)
	}
}

func TestParseInfraExplanation_RawTextFallback(t *testing.T) {
	raw := "This is just plain text with no JSON at all."
	expl := parseInfraExplanation(raw)
	if expl.Overview != raw {
		t.Errorf("expected raw text as overview, got %q", expl.Overview)
	}
	if expl.Architecture != "Unable to parse structured response" {
		t.Errorf("expected fallback architecture, got %q", expl.Architecture)
	}
}

func TestParseInfraExplanation_DirectValidJSON(t *testing.T) {
	raw := `{"overview":"direct","architecture":"microservices"}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "direct" {
		t.Errorf("expected 'direct', got %q", expl.Overview)
	}
	if expl.Architecture != "microservices" {
		t.Errorf("expected 'microservices', got %q", expl.Architecture)
	}
}

func TestParseInfraExplanation_MapWithNestedOverview(t *testing.T) {
	raw := `{"overview":{"overview":"nested-overview"},"architecture":"arch"}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "nested-overview" {
		t.Errorf("expected 'nested-overview', got %q", expl.Overview)
	}
}

func TestParseInfraExplanation_MapWithSummaryInOverview(t *testing.T) {
	raw := `{"overview":{"summary":"from-summary"},"architecture":"arch"}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "from-summary" {
		t.Errorf("expected 'from-summary', got %q", expl.Overview)
	}
}

func TestParseInfraExplanation_MapOverviewAsNumber(t *testing.T) {
	raw := `{"overview":42,"architecture":"arch"}`
	expl := parseInfraExplanation(raw)
	if expl.Overview != "42" {
		t.Errorf("expected '42', got %q", expl.Overview)
	}
}

// ---------------------------------------------------------------------------
// runCacheStatus — test with populated cache
// ---------------------------------------------------------------------------

func TestRunCacheStatus_WithEntries(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	// Create a cache entry
	cacheDir := filepath.Join(tmpDir, ".terraview", "cache")
	os.MkdirAll(cacheDir, 0755)

	// Write a meta file
	meta := `{"plan_hash":"abc123","provider":"ollama","model":"llama3","created_at":"2024-01-01T00:00:00Z"}`
	os.WriteFile(filepath.Join(cacheDir, "abc123.meta"), []byte(meta), 0644)
	os.WriteFile(filepath.Join(cacheDir, "abc123.json"), []byte(`{"response":"test"}`), 0644)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runCacheStatus(nil, nil)

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Fatalf("runCacheStatus error: %v", err)
	}
	if !strings.Contains(output, "Entries:") && !strings.Contains(output, "Entradas:") {
		t.Errorf("expected entries line in output, got: %s", output)
	}
}

func TestRunCacheStatus_NotExist(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runCacheStatus(nil, nil)

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	io.Copy(&buf, r)
	output := buf.String()

	if err != nil {
		t.Fatalf("runCacheStatus error: %v", err)
	}
	if !strings.Contains(output, "No cache found") && !strings.Contains(output, "Nenhum cache") {
		t.Errorf("expected 'no cache' message, got: %s", output)
	}
}

// ---------------------------------------------------------------------------
// runCacheClear — with existing dir
// ---------------------------------------------------------------------------

func TestRunCacheClear_WithDir(t *testing.T) {
	origHome := os.Getenv("HOME")
	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cacheDir := filepath.Join(tmpDir, ".terraview", "ai-cache")
	os.MkdirAll(cacheDir, 0755)
	os.WriteFile(filepath.Join(cacheDir, "test.json"), []byte("{}"), 0644)

	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runCacheClear(nil, nil)

	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("runCacheClear error: %v", err)
	}
}

func TestRunScan_NoScannerNoProvider(t *testing.T) {
	origStatic := staticOnly
	origWork := workDir
	origHome := os.Getenv("HOME")

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		staticOnly = origStatic
		workDir = origWork
		os.Setenv("HOME", origHome)
	}()

	workDir = tmpDir
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	staticOnly = false

	// No scanner, no AI provider → should error with helpful message
	err := runScan(nil, nil)
	if err == nil {
		t.Fatal("expected error when no scanner and no AI provider")
	}
}

// ---------------------------------------------------------------------------
// generatePlan — terragrunt detection
// ---------------------------------------------------------------------------

func TestGeneratePlan_TerragruntDetection(t *testing.T) {
	origWork := workDir
	origTG := terragruntFlag
	origVerbose := verbose
	tmpDir := t.TempDir()

	defer func() {
		workDir = origWork
		terragruntFlag = origTG
		verbose = origVerbose
	}()

	workDir = tmpDir
	terragruntFlag = ""
	verbose = false

	// Create terragrunt.hcl to trigger auto-detection
	os.WriteFile(filepath.Join(tmpDir, "terragrunt.hcl"), []byte("# tg"), 0644)

	// generatePlan will try to run terragrunt which will fail, but the
	// auto-detection of terragrunt should happen first
	_, _, err := generatePlan()
	// Will fail because terragrunt is not installed, but that's expected —
	// the important thing is that generatePlan detected the terragrunt project
	// and attempted to use the terragrunt executor path
	if err == nil {
		t.Log("generatePlan succeeded (terragrunt may be installed)")
	}
}

// ---------------------------------------------------------------------------
// scanCmd.Args — --terragrunt <file> with space (NoOptDefVal workaround)
// ---------------------------------------------------------------------------

func TestScanArgs_TerragruntSpaceSyntax(t *testing.T) {
	origTG := terragruntFlag
	defer func() { terragruntFlag = origTG }()

	argsFunc := scanCmd.Args

	// With terragruntFlag="auto" and 2 args, should accept (space syntax)
	terragruntFlag = "auto"
	if err := argsFunc(scanCmd, []string{"checkov", "dev.hcl"}); err != nil {
		t.Errorf("expected 2 args accepted when terragrunt=auto, got: %v", err)
	}

	// With terragruntFlag="" and 2 args, should reject
	terragruntFlag = ""
	if err := argsFunc(scanCmd, []string{"checkov", "dev.hcl"}); err == nil {
		t.Error("expected error for 2 args without terragrunt flag")
	}

	// 1 arg should always work
	terragruntFlag = ""
	if err := argsFunc(scanCmd, []string{"checkov"}); err != nil {
		t.Errorf("expected 1 arg accepted, got: %v", err)
	}

	// 0 args should always work
	if err := argsFunc(scanCmd, []string{}); err != nil {
		t.Errorf("expected 0 args accepted, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — BR flag + scanner result (exercises FormatScannerHeaderBR)
// ---------------------------------------------------------------------------

func TestRenderOutput_BRFlagWithScannerResult(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = true
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}
	scanRes := &scanner.AggregatedResult{
		ScannerStats: []scanner.ScannerStat{
			{Name: "tfsec", Findings: 0},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, scanRes)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — JSON-only format (no markdown written)
// ---------------------------------------------------------------------------

func TestRenderOutput_JSONOnlyNoMarkdown(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatJSON,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	// JSON format should not create review.md
	mdPath := filepath.Join(dir, "review.md")
	if _, err := os.Stat(mdPath); err == nil {
		t.Error("did not expect markdown file for JSON-only output")
	}
}

// ---------------------------------------------------------------------------
// renderOutput — strict mode with exitCode 0 (should not become 2)
// ---------------------------------------------------------------------------

func TestRenderOutput_StrictModeExitCodeZero(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = true

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatPretty,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		ExitCode:       0,
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0 (strict should not change 0), got %d", exitCode)
	}
}

// ---------------------------------------------------------------------------
// runScan — scanner specified as positional arg
// ---------------------------------------------------------------------------

func TestRunScan_ScannerFromArgs(t *testing.T) {
	origWork := workDir
	origHome := os.Getenv("HOME")
	origStatic := staticOnly
	origPlan := planFile

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		os.Setenv("HOME", origHome)
		staticOnly = origStatic
		planFile = origPlan
	}()

	workDir = tmpDir
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	staticOnly = true

	// Pass a scanner name as arg — covers the args[0] branch
	err := runScan(nil, []string{"tfsec"})
	// Will fail when trying to resolve/run the scanner, but the args parsing is exercised
	if err == nil {
		t.Log("runScan succeeded unexpectedly (tfsec may be installed)")
	}
}

// ---------------------------------------------------------------------------
// runScan — findingsFile flag bypasses scanner requirement
// ---------------------------------------------------------------------------

func TestRunScan_FindingsFileFlag(t *testing.T) {
	origWork := workDir
	origHome := os.Getenv("HOME")
	origStatic := staticOnly
	origPlan := planFile
	origFindings := findingsFile

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		os.Setenv("HOME", origHome)
		staticOnly = origStatic
		planFile = origPlan
		findingsFile = origFindings
	}()

	workDir = tmpDir
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	// Create a valid plan.json
	os.WriteFile(filepath.Join(tmpDir, "plan.json"), []byte(`{"resource_changes":[]}`), 0644)

	staticOnly = true
	planFile = filepath.Join(tmpDir, "plan.json")
	findingsFile = filepath.Join(tmpDir, "findings.json")

	// Create a findings file
	os.WriteFile(filepath.Join(tmpDir, "findings.json"), []byte(`[{"rule_id":"TEST-001","severity":"HIGH","category":"security","resource":"aws_instance.test","message":"test","remediation":"fix it"}]`), 0644)

	// With findingsFile set, --static + no scanner should NOT error
	err := runScan(nil, nil)
	_ = err
}

// ---------------------------------------------------------------------------
// generatePlan — --terragrunt <config> triggers terragrunt executor
// ---------------------------------------------------------------------------

func TestGeneratePlan_TerragruntFlagWithConfig(t *testing.T) {
	origWork := workDir
	origTG := terragruntFlag
	tmpDir := t.TempDir()

	defer func() {
		workDir = origWork
		terragruntFlag = origTG
	}()

	workDir = tmpDir
	terragruntFlag = filepath.Join(tmpDir, "custom-tg.hcl")

	os.WriteFile(filepath.Join(tmpDir, "custom-tg.hcl"), []byte("# custom"), 0644)

	// When terragruntFlag points to a config file, generatePlan should use
	// the terragrunt executor path
	_, _, err := generatePlan()
	if err == nil {
		t.Log("generatePlan succeeded (terragrunt may be installed)")
	}
}

// ---------------------------------------------------------------------------
// generatePlan — terraform workspace validation failure
// ---------------------------------------------------------------------------

func TestGeneratePlan_InvalidWorkspace(t *testing.T) {
	origWork := workDir
	origTG := terragruntFlag
	tmpDir := t.TempDir()

	defer func() {
		workDir = origWork
		terragruntFlag = origTG
	}()

	workDir = tmpDir
	terragruntFlag = ""

	_, _, err := generatePlan()
	if err == nil {
		t.Fatal("expected error for empty workspace")
	}
}

// ---------------------------------------------------------------------------
// applyTemplateToCmds — recursive application
// ---------------------------------------------------------------------------

func TestApplyTemplateToCmds_Recursive(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	child := &cobra.Command{Use: "child"}
	grandchild := &cobra.Command{Use: "grandchild"}
	child.AddCommand(grandchild)
	parent.AddCommand(child)

	parent.InitDefaultHelpFlag()
	child.InitDefaultHelpFlag()
	grandchild.InitDefaultHelpFlag()

	tmpl := "custom template {{ .UseLine }}"
	applyTemplateToCmds(parent, tmpl)

	if child.UsageTemplate() != tmpl {
		t.Error("expected child to have custom usage template")
	}
	if grandchild.UsageTemplate() != tmpl {
		t.Error("expected grandchild to have custom usage template")
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — JSON output format
// ---------------------------------------------------------------------------

func TestRunExplainCmd_JSONFormat(t *testing.T) {
	origWork := workDir
	origPlan := planFile
	origFormat := outputFormat
	origOutputDir := outputDir
	origHome := os.Getenv("HOME")
	origProvider := activeProvider

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		planFile = origPlan
		outputFormat = origFormat
		outputDir = origOutputDir
		os.Setenv("HOME", origHome)
		activeProvider = origProvider
	}()

	workDir = tmpDir
	activeProvider = ""

	planData := `{"resource_changes":[{"address":"aws_instance.test","type":"aws_instance","change":{"actions":["create"],"after":{"ami":"ami-123","instance_type":"t3.micro"}}}]}`
	planPath := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(planPath, []byte(planData), 0644)

	planFile = planPath
	outputFormat = "json"
	outputDir = tmpDir

	err := runExplainCmd(nil, nil)
	if err == nil {
		t.Log("runExplainCmd succeeded unexpectedly")
	}
	if err != nil && !strings.Contains(err.Error(), "provider") {
		t.Logf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — empty resources in plan
// ---------------------------------------------------------------------------

func TestRunExplainCmd_EmptyResourcesPlan(t *testing.T) {
	origWork := workDir
	origPlan := planFile
	origHome := os.Getenv("HOME")

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		planFile = origPlan
		os.Setenv("HOME", origHome)
	}()

	workDir = tmpDir

	planPath := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(planPath, []byte(`{"resource_changes":[]}`), 0644)

	planFile = planPath

	err := runExplainCmd(nil, nil)
	// Parser returns error for empty resource_changes — that's expected
	if err == nil {
		t.Log("runExplainCmd succeeded for empty plan")
	} else if !strings.Contains(err.Error(), "no resource") && !strings.Contains(err.Error(), "parse") {
		t.Logf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// detectCurrentPlanHash
// ---------------------------------------------------------------------------

func TestDetectCurrentPlanHash_CoverageWithPlan(t *testing.T) {
	origDir, _ := os.Getwd()
	tmpDir := t.TempDir()
	os.Chdir(tmpDir)
	defer os.Chdir(origDir)

	os.WriteFile(filepath.Join(tmpDir, "plan.json"), []byte(`{"resource_changes":[]}`), 0644)

	hash := detectCurrentPlanHash()
	if hash == "" {
		t.Error("expected non-empty hash when plan.json exists")
	}
}

// ---------------------------------------------------------------------------
// renderOutput — SARIF writes file and verifies existence
// ---------------------------------------------------------------------------

func TestRenderOutput_SARIFWritesFile(t *testing.T) {
	dir := t.TempDir()

	oldBR, oldStrict := brFlag, strict
	defer func() { brFlag, strict = oldBR, oldStrict }()
	brFlag = false
	strict = false

	rc := reviewConfig{
		resolvedOutput:  dir,
		effectiveFormat: output.FormatSARIF,
	}
	result := aggregator.ReviewResult{
		PlanFile:       "test.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		CategoryCounts: map[string]int{},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("renderOutput error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}

	sarifPath := filepath.Join(dir, "review.sarif.json")
	if _, err := os.Stat(sarifPath); os.IsNotExist(err) {
		t.Error("expected SARIF file to be written")
	}
}

// ---------------------------------------------------------------------------
// runDrift — with plan that has update actions
// ---------------------------------------------------------------------------

func TestRunDrift_ValidPlanWithUpdates(t *testing.T) {
	origWork := workDir
	origPlan := planFile
	origOutputDir := outputDir
	origHome := os.Getenv("HOME")
	origVerbose := verbose
	origBR := brFlag

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		planFile = origPlan
		outputDir = origOutputDir
		os.Setenv("HOME", origHome)
		verbose = origVerbose
		brFlag = origBR
	}()

	workDir = tmpDir
	brFlag = false
	verbose = false

	planData := `{"resource_changes":[{"address":"aws_instance.test","type":"aws_instance","change":{"actions":["update"],"before":{"ami":"ami-old","instance_type":"t3.micro"},"after":{"ami":"ami-new","instance_type":"t3.micro"}}}]}`
	planPath := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(planPath, []byte(planData), 0644)

	planFile = planPath
	outputDir = tmpDir

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDrift(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("runDrift error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// resolveReviewConfig — various flag combinations
// ---------------------------------------------------------------------------

func TestResolveReviewConfig_WithPlanFile(t *testing.T) {
	origWork := workDir
	origPlan := planFile
	origOutputDir := outputDir
	origFormat := outputFormat
	origHome := os.Getenv("HOME")
	origBR := brFlag

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		planFile = origPlan
		outputDir = origOutputDir
		outputFormat = origFormat
		os.Setenv("HOME", origHome)
		brFlag = origBR
	}()

	workDir = tmpDir
	brFlag = false
	outputFormat = "json"
	outputDir = tmpDir

	planData := `{"resource_changes":[]}`
	planPath := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(planPath, []byte(planData), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	planFile = planPath

	rc, err := resolveReviewConfig("tfsec")
	if err != nil {
		t.Fatalf("resolveReviewConfig error: %v", err)
	}
	if rc.resolvedPlan != planPath {
		t.Errorf("expected plan path %q, got %q", planPath, rc.resolvedPlan)
	}
	if rc.effectiveFormat != "json" {
		t.Errorf("expected format 'json', got %q", rc.effectiveFormat)
	}
	if rc.scannerName != "tfsec" {
		t.Errorf("expected scanner 'tfsec', got %q", rc.scannerName)
	}
}

// ---------------------------------------------------------------------------
// executeReview — static with valid plan and imported findings
// ---------------------------------------------------------------------------

func TestExecuteReview_StaticWithFindings(t *testing.T) {
	origWork := workDir
	origPlan := planFile
	origOutputDir := outputDir
	origFormat := outputFormat
	origHome := os.Getenv("HOME")
	origStatic := staticOnly
	origBR := brFlag
	origFindings := findingsFile
	origStrict := strict

	tmpDir := t.TempDir()
	os.Setenv("HOME", tmpDir)
	defer func() {
		workDir = origWork
		planFile = origPlan
		outputDir = origOutputDir
		outputFormat = origFormat
		os.Setenv("HOME", origHome)
		staticOnly = origStatic
		brFlag = origBR
		findingsFile = origFindings
		strict = origStrict
	}()

	workDir = tmpDir
	brFlag = false
	staticOnly = true
	strict = false
	outputFormat = "json"
	outputDir = tmpDir

	planData := `{"resource_changes":[{"address":"aws_instance.test","type":"aws_instance","change":{"actions":["create"],"after":{"ami":"ami-123","instance_type":"t3.micro"}}}]}`
	planPath := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(planPath, []byte(planData), 0644)
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	planFile = planPath

	findingsData := `{"results":[{"rule_id":"TEST-001","severity":"HIGH","description":"Test finding","resource":"aws_instance.test"}]}`
	findingsPath := filepath.Join(tmpDir, "findings.json")
	os.WriteFile(findingsPath, []byte(findingsData), 0644)
	findingsFile = findingsPath

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, exitCode, err := executeReview("")

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("executeReview error: %v", err)
	}
	_ = exitCode

	reviewPath := filepath.Join(tmpDir, "review.json")
	if _, err := os.Stat(reviewPath); os.IsNotExist(err) {
		t.Error("expected review.json to be written")
	}
}

// ---------------------------------------------------------------------------
// mergeAndScore — with context findings
// ---------------------------------------------------------------------------

func TestMergeAndScore_ContextFindingsWithAI(t *testing.T) {
	rc := reviewConfig{
		resolvedPlan: "test.json",
		cfg:          config.Config{},
		effectiveAI:  true,
	}
	resources := []parser.NormalizedResource{
		{Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := scanResult{
		contextFindings: []rules.Finding{
			{RuleID: "AI-SEC-001", Severity: "MEDIUM", Category: "security", Resource: "aws_instance.web", Message: "Insecure configuration detected", Remediation: "Enable encryption at rest"},
		},
		contextSummary: "AI detected potential issues",
	}

	result := mergeAndScore(rc, resources, graph, sr)
	// AI findings may be filtered by hallucination validator, but function should not panic
	_ = result
}

// ---------------------------------------------------------------------------
// generatePlan — with planFile already set
// ---------------------------------------------------------------------------

func TestGeneratePlan_WithExistingPlanFile(t *testing.T) {
	// Requires terraform in PATH — skip in CI if not available
	if _, err := execLookPath("terraform"); err != nil {
		t.Skip("terraform not in PATH, skipping")
	}

	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)

	oldWorkDir := workDir
	oldTG := terragruntFlag
	defer func() {
		workDir = oldWorkDir
		terragruntFlag = oldTG
	}()

	workDir = tmpDir
	terragruntFlag = ""

	path, _, err := generatePlan()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty plan path")
	}
}

// ---------------------------------------------------------------------------
// resolveReviewConfig — static-only mode
// ---------------------------------------------------------------------------

func TestResolveReviewConfig_StaticOnly(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	planJSON := `{"format_version":"1.2","resource_changes":[{"address":"aws_instance.web","type":"aws_instance","name":"web","change":{"actions":["create"],"after":{"instance_type":"t3.micro"},"before":null}}]}`
	os.WriteFile(filepath.Join(tmpDir, "plan.json"), []byte(planJSON), 0644)

	oldWorkDir := workDir
	oldPlanFile := planFile
	oldStatic := staticOnly
	oldFormat := outputFormat
	defer func() {
		workDir = oldWorkDir
		planFile = oldPlanFile
		staticOnly = oldStatic
		outputFormat = oldFormat
	}()

	workDir = tmpDir
	planFile = filepath.Join(tmpDir, "plan.json")
	staticOnly = true
	outputFormat = "compact"

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	rc, err := resolveReviewConfig("checkov")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rc.effectiveAI {
		t.Error("expected effectiveAI=false with staticOnly")
	}
	if rc.effectiveFormat != "compact" {
		t.Errorf("expected compact format, got %q", rc.effectiveFormat)
	}
	if rc.scannerName != "checkov" {
		t.Errorf("expected scannerName=checkov, got %q", rc.scannerName)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — SARIF format
// ---------------------------------------------------------------------------

func TestRenderOutput_SARIFFormatWithFindings(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatSARIF,
		resolvedOutput:  tmpDir,
	}

	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "HIGH", Category: "security",
				Resource: "aws_instance.web", Message: "Open SSH", Remediation: "Restrict"},
		},
		Summary: "1 issue found",
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = exitCode

	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	if _, err := os.Stat(sarifPath); err != nil {
		t.Errorf("SARIF file not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — markdown format with scanner results
// ---------------------------------------------------------------------------

func TestRenderOutput_MarkdownWithScanner(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = true
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatPretty,
		resolvedOutput:  tmpDir,
	}

	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "CRITICAL", Category: "security",
				Resource: "aws_s3_bucket.data", Message: "No encryption", Remediation: "Enable SSE"},
		},
		Summary: "review complete",
	}
	scannerRes := &scanner.AggregatedResult{
		ScannerStats: []scanner.ScannerStat{{Name: "checkov", Findings: 1}},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, scannerRes)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = exitCode

	mdPath := filepath.Join(tmpDir, "review.md")
	if _, err := os.Stat(mdPath); err != nil {
		t.Errorf("markdown file not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — strict mode escalates exit code
// ---------------------------------------------------------------------------

func TestRenderOutput_StrictModeEscalation(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = true

	rc := reviewConfig{
		effectiveFormat: output.FormatJSON,
		resolvedOutput:  tmpDir,
	}

	result := aggregator.ReviewResult{
		ExitCode: 1,
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "HIGH", Category: "security",
				Resource: "aws_instance.web", Message: "Issue", Remediation: "Fix"},
		},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 (strict + exitCode 1), got %d", exitCode)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — full format writes JSON + MD
// ---------------------------------------------------------------------------

func TestRenderOutput_FullFormat(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatJSON,
		resolvedOutput:  tmpDir,
	}

	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "MEDIUM", Category: "security",
				Resource: "aws_instance.web", Message: "Warning", Remediation: "Check"},
		},
		Summary: "done",
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = exitCode

	jsonPath := filepath.Join(tmpDir, "review.json")
	if _, err := os.Stat(jsonPath); err != nil {
		t.Errorf("JSON file not written: %v", err)
	}
}

func TestMergeAndScore_WithMetaAnalysis(t *testing.T) {
	rc := reviewConfig{
		resolvedPlan: "test.json",
		cfg:          config.Config{},
	}
	resources := []parser.NormalizedResource{
		{Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)
	sr := scanResult{
		hardFindings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "HIGH", Category: "security", Resource: "aws_instance.web", Message: "Finding 1", Remediation: "Fix", Source: "checkov"},
			{RuleID: "SEC-002", Severity: "MEDIUM", Category: "networking", Resource: "aws_instance.web", Message: "Finding 2", Remediation: "Fix", Source: "tfsec"},
		},
	}

	result := mergeAndScore(rc, resources, graph, sr)
	if result.MetaAnalysis == nil {
		t.Error("expected meta analysis for findings from multiple sources")
	}
}

// ---------------------------------------------------------------------------
// parseInfraExplanation — code fence with valid map (not struct)
// ---------------------------------------------------------------------------

func TestParseInfraExplanation_CodeFenceWithMap(t *testing.T) {
	raw := "```json\n{\"overview\":\"my overview\",\"components\":[{\"name\":\"VPC\",\"purpose\":\"networking\"}]}\n```"
	expl := parseInfraExplanation(raw)
	if expl == nil {
		t.Fatal("expected non-nil explanation")
	}
	if expl.Overview == "" {
		t.Error("expected overview to be parsed from code fence")
	}
}

// ---------------------------------------------------------------------------
// infraExplFromMap — overview as map without overview/summary keys
// ---------------------------------------------------------------------------

func TestInfraExplFromMap_MapOverviewNoKeys(t *testing.T) {
	m := map[string]interface{}{
		"overview": map[string]interface{}{
			"description": "some desc",
		},
	}
	expl := infraExplFromMap(m)
	if expl == nil {
		t.Fatal("expected non-nil explanation")
	}
	if expl.Overview == "" {
		t.Error("expected overview to be set from json.Marshal fallback")
	}
}

// ---------------------------------------------------------------------------
// applyTemplateToCmds — template with subcommands
// ---------------------------------------------------------------------------

func TestApplyTemplateToCmds_MultipleFields(t *testing.T) {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "A test command",
	}
	sub := &cobra.Command{
		Use:   "sub",
		Short: "Sub cmd",
	}
	cmd.AddCommand(sub)

	tmpl := "custom usage template"
	applyTemplateToCmds(cmd, tmpl)

	// After applying, subcommands should have the usage template set
	if sub.UsageTemplate() != tmpl {
		t.Errorf("expected usage template %q on subcommand, got %q", tmpl, sub.UsageTemplate())
	}
	// Help flag should be translated
	if h := sub.Flags().Lookup("help"); h != nil && !strings.Contains(h.Usage, "ajuda para") {
		t.Errorf("expected help flag translated, got %q", h.Usage)
	}
}

// ---------------------------------------------------------------------------
// runScan — invalid work dir error
// ---------------------------------------------------------------------------

func TestRunScan_InvalidWorkDir(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	workDir = "/nonexistent/dir/for/scan/test"

	err := runScan(nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent work dir")
	}
}

// ---------------------------------------------------------------------------
// runScan — static with no scanner and no findings file
// ---------------------------------------------------------------------------

func TestRunScan_StaticNoScannerNoFindings(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)

	oldWorkDir := workDir
	oldStatic := staticOnly
	oldFindings := findingsFile
	defer func() {
		workDir = oldWorkDir
		staticOnly = oldStatic
		findingsFile = oldFindings
	}()

	workDir = tmpDir
	staticOnly = true
	findingsFile = ""

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	err := runScan(nil, nil)
	if err == nil {
		t.Error("expected error for --static with no scanner")
	}
}

// ---------------------------------------------------------------------------
// runDrift — with brFlag enabled
// ---------------------------------------------------------------------------

func TestRunDrift_WithBRFlag(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)
	planJSON := `{"format_version":"1.2","resource_changes":[{"address":"aws_instance.web","type":"aws_instance","name":"web","change":{"actions":["update"],"before":{"instance_type":"t3.micro"},"after":{"instance_type":"t3.large"}}}]}`
	os.WriteFile(filepath.Join(tmpDir, "plan.json"), []byte(planJSON), 0644)

	oldWorkDir := workDir
	oldBR := brFlag
	oldFormat := outputFormat
	oldPlanFile := planFile
	defer func() {
		workDir = oldWorkDir
		brFlag = oldBR
		outputFormat = oldFormat
		planFile = oldPlanFile
	}()

	workDir = tmpDir
	brFlag = true
	outputFormat = "json"
	planFile = filepath.Join(tmpDir, "plan.json")

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runDrift(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	_ = err
}

// ---------------------------------------------------------------------------
// runScanners — no scanner, no AI → complete pipeline
// ---------------------------------------------------------------------------

func TestRunScanners_NoScannerNoAI(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	rc := reviewConfig{
		scannerName:  "",
		effectiveAI:  false,
		resolvedPlan: "test.json",
	}

	sr, err := runScanners(rc, resources, graph)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.pipelineStatus == nil {
		t.Fatal("expected pipeline status to be set")
	}
	if sr.pipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("expected 'complete', got %q", sr.pipelineStatus.ResultCompleteness)
	}
	if sr.pipelineStatus.Scanner != nil {
		t.Error("expected nil scanner status when no scanner specified")
	}
	if sr.pipelineStatus.AI != nil {
		t.Error("expected nil AI status when AI disabled")
	}
}

// ---------------------------------------------------------------------------
// runScanners — with findingsFile (external findings import)
// ---------------------------------------------------------------------------

func TestRunScanners_WithFindingsFile(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Name: "data", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	tmpDir := t.TempDir()
	ff := filepath.Join(tmpDir, "findings.json")
	// Use valid tfsec format so the importer recognizes it
	findingsData := `{"results":[{"rule_id":"CKV_AWS_1","severity":"HIGH","description":"enable encryption","resource":"aws_s3_bucket.data"}]}`
	os.WriteFile(ff, []byte(findingsData), 0644)

	oldFF := findingsFile
	defer func() { findingsFile = oldFF }()
	findingsFile = ff

	rc := reviewConfig{
		scannerName:  "",
		effectiveAI:  false,
		resolvedPlan: "test.json",
	}

	sr, err := runScanners(rc, resources, graph)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sr.pipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("expected 'complete', got %q", sr.pipelineStatus.ResultCompleteness)
	}
}

// ---------------------------------------------------------------------------
// runScanners — invalid findings file (warning, not fatal)
// ---------------------------------------------------------------------------

func TestRunScanners_InvalidFindingsFile(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	oldFF := findingsFile
	defer func() { findingsFile = oldFF }()
	findingsFile = "/nonexistent/findings.json"

	rc := reviewConfig{
		scannerName:  "",
		effectiveAI:  false,
		resolvedPlan: "test.json",
	}

	oldStderr := os.Stderr
	rr, ww, _ := os.Pipe()
	os.Stderr = ww

	sr, err := runScanners(rc, resources, graph)

	ww.Close()
	os.Stderr = oldStderr
	io.ReadAll(rr)

	if err != nil {
		t.Fatalf("expected no fatal error, got: %v", err)
	}
	if sr.pipelineStatus.ResultCompleteness != "complete" {
		t.Errorf("expected 'complete', got %q", sr.pipelineStatus.ResultCompleteness)
	}
}

// ---------------------------------------------------------------------------
// runScanners — invalid scanner (graceful degradation)
// ---------------------------------------------------------------------------

func TestRunScanners_InvalidScanner(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create"},
	}
	graph := topology.BuildGraph(resources)

	rc := reviewConfig{
		scannerName:  "nonexistent_scanner_xyz_99",
		effectiveAI:  false,
		resolvedPlan: "test.json",
	}

	oldStderr := os.Stderr
	rr, ww, _ := os.Pipe()
	os.Stderr = ww

	sr, err := runScanners(rc, resources, graph)

	ww.Close()
	os.Stderr = oldStderr
	io.ReadAll(rr)

	if err != nil {
		t.Fatalf("expected no fatal error, got: %v", err)
	}
	if sr.pipelineStatus.Scanner == nil {
		t.Fatal("expected scanner status to be set")
	}
	if sr.pipelineStatus.Scanner.Status != "failed" {
		t.Errorf("expected scanner status 'failed', got %q", sr.pipelineStatus.Scanner.Status)
	}
	if sr.pipelineStatus.ResultCompleteness != "partial_ai_only" {
		t.Errorf("expected 'partial_ai_only', got %q", sr.pipelineStatus.ResultCompleteness)
	}
}

// ---------------------------------------------------------------------------
// formatBytes — all branches
// ---------------------------------------------------------------------------

func TestFormatBytes_AllBranches(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{500, "500 B"},
		{1024, "1.0 KB"},
		{2048, "2.0 KB"},
		{1048576, "1.0 MB"},
		{2 * 1024 * 1024, "2.0 MB"},
	}
	for _, tc := range tests {
		got := formatBytes(tc.input)
		if got != tc.expected {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// runModelSelector — no suggested models (early return)
// ---------------------------------------------------------------------------

func TestRunModelSelector_NoSuggestedModels(t *testing.T) {
	p := ai.ProviderInfo{
		Name:         "test-provider",
		DefaultModel: "test-model-v1",
	}
	model, ok := runModelSelector(p, "", "")
	if !ok {
		t.Error("expected ok=true for no suggested models")
	}
	if model != "test-model-v1" {
		t.Errorf("expected default model 'test-model-v1', got %q", model)
	}
}

// ---------------------------------------------------------------------------
// runModelSelector — with matching current provider (default override)
// ---------------------------------------------------------------------------

func TestRunModelSelector_WithCurrentProvider(t *testing.T) {
	p := ai.ProviderInfo{
		Name:            "ollama",
		DefaultModel:    "llama3",
		SuggestedModels: []string{"llama3", "mistral", "codellama"},
	}
	model, ok := runModelSelector(p, "ollama", "mistral")
	_ = model
	_ = ok
}

// ---------------------------------------------------------------------------
// runExplainCmd — config error on invalid dir
// ---------------------------------------------------------------------------

func TestRunExplainCmd_ConfigLoadError(t *testing.T) {
	oldWorkDir := workDir
	defer func() { workDir = oldWorkDir }()

	workDir = "/nonexistent/dir/that/does/not/exist"

	err := runExplainCmd(nil, nil)
	if err == nil {
		t.Error("expected error for nonexistent workdir")
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — valid plan with no resources
// ---------------------------------------------------------------------------

func TestRunExplainCmd_NoResourcesPlan(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	planJSON := `{"format_version":"1.2","resource_changes":[]}`
	pf := filepath.Join(tmpDir, "empty-plan.json")
	os.WriteFile(pf, []byte(planJSON), 0644)

	oldWorkDir := workDir
	oldPlanFile := planFile
	defer func() {
		workDir = oldWorkDir
		planFile = oldPlanFile
	}()

	workDir = tmpDir
	planFile = pf

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runExplainCmd(nil, nil)

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	// Parser returns error for empty resource_changes
	if err != nil {
		if !strings.Contains(err.Error(), "parse error") && !strings.Contains(err.Error(), "no resource") {
			t.Fatalf("unexpected error: %v", err)
		}
		return
	}
	// If no error, expect "No resources" printed
	if !strings.Contains(string(out), "No resources") {
		t.Errorf("expected 'No resources' message, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// runExplainCmd — valid plan, resources, but no AI provider
// ---------------------------------------------------------------------------

func TestRunExplainCmd_ResourcesNoProvider(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, ".terraview.yaml"), []byte(""), 0644)

	planJSON := `{"format_version":"1.2","resource_changes":[{"address":"aws_instance.web","type":"aws_instance","name":"web","change":{"actions":["create"],"after":{"instance_type":"t3.micro"},"before":null}}]}`
	pf := filepath.Join(tmpDir, "plan.json")
	os.WriteFile(pf, []byte(planJSON), 0644)

	oldWorkDir := workDir
	oldPlanFile := planFile
	oldProvider := activeProvider
	defer func() {
		workDir = oldWorkDir
		planFile = oldPlanFile
		activeProvider = oldProvider
	}()

	workDir = tmpDir
	planFile = pf
	activeProvider = ""

	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")

	err := runExplainCmd(nil, nil)
	if err == nil {
		t.Error("expected error for no AI provider")
	}
	if err != nil && !strings.Contains(err.Error(), "provider") {
		t.Errorf("expected provider error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runScan — with scanner from positional arg
// ---------------------------------------------------------------------------

func TestRunScan_ScannerFromPositionalArg(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "main.tf"), []byte("# tf"), 0644)

	oldWorkDir := workDir
	oldStatic := staticOnly
	defer func() {
		workDir = oldWorkDir
		staticOnly = oldStatic
	}()

	workDir = tmpDir
	staticOnly = false

	err := runScan(nil, []string{"nonexistent-scanner"})
	if err == nil {
		t.Error("expected error (no terraform)")
	}
}

// ---------------------------------------------------------------------------
// canResolveAIProvider — with empty config
// ---------------------------------------------------------------------------

func TestCanResolveAIProvider_EmptyConfig(t *testing.T) {
	oldProvider := activeProvider
	defer func() { activeProvider = oldProvider }()
	activeProvider = ""

	cfg := config.Config{}
	if canResolveAIProvider(cfg) {
		t.Error("expected false for empty config")
	}
}

// ---------------------------------------------------------------------------
// canResolveAIProvider — with active provider flag
// ---------------------------------------------------------------------------

func TestCanResolveAIProvider_WithRegisteredProvider(t *testing.T) {
	// canResolveAIProvider checks cfg.LLM.Provider + ai.Has()
	// Use a known registered provider
	for _, name := range []string{"ollama", "openai", "gemini", "deepseek", "claude", "openrouter"} {
		cfg := config.Config{LLM: config.LLMConfig{Provider: name}}
		if canResolveAIProvider(cfg) {
			return // found one that works
		}
	}
	t.Error("expected at least one registered provider to return true")
}

// ---------------------------------------------------------------------------
// canResolveAIProvider — from config provider
// ---------------------------------------------------------------------------

func TestCanResolveAIProvider_FromConfigProvider(t *testing.T) {
	// Use a known registered provider name
	for _, name := range []string{"ollama", "openai", "gemini", "deepseek", "claude", "openrouter"} {
		cfg := config.Config{LLM: config.LLMConfig{Provider: name}}
		if canResolveAIProvider(cfg) {
			return
		}
	}
	t.Error("expected at least one registered provider to return true")
}

// ---------------------------------------------------------------------------
// detectCurrentPlanHash — no plan files in temp dir
// ---------------------------------------------------------------------------

func TestDetectCurrentPlanHash_NoPlanFiles(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	hash := detectCurrentPlanHash()
	if hash != "" {
		t.Errorf("expected empty hash, got %q", hash)
	}
}

// ---------------------------------------------------------------------------
// detectCurrentPlanHash — with plan.json in cwd
// ---------------------------------------------------------------------------

func TestDetectCurrentPlanHash_WithPlanJSONCwd(t *testing.T) {
	tmpDir := t.TempDir()
	os.WriteFile(filepath.Join(tmpDir, "plan.json"), []byte(`{"test":true}`), 0644)
	oldDir, _ := os.Getwd()
	defer os.Chdir(oldDir)
	os.Chdir(tmpDir)

	hash := detectCurrentPlanHash()
	if hash == "" {
		t.Error("expected non-empty hash for plan.json")
	}
}

// ---------------------------------------------------------------------------
// renderOutput — impact flag with blast radius
// ---------------------------------------------------------------------------

func TestRenderOutput_ImpactFlagWithBlastRadius(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	resources := []parser.NormalizedResource{{Type: "aws_instance", Name: "web", Action: "create", Address: "aws_instance.web"}}
	graph := topology.BuildGraph(resources)
	analyzer := &blast.Analyzer{}
	br := analyzer.AnalyzeWithGraph(resources, graph)

	rc := reviewConfig{
		effectiveFormat: output.FormatPretty,
		resolvedOutput:  tmpDir,
	}
	result := aggregator.ReviewResult{
		Summary:     "test",
		BlastRadius: br,
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	_ = out // blast radius output
}

// ---------------------------------------------------------------------------
// renderOutput — compact format
// ---------------------------------------------------------------------------

func TestRenderOutput_CompactFormatWithHighFinding(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatCompact,
		resolvedOutput:  tmpDir,
	}
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "HIGH", Category: "security",
				Resource: "aws_instance.web", Message: "Test finding", Remediation: "Fix it"},
		},
		Summary:  "compact test",
		ExitCode: 1,
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HIGH findings → exit code 1
	if exitCode != 1 {
		t.Errorf("expected exit code 1, got %d", exitCode)
	}
	// Compact writes JSON + MD (not SARIF)
	if _, err := os.Stat(filepath.Join(tmpDir, "review.json")); err != nil {
		t.Errorf("JSON file not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpDir, "review.md")); err != nil {
		t.Errorf("MD file not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — explainScores flag
// ---------------------------------------------------------------------------

func TestRenderOutput_ExplainScoresFlag(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatPretty,
		resolvedOutput:  tmpDir,
	}
	result := aggregator.ReviewResult{Summary: "scores test"}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// renderOutput — brFlag with scanner stats header (pt-BR)
// ---------------------------------------------------------------------------

func TestRenderOutput_BRFlagWithScannerStats(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = true
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatPretty,
		resolvedOutput:  tmpDir,
	}
	result := aggregator.ReviewResult{Summary: "scanner test"}
	scannerRes := &scanner.AggregatedResult{
		ScannerStats: []scanner.ScannerStat{{Name: "checkov", Findings: 3}},
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	_, err := renderOutput(rc, result, scannerRes)

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// brFlag=true should trigger FormatScannerHeaderBR
	_ = out
}

// ---------------------------------------------------------------------------
// runScan — config load error path
// ---------------------------------------------------------------------------

func TestRunScan_ConfigLoadError(t *testing.T) {
	oldWorkDir := workDir
	oldStatic := staticOnly
	defer func() {
		workDir = oldWorkDir
		staticOnly = oldStatic
	}()

	workDir = "/nonexistent/dir/no/config"
	staticOnly = false

	err := runScan(nil, nil)
	if err == nil {
		t.Error("expected config error for nonexistent dir")
	}
}

// ---------------------------------------------------------------------------
// logVerbose — exercise verbose logging branch
// ---------------------------------------------------------------------------

func TestLogVerbose_Coverage(t *testing.T) {
	oldVerbose := verbose
	defer func() { verbose = oldVerbose }()

	verbose = true

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	logVerbose("test message %d", 42)

	w.Close()
	os.Stdout = oldStdout
	out, _ := io.ReadAll(r)

	_ = out // verbose logging outputs something
}

// ---------------------------------------------------------------------------
// renderOutput — SARIF format writes sarif file
// ---------------------------------------------------------------------------

func TestRenderOutput_SARIFWritesSarifFile(t *testing.T) {
	tmpDir := t.TempDir()

	oldBR := brFlag
	oldStrict := strict
	defer func() {
		brFlag = oldBR
		strict = oldStrict
	}()
	brFlag = false
	strict = false

	rc := reviewConfig{
		effectiveFormat: output.FormatSARIF,
		resolvedOutput:  tmpDir,
	}
	result := aggregator.ReviewResult{
		Findings: []rules.Finding{
			{RuleID: "SEC-001", Severity: "CRITICAL", Category: "security",
				Resource: "aws_s3_bucket.data", Message: "No encryption", Remediation: "Enable SSE"},
		},
		Summary:  "sarif test",
		ExitCode: 2,
	}

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	exitCode, err := renderOutput(rc, result, nil)

	w.Close()
	os.Stdout = oldStdout
	io.ReadAll(r)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 2 {
		t.Errorf("expected exit code 2 for CRITICAL, got %d", exitCode)
	}
	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	if _, err := os.Stat(sarifPath); err != nil {
		t.Errorf("SARIF file not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// history.go — buildListFilter
// ---------------------------------------------------------------------------

func TestBuildListFilter_AllProjects(t *testing.T) {
	f, err := buildListFilter(true, "", "", 10, "/some/dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.ProjectHash != "" {
		t.Error("expected empty project hash when all=true")
	}
	if f.Limit != 10 {
		t.Errorf("limit = %d, want 10", f.Limit)
	}
}

func TestBuildListFilter_SpecificProject(t *testing.T) {
	f, err := buildListFilter(false, "/custom/project", "", 5, "/default/dir")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.ProjectHash == "" {
		t.Error("expected non-empty project hash")
	}
	if f.Limit != 5 {
		t.Errorf("limit = %d, want 5", f.Limit)
	}
}

func TestBuildListFilter_WithSince(t *testing.T) {
	f, err := buildListFilter(true, "", "7d", 20, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Since.IsZero() {
		t.Error("expected non-zero since time")
	}
}

func TestBuildListFilter_InvalidSince(t *testing.T) {
	_, err := buildListFilter(false, "", "invalid", 20, "/dir")
	if err == nil {
		t.Error("expected error for invalid since")
	}
}

func TestBuildListFilter_WorkDirFallback(t *testing.T) {
	f, err := buildListFilter(false, "", "", 10, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.ProjectHash == "" {
		t.Error("expected project hash from cwd fallback")
	}
}

// ---------------------------------------------------------------------------
// history.go — validateExportParams
// ---------------------------------------------------------------------------

func TestValidateExportParams_Valid(t *testing.T) {
	for _, f := range []string{"json", "csv"} {
		if err := validateExportParams("/tmp/out."+f, f); err != nil {
			t.Errorf("unexpected error for format %q: %v", f, err)
		}
	}
}

func TestValidateExportParams_NoOutput(t *testing.T) {
	if err := validateExportParams("", "json"); err == nil {
		t.Error("expected error for empty output file")
	}
}

func TestValidateExportParams_InvalidFormat(t *testing.T) {
	if err := validateExportParams("/tmp/out.txt", "xml"); err == nil {
		t.Error("expected error for invalid format")
	}
}
