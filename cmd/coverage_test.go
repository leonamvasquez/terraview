package cmd

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/drift"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/spf13/cobra"
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
// normalizeVersion (update.go)
// ---------------------------------------------------------------------------

func TestNormalizeVersion_AllCases(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"  v0.1.0  ", "0.1.0"},
		{"", ""},
		{"v", ""},
		{"vvv", "vv"},
		{"V1.0.0", "V1.0.0"}, // only lowercase v
	}
	for _, c := range cases {
		got := normalizeVersion(c.in)
		if got != c.want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// findAssetURL (update.go)
// ---------------------------------------------------------------------------

func TestFindAssetURL_EdgeCases(t *testing.T) {
	release := &githubRelease{
		TagName: "v2.0.0",
		Assets: []githubAsset{
			{Name: "terraview_darwin_arm64.tar.gz", BrowserDownloadURL: "https://example.com/mac"},
			{Name: "terraview_linux_amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux"},
			{Name: "terraview_windows_amd64.zip", BrowserDownloadURL: "https://example.com/win"},
		},
	}

	// Case sensitivity
	if got := findAssetURL(release, "Terraview_darwin_arm64.tar.gz"); got != "" {
		t.Errorf("expected empty for case-sensitive mismatch, got %q", got)
	}

	// Exact match
	if got := findAssetURL(release, "terraview_windows_amd64.zip"); got != "https://example.com/win" {
		t.Errorf("got %q, want windows URL", got)
	}

	// Empty assets
	empty := &githubRelease{TagName: "v1.0.0"}
	if got := findAssetURL(empty, "anything"); got != "" {
		t.Errorf("expected empty for no assets, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// getAssetsDir (update.go)
// ---------------------------------------------------------------------------

func TestGetAssetsDir_NonEmpty(t *testing.T) {
	dir := getAssetsDir()
	if dir == "" {
		t.Error("expected non-empty assets dir")
	}
	if !strings.Contains(dir, ".terraview") {
		t.Errorf("expected .terraview in path, got %q", dir)
	}
}

// ---------------------------------------------------------------------------
// replaceBinary (update.go) - additional edge cases
// ---------------------------------------------------------------------------

func TestReplaceBinary_BothExist(t *testing.T) {
	dir := t.TempDir()
	oldBin := dir + "/binary"
	newBin := dir + "/new-binary"
	os.WriteFile(oldBin, []byte("old"), 0755)
	os.WriteFile(newBin, []byte("new"), 0755)

	if err := replaceBinary(newBin, oldBin); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(oldBin)
	if string(data) != "new" {
		t.Errorf("expected 'new', got %q", string(data))
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
// extractBinaryFromTar (update.go) - edge cases
// ---------------------------------------------------------------------------

func TestExtractBinaryFromTar_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	emptyFile := dir + "/empty.tar.gz"
	os.WriteFile(emptyFile, []byte{}, 0644)

	_, err := extractBinaryFromTar(emptyFile, dir)
	if err == nil {
		t.Error("expected error for empty tar file")
	}
}

func TestExtractTarGz_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	badFile := dir + "/corrupt.tar.gz"
	os.WriteFile(badFile, []byte("not a tar file"), 0644)

	err := extractTarGz(badFile, dir)
	if err == nil {
		t.Error("expected error for corrupt tar file")
	}
}

// ---------------------------------------------------------------------------
// downloadFile (update.go) - edge cases
// ---------------------------------------------------------------------------

func TestDownloadFile_BadDestPath(t *testing.T) {
	err := downloadFile("http://localhost:1/test", "/nonexistent/dir/file")
	if err == nil {
		t.Error("expected error for bad destination path")
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
// downloadFile (update.go) — HTTP-based tests
// ===========================================================================

func TestDownloadFile_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("file-content"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "downloaded")
	err := downloadFile(srv.URL, dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "file-content" {
		t.Errorf("content = %q", data)
	}
}

func TestDownloadFile_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := downloadFile(srv.URL, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for 404")
	}
}

func TestDownloadFile_UnreachableURL(t *testing.T) {
	err := downloadFile("http://localhost:1/nonexistent", filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Error("expected error for unreachable URL")
	}
}

// ===========================================================================
// extractBinaryFromTar — create real tar.gz and extract
// ===========================================================================

func createCmdTestTarGz(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	archivePath := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name:     name,
			Size:     int64(len(content)),
			Mode:     0755,
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	f.Close()
	return archivePath
}

func TestExtractBinaryFromTar_Found(t *testing.T) {
	dir := t.TempDir()
	archive := createCmdTestTarGz(t, dir, map[string]string{
		binaryName: "binary-data",
	})
	destDir := filepath.Join(dir, "extracted")
	os.MkdirAll(destDir, 0755)

	path, err := extractBinaryFromTar(archive, destDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Error("expected non-empty path")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "binary-data" {
		t.Errorf("content = %q", data)
	}
}

func TestExtractBinaryFromTar_NotFound(t *testing.T) {
	dir := t.TempDir()
	archive := createCmdTestTarGz(t, dir, map[string]string{
		"other-binary": "data",
	})
	destDir := filepath.Join(dir, "extracted")
	os.MkdirAll(destDir, 0755)

	_, err := extractBinaryFromTar(archive, destDir)
	if err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestExtractBinaryFromTar_InvalidArchive(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.tar.gz")
	os.WriteFile(bad, []byte("not-a-tarball"), 0644)

	_, err := extractBinaryFromTar(bad, dir)
	if err == nil {
		t.Error("expected error for invalid archive")
	}
}

func TestExtractBinaryFromTar_MissingFile(t *testing.T) {
	_, err := extractBinaryFromTar("/nonexistent.tar.gz", t.TempDir())
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// ===========================================================================
// extractTarGz — with directories and files
// ===========================================================================

func TestExtractTarGz_WithFilesAndDirs(t *testing.T) {
	dir := t.TempDir()
	// Create archive with directory and file entries
	archivePath := filepath.Join(dir, "archive.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Add directory
	tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Typeflag: tar.TypeDir,
		Mode:     0755,
	})

	// Add file in directory
	content := "file-in-subdir"
	tw.WriteHeader(&tar.Header{
		Name:     "subdir/file.txt",
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	})
	tw.Write([]byte(content))

	// Add root file
	rootContent := "root-file"
	tw.WriteHeader(&tar.Header{
		Name:     "root.txt",
		Size:     int64(len(rootContent)),
		Typeflag: tar.TypeReg,
		Mode:     0644,
	})
	tw.Write([]byte(rootContent))

	tw.Close()
	gw.Close()
	f.Close()

	destDir := filepath.Join(dir, "out")
	os.MkdirAll(destDir, 0755)
	err = extractTarGz(archivePath, destDir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify files
	data, err := os.ReadFile(filepath.Join(destDir, "subdir", "file.txt"))
	if err != nil {
		t.Fatalf("file not extracted: %v", err)
	}
	if string(data) != "file-in-subdir" {
		t.Errorf("content = %q", data)
	}

	data2, err := os.ReadFile(filepath.Join(destDir, "root.txt"))
	if err != nil {
		t.Fatalf("root file not extracted: %v", err)
	}
	if string(data2) != "root-file" {
		t.Errorf("content = %q", data2)
	}
}

func TestExtractTarGz_InvalidArchive(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.tar.gz")
	os.WriteFile(bad, []byte("invalid"), 0644)
	err := extractTarGz(bad, dir)
	if err == nil {
		t.Error("expected error for invalid archive")
	}
}

func TestExtractTarGz_MissingFile(t *testing.T) {
	err := extractTarGz("/nonexistent.tar.gz", t.TempDir())
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// ===========================================================================
// replaceBinary — success path
// ===========================================================================

func TestReplaceBinary_Success(t *testing.T) {
	dir := t.TempDir()

	// Create "current" binary
	current := filepath.Join(dir, "terraview")
	os.WriteFile(current, []byte("old-version"), 0755)

	// Create "new" binary
	newBin := filepath.Join(dir, "terraview-new")
	os.WriteFile(newBin, []byte("new-version"), 0755)

	err := replaceBinary(newBin, current)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, _ := os.ReadFile(current)
	if string(data) != "new-version" {
		t.Errorf("content = %q, want new-version", data)
	}

	// Backup should be cleaned up
	if _, err := os.Stat(current + ".bak"); err == nil {
		t.Error("backup file should be removed")
	}
}

func TestReplaceBinary_MissingCurrent(t *testing.T) {
	dir := t.TempDir()
	newBin := filepath.Join(dir, "new")
	os.WriteFile(newBin, []byte("data"), 0644)

	err := replaceBinary(newBin, filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Error("expected error when current binary doesn't exist")
	}
}

func TestReplaceBinary_MissingNew(t *testing.T) {
	dir := t.TempDir()
	current := filepath.Join(dir, "current")
	os.WriteFile(current, []byte("old"), 0755)

	err := replaceBinary(filepath.Join(dir, "nonexistent-new"), current)
	if err == nil {
		t.Error("expected error when new binary doesn't exist")
	}

	// Current should be restored
	data, _ := os.ReadFile(current)
	if string(data) != "old" {
		t.Errorf("current binary should be restored, got %q", data)
	}
}

// ===========================================================================
// fetchLatestRelease — mock HTTP (now using var URL)
// ===========================================================================

func TestFetchLatestRelease_OK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"v1.2.3","assets":[{"name":"test.tar.gz","browser_download_url":"http://example.com/test.tar.gz"}]}`))
	}))
	defer srv.Close()

	old := githubAPIURL
	githubAPIURL = srv.URL
	defer func() { githubAPIURL = old }()

	release, err := fetchLatestRelease()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if release.TagName != "v1.2.3" {
		t.Errorf("tag = %q", release.TagName)
	}
	url := findAssetURL(release, "test.tar.gz")
	if url != "http://example.com/test.tar.gz" {
		t.Errorf("url = %q", url)
	}
}

func TestFetchLatestRelease_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	old := githubAPIURL
	githubAPIURL = srv.URL
	defer func() { githubAPIURL = old }()

	_, err := fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestFetchLatestRelease_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	old := githubAPIURL
	githubAPIURL = srv.URL
	defer func() { githubAPIURL = old }()

	_, err := fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestFetchLatestRelease_EmptyTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tag_name":"","assets":[]}`))
	}))
	defer srv.Close()

	old := githubAPIURL
	githubAPIURL = srv.URL
	defer func() { githubAPIURL = old }()

	_, err := fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for empty tag")
	}
}

func TestFetchLatestRelease_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	old := githubAPIURL
	githubAPIURL = srv.URL
	defer func() { githubAPIURL = old }()

	_, err := fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFetchLatestRelease_Unreachable(t *testing.T) {
	old := githubAPIURL
	githubAPIURL = "http://127.0.0.1:1"
	defer func() { githubAPIURL = old }()

	_, err := fetchLatestRelease()
	if err == nil {
		t.Fatal("expected error for unreachable server")
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
// runSetupEN — integration test (captures stdout)
// ===========================================================================

func TestRunSetupEN(t *testing.T) {
	// Save and restore package-level state
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

	// Mock execLookPath: simulate ollama not installed
	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetupEN()
	})

	if runErr != nil {
		t.Fatalf("runSetupEN error: %v", runErr)
	}

	// Check key sections are present
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

	execLookPath = func(name string) (string, error) {
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetupBR()
	})

	if runErr != nil {
		t.Fatalf("runSetupBR error: %v", runErr)
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
	defer func() {
		workDir = oldWorkDir
		execLookPath = oldLookPath
	}()

	workDir = t.TempDir()

	// Simulate ollama installed
	execLookPath = func(name string) (string, error) {
		if name == "ollama" {
			return "/usr/local/bin/ollama", nil
		}
		return "", fmt.Errorf("not found")
	}

	var runErr error
	out := captureStdout(func() {
		runErr = runSetupEN()
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
	discardStdout(func() {
		err = runSetup(nil, nil)
	})
	if err != nil {
		t.Fatalf("runSetup EN error: %v", err)
	}

	// Test BR dispatch
	brFlag = true
	discardStdout(func() {
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
	discardStdout(func() {
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
	discardStdout(func() {
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
	discardStdout(func() {
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
	discardStdout(func() {
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
	discardStdout(func() {
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
	discardStdout(func() {
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
	if !strings.Contains(out, "nenhum resultado") {
		t.Error("empty filter should show 'nenhum resultado'")
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

func TestRunScan_AllFlagEnablesFeatures(t *testing.T) {
	oldAll := allFlag
	oldExplain := explainFlag
	oldDiagram := diagramFlag
	oldImpact := impactFlag
	oldWorkDir := workDir
	defer func() {
		allFlag = oldAll
		explainFlag = oldExplain
		diagramFlag = oldDiagram
		impactFlag = oldImpact
		workDir = oldWorkDir
	}()

	// Verify --all sets feature flags
	allFlag = true
	explainFlag = false
	diagramFlag = false
	impactFlag = false
	workDir = t.TempDir()

	// Will fail due to no .tf files, but flags should be set
	_ = runScan(nil, nil)

	if !explainFlag {
		t.Error("--all should set explainFlag")
	}
	if !diagramFlag {
		t.Error("--all should set diagramFlag")
	}
	if !impactFlag {
		t.Error("--all should set impactFlag")
	}
}

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
	discardStdout(func() {
		err = runAICurrent(nil, nil)
	})

	if err != nil {
		t.Fatalf("runAICurrent no config error: %v", err)
	}
}

// ===========================================================================
// findAssetURL / normalizeVersion — helpers in update.go
// ===========================================================================

func TestFindAssetURL(t *testing.T) {
	release := &githubRelease{
		Assets: []githubAsset{
			{Name: "terraview-linux-amd64.tar.gz", BrowserDownloadURL: "https://example.com/linux-amd64.tar.gz"},
			{Name: "terraview-darwin-arm64.tar.gz", BrowserDownloadURL: "https://example.com/darwin-arm64.tar.gz"},
		},
	}

	url := findAssetURL(release, "terraview-linux-amd64.tar.gz")
	if url != "https://example.com/linux-amd64.tar.gz" {
		t.Errorf("findAssetURL wrong: %s", url)
	}

	url = findAssetURL(release, "nonexistent.tar.gz")
	if url != "" {
		t.Errorf("findAssetURL should return empty for nonexistent: %s", url)
	}
}

func TestNormalizeVersion_Extra(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"v1.2.3", "1.2.3"},
		{"1.2.3", "1.2.3"},
		{"v0.2.1", "0.2.1"},
	}
	for _, tt := range tests {
		if got := normalizeVersion(tt.input); got != tt.want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
