package scanner

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// Mock scanner for unit testing
// ---------------------------------------------------------------------------

type mockScanner struct {
	name      string
	available bool
	version   string
	priority  int
	hint      InstallHint
	findings  []rules.Finding
	scanErr   error
}

func (m *mockScanner) Name() string                                  { return m.name }
func (m *mockScanner) Available() bool                               { return m.available }
func (m *mockScanner) Version() string                               { return m.version }
func (m *mockScanner) SupportedModes() []ScanMode                    { return []ScanMode{ScanModePlan} }
func (m *mockScanner) Priority() int                                 { return m.priority }
func (m *mockScanner) Scan(ctx ScanContext) ([]rules.Finding, error) { return m.findings, m.scanErr }

func (m *mockScanner) EnsureInstalled() (bool, InstallHint) {
	if m.available {
		return true, InstallHint{}
	}
	return false, m.hint
}

var errMock = fmt.Errorf("mock scan error")

// ---------------------------------------------------------------------------
// ScannerManager tests
// ---------------------------------------------------------------------------

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if len(mgr.All()) != 0 {
		t.Errorf("new manager should have 0 scanners, got %d", len(mgr.All()))
	}
}

func TestRegisterAndGet(t *testing.T) {
	mgr := NewManager()
	s := &mockScanner{name: "mock-a", available: true, priority: 1}
	mgr.Register(s)

	got, ok := mgr.Get("mock-a")
	if !ok {
		t.Fatal("expected to find mock-a")
	}
	if got.Name() != "mock-a" {
		t.Errorf("expected name mock-a, got %s", got.Name())
	}

	_, ok = mgr.Get("nonexistent")
	if ok {
		t.Error("should not find nonexistent scanner")
	}
}

func TestAll(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "a", priority: 3})
	mgr.Register(&mockScanner{name: "b", priority: 1})
	mgr.Register(&mockScanner{name: "c", priority: 2})

	all := mgr.All()
	if len(all) != 3 {
		t.Errorf("expected 3 scanners, got %d", len(all))
	}
}

func TestAvailable(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "low-pri", available: true, priority: 4})
	mgr.Register(&mockScanner{name: "high-pri", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "mid-pri", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "unavail", available: false, priority: 0})

	avail := mgr.Available()
	if len(avail) != 3 {
		t.Fatalf("expected 3 available scanners, got %d", len(avail))
	}
	// All three available scanners should be present (order not guaranteed)
	names := map[string]bool{}
	for _, s := range avail {
		names[s.Name()] = true
	}
	for _, expected := range []string{"low-pri", "high-pri", "mid-pri"} {
		if !names[expected] {
			t.Errorf("expected %s in available scanners", expected)
		}
	}
	if names["unavail"] {
		t.Error("unavail should not be in available list")
	}
}

func TestMissing(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "installed", available: true, priority: 1})
	mgr.Register(&mockScanner{
		name: "missing", available: false, priority: 2,
		hint: InstallHint{Brew: "brew install missing", Default: "install missing"},
	})

	missing := mgr.Missing()
	if len(missing) != 1 {
		t.Fatalf("expected 1 missing scanner, got %d", len(missing))
	}
	if missing[0].Name != "missing" {
		t.Errorf("expected missing scanner name 'missing', got %s", missing[0].Name)
	}
	if missing[0].Hint.Brew != "brew install missing" {
		t.Errorf("wrong hint: %s", missing[0].Hint.Brew)
	}
}

func TestResolveAuto(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "s1", available: true, priority: 3})
	mgr.Register(&mockScanner{name: "s2", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "s3", available: false, priority: 2})

	_, err := mgr.Resolve("auto")
	if err == nil {
		t.Fatal("Resolve(\"auto\") should return error")
	}
	if !stringContains(err.Error(), "not supported") {
		t.Errorf("expected 'not supported' in error, got: %s", err.Error())
	}
}

func TestResolveAll(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "s1", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "s2", available: true, priority: 1})

	_, err := mgr.Resolve("all")
	if err == nil {
		t.Fatal("Resolve(\"all\") should return error")
	}
	if !stringContains(err.Error(), "not supported") {
		t.Errorf("expected 'not supported' in error, got: %s", err.Error())
	}
}

func TestResolveSingleExplicit(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "tfsec", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "terrascan", available: true, priority: 3})

	s, err := mgr.Resolve("tfsec")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if s.Name() != "tfsec" {
		t.Errorf("expected tfsec, got %s", s.Name())
	}
}

func TestResolveMultipleReturnsError(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "tfsec", available: true, priority: 2})

	_, err := mgr.Resolve("tfsec,checkov")
	if err == nil {
		t.Fatal("Resolve with comma-separated should return error")
	}
	if !stringContains(err.Error(), "only one scanner") {
		t.Errorf("expected 'only one scanner' in error, got: %s", err.Error())
	}
}

func TestResolveUnknownScanner(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})

	_, err := mgr.Resolve("unknown")
	if err == nil {
		t.Error("expected error for unknown scanner")
	}
}

func TestResolveUnavailableScanner(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{
		name: "checkov", available: false, priority: 1,
		hint: InstallHint{Default: "install checkov"},
	})

	_, err := mgr.Resolve("checkov")
	if err == nil {
		t.Error("expected error for unavailable scanner")
	}
}

func TestResolveEmpty(t *testing.T) {
	mgr := NewManager()
	s, err := mgr.Resolve("")
	if err != nil {
		t.Fatalf("Resolve(\"\") should return nil error, got: %v", err)
	}
	if s != nil {
		t.Fatal("Resolve(\"\") should return nil scanner")
	}
}

func TestRunAllConcurrent(t *testing.T) {
	mgr := NewManager()
	findings1 := []rules.Finding{{RuleID: "R1", Severity: "HIGH"}}
	findings2 := []rules.Finding{{RuleID: "R2", Severity: "MEDIUM"}}
	s1 := &mockScanner{name: "s1", available: true, priority: 1, findings: findings1}
	s2 := &mockScanner{name: "s2", available: true, priority: 2, findings: findings2}

	ctx := ScanContext{PlanPath: "/tmp/plan.json", SourceDir: "/tmp/src"}
	results := mgr.RunAll([]Scanner{s1, s2}, ctx)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Scanner != "s1" {
		t.Errorf("expected first result from s1, got %s", results[0].Scanner)
	}
	if len(results[0].Findings) != 1 || results[0].Findings[0].RuleID != "R1" {
		t.Error("s1 findings mismatch")
	}
	if results[1].Scanner != "s2" {
		t.Errorf("expected second result from s2, got %s", results[1].Scanner)
	}
}

func TestRunAllWithError(t *testing.T) {
	mgr := NewManager()
	s := &mockScanner{name: "failing", available: true, priority: 1, scanErr: errMock}
	results := mgr.RunAll([]Scanner{s}, ScanContext{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Error == nil {
		t.Error("expected error in result")
	}
}

func TestStatusReport(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "alpha", available: true, version: "1.0.0", priority: 1})
	mgr.Register(&mockScanner{
		name: "beta", available: false, priority: 2,
		hint: InstallHint{Default: "Install beta"},
	})

	report := mgr.StatusReport()
	if report == "" {
		t.Error("expected non-empty status report")
	}
	if !stringContains(report, "alpha") {
		t.Error("report should contain alpha")
	}
	if !stringContains(report, "beta") {
		t.Error("report should contain beta")
	}
}

func stringContains(s, sub string) bool {
	return len(s) >= len(sub) && searchSubstring(s, sub)
}

func searchSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// InstallHint tests
// ---------------------------------------------------------------------------

func TestInstallHintFields(t *testing.T) {
	hint := InstallHint{
		Brew:    "brew install checkov",
		Pip:     "pip install checkov",
		URL:     "https://checkov.io",
		Default: "Install: pip install checkov",
	}
	if hint.Brew != "brew install checkov" {
		t.Errorf("wrong Brew: %s", hint.Brew)
	}
	if hint.Pip != "pip install checkov" {
		t.Errorf("wrong Pip: %s", hint.Pip)
	}
}

// ---------------------------------------------------------------------------
// Adapter interface compliance tests
// ---------------------------------------------------------------------------

func TestAdaptersPriority(t *testing.T) {
	adapters := []struct {
		name     string
		priority int
	}{
		{"checkov", 1},
		{"tfsec", 2},
		{"terrascan", 3},
	}

	all := DefaultManager.All()
	for _, tc := range adapters {
		s, ok := all[tc.name]
		if !ok {
			t.Errorf("adapter %s not registered in DefaultManager", tc.name)
			continue
		}
		if s.Priority() != tc.priority {
			t.Errorf("adapter %s: expected priority %d, got %d", tc.name, tc.priority, s.Priority())
		}
	}
}

func TestAdaptersEnsureInstalled(t *testing.T) {
	all := DefaultManager.All()
	for name, s := range all {
		installed, hint := s.EnsureInstalled()
		if installed && hint.Default != "" {
			t.Errorf("adapter %s: installed=true but hint.Default set: %q", name, hint.Default)
		}
		if !installed && hint.Default == "" {
			t.Errorf("adapter %s: installed=false but no Default hint", name)
		}
	}
}

func TestAdaptersRegisteredInDefaultManager(t *testing.T) {
	expected := []string{"checkov", "tfsec", "terrascan"}
	all := DefaultManager.All()
	for _, name := range expected {
		if _, ok := all[name]; !ok {
			t.Errorf("adapter %s not found in DefaultManager", name)
		}
	}
}

func TestDefaultManagerAvailable(t *testing.T) {
	avail := DefaultManager.Available()
	// Just verify it returns without error; actual availability depends on environment
	_ = avail
}

// ---------------------------------------------------------------------------
// Backward compat wrapper tests
// ---------------------------------------------------------------------------

func TestGlobalRegisterAndGet(t *testing.T) {
	s, ok := Get("checkov")
	if !ok {
		t.Error("global Get should find checkov (registered via init)")
	}
	if s != nil && s.Name() != "checkov" {
		t.Errorf("expected checkov, got %s", s.Name())
	}
}

func TestGlobalAll(t *testing.T) {
	all := All()
	if len(all) < 3 {
		t.Errorf("expected at least 3 registered scanners, got %d", len(all))
	}
}

func TestGlobalResolve(t *testing.T) {
	// auto and all should both return errors
	for _, input := range []string{"auto", "all"} {
		_, err := Resolve(input)
		if err == nil {
			t.Errorf("Resolve(%q) should return error", input)
		}
	}
	// empty should return nil scanner and nil error (auto-select)
	s, err := Resolve("")
	if err != nil {
		t.Errorf("Resolve(\"\") should return nil error, got: %v", err)
	}
	if s != nil {
		t.Error("Resolve(\"\") should return nil scanner")
	}
}

// ---------------------------------------------------------------------------
// sortedKeys helper test
// ---------------------------------------------------------------------------

func TestSortedKeys(t *testing.T) {
	m := map[string]Scanner{
		"c": &mockScanner{name: "c"},
		"a": &mockScanner{name: "a"},
		"b": &mockScanner{name: "b"},
	}
	keys := sortedKeys(m)
	if !sort.StringsAreSorted(keys) {
		t.Errorf("keys not sorted: %v", keys)
	}
}

// ---------------------------------------------------------------------------
// ResolveDefault tests
// ---------------------------------------------------------------------------

func TestResolveDefault_ConfiguredDefault(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "tfsec", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})

	s, err := mgr.ResolveDefault("tfsec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil || s.Name() != "tfsec" {
		t.Errorf("expected tfsec, got %v", s)
	}
}

func TestResolveDefault_ConfiguredNotAvailable_FallsThrough(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "tfsec", available: false, priority: 2})
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})

	s, err := mgr.ResolveDefault("tfsec")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall through to priority-based selection (checkov is higher priority)
	if s == nil || s.Name() != "checkov" {
		t.Errorf("expected checkov (fallback), got %v", s)
	}
}

func TestResolveDefault_Empty_PicksByPriority(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "terrascan", available: true, priority: 3})
	mgr.Register(&mockScanner{name: "tfsec", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})

	s, err := mgr.ResolveDefault("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s == nil || s.Name() != "checkov" {
		t.Errorf("expected checkov (priority 1), got %v", s)
	}
}

func TestResolveDefault_NoneAvailable(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "tfsec", available: false, priority: 2})
	mgr.Register(&mockScanner{name: "checkov", available: false, priority: 1})

	s, err := mgr.ResolveDefault("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != nil {
		t.Errorf("expected nil scanner, got %v", s.Name())
	}
}

func TestResolveDefault_EmptyManager(t *testing.T) {
	mgr := NewManager()
	s, err := mgr.ResolveDefault("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s != nil {
		t.Error("expected nil scanner from empty manager")
	}
}

func TestGlobalResolveDefault(t *testing.T) {
	// Test global wrapper — just ensure it doesn't panic
	_, err := ResolveDefault("")
	if err != nil {
		t.Errorf("ResolveDefault(\"\") error: %v", err)
	}
}

func TestGlobalRunAll_Empty(t *testing.T) {
	results := RunAll(nil, ScanContext{})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestRunAllEmpty(t *testing.T) {
	mgr := NewManager()
	results := mgr.RunAll(nil, ScanContext{})
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

// ---------------------------------------------------------------------------
// commandExists and getCommandVersion tests
// ---------------------------------------------------------------------------

func TestCommandExists_Echo(t *testing.T) {
	if !commandExists("echo") {
		t.Skip("echo not available")
	}
}

func TestCommandExists_Nonexistent(t *testing.T) {
	if commandExists("nonexistent-cmd-xyz-12345") {
		t.Error("expected false for nonexistent command")
	}
}

func TestGetCommandVersion_Echo(t *testing.T) {
	v := getCommandVersion("echo")
	// echo --version may or may not return a version, just ensure no panic
	_ = v
}

func TestGetCommandVersionArgs_Nonexistent(t *testing.T) {
	v := getCommandVersionArgs("nonexistent-cmd-xyz-12345", "--version")
	if v != "" {
		t.Errorf("expected empty string for nonexistent command, got %q", v)
	}
}

// ---------------------------------------------------------------------------
// SupportedModes
// ---------------------------------------------------------------------------

func TestCheckovSupportedModes(t *testing.T) {
	s := &CheckovScanner{}
	modes := s.SupportedModes()
	if len(modes) != 2 {
		t.Fatalf("expected 2 modes, got %d", len(modes))
	}
	if modes[0] != ScanModePlan || modes[1] != ScanModeSource {
		t.Errorf("unexpected modes: %v", modes)
	}
}

func TestTfsecSupportedModes(t *testing.T) {
	s := &TfsecScanner{}
	modes := s.SupportedModes()
	if len(modes) != 1 || modes[0] != ScanModeSource {
		t.Errorf("expected [source], got %v", modes)
	}
}

func TestTerrascanSupportedModes(t *testing.T) {
	s := &TerrascanScanner{}
	modes := s.SupportedModes()
	if len(modes) != 1 || modes[0] != ScanModeSource {
		t.Errorf("expected [source], got %v", modes)
	}
}

// ---------------------------------------------------------------------------
// FormatScannerHeaderBR — dedup branch
// ---------------------------------------------------------------------------

func TestFormatScannerHeaderBR_WithDedup(t *testing.T) {
	result := AggregatedResult{
		ScannerStats: []ScannerStat{{Name: "checkov", Findings: 5}},
		TotalRaw:     10,
		TotalDeduped: 5,
	}
	header := FormatScannerHeaderBR(result)
	if !strings.Contains(header, "Dedup") {
		t.Error("expected dedup line when TotalRaw != TotalDeduped")
	}
	if !strings.Contains(header, "duplicados") {
		t.Error("expected Portuguese text in BR header")
	}
}

func TestFormatScannerHeaderBR_NoDedup(t *testing.T) {
	result := AggregatedResult{
		ScannerStats: []ScannerStat{{Name: "tfsec", Findings: 3}},
		TotalRaw:     3,
		TotalDeduped: 3,
	}
	header := FormatScannerHeaderBR(result)
	if strings.Contains(header, "Dedup") {
		t.Error("expected no dedup line when TotalRaw == TotalDeduped")
	}
}

func TestFormatScannerHeaderBR_ErrorScanner(t *testing.T) {
	result := AggregatedResult{
		ScannerStats: []ScannerStat{{Name: "terrascan", Error: "timeout"}},
		TotalRaw:     0,
		TotalDeduped: 0,
	}
	header := FormatScannerHeaderBR(result)
	if !strings.Contains(header, "erro") {
		t.Error("expected 'erro' for scanner with error in BR header")
	}
}

// ---------------------------------------------------------------------------
// convertCheckovFindings edge cases
// ---------------------------------------------------------------------------

func TestConvertCheckovFindings_EmptyResourceAddr(t *testing.T) {
	checks := []checkovCheck{
		{
			CheckID:      "CKV_AWS_1",
			CheckName:    "test check",
			ResourceAddr: "",
			FilePath:     "/main.tf",
			Severity:     "HIGH",
		},
	}
	findings := convertCheckovFindings(checks)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Resource != "/main.tf" {
		t.Errorf("expected resource to fallback to FilePath, got %q", findings[0].Resource)
	}
}

func TestConvertCheckovFindings_GuidelineFallback(t *testing.T) {
	checks := []checkovCheck{
		{
			CheckID:   "CKV_AWS_2",
			CheckName: "",
			Guideline: "https://example.com",
			Severity:  "MEDIUM",
		},
	}
	findings := convertCheckovFindings(checks)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	// Should fallback to guideline when checkname and description are empty
	if !strings.Contains(findings[0].Message, "https://example.com") {
		t.Errorf("expected guideline in message, got %q", findings[0].Message)
	}
}
