package scanner

import (
	"fmt"
	"sort"
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

func TestAvailableSortedByPriority(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "low-pri", available: true, priority: 4})
	mgr.Register(&mockScanner{name: "high-pri", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "mid-pri", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "unavail", available: false, priority: 0})

	avail := mgr.Available()
	if len(avail) != 3 {
		t.Fatalf("expected 3 available scanners, got %d", len(avail))
	}
	for i := 1; i < len(avail); i++ {
		if avail[i].Priority() < avail[i-1].Priority() {
			t.Errorf("not sorted by priority: %s(%d) before %s(%d)",
				avail[i-1].Name(), avail[i-1].Priority(),
				avail[i].Name(), avail[i].Priority())
		}
	}
	if avail[0].Name() != "high-pri" {
		t.Errorf("expected first scanner to be high-pri, got %s", avail[0].Name())
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

	scanners, err := mgr.Resolve("auto")
	if err != nil {
		t.Fatalf("Resolve(auto) error: %v", err)
	}
	if len(scanners) != 1 {
		t.Fatalf("expected 1 scanner (single-scanner mode), got %d", len(scanners))
	}
	if scanners[0].Name() != "s2" {
		t.Errorf("expected s2 (highest priority), got %s", scanners[0].Name())
	}
}

func TestResolveAll(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "s1", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "s2", available: true, priority: 1})

	scanners, err := mgr.Resolve("all")
	if err != nil {
		t.Fatalf("Resolve(all) error: %v", err)
	}
	if len(scanners) != 1 {
		t.Fatalf("expected 1 scanner (single-scanner mode), got %d", len(scanners))
	}
	if scanners[0].Name() != "s2" {
		t.Errorf("expected s2 (highest priority), got %s", scanners[0].Name())
	}
}

func TestResolveExplicitNames(t *testing.T) {
	mgr := NewManager()
	mgr.Register(&mockScanner{name: "checkov", available: true, priority: 1})
	mgr.Register(&mockScanner{name: "tfsec", available: true, priority: 2})
	mgr.Register(&mockScanner{name: "terrascan", available: true, priority: 3})

	scanners, err := mgr.Resolve("tfsec,checkov")
	if err != nil {
		t.Fatalf("Resolve error: %v", err)
	}
	if len(scanners) != 1 {
		t.Fatalf("expected 1 (single-scanner picks highest priority), got %d", len(scanners))
	}
	if scanners[0].Name() != "checkov" {
		t.Errorf("expected checkov (highest priority), got %s", scanners[0].Name())
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
	scanners, err := mgr.Resolve("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scanners != nil {
		t.Errorf("expected nil, got %v", scanners)
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

func TestDefaultManagerPriorityOrder(t *testing.T) {
	avail := DefaultManager.Available()
	if len(avail) < 2 {
		t.Skip("need at least 2 available scanners to test ordering")
	}
	for i := 1; i < len(avail); i++ {
		if avail[i].Priority() < avail[i-1].Priority() {
			t.Errorf("Available() not sorted: %s(%d) before %s(%d)",
				avail[i-1].Name(), avail[i-1].Priority(),
				avail[i].Name(), avail[i].Priority())
		}
	}
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
	for _, input := range []string{"auto", "all"} {
		scanners, err := Resolve(input)
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", input, err)
		}
		_ = scanners
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
