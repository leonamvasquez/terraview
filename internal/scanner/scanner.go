package scanner

import (
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ScanMode indicates what the scanner operates on.
type ScanMode string

const (
	ScanModePlan   ScanMode = "plan"   // scans plan.json
	ScanModeSource ScanMode = "source" // scans .tf source files
	ScanModeBoth   ScanMode = "both"   // supports both modes
)

// ScanContext carries all paths needed for scanning.
type ScanContext struct {
	PlanPath  string // absolute path to plan.json
	SourceDir string // absolute path to terraform source directory
	WorkDir   string // working directory
}

// InstallHint describes how to install a scanner.
type InstallHint struct {
	Brew    string // e.g. "brew install checkov"
	Pip     string // e.g. "pip install checkov"
	Go      string // e.g. "go install ..."
	URL     string // download page
	Default string // fallback message
}

// ValidScanners lists all accepted scanner names.
var ValidScanners = []string{"checkov", "tfsec", "terrascan", "builtin"}

// Scanner is the interface each vendor adapter must implement.
type Scanner interface {
	// Name returns the scanner's display name (e.g., "checkov", "tfsec").
	Name() string
	// Available checks if the scanner binary is installed and reachable.
	Available() bool
	// Version returns the installed version string, or "" if unavailable.
	Version() string
	// SupportedModes returns which scan modes this scanner supports.
	SupportedModes() []ScanMode
	// Scan executes the scanner and returns normalized findings.
	Scan(ctx ScanContext) ([]rules.Finding, error)
	// EnsureInstalled checks availability and returns an install hint if missing.
	EnsureInstalled() (bool, InstallHint)
	// Priority returns the scanner's precedence rank (lower = higher priority).
	Priority() int
}

// ScanResult holds the output of one scanner run.
type ScanResult struct {
	Scanner  string          `json:"scanner"`
	Version  string          `json:"version"`
	Findings []rules.Finding `json:"findings"`
	Error    error           `json:"error,omitempty"`
}

// ---------------------------------------------------------------------------
// ScannerManager — replaces the global registry for structured lifecycle mgmt.
// ---------------------------------------------------------------------------

// ScannerManager manages the scanner lifecycle: registration, resolution,
// availability checks, concurrent execution, and priority ordering.
type ScannerManager struct {
	mu       sync.RWMutex
	scanners map[string]Scanner
}

// NewManager creates a ScannerManager with no scanners registered.
func NewManager() *ScannerManager {
	return &ScannerManager{scanners: make(map[string]Scanner)}
}

// Register adds a scanner adapter to this manager.
func (m *ScannerManager) Register(s Scanner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanners[s.Name()] = s
}

// Get returns a registered scanner by name.
func (m *ScannerManager) Get(name string) (Scanner, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scanners[name]
	return s, ok
}

// All returns a copy of all registered scanners.
func (m *ScannerManager) All() map[string]Scanner {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]Scanner, len(m.scanners))
	for k, v := range m.scanners {
		result[k] = v
	}
	return result
}

// Available returns only scanners whose binary is installed.
func (m *ScannerManager) Available() []Scanner {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var avail []Scanner
	for _, s := range m.scanners {
		if s.Available() {
			avail = append(avail, s)
		}
	}
	return avail
}

// Missing returns scanners that are NOT installed, with install hints.
func (m *ScannerManager) Missing() []struct {
	Name string
	Hint InstallHint
} {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var missing []struct {
		Name string
		Hint InstallHint
	}
	for _, s := range m.scanners {
		ok, hint := s.EnsureInstalled()
		if !ok {
			missing = append(missing, struct {
				Name string
				Hint InstallHint
			}{Name: s.Name(), Hint: hint})
		}
	}
	return missing
}

// Resolve validates and returns exactly one scanner.
//
// Accepts a single scanner name (checkov, tfsec, terrascan).
// Returns an error if input contains commas, or is "auto"/"all".
// If input is empty, returns nil (caller should use ResolveDefault instead).
func (m *ScannerManager) Resolve(input string) (Scanner, error) {
	input = strings.TrimSpace(input)

	if input == "" {
		return nil, nil
	}

	if strings.Contains(input, ",") {
		return nil, fmt.Errorf("only one scanner is allowed per execution. Allowed values: %s",
			strings.Join(ValidScanners, ", "))
	}

	if input == "auto" || input == "all" {
		return nil, fmt.Errorf("'%s' is not supported. Specify one scanner explicitly. Allowed values: %s",
			input, strings.Join(ValidScanners, ", "))
	}

	s, ok := m.Get(input)
	if !ok {
		// Unknown scanner name — show only installed scanners as suggestions
		avail := m.Available()
		if len(avail) == 0 {
			return nil, fmt.Errorf("unknown scanner %q. No scanners installed.\nInstall with: terraview scanners install checkov", input)
		}
		names := make([]string, 0, len(avail))
		for _, a := range avail {
			names = append(names, a.Name())
		}
		sort.Strings(names)
		return nil, fmt.Errorf("unknown scanner %q. Available scanners:\n  %s", input, strings.Join(names, "\n  "))
	}

	if !s.Available() {
		_, hint := s.EnsureInstalled()
		return nil, fmt.Errorf("scanner %q is not installed.\nInstall with: terraview scanners install %s\n%s", input, input, hint.Default)
	}

	return s, nil
}

// ResolveDefault returns the best scanner to use when none is specified.
// Priority: 1) configured default, 2) highest-priority installed scanner.
// Returns ("", nil) if no scanner is available.
func (m *ScannerManager) ResolveDefault(configDefault string) (Scanner, error) {
	// 1. Try configured default
	if configDefault != "" {
		s, ok := m.Get(configDefault)
		if ok && s.Available() {
			return s, nil
		}
		// Default is set but not available — warn but fall through
	}

	// 2. Pick by priority (lower number = higher priority): checkov(1) > tfsec(2) > terrascan(3)
	avail := m.Available()
	if len(avail) == 0 {
		return nil, nil
	}

	// Sort by priority
	sort.Slice(avail, func(i, j int) bool {
		return avail[i].Priority() < avail[j].Priority()
	})

	return avail[0], nil
}

// RunAll executes multiple scanners concurrently and returns all results.
func (m *ScannerManager) RunAll(scanners []Scanner, ctx ScanContext) []ScanResult {
	results := make([]ScanResult, len(scanners))
	var wg sync.WaitGroup
	for i, s := range scanners {
		wg.Add(1)
		go func(idx int, sc Scanner) {
			defer wg.Done()
			findings, err := sc.Scan(ctx)
			results[idx] = ScanResult{
				Scanner:  sc.Name(),
				Version:  sc.Version(),
				Findings: findings,
				Error:    err,
			}
		}(i, s)
	}
	wg.Wait()
	return results
}

// StatusReport returns a human-readable summary of all scanner statuses.
func (m *ScannerManager) StatusReport() string {
	var sb strings.Builder
	all := m.All()
	for _, name := range sortedKeys(all) {
		s := all[name]
		if s.Available() {
			sb.WriteString(fmt.Sprintf("  [✓] %s %s\n", s.Name(), s.Version()))
		} else {
			_, hint := s.EnsureInstalled()
			sb.WriteString(fmt.Sprintf("  [✗] %s — %s\n", s.Name(), hint.Default))
		}
	}
	return sb.String()
}

func sortedKeys(m map[string]Scanner) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Global registry — backward compatibility wrapper around DefaultManager.
// ---------------------------------------------------------------------------

// DefaultManager is the global ScannerManager populated by init() functions.
var DefaultManager = NewManager()

// Register adds a scanner adapter to the global DefaultManager.
func Register(s Scanner) {
	DefaultManager.Register(s)
}

// Get returns a registered scanner by name from DefaultManager.
func Get(name string) (Scanner, bool) {
	return DefaultManager.Get(name)
}

// All returns all registered scanners from DefaultManager.
func All() map[string]Scanner {
	return DefaultManager.All()
}

// Resolve validates and returns exactly one scanner using DefaultManager.
func Resolve(input string) (Scanner, error) {
	return DefaultManager.Resolve(input)
}

// ResolveDefault returns the best scanner when none is specified using DefaultManager.
func ResolveDefault(configDefault string) (Scanner, error) {
	return DefaultManager.ResolveDefault(configDefault)
}

// RunAll executes multiple scanners concurrently using DefaultManager.
func RunAll(scanners []Scanner, ctx ScanContext) []ScanResult {
	return DefaultManager.RunAll(scanners, ctx)
}

// commandExists checks if a command is available in PATH or in ~/.terraview/bin/.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	if err == nil {
		return true
	}
	return binaryInBinDir(name)
}

// semverRe matches semantic version strings like v1.28.11 or 1.28.11.
var semverRe = regexp.MustCompile(`v?\d+\.\d+[.\w-]*`)

// getCommandVersion runs "cmd --version" and returns the version string.
// It scans all output lines for a semver-like pattern so that tools that
// print banners or warnings before the actual version (e.g., tfsec) are
// handled correctly.
func getCommandVersion(name string) string {
	return getCommandVersionArgs(name, "--version")
}

// getCommandVersionArgs runs cmd with the given args and extracts a semver string.
// It intentionally ignores the exit code because some tools (e.g., older tfsec)
// print a version string even when they exit non-zero.
func getCommandVersionArgs(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, _ := cmd.CombinedOutput() // ignore error — parse whatever was printed
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if m := semverRe.FindString(line); m != "" {
			return m
		}
	}
	// Fallback: return the last non-empty line
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}
