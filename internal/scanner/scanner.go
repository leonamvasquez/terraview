package scanner

import (
	"fmt"
	"os/exec"
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
}

// ScanResult holds the output of one scanner run.
type ScanResult struct {
	Scanner  string          `json:"scanner"`
	Version  string          `json:"version"`
	Findings []rules.Finding `json:"findings"`
	Error    error           `json:"error,omitempty"`
}

// Registry holds all registered scanner adapters.
var (
	registryMu sync.RWMutex
	registry   = make(map[string]Scanner)
)

// Register adds a scanner adapter to the global registry.
func Register(s Scanner) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[s.Name()] = s
}

// Get returns a registered scanner by name.
func Get(name string) (Scanner, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[name]
	return s, ok
}

// All returns all registered scanners.
func All() map[string]Scanner {
	registryMu.RLock()
	defer registryMu.RUnlock()
	result := make(map[string]Scanner, len(registry))
	for k, v := range registry {
		result[k] = v
	}
	return result
}

// AvailableNames returns names of all scanners that are installed on the system.
func AvailableNames() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	var names []string
	for _, s := range registry {
		if s.Available() {
			names = append(names, s.Name())
		}
	}
	return names
}

// Resolve parses a comma-separated scanner list. "auto" detects all installed scanners.
func Resolve(input string) ([]Scanner, error) {
	if input == "" {
		return nil, nil
	}

	if input == "auto" {
		var scanners []Scanner
		for _, s := range All() {
			if s.Available() {
				scanners = append(scanners, s)
			}
		}
		return scanners, nil
	}

	names := strings.Split(input, ",")
	var scanners []Scanner
	for _, name := range names {
		name = strings.TrimSpace(name)
		s, ok := Get(name)
		if !ok {
			return nil, fmt.Errorf("unknown scanner %q. Available: checkov, tfsec, terrascan, kics", name)
		}
		if !s.Available() {
			return nil, fmt.Errorf("scanner %q is not installed. Install it first", name)
		}
		scanners = append(scanners, s)
	}
	return scanners, nil
}

// RunAll executes multiple scanners concurrently and returns all results.
func RunAll(scanners []Scanner, ctx ScanContext) []ScanResult {
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

// commandExists checks if a command is available in PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// getCommandVersion runs "cmd --version" and returns the first line.
func getCommandVersion(name string) string {
	out, err := exec.Command(name, "--version").CombinedOutput()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return ""
}
