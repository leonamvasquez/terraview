package history

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// LastScan holds the full findings from the most recent scan for a project.
// It is persisted to disk so that `terraview status` and `terraview fix` can
// operate without re-running the scanner.
type LastScan struct {
	Timestamp      time.Time       `json:"timestamp"`
	ProjectDir     string          `json:"project_dir"`
	PlanFile       string          `json:"plan_file"`
	Scanner        string          `json:"scanner"`
	Provider       string          `json:"provider,omitempty"`
	Model          string          `json:"model,omitempty"`
	TotalResources int             `json:"total_resources"`
	Findings       []rules.Finding `json:"findings"`
}

// SaveLastScan writes ls to ~/.terraview/<project_hash>-last.json.
func SaveLastScan(ls LastScan) error {
	path, err := lastScanPath(ls.ProjectDir)
	if err != nil {
		return err
	}
	data, err := json.Marshal(ls)
	if err != nil {
		return fmt.Errorf("marshal last scan: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadLastScan reads the most recent scan for projectDir.
// Returns nil, nil when no previous scan exists (non-fatal).
func LoadLastScan(projectDir string) (*LastScan, error) {
	path, err := lastScanPath(projectDir)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read last scan: %w", err)
	}
	var ls LastScan
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, fmt.Errorf("parse last scan: %w", err)
	}
	return &ls, nil
}

// FindingsBySeverity returns findings filtered to the given severities.
func (ls *LastScan) FindingsBySeverity(severities ...string) []rules.Finding {
	set := make(map[string]bool, len(severities))
	for _, s := range severities {
		set[s] = true
	}
	out := make([]rules.Finding, 0)
	for _, f := range ls.Findings {
		if set[f.Severity] {
			out = append(out, f)
		}
	}
	return out
}

// CountBySeverity returns a map of severity → count.
func (ls *LastScan) CountBySeverity() map[string]int {
	counts := map[string]int{
		"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
	}
	for _, f := range ls.Findings {
		counts[f.Severity]++
	}
	return counts
}

// lastScanPath returns ~/.terraview/<project_hash>-last.json.
func lastScanPath(projectDir string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("user home: %w", err)
	}
	hash := ProjectHash(projectDir)
	dir := filepath.Join(home, ".terraview")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create ~/.terraview: %w", err)
	}
	return filepath.Join(dir, hash+"-last.json"), nil
}
