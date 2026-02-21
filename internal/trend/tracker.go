package trend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/leonamvasquez/terraview/internal/scoring"
)

const baselineFile = ".terraview/baseline.json"

// Snapshot represents a point-in-time score record.
type Snapshot struct {
	Timestamp      time.Time      `json:"timestamp"`
	Score          scoring.Score  `json:"score"`
	TotalFindings  int            `json:"total_findings"`
	TotalResources int            `json:"total_resources"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Label          string         `json:"label,omitempty"`
}

// Baseline stores historical snapshots for trend tracking.
type Baseline struct {
	ProjectPath string     `json:"project_path"`
	Snapshots   []Snapshot `json:"snapshots"`
}

// Delta represents the change between two snapshots.
type Delta struct {
	SecurityDelta        float64 `json:"security_delta"`
	MaintainabilityDelta float64 `json:"maintainability_delta"`
	ComplianceDelta      float64 `json:"compliance_delta"`
	OverallDelta         float64 `json:"overall_delta"`
	FindingsDelta        int     `json:"findings_delta"`
	Direction            string  `json:"direction"`
	Summary              string  `json:"summary"`
}

// TrendResult is the full trend analysis result.
type TrendResult struct {
	Current   Snapshot   `json:"current"`
	Previous  *Snapshot  `json:"previous,omitempty"`
	Delta     *Delta     `json:"delta,omitempty"`
	History   []Snapshot `json:"history"`
	TrendLine string     `json:"trend_line"`
	Narrative string     `json:"narrative"`
}

// Tracker manages score baselines and trend computation.
type Tracker struct {
	workDir string
}

// NewTracker creates a new Tracker for the given workspace.
func NewTracker(workDir string) *Tracker {
	return &Tracker{workDir: workDir}
}

// Record saves a new snapshot and returns the trend result.
func (t *Tracker) Record(score scoring.Score, totalFindings, totalResources int, severityCounts map[string]int, label string) (*TrendResult, error) {
	baseline, err := t.loadBaseline()
	if err != nil {
		baseline = &Baseline{ProjectPath: t.workDir}
	}

	snapshot := Snapshot{
		Timestamp:      time.Now(),
		Score:          score,
		TotalFindings:  totalFindings,
		TotalResources: totalResources,
		SeverityCounts: severityCounts,
		Label:          label,
	}

	baseline.Snapshots = append(baseline.Snapshots, snapshot)
	if len(baseline.Snapshots) > 50 {
		baseline.Snapshots = baseline.Snapshots[len(baseline.Snapshots)-50:]
	}

	if err := t.saveBaseline(baseline); err != nil {
		return nil, err
	}

	return t.computeTrend(baseline, snapshot), nil
}

// GetTrend returns the current trend without recording.
func (t *Tracker) GetTrend() (*TrendResult, error) {
	baseline, err := t.loadBaseline()
	if err != nil {
		return nil, fmt.Errorf("no baseline found: %w", err)
	}
	if len(baseline.Snapshots) == 0 {
		return nil, fmt.Errorf("no snapshots recorded")
	}
	current := baseline.Snapshots[len(baseline.Snapshots)-1]
	return t.computeTrend(baseline, current), nil
}

func (t *Tracker) computeTrend(baseline *Baseline, current Snapshot) *TrendResult {
	result := &TrendResult{
		Current: current,
		History: baseline.Snapshots,
	}
	if len(baseline.Snapshots) >= 2 {
		prev := baseline.Snapshots[len(baseline.Snapshots)-2]
		result.Previous = &prev
		result.Delta = ComputeDelta(prev, current)
	}
	result.TrendLine = ComputeTrendLine(baseline.Snapshots)
	result.Narrative = BuildTrendNarrative(result)
	return result
}

func (t *Tracker) loadBaseline() (*Baseline, error) {
	path := filepath.Join(t.workDir, baselineFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, err
	}
	sort.Slice(baseline.Snapshots, func(i, j int) bool {
		return baseline.Snapshots[i].Timestamp.Before(baseline.Snapshots[j].Timestamp)
	})
	return &baseline, nil
}

func (t *Tracker) saveBaseline(baseline *Baseline) error {
	path := filepath.Join(t.workDir, baselineFile)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create baseline directory: %w", err)
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal baseline: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
