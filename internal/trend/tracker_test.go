package trend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/scoring"
)

func TestTracker_RecordAndTrend(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewTracker(tmpDir)

	score1 := scoring.Score{
		SecurityScore:        8.0,
		MaintainabilityScore: 7.0,
		ComplianceScore:      9.0,
		OverallScore:         8.0,
	}
	result1, err := tracker.Record(score1, 3, 10, map[string]int{"HIGH": 2, "MEDIUM": 1}, "run 1")
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if result1.Delta != nil {
		t.Error("expected no delta on first record")
	}

	score2 := scoring.Score{
		SecurityScore:        9.0,
		MaintainabilityScore: 8.0,
		ComplianceScore:      9.5,
		OverallScore:         9.0,
	}
	result2, err := tracker.Record(score2, 1, 10, map[string]int{"MEDIUM": 1}, "run 2")
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if result2.Delta == nil {
		t.Fatal("expected delta on second record")
	}
	if result2.Delta.Direction != "improving" {
		t.Errorf("expected improving, got %s", result2.Delta.Direction)
	}
	if result2.Delta.OverallDelta != 1.0 {
		t.Errorf("expected overall delta 1.0, got %.1f", result2.Delta.OverallDelta)
	}
}

func TestTracker_BaselineFile(t *testing.T) {
	tmpDir := t.TempDir()
	tracker := NewTracker(tmpDir)

	score := scoring.Score{OverallScore: 7.5}
	_, err := tracker.Record(score, 2, 5, nil, "")
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}

	path := filepath.Join(tmpDir, ".terraview", "baseline.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("baseline file was not created")
	}
}

func TestComputeDelta(t *testing.T) {
	prev := Snapshot{Score: scoring.Score{OverallScore: 8.0, SecurityScore: 7.0}, TotalFindings: 5}
	curr := Snapshot{Score: scoring.Score{OverallScore: 6.0, SecurityScore: 5.0}, TotalFindings: 8}

	d := ComputeDelta(prev, curr)
	if d.Direction != "degrading" {
		t.Errorf("expected degrading, got %s", d.Direction)
	}
	if d.FindingsDelta != 3 {
		t.Errorf("expected +3 findings, got %d", d.FindingsDelta)
	}
}

func TestComputeTrendLine(t *testing.T) {
	snapshots := []Snapshot{
		{Score: scoring.Score{OverallScore: 5.0}},
		{Score: scoring.Score{OverallScore: 6.0}},
		{Score: scoring.Score{OverallScore: 7.0}},
		{Score: scoring.Score{OverallScore: 8.0}},
	}
	line := ComputeTrendLine(snapshots)
	if line != "improving" {
		t.Errorf("expected improving, got %s", line)
	}
}

func TestFormatTrend(t *testing.T) {
	result := &TrendResult{
		Current:   Snapshot{Score: scoring.Score{OverallScore: 8.5}, TotalFindings: 2},
		TrendLine: "stable",
		Narrative: "Current score: 8.5/10.",
	}
	output := FormatTrend(result)
	if output == "" {
		t.Error("expected non-empty trend format")
	}
}
