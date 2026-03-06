package history

import (
	"testing"
)

func TestCompareTwoScans_Basic(t *testing.T) {
	oldScan := ScanRecord{
		ScoreOverall:    6.0,
		ScoreSecurity:   5.0,
		ScoreCompliance: 7.0,
		ScoreMaintain:   8.0,
		CountCritical:   3,
		CountHigh:       5,
		CountMedium:     8,
		CountLow:        10,
	}
	newScan := ScanRecord{
		ScoreOverall:    8.0,
		ScoreSecurity:   7.0,
		ScoreCompliance: 9.0,
		ScoreMaintain:   8.5,
		CountCritical:   1,
		CountHigh:       2,
		CountMedium:     5,
		CountLow:        8,
	}

	cr := CompareTwoScans("Antes", oldScan, newScan)

	if len(cr.Deltas) != 8 {
		t.Fatalf("expected 8 delta rows, got %d", len(cr.Deltas))
	}
	if cr.Label != "Antes" {
		t.Errorf("Label = %q, want Antes", cr.Label)
	}
}

func TestCompareTwoScans_ScoresImproved(t *testing.T) {
	oldScan := ScanRecord{ScoreOverall: 5.0, ScoreSecurity: 4.0, ScoreCompliance: 6.0, ScoreMaintain: 7.0}
	newScan := ScanRecord{ScoreOverall: 8.0, ScoreSecurity: 7.0, ScoreCompliance: 9.0, ScoreMaintain: 9.5}

	cr := CompareTwoScans("", oldScan, newScan)

	// Score improvements should have ↑ direction
	for _, d := range cr.Deltas[:4] {
		if d.Arrow != "↑" {
			t.Errorf("%s Arrow = %q, want ↑ (score improved)", d.Metric, d.Arrow)
		}
		if d.Delta <= 0 {
			t.Errorf("%s Delta = %.1f, want positive", d.Metric, d.Delta)
		}
	}
}

func TestCompareTwoScans_ScoresDegraded(t *testing.T) {
	oldScan := ScanRecord{ScoreOverall: 9.0, ScoreSecurity: 8.0, ScoreCompliance: 9.0, ScoreMaintain: 9.0}
	newScan := ScanRecord{ScoreOverall: 6.0, ScoreSecurity: 5.0, ScoreCompliance: 6.0, ScoreMaintain: 7.0}

	cr := CompareTwoScans("", oldScan, newScan)

	for _, d := range cr.Deltas[:4] {
		if d.Arrow != "↓" {
			t.Errorf("%s Arrow = %q, want ↓ (score degraded)", d.Metric, d.Arrow)
		}
	}
}

func TestCompareTwoScans_CountsReduced(t *testing.T) {
	// Reduction in findings = improvement → ↑
	oldScan := ScanRecord{CountCritical: 5, CountHigh: 10, CountMedium: 15, CountLow: 20}
	newScan := ScanRecord{CountCritical: 1, CountHigh: 3, CountMedium: 5, CountLow: 8}

	cr := CompareTwoScans("", oldScan, newScan)

	for _, d := range cr.Deltas[4:] {
		if d.Arrow != "↑" {
			t.Errorf("%s Arrow = %q, want ↑ (fewer findings = improvement)", d.Metric, d.Arrow)
		}
		if d.Delta >= 0 {
			t.Errorf("%s Delta = %.0f, want negative (fewer findings)", d.Metric, d.Delta)
		}
	}
}

func TestCompareTwoScans_CountsIncreased(t *testing.T) {
	// Increase in findings = worse → ↓
	oldScan := ScanRecord{CountCritical: 0, CountHigh: 1, CountMedium: 2, CountLow: 3}
	newScan := ScanRecord{CountCritical: 5, CountHigh: 8, CountMedium: 10, CountLow: 15}

	cr := CompareTwoScans("", oldScan, newScan)

	for _, d := range cr.Deltas[4:] {
		if d.Arrow != "↓" {
			t.Errorf("%s Arrow = %q, want ↓ (more findings = degradation)", d.Metric, d.Arrow)
		}
	}
}

func TestCompareTwoScans_NoChange(t *testing.T) {
	scan := ScanRecord{
		ScoreOverall: 7.0, ScoreSecurity: 7.0, ScoreCompliance: 7.0, ScoreMaintain: 7.0,
		CountCritical: 2, CountHigh: 3, CountMedium: 5, CountLow: 8,
	}

	cr := CompareTwoScans("", scan, scan)

	for _, d := range cr.Deltas {
		if d.Arrow != "→" {
			t.Errorf("%s Arrow = %q, want → (no change)", d.Metric, d.Arrow)
		}
		if d.Delta != 0 {
			t.Errorf("%s Delta = %.1f, want 0", d.Metric, d.Delta)
		}
	}
}

func TestDirectionArrow_Threshold(t *testing.T) {
	tests := []struct {
		delta          float64
		higherIsBetter bool
		want           string
	}{
		{0.005, true, "→"},   // Below threshold
		{-0.005, true, "→"},  // Below threshold
		{0.02, true, "↑"},    // Above threshold, higher better
		{-0.02, true, "↓"},   // Above threshold, lower = worse
		{0.02, false, "↓"},   // Above threshold, higher is worse for counts
		{-0.02, false, "↑"},  // Above threshold, lower is better for counts
		{0.0, true, "→"},     // Exact zero
	}

	for _, tt := range tests {
		got := directionArrow(tt.delta, tt.higherIsBetter)
		if got != tt.want {
			t.Errorf("directionArrow(%.3f, %v) = %q, want %q",
				tt.delta, tt.higherIsBetter, got, tt.want)
		}
	}
}

func TestFormatDeltaRow_Score(t *testing.T) {
	row := DeltaRow{Metric: "Overall", OldValue: 5.0, NewValue: 8.0, Delta: 3.0, Arrow: "↑"}
	out := FormatDeltaRow(row)

	if out == "" {
		t.Error("FormatDeltaRow returned empty")
	}
	if !containsStr(out, "Overall") {
		t.Errorf("missing metric name: %s", out)
	}
	if !containsStr(out, "5.0") || !containsStr(out, "8.0") {
		t.Errorf("missing values: %s", out)
	}
}

func TestFormatDeltaRow_Count(t *testing.T) {
	row := DeltaRow{Metric: "CRITICAL", OldValue: 5, NewValue: 2, Delta: -3, Arrow: "↑"}
	out := FormatDeltaRow(row)

	// Counts should be formatted as integers
	if !containsStr(out, "CRITICAL") {
		t.Errorf("missing metric name: %s", out)
	}
}
