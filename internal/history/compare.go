package history

import (
	"fmt"
	"math"
)

// CompareResult holds the comparison between two scans.
type CompareResult struct {
	Label    string
	OldScan  ScanRecord
	NewScan  ScanRecord
	Deltas   []DeltaRow
}

// DeltaRow is a single metric comparison row.
type DeltaRow struct {
	Metric   string
	OldValue float64
	NewValue float64
	Delta    float64
	Arrow    string // "↑" (better), "↓" (worse), "→" (same)
}

// CompareTwoScans compares two scan records and produces delta rows.
func CompareTwoScans(label string, oldScan, newScan ScanRecord) CompareResult {
	return CompareResult{
		Label:   label,
		OldScan: oldScan,
		NewScan: newScan,
		Deltas: []DeltaRow{
			scoreRow("Overall", oldScan.ScoreOverall, newScan.ScoreOverall, true),
			scoreRow("Security", oldScan.ScoreSecurity, newScan.ScoreSecurity, true),
			scoreRow("Compliance", oldScan.ScoreCompliance, newScan.ScoreCompliance, true),
			scoreRow("Maintain", oldScan.ScoreMaintain, newScan.ScoreMaintain, true),
			countRow("CRITICAL", float64(oldScan.CountCritical), float64(newScan.CountCritical)),
			countRow("HIGH", float64(oldScan.CountHigh), float64(newScan.CountHigh)),
			countRow("MEDIUM", float64(oldScan.CountMedium), float64(newScan.CountMedium)),
			countRow("LOW", float64(oldScan.CountLow), float64(newScan.CountLow)),
		},
	}
}

// scoreRow creates a delta row for a score metric.
// Higher scores are better, so positive delta = improvement = ↑.
func scoreRow(metric string, old, new float64, higherIsBetter bool) DeltaRow {
	delta := new - old
	arrow := directionArrow(delta, higherIsBetter)
	return DeltaRow{
		Metric:   metric,
		OldValue: old,
		NewValue: new,
		Delta:    delta,
		Arrow:    arrow,
	}
}

// countRow creates a delta row for a finding count.
// Fewer findings is better, so negative delta = improvement = ↓.
func countRow(metric string, old, new float64) DeltaRow {
	delta := new - old
	arrow := directionArrow(delta, false) // lower is better for counts
	return DeltaRow{
		Metric:   metric,
		OldValue: old,
		NewValue: new,
		Delta:    delta,
		Arrow:    arrow,
	}
}

// directionArrow returns the appropriate direction arrow.
func directionArrow(delta float64, higherIsBetter bool) string {
	if math.Abs(delta) < 0.01 {
		return "→"
	}
	improved := (delta > 0 && higherIsBetter) || (delta < 0 && !higherIsBetter)
	if improved {
		return "↑"
	}
	return "↓"
}

// FormatDeltaRow formats a single delta row for display.
func FormatDeltaRow(row DeltaRow) string {
	isCount := row.Metric == "CRITICAL" || row.Metric == "HIGH" ||
		row.Metric == "MEDIUM" || row.Metric == "LOW"

	var oldStr, newStr, deltaStr string
	if isCount {
		oldStr = fmt.Sprintf("%.0f", row.OldValue)
		newStr = fmt.Sprintf("%.0f", row.NewValue)
		deltaStr = fmt.Sprintf("%+.0f", row.Delta)
	} else {
		oldStr = fmt.Sprintf("%.1f", row.OldValue)
		newStr = fmt.Sprintf("%.1f", row.NewValue)
		deltaStr = fmt.Sprintf("%+.1f", row.Delta)
	}

	return fmt.Sprintf("%-20s %-16s %-12s %-6s %s",
		row.Metric+":", oldStr, newStr, deltaStr, row.Arrow)
}
