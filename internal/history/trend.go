package history

import (
	"fmt"
	"math"
	"strings"
)

// TrendData holds the computed trend for a metric.
type TrendData struct {
	Metric    string
	Values    []float64
	First     float64
	Last      float64
	DeltaPct  float64
	DeltaAbs  float64
	Sparkline string
	Direction string // "↑", "↓", "→"
}

// sparkBlocks are the Unicode block elements for sparklines.
var sparkBlocks = []rune{'░', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// ComputeTrend calculates trend data for a named metric from a series of values.
// Values should be in chronological order (oldest first).
func ComputeTrend(metric string, values []float64) TrendData {
	td := TrendData{Metric: metric, Values: values}

	if len(values) == 0 {
		td.Sparkline = "(sem dados)"
		td.Direction = "→"
		return td
	}

	if len(values) == 1 {
		td.First = values[0]
		td.Last = values[0]
		td.Sparkline = string(sparkBlocks[4]) // single mid-point block
		td.Direction = "→"
		return td
	}

	td.First = values[0]
	td.Last = values[len(values)-1]
	td.DeltaAbs = td.Last - td.First

	if td.First == 0 {
		if td.Last > 0 {
			td.DeltaPct = 100
		} else if td.Last < 0 {
			td.DeltaPct = -100
		} else {
			td.DeltaPct = 0
		}
	} else {
		td.DeltaPct = (td.DeltaAbs / math.Abs(td.First)) * 100
	}

	td.Sparkline = buildSparkline(values)

	switch {
	case td.DeltaAbs > 0.01:
		td.Direction = "↑"
	case td.DeltaAbs < -0.01:
		td.Direction = "↓"
	default:
		td.Direction = "→"
	}

	return td
}

// buildSparkline creates a sparkline string from a series of values.
func buildSparkline(values []float64) string {
	if len(values) == 0 {
		return ""
	}

	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	span := max - min
	if span == 0 {
		// Constant values — use mid block
		return strings.Repeat(string(sparkBlocks[4]), len(values))
	}

	var sb strings.Builder
	maxIdx := len(sparkBlocks) - 1
	for _, v := range values {
		normalized := (v - min) / span
		idx := int(math.Round(normalized * float64(maxIdx)))
		if idx < 0 {
			idx = 0
		}
		if idx > maxIdx {
			idx = maxIdx
		}
		sb.WriteRune(sparkBlocks[idx])
	}
	return sb.String()
}

// ComputeTrendsFromRecords builds trend data from scan records (newest-first input).
func ComputeTrendsFromRecords(records []ScanRecord) []TrendData {
	if len(records) == 0 {
		return nil
	}

	// Reverse to chronological order
	chrono := make([]ScanRecord, len(records))
	for i, r := range records {
		chrono[len(records)-1-i] = r
	}

	overall := make([]float64, len(chrono))
	security := make([]float64, len(chrono))
	critical := make([]float64, len(chrono))
	high := make([]float64, len(chrono))

	for i, r := range chrono {
		overall[i] = r.ScoreOverall
		security[i] = r.ScoreSecurity
		critical[i] = float64(r.CountCritical)
		high[i] = float64(r.CountHigh)
	}

	return []TrendData{
		ComputeTrend("Overall", overall),
		ComputeTrend("Security", security),
		ComputeTrend("CRITICAL", critical),
		ComputeTrend("HIGH", high),
	}
}

// FormatTrend formats a single TrendData for display.
func FormatTrend(td TrendData) string {
	if len(td.Values) == 0 {
		return fmt.Sprintf("%-16s %s", td.Metric+":", td.Sparkline)
	}

	var deltaStr string
	if td.DeltaPct == 0 {
		deltaStr = "(=)"
	} else {
		sign := "+"
		if td.DeltaPct < 0 {
			sign = ""
		}
		deltaStr = fmt.Sprintf("(%s%.0f%%)", sign, td.DeltaPct)
	}

	// For counts (CRITICAL, HIGH), format as integers
	if td.Metric == "CRITICAL" || td.Metric == "HIGH" || td.Metric == "MEDIUM" || td.Metric == "LOW" {
		return fmt.Sprintf("%-16s %s  %.0f → %.0f %s",
			td.Metric+":", td.Sparkline, td.First, td.Last, deltaStr)
	}

	return fmt.Sprintf("%-16s %s  %.1f → %.1f %s",
		td.Metric+":", td.Sparkline, td.First, td.Last, deltaStr)
}
