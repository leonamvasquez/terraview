package trend

import (
	"fmt"
	"strings"
)

// ComputeDelta calculates the change between two snapshots.
func ComputeDelta(prev, current Snapshot) *Delta {
	d := &Delta{
		SecurityDelta:        current.Score.SecurityScore - prev.Score.SecurityScore,
		MaintainabilityDelta: current.Score.MaintainabilityScore - prev.Score.MaintainabilityScore,
		ComplianceDelta:      current.Score.ComplianceScore - prev.Score.ComplianceScore,
		OverallDelta:         current.Score.OverallScore - prev.Score.OverallScore,
		FindingsDelta:        current.TotalFindings - prev.TotalFindings,
	}

	if d.OverallDelta > 0.5 {
		d.Direction = "improving"
	} else if d.OverallDelta < -0.5 {
		d.Direction = "degrading"
	} else {
		d.Direction = "stable"
	}

	d.Summary = formatDeltaSummary(d)
	return d
}

func formatDeltaSummary(d *Delta) string {
	var parts []string
	parts = append(parts, formatChange("overall", d.OverallDelta))
	if d.FindingsDelta != 0 {
		if d.FindingsDelta > 0 {
			parts = append(parts, fmt.Sprintf("+%d findings", d.FindingsDelta))
		} else {
			parts = append(parts, fmt.Sprintf("%d findings", d.FindingsDelta))
		}
	}
	return fmt.Sprintf("Score %s. %s", d.Direction, strings.Join(parts, ", "))
}

func formatChange(label string, delta float64) string {
	if delta > 0 {
		return fmt.Sprintf("%s +%.1f", label, delta)
	} else if delta < 0 {
		return fmt.Sprintf("%s %.1f", label, delta)
	}
	return fmt.Sprintf("%s unchanged", label)
}

// ComputeTrendLine determines the overall trend direction.
func ComputeTrendLine(snapshots []Snapshot) string {
	if len(snapshots) < 3 {
		return "insufficient data"
	}
	start := 0
	if len(snapshots) > 5 {
		start = len(snapshots) - 5
	}
	recent := snapshots[start:]

	improving := 0
	degrading := 0
	for i := 1; i < len(recent); i++ {
		diff := recent[i].Score.OverallScore - recent[i-1].Score.OverallScore
		if diff > 0.3 {
			improving++
		} else if diff < -0.3 {
			degrading++
		}
	}

	if improving > degrading+1 {
		return "improving"
	} else if degrading > improving+1 {
		return "degrading"
	}
	return "stable"
}

// BuildTrendNarrative creates a human-readable narrative.
func BuildTrendNarrative(result *TrendResult) string {
	var parts []string
	parts = append(parts, fmt.Sprintf("Current score: %.1f/10.", result.Current.Score.OverallScore))
	if result.Delta != nil {
		parts = append(parts, result.Delta.Summary)
	}
	if result.TrendLine != "insufficient data" {
		parts = append(parts, fmt.Sprintf("Overall trend: %s.", result.TrendLine))
	} else {
		parts = append(parts, "Not enough data points for trend analysis.")
	}
	return strings.Join(parts, " ")
}

// FormatTrend produces a human-readable trend report.
func FormatTrend(result *TrendResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Score Trend Report (%d snapshots)\n\n", len(result.History)))
	sb.WriteString(fmt.Sprintf("Current Score: %.1f/10\n", result.Current.Score.OverallScore))
	sb.WriteString(fmt.Sprintf("  Security:        %.1f\n", result.Current.Score.SecurityScore))
	sb.WriteString(fmt.Sprintf("  Maintainability: %.1f\n", result.Current.Score.MaintainabilityScore))
	sb.WriteString(fmt.Sprintf("  Compliance:      %.1f\n", result.Current.Score.ComplianceScore))
	sb.WriteString(fmt.Sprintf("  Findings:        %d\n", result.Current.TotalFindings))
	sb.WriteString("\n")

	if result.Delta != nil {
		sb.WriteString("Changes from previous:\n")
		sb.WriteString(fmt.Sprintf("  Overall:         %s\n", fmtDelta(result.Delta.OverallDelta)))
		sb.WriteString(fmt.Sprintf("  Security:        %s\n", fmtDelta(result.Delta.SecurityDelta)))
		sb.WriteString(fmt.Sprintf("  Maintainability: %s\n", fmtDelta(result.Delta.MaintainabilityDelta)))
		sb.WriteString(fmt.Sprintf("  Compliance:      %s\n", fmtDelta(result.Delta.ComplianceDelta)))
		sb.WriteString(fmt.Sprintf("  Findings:        %+d\n", result.Delta.FindingsDelta))
		sb.WriteString(fmt.Sprintf("  Direction:       %s\n", result.Delta.Direction))
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Trend: %s\n", result.TrendLine))
	sb.WriteString(fmt.Sprintf("\n%s\n", result.Narrative))
	return sb.String()
}

func fmtDelta(d float64) string {
	if d > 0 {
		return fmt.Sprintf("+%.1f", d)
	}
	return fmt.Sprintf("%.1f", d)
}
