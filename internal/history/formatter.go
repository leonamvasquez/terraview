package history

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/leonamvasquez/terraview/internal/i18n"
)

const (
	FormatPretty = "pretty"
	FormatJSON   = "json"
	FormatCSV    = "csv"
)

// FormatList formats a list of scan records for output.
func FormatList(w io.Writer, records []ScanRecord, format, projectName string) error {
	switch format {
	case FormatJSON:
		return formatJSON(w, records)
	case FormatCSV:
		return formatCSV(w, records)
	default:
		return formatPretty(w, records, projectName)
	}
}

func formatPretty(w io.Writer, records []ScanRecord, projectName string) error {
	msgs := i18n.T()
	if len(records) == 0 {
		fmt.Fprintln(w, msgs.HistoryNoScans)
		return nil
	}

	if projectName == "" {
		projectName = records[0].ProjectDir
	}

	title := fmt.Sprintf(msgs.HistoryTitle, projectName)
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("═", len([]rune(title))))
	fmt.Fprintln(w)

	// Header
	fmt.Fprintf(w, "%-4s %-20s %-10s %-10s %-8s %-10s %s\n",
		"#", msgs.HistoryColDate, "Scanner", "Provider", "Overall", "Security", "Findings")
	fmt.Fprintf(w, "%-4s %-20s %-10s %-10s %-8s %-10s %s\n",
		"───", "────────────────────", "──────────", "──────────", "────────", "──────────", "─────────────")

	for _, r := range records {
		provider := r.Provider
		if provider == "" {
			if r.StaticOnly {
				provider = "(static)"
			} else {
				provider = "-"
			}
		}

		fmt.Fprintf(w, "%-4d %-20s %-10s %-10s %-8.1f %-10.1f %s\n",
			r.ID,
			r.Timestamp.Local().Format("2006-01-02 15:04"),
			truncate(r.Scanner, 10),
			truncate(provider, 10),
			r.ScoreOverall,
			r.ScoreSecurity,
			r.FindingsSummary(),
		)
	}

	return nil
}

func formatJSON(w io.Writer, records []ScanRecord) error {
	if records == nil {
		records = []ScanRecord{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(records)
}

func formatCSV(w io.Writer, records []ScanRecord) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header
	if err := cw.Write([]string{
		"id", "timestamp", "project_dir", "scanner", "provider", "model",
		"score_overall", "score_security", "score_compliance", "score_maintain",
		"critical", "high", "medium", "low", "info",
		"duration_ms", "static_only",
	}); err != nil {
		return err
	}

	for _, r := range records {
		if err := cw.Write([]string{
			fmt.Sprintf("%d", r.ID),
			r.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			r.ProjectDir,
			r.Scanner,
			r.Provider,
			r.Model,
			fmt.Sprintf("%.1f", r.ScoreOverall),
			fmt.Sprintf("%.1f", r.ScoreSecurity),
			fmt.Sprintf("%.1f", r.ScoreCompliance),
			fmt.Sprintf("%.1f", r.ScoreMaintain),
			fmt.Sprintf("%d", r.CountCritical),
			fmt.Sprintf("%d", r.CountHigh),
			fmt.Sprintf("%d", r.CountMedium),
			fmt.Sprintf("%d", r.CountLow),
			fmt.Sprintf("%d", r.CountInfo),
			fmt.Sprintf("%d", r.DurationMs),
			fmt.Sprintf("%t", r.StaticOnly),
		}); err != nil {
			return err
		}
	}

	return nil
}

// FormatTrendOutput formats the full trend display.
func FormatTrendOutput(w io.Writer, trends []TrendData, projectName string, count int) {
	msgs := i18n.T()
	if len(trends) == 0 {
		fmt.Fprintln(w, msgs.TrendNoData)
		return
	}

	title := fmt.Sprintf(msgs.TrendTitle, projectName, count)
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("═", len([]rune(title))))
	fmt.Fprintln(w)

	for _, td := range trends {
		fmt.Fprintln(w, FormatTrend(td))
	}
}

// FormatCompareOutput formats a comparison result.
func FormatCompareOutput(w io.Writer, cr CompareResult, projectName string) {
	msgs := i18n.T()
	title := fmt.Sprintf(msgs.CompareTitle, projectName)
	fmt.Fprintln(w, title)
	fmt.Fprintln(w, strings.Repeat("═", len([]rune(title))))
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%-20s %-16s %-12s %-6s\n",
		"", cr.Label, msgs.CompareColNow, "Delta")
	fmt.Fprintf(w, "%-20s %-16s %-12s %-6s\n",
		"────────────────────", "────────────────", "────────────", "──────")

	for _, d := range cr.Deltas {
		fmt.Fprintln(w, FormatDeltaRow(d))
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
