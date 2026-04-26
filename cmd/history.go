package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/history"
)

var (
	historyAll       bool
	historyLimit     int
	historyProject   string
	historySince     string
	historyFormat    string
	historyExportFmt string
	historyWith      int64
	historyBefore    string
	historyOutFile   string
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View scan history and trends",
	Long: `View scan history stored locally in SQLite.

Every terraview scan automatically records results. Use history to query,
compare, and track security posture over time.

Usage:
  terraview history                           # last 20 scans, current project
  terraview history --all                     # all projects
  terraview history --limit 50
  terraview history --since 7d
  terraview history --since 2025-01-01
  terraview history --format json|csv
  terraview history trend                     # sparkline trends
  terraview history compare                   # last vs previous
  terraview history clear                     # clear current project
  terraview history export --format csv -o scans.csv`,
	RunE: runHistoryList,
}

var historyTrendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show score trends with sparklines",
	Long: `Show how security scores and finding counts trend over time.
Displays sparkline charts and delta percentages.

Usage:
  terraview history trend
  terraview history trend --limit 30`,
	RunE: runHistoryTrend,
}

var historyCompareCmd = &cobra.Command{
	Use:   "compare",
	Short: "Compare latest scan with a previous one",
	Long: `Compare the latest scan against a previous scan or point in time.

Usage:
  terraview history compare                   # last vs previous
  terraview history compare --with 5          # last vs scan #5
  terraview history compare --since 7d        # last vs oldest scan in 7 days`,
	RunE: runHistoryCompare,
}

var historyClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear scan history",
	Long: `Remove scan history records.

Usage:
  terraview history clear                     # current project only
  terraview history clear --all               # all projects
  terraview history clear --before 30d        # older than 30 days`,
	RunE: runHistoryClear,
}

var historyExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export scan history to file",
	Long: `Export scan history to CSV or JSON file.

Usage:
  terraview history export --format csv -o scans.csv
  terraview history export --format json -o scans.json`,
	RunE: runHistoryExport,
}

func init() {
	// List flags
	historyCmd.Flags().BoolVar(&historyAll, "all", false, "Show all projects")
	historyCmd.Flags().IntVar(&historyLimit, "limit", 20, "Maximum number of scans to show")
	historyCmd.Flags().StringVar(&historyProject, "project", "", "Filter by project directory")
	historyCmd.Flags().StringVar(&historySince, "since", "", "Show scans since (e.g. 7d, 30d, 2025-01-01)")
	historyCmd.Flags().StringVarP(&historyFormat, "format", "f", "pretty", "Output format: pretty, json, csv")

	// Trend flags
	historyTrendCmd.Flags().IntVar(&historyLimit, "limit", 20, "Number of scans for trend")
	historyTrendCmd.Flags().StringVar(&historySince, "since", "", "Trend since (e.g. 7d, 30d)")

	// Compare flags
	historyCompareCmd.Flags().Int64Var(&historyWith, "with", 0, "Compare with scan #ID")
	historyCompareCmd.Flags().StringVar(&historySince, "since", "", "Compare with oldest scan since (e.g. 7d)")

	// Clear flags
	historyClearCmd.Flags().BoolVar(&historyAll, "all", false, "Clear all projects")
	historyClearCmd.Flags().StringVar(&historyBefore, "before", "", "Clear scans older than (e.g. 30d, 0d)")

	// Export flags
	historyExportCmd.Flags().StringVarP(&historyExportFmt, "format", "f", "json", "Export format: json, csv")
	historyExportCmd.Flags().StringVarP(&historyOutFile, "output", "o", "", "Output file path (required)")
	historyExportCmd.Flags().IntVar(&historyLimit, "limit", 0, "Maximum number of records to export (0 = all)")

	// Register subcommands
	historyCmd.AddCommand(historyTrendCmd)
	historyCmd.AddCommand(historyCompareCmd)
	historyCmd.AddCommand(historyClearCmd)
	historyCmd.AddCommand(historyExportCmd)

	rootCmd.AddCommand(historyCmd)
}

func runHistoryList(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	if !cfg.History.Enabled {
		fmt.Fprintln(os.Stderr, pick(
			"History disabled. Set 'history.enabled: true' in .terraview.yaml",
			"Histórico desabilitado. Configure 'history.enabled: true' em .terraview.yaml",
		))
		return nil
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer store.Close()

	filter, err := buildListFilter(historyAll, historyProject, historySince, historyLimit, workDir)
	if err != nil {
		return err
	}

	records, err := store.List(filter)
	if err != nil {
		return err
	}

	projectName := resolveProjectName()
	if historyAll {
		projectName = pick("all projects", "todos os projetos")
	}

	return history.FormatList(os.Stdout, records, historyFormat, projectName)
}

// buildListFilter constructs a ListFilter from CLI flags. Pure function, no I/O.
func buildListFilter(all bool, project, since string, limit int, wd string) (history.ListFilter, error) {
	filter := history.ListFilter{Limit: limit}

	if !all {
		projectDir := wd
		if projectDir == "" || projectDir == "." {
			if d, err := os.Getwd(); err == nil {
				projectDir = d
			}
		}
		if project != "" {
			projectDir = project
		}
		filter.ProjectHash = history.ProjectHash(projectDir)
	}

	if since != "" {
		t, err := parseSince(since)
		if err != nil {
			return filter, err
		}
		filter.Since = t
	}

	return filter, nil
}

func runHistoryTrend(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	if !cfg.History.Enabled {
		fmt.Fprintln(os.Stderr, pick(
			"History disabled. Set 'history.enabled: true' in .terraview.yaml",
			"Histórico desabilitado. Configure 'history.enabled: true' em .terraview.yaml",
		))
		return nil
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer store.Close()

	filter := history.ListFilter{
		ProjectHash: history.ProjectHash(resolveProjectDir()),
		Limit:       historyLimit,
	}

	if historySince != "" {
		since, err := parseSince(historySince)
		if err != nil {
			return err
		}
		filter.Since = since
	}

	records, err := store.List(filter)
	if err != nil {
		return err
	}

	if len(records) == 0 {
		fmt.Fprintln(os.Stdout, pick("No scans found for trend.", "Nenhum scan encontrado para tendência."))
		return nil
	}

	trends := history.ComputeTrendsFromRecords(records)
	history.FormatTrendOutput(os.Stdout, trends, resolveProjectName(), len(records))
	return nil
}

func runHistoryCompare(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return err
	}
	if !cfg.History.Enabled {
		fmt.Fprintln(os.Stderr, pick(
			"History disabled. Set 'history.enabled: true' in .terraview.yaml",
			"Histórico desabilitado. Configure 'history.enabled: true' em .terraview.yaml",
		))
		return nil
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer store.Close()

	projectHash := history.ProjectHash(resolveProjectDir())

	// Get latest scan
	latest, err := store.GetLatest(projectHash)
	if err != nil {
		return fmt.Errorf("%s: %w", pick("no scans to compare", "sem scans para comparar"), err)
	}

	var oldScan *history.ScanRecord
	label := pick("Previous", "Anterior")

	if historyWith > 0 {
		// Compare with specific scan ID
		oldScan, err = store.GetByID(historyWith)
		if err != nil {
			return fmt.Errorf("scan #%d %s: %w", historyWith, pick("not found", "não encontrado"), err)
		}
		label = fmt.Sprintf("Scan #%d", historyWith)
	} else if historySince != "" {
		// Compare with oldest scan since the given date
		since, err := parseSince(historySince)
		if err != nil {
			return err
		}
		oldScan, err = store.GetOldestSince(projectHash, since)
		if err != nil {
			return fmt.Errorf("%s: %w", pick("no scans in range", "sem scans no período"), err)
		}
		label = historySince + pick(" ago", " atrás")
	} else {
		// Default: compare with previous scan
		oldScan, err = store.GetPrevious(projectHash)
		if err != nil {
			return fmt.Errorf("%s: %w", pick("no previous scan to compare", "sem scan anterior para comparar"), err)
		}
	}

	cr := history.CompareTwoScans(label, *oldScan, *latest)
	history.FormatCompareOutput(os.Stdout, cr, resolveProjectName())
	return nil
}

func runHistoryClear(cmd *cobra.Command, args []string) error {
	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer store.Close()

	var removed int64

	if historyBefore != "" {
		before, err := parseSince(historyBefore)
		if err != nil {
			return err
		}
		removed, err = store.DeleteBefore(before)
		if err != nil {
			return err
		}
	} else if historyAll {
		removed, err = store.DeleteAll()
		if err != nil {
			return err
		}
	} else {
		projectHash := history.ProjectHash(resolveProjectDir())
		removed, err = store.DeleteByProject(projectHash)
		if err != nil {
			return err
		}
	}

	fmt.Fprintf(os.Stdout, pick("%d record(s) removed.\n", "%d registro(s) removido(s).\n"), removed)
	return nil
}

// validateExportParams checks export parameters before I/O. Pure function.
func validateExportParams(outFile, format string) error {
	if outFile == "" {
		return fmt.Errorf("%s", pick("specify output file with -o/--output", "especifique o arquivo de saída com -o/--output"))
	}
	switch format {
	case "json", "csv":
		return nil
	default:
		return fmt.Errorf("%s: %q", pick("invalid export format (use json or csv)", "formato de exportação inválido (use json ou csv)"), format)
	}
}

func runHistoryExport(cmd *cobra.Command, args []string) error {
	if err := validateExportParams(historyOutFile, historyExportFmt); err != nil {
		return err
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		return fmt.Errorf("open history: %w", err)
	}
	defer store.Close()

	filter := history.ListFilter{Limit: historyLimit}
	if !historyAll {
		filter.ProjectHash = history.ProjectHash(resolveProjectDir())
	}

	records, err := store.List(filter)
	if err != nil {
		return err
	}

	f, err := os.Create(historyOutFile)
	if err != nil {
		return fmt.Errorf("criar arquivo: %w", err)
	}
	defer f.Close()

	if err := history.FormatList(f, records, historyExportFmt, ""); err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, pick("Exported %d record(s) to %s\n", "Exportado(s) %d registro(s) para %s\n"), len(records), historyOutFile)
	return nil
}

// parseSince parses a duration string like "7d", "30d", "24h" or a date like "2025-01-01".
func parseSince(s string) (time.Time, error) {
	// Try date format first
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}

	// Try duration-like format: Nd (days), Nh (hours)
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return time.Time{}, fmt.Errorf("invalid format: %q (use 7d, 30d, 2025-01-01)", s)
	}

	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	num, err := strconv.Atoi(numStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid format: %q (use 7d, 30d, 2025-01-01)", s)
	}

	switch unit {
	case 'd':
		return time.Now().AddDate(0, 0, -num), nil
	case 'h':
		return time.Now().Add(-time.Duration(num) * time.Hour), nil
	default:
		return time.Time{}, fmt.Errorf("invalid unit %q (use d or h)", string(unit))
	}
}

// resolveProjectDir returns the effective project directory.
func resolveProjectDir() string {
	if workDir != "" && workDir != "." {
		return workDir
	}
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

// resolveProjectName returns a human-friendly name for the project.
func resolveProjectName() string {
	dir := resolveProjectDir()
	return filepath.Base(dir)
}
