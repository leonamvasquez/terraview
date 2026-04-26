package cmd

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
)

var (
	statusAllFlag           bool
	statusExplainScoresFlag bool
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show open findings from the last scan",
	Long: `Show the security findings from the most recent scan for this project.
Displays a delta against the previous scan and lists all open CRITICAL/HIGH findings.

Use --explain-scores to see the detailed score decomposition from the last scan.

Run 'terraview fix apply' to interactively patch these findings.`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusAllFlag, "all", false, "Show all severities, not just CRITICAL/HIGH")
	statusCmd.Flags().BoolVar(&statusExplainScoresFlag, "explain-scores", false, "Show detailed score decomposition from the last scan")

	// pt-BR flag translations (brFlag set in root.go init which runs before status.go init)
	if brFlag {
		translateFlags(statusCmd, map[string]string{
			"all":            "Exibir todas as severidades, não apenas CRITICAL/HIGH",
			"explain-scores": "Exibir decomposição detalhada dos scores do último scan",
		})
	}
}

func runStatus(cmd *cobra.Command, _ []string) error {
	projectDir := resolveProjectDir()

	ls, err := history.LoadLastScan(projectDir)
	if err != nil {
		return fmt.Errorf("reading last scan: %w", err)
	}
	if ls == nil {
		fmt.Printf("%s No scan found for this project.\n", output.Prefix())
		fmt.Printf("  Run %sterraview scan checkov%s first.\n\n", bold, reset)
		return nil
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err == nil {
		defer store.Close()
	}

	printStatusHeader(ls, projectDir)
	printSeverityTable(ls, store)
	printOpenFindings(ls)

	if statusExplainScoresFlag {
		if ls.ScoreDecomposition != nil {
			fmt.Println()
			output.PrintScoreDecomposition(ls.ScoreDecomposition, brFlag)
		} else {
			fmt.Printf("  %s⚠ No score decomposition available — re-run 'terraview scan' to populate it.%s\n\n", yellow, reset)
		}
	}

	printStatusFooter(ls)

	return nil
}

func printStatusHeader(ls *history.LastScan, projectDir string) {
	msgs := i18n.T()
	age := time.Since(ls.Timestamp)
	ageStr := humanAge(age)

	scanner := ls.Scanner
	if ls.Provider != "" {
		scanner += " + " + ls.Provider
		if ls.Model != "" {
			scanner += "/" + ls.Model
		}
	}

	fmt.Printf("\n%s%s%s %s\n", bold, msgs.StatusOnProject, reset, projectDir)
	fmt.Printf("%s%s%s %s (%s)  ·  %d resources  ·  %s\n\n",
		dim, msgs.StatusLastScan, reset,
		ls.Timestamp.Format("2006-01-02 15:04"),
		ageStr,
		ls.TotalResources,
		scanner,
	)
}

func printSeverityTable(ls *history.LastScan, store *history.Store) {
	current := ls.CountBySeverity()

	// Try to load previous scan counts for delta
	var prev *history.ScanRecord
	if store != nil {
		records, err := store.List(history.ListFilter{
			ProjectHash: history.ProjectHash(ls.ProjectDir),
			Limit:       2,
		})
		if err == nil && len(records) >= 2 {
			prev = &records[1]
		}
	}

	type row struct {
		sev   string
		color string
		count int
		old   int
	}

	rows := []row{
		{"CRITICAL", red, current["CRITICAL"], 0},
		{"HIGH", yellow, current["HIGH"], 0},
		{"MEDIUM", dim, current["MEDIUM"], 0},
		{"LOW", dim, current["LOW"], 0},
	}
	if prev != nil {
		rows[0].old = prev.CountCritical
		rows[1].old = prev.CountHigh
		rows[2].old = prev.CountMedium
		rows[3].old = prev.CountLow
	}

	for _, r := range rows {
		delta := ""
		if prev != nil {
			diff := r.count - r.old
			switch {
			case diff > 0:
				delta = fmt.Sprintf("%s↑ %d new%s", red, diff, reset)
			case diff < 0:
				delta = fmt.Sprintf("%s↓ %d resolved%s", green, -diff, reset)
			default:
				delta = fmt.Sprintf("%s──%s", dim, reset)
			}
		}

		countStr := fmt.Sprintf("%d", r.count)
		if r.count > 0 && (r.sev == "CRITICAL" || r.sev == "HIGH") {
			countStr = r.color + countStr + reset
		}

		fmt.Printf("  %-10s %s%-3s%s   %s\n", r.sev, r.color, countStr, reset, delta)
	}
	fmt.Println()
}

func printOpenFindings(ls *history.LastScan) {
	severities := []string{"CRITICAL", "HIGH"}
	if statusAllFlag {
		severities = append(severities, "MEDIUM", "LOW", "INFO")
	}

	targets := ls.FindingsBySeverity(severities...)
	if len(targets) == 0 {
		fmt.Printf("  %s✓ No open findings.%s\n\n", green, reset)
		return
	}

	shown := targets
	maxShown := 10
	if statusAllFlag {
		maxShown = len(targets)
	}
	if len(targets) > maxShown {
		shown = targets[:maxShown]
	}

	fmt.Printf("%s%s%s\n\n", bold, i18n.T().StatusOpenFindings, reset)
	for _, f := range shown {
		sevColor := yellow
		if f.Severity == "CRITICAL" {
			sevColor = red
		}
		fmt.Printf("  %s%-8s%s  %s%-16s%s  %s\n",
			sevColor, f.Severity, reset,
			dim, f.RuleID, reset,
			f.Resource,
		)
		if f.Message != "" {
			msg := f.Message
			if len(msg) > 90 {
				msg = msg[:87] + "..."
			}
			fmt.Printf("            %s%s%s\n", dim, msg, reset)
		}
		fmt.Println()
	}

	remaining := len(targets) - len(shown)
	if remaining > 0 {
		fmt.Printf("  %s+ %d more — run with --all to show all%s\n\n", dim, remaining, reset)
	}
}

func printStatusFooter(ls *history.LastScan) {
	counts := ls.CountBySeverity()
	actionable := counts["CRITICAL"] + counts["HIGH"]

	if actionable > 0 {
		fmt.Printf("  Run %sterraview fix apply%s to interactively patch these findings.\n\n", bold, reset)
	} else {
		fmt.Printf("  %sNo CRITICAL/HIGH findings — run terraview scan to re-check.%s\n\n", dim, reset)
	}
}

func humanAge(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// ANSI helpers shared across status/fix commands.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
)
