package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ── flags ───────────────────────────────────────────────────────────────────

var (
	// shared across plan + apply
	fixProviderFlag string
	fixModelFlag    string
	fixMaxFlag      int
	fixSeverityFlag string
	fixFileFlag     string

	// apply-only
	fixAutoApproveFlag bool
)

// ── commands ────────────────────────────────────────────────────────────────

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Preview and apply AI-generated fixes for open findings",
	Long: `Parent command for fix workflows. Reads findings from the last scan and
generates AI-powered HCL fixes.

Subcommands:
  plan    Dry-run — generate fixes and show colored diffs without writing
  apply   Apply fixes interactively (default) or automatically (--auto-approve)

Requires a previous 'terraview scan' in this project directory.`,
	Example: `  terraview fix plan
  terraview fix apply
  terraview fix apply --auto-approve
  terraview fix apply CKV_AWS_18
  terraview fix apply --severity CRITICAL --file vpc.tf`,
}

var fixPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Dry-run: generate fixes and show diffs without writing",
	Long: `Generates AI-powered fix suggestions for CRITICAL/HIGH findings from the
last scan and displays colored diffs for each. No files are modified.

Run 'terraview fix apply' to apply these fixes.`,
	Example: `  terraview fix plan
  terraview fix plan --severity CRITICAL
  terraview fix plan --file vpc.tf`,
	RunE: runFixPlan,
}

var fixApplyCmd = &cobra.Command{
	Use:   "apply [finding-id]",
	Short: "Apply AI-generated fixes (interactive by default)",
	Long: `Generates AI-powered fix suggestions and applies them to .tf files.

Default mode is interactive: each fix is shown with a diff, and you approve or
reject per fix. Use --auto-approve to apply all without prompting (CI/scripts).

Filters:
  [finding-id]      positional arg — only fix findings with this rule ID
  --severity LEVEL  only CRITICAL or HIGH
  --file PATH       only fixes that modify this file
  --max N           cap the number of fixes generated (0 = unlimited)`,
	Example: `  terraview fix apply
  terraview fix apply --auto-approve
  terraview fix apply CKV_AWS_18
  terraview fix apply --severity CRITICAL
  terraview fix apply --file vpc.tf
  terraview fix apply --severity HIGH --max 5`,
	Args: cobra.MaximumNArgs(1),
	RunE: runFixApply,
}

func init() {
	rootCmd.AddCommand(fixCmd)
	fixCmd.AddCommand(fixPlanCmd)
	fixCmd.AddCommand(fixApplyCmd)

	// Shared flags on both subcommands
	for _, c := range []*cobra.Command{fixPlanCmd, fixApplyCmd} {
		c.Flags().StringVar(&fixProviderFlag, "provider", "", "AI provider override (default: from last scan or config)")
		c.Flags().StringVar(&fixModelFlag, "model", "", "AI model override")
		c.Flags().IntVar(&fixMaxFlag, "max", 0, "Maximum number of fixes to generate (0 = unlimited)")
		c.Flags().StringVar(&fixSeverityFlag, "severity", "", "Only fix findings of this severity (CRITICAL, HIGH)")
		c.Flags().StringVar(&fixFileFlag, "file", "", "Only fix findings whose .tf file matches this path")
	}

	fixApplyCmd.Flags().BoolVar(&fixAutoApproveFlag, "auto-approve", false, "Apply all fixes without interactive confirmation")
}

// ── run handlers ────────────────────────────────────────────────────────────

type fixFilter struct {
	findingID string
	severity  string
	file      string
	max       int
}

func runFixPlan(_ *cobra.Command, _ []string) error {
	filter := fixFilter{
		findingID: "",
		severity:  strings.ToUpper(fixSeverityFlag),
		file:      fixFileFlag,
		max:       fixMaxFlag,
	}
	return generateAndHandleFixes(filter, func(session *fix.ApplySession, pending []fix.PendingFix) {
		session.Preview(pending)
	})
}

func runFixApply(_ *cobra.Command, args []string) error {
	filter := fixFilter{
		severity: strings.ToUpper(fixSeverityFlag),
		file:     fixFileFlag,
		max:      fixMaxFlag,
	}
	if len(args) > 0 {
		filter.findingID = args[0]
	}

	return generateAndHandleFixes(filter, func(session *fix.ApplySession, pending []fix.PendingFix) {
		if fixAutoApproveFlag {
			session.ApplyAll(pending)
		} else {
			session.Review(pending)
		}
	})
}

// ── core generator ──────────────────────────────────────────────────────────

func generateAndHandleFixes(filter fixFilter, handler func(*fix.ApplySession, []fix.PendingFix)) error {
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

	age := time.Since(ls.Timestamp)
	fmt.Printf("\n%s Last scan:%s %s (%s)  ·  %d findings\n",
		output.Prefix(), reset,
		ls.Timestamp.Format("2006-01-02 15:04"),
		humanAge(age),
		len(ls.Findings),
	)
	if age > 24*time.Hour {
		fmt.Printf("  %s⚠ Last scan is over 24h old — consider running terraview scan first.%s\n", yellow, reset)
	}

	// Filter eligible findings
	targets := filterFixTargets(ls.Findings, filter)
	if len(targets) == 0 {
		fmt.Printf("\n  %s✓ No findings match the filter.%s\n\n", green, reset)
		return nil
	}
	fmt.Printf("  %d finding(s) to process\n\n", len(targets))

	// Resolve AI provider
	providerName := fixProviderFlag
	modelName := fixModelFlag
	if providerName == "" {
		providerName = ls.Provider
		if providerName == "" {
			if cfg, cfgErr := config.Load(workDir); cfgErr == nil {
				providerName = cfg.LLM.Provider
				if modelName == "" {
					modelName = cfg.LLM.Model
				}
			}
		}
	}
	if modelName == "" {
		modelName = ls.Model
	}
	if providerName == "" {
		return fmt.Errorf("no AI provider configured — use --provider or run: terraview provider list")
	}

	searchDir := ls.ProjectDir
	if workDir != "" && workDir != "." {
		searchDir = workDir
	}

	// Load plan for resource context
	planPath := ls.PlanFile
	if planFile != "" {
		planPath = planFile
	}
	rawPlan, resources, _, planErr := parsePlan(planPath)
	if planErr != nil {
		fmt.Printf("  %s⚠ Could not load plan (%v) — fixes will have less context.%s\n", yellow, planErr, reset)
	}

	// Build provider
	const perCallTimeout = 30
	const perFindingBudget = perCallTimeout*2 + 5

	providerCfg := ai.ProviderConfig{
		Model:       modelName,
		APIKey:      resolveAPIKey(providerName),
		Temperature: 0.1,
		MaxTokens:   1024,
		MaxRetries:  1,
		TimeoutSecs: perCallTimeout,
	}

	globalCtx, cancel := context.WithTimeout(context.Background(),
		time.Duration(perFindingBudget*len(targets)+30)*time.Second)
	defer cancel()

	provider, err := ai.NewProvider(globalCtx, providerName, providerCfg)
	if err != nil {
		return fmt.Errorf("AI provider: %w", err)
	}
	suggester := fix.NewSuggester(provider)

	resourceMap := make(map[string]parsedResource, len(resources))
	for _, r := range resources {
		resourceMap[r.Address] = parsedResource{typ: r.Type, values: r.Values}
	}

	var planIndex *fix.PlanIndex
	if rawPlan != nil {
		planIndex = fix.BuildIndex(rawPlan, resources)
	}

	// Phase 1: generate suggestions
	fmt.Printf("%s Generating %d fix suggestion(s)...\n", output.Prefix(), len(targets))

	pending := make([]fix.PendingFix, 0, len(targets))
	for i, f := range targets {
		fmt.Printf("  [%d/%d] %s on %s... ", i+1, len(targets), f.RuleID, f.Resource)

		resourceType := extractType(f.Resource)
		var resourceConfig map[string]interface{}
		if pr, ok := resourceMap[f.Resource]; ok {
			resourceType = pr.typ
			resourceConfig = pr.values
		}

		loc, _ := fix.FindResource(searchDir, f.Resource)

		// --file filter: skip if the located file doesn't match
		if filter.file != "" && !locationMatchesFile(loc, filter.file, searchDir) {
			fmt.Printf("⏩ skipped (file filter)\n")
			continue
		}

		findingCtx, findingCancel := context.WithTimeout(globalCtx, time.Duration(perFindingBudget)*time.Second)
		req := fix.FixRequest{
			Finding: fix.FixFinding{
				RuleID:   f.RuleID,
				Severity: f.Severity,
				Message:  f.Message,
				Category: f.Category,
			},
			ResourceAddr:   f.Resource,
			ResourceType:   resourceType,
			ResourceConfig: resourceConfig,
			PlanIndex:      planIndex,
		}
		if loc != nil {
			if lines, err := fix.ReadLines(loc); err == nil {
				req.CurrentHCL = strings.Join(lines, "\n")
			}
			req.FileContext = fix.ReadFileContext(loc, searchDir)
		}

		suggestion, err := suggester.Suggest(findingCtx, req)
		findingCancel()

		if err != nil {
			if isTimeoutErr(err) {
				fmt.Printf("⏩ skipped (timeout)\n")
			} else {
				fmt.Printf("✗ %v\n", err)
			}
			continue
		}
		fmt.Printf("✓\n")

		pending = append(pending, fix.PendingFix{
			Finding:    f,
			Suggestion: suggestion,
			Location:   loc,
			Warnings:   fix.ValidateFix(suggestion),
		})
	}

	if len(pending) == 0 {
		fmt.Printf("\n%s No fix suggestions could be generated.\n\n", output.Prefix())
		return nil
	}

	session := &fix.ApplySession{WorkDir: searchDir, NoColor: noColor}
	handler(session, pending)
	return nil
}

// ── helpers ─────────────────────────────────────────────────────────────────

type parsedResource struct {
	typ    string
	values map[string]interface{}
}

func filterFixTargets(findings []rules.Finding, f fixFilter) []rules.Finding {
	out := make([]rules.Finding, 0)
	seen := map[string]bool{}
	for _, fnd := range findings {
		// default eligibility: CRITICAL/HIGH only
		if fnd.Severity != "CRITICAL" && fnd.Severity != "HIGH" {
			continue
		}
		if f.severity != "" && fnd.Severity != f.severity {
			continue
		}
		if f.findingID != "" && !strings.EqualFold(fnd.RuleID, f.findingID) {
			continue
		}
		key := fnd.RuleID + "|" + fnd.Resource
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, fnd)
		if f.max > 0 && len(out) == f.max {
			break
		}
	}
	return out
}

// locationMatchesFile returns true when the located .tf file matches the user's
// --file filter. Accepts either a basename match or a substring of the relative
// path so users can pass `vpc.tf` or `modules/vpc/main.tf`.
func locationMatchesFile(loc *fix.Location, want, base string) bool {
	if loc == nil {
		return false
	}
	rel, err := filepath.Rel(base, loc.File)
	if err != nil {
		rel = loc.File
	}
	want = filepath.ToSlash(want)
	rel = filepath.ToSlash(rel)
	if strings.EqualFold(filepath.Base(rel), filepath.Base(want)) {
		return true
	}
	return strings.Contains(rel, want)
}

func extractType(addr string) string {
	if idx := strings.Index(addr, "."); idx >= 0 {
		return addr[:idx]
	}
	return addr
}

func resolveAPIKey(providerName string) string {
	switch {
	case strings.HasPrefix(providerName, "claude"):
		return os.Getenv("ANTHROPIC_API_KEY")
	case strings.HasPrefix(providerName, "gemini"):
		return os.Getenv("GEMINI_API_KEY")
	case strings.HasPrefix(providerName, "openai"):
		return os.Getenv("OPENAI_API_KEY")
	case strings.HasPrefix(providerName, "deepseek"):
		return os.Getenv("DEEPSEEK_API_KEY")
	case strings.HasPrefix(providerName, "openrouter"):
		return os.Getenv("OPENROUTER_API_KEY")
	default:
		return ""
	}
}

func isTimeoutErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline")
}
