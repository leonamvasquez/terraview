package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/spf13/cobra"
)

var (
	fixMaxFlag      int
	fixAllFlag      bool
	fixProviderFlag string
	fixModelFlag    string
)

var fixCmd = &cobra.Command{
	Use:   "fix",
	Short: "Interactively review and apply AI-generated fixes for open findings",
	Long: `Reads findings from the last scan and generates AI-powered HCL fixes.
Each fix is presented for approval before being applied directly to the .tf file.

Requires a previous 'terraview scan' in this project directory.`,
	Example: `  terraview fix
  terraview fix --max-fix 10
  terraview fix --provider claude --model claude-haiku-4-5`,
	RunE: runFix,
}

func init() {
	fixCmd.Flags().IntVar(&fixMaxFlag, "max-fix", 5, "Maximum number of findings to fix")
	fixCmd.Flags().BoolVar(&fixAllFlag, "all", false, "Fix all CRITICAL/HIGH findings without interactive prompts")
	fixCmd.Flags().StringVar(&fixProviderFlag, "provider", "", "AI provider override (default: from last scan or config)")
	fixCmd.Flags().StringVar(&fixModelFlag, "model", "", "AI model override")
}

func runFix(cmd *cobra.Command, _ []string) error {
	projectDir := resolveProjectDir()

	// ── Load last scan ──────────────────────────────────────────────────────
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

	// ── Filter to actionable findings ───────────────────────────────────────
	// --all means "apply without interactive prompts".
	// It only removes the cap when --max-fix was NOT explicitly set by the user;
	// if both are provided (--all --max-fix 30), the explicit limit is respected.
	maxFix := fixMaxFlag
	if fixAllFlag && !cmd.Flags().Changed("max-fix") {
		maxFix = 0 // no cap: fix everything
	}
	targets := filterFixTargets(ls.Findings, maxFix)
	if len(targets) == 0 {
		fmt.Printf("\n  %s✓ No CRITICAL/HIGH findings to fix.%s\n\n", green, reset)
		return nil
	}
	eligible := len(ls.FindingsBySeverity("CRITICAL", "HIGH"))
	if fixAllFlag && maxFix == 0 {
		fmt.Printf("  %d CRITICAL/HIGH finding(s) — fixing all\n\n", eligible)
	} else {
		fmt.Printf("  %d CRITICAL/HIGH finding(s) eligible · fixing up to %d\n\n", eligible, fixMaxFlag)
	}

	// ── Resolve AI provider ─────────────────────────────────────────────────
	providerName := fixProviderFlag
	modelName := fixModelFlag
	if providerName == "" {
		providerName = ls.Provider
		if providerName == "" {
			cfg, cfgErr := config.Load(workDir)
			if cfgErr == nil {
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

	// searchDir: where to find and patch .tf files.
	// Prefer ls.ProjectDir (saved from the scan run) so that `terraview fix`
	// works correctly regardless of the current working directory.
	// --dir overrides when explicitly provided.
	searchDir := ls.ProjectDir
	if workDir != "" && workDir != "." {
		searchDir = workDir
	}

	// ── Load plan for resource context ─────────────────────────────────────
	planPath := ls.PlanFile
	if planFile != "" {
		planPath = planFile // explicit --plan flag overrides
	}

	var rc reviewConfig
	rawPlan, resources, _, planErr := parsePlan(planPath)
	if planErr != nil {
		fmt.Printf("  %s⚠ Could not load plan (%v) — fixes will have less context.%s\n", yellow, planErr, reset)
	} else {
		rc.resolvedPlan = planPath
	}

	// Resolve API key from env / config
	apiKey := resolveAPIKey(providerName)

	// ── Build provider ──────────────────────────────────────────────────────
	const perCallTimeout = 30
	const perFindingBudget = perCallTimeout*2 + 5

	providerCfg := ai.ProviderConfig{
		Model:       modelName,
		APIKey:      apiKey,
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

	// ── Build resource index ────────────────────────────────────────────────
	resourceMap := make(map[string]parsedResource, len(resources))
	for _, r := range resources {
		resourceMap[r.Address] = parsedResource{typ: r.Type, values: r.Values}
	}

	var planIndex *fix.PlanIndex
	if rawPlan != nil {
		planIndex = fix.BuildIndex(rawPlan, resources)
	}

	// ── Phase 1: generate suggestions ──────────────────────────────────────
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

		// Locate the resource in the .tf files BEFORE calling the AI so we can
		// send the actual HCL source as context. The AI uses this to make a
		// minimal targeted change instead of rewriting the block from scratch.
		loc, _ := fix.FindResource(searchDir, f.Resource)

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

		// Enrich the request with actual source context when available.
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

	// ── Phase 2: apply ──────────────────────────────────────────────────────
	_ = rc
	session := fix.ApplySession{
		WorkDir: searchDir,
		NoColor: noColor,
	}
	if fixAllFlag {
		session.ApplyAll(pending)
	} else {
		session.Review(pending)
	}

	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

type parsedResource struct {
	typ    string
	values map[string]interface{}
}

func filterFixTargets(findings []rules.Finding, max int) []rules.Finding {
	out := make([]rules.Finding, 0)
	seen := map[string]bool{}
	for _, f := range findings {
		if f.Severity != "CRITICAL" && f.Severity != "HIGH" {
			continue
		}
		key := f.RuleID + "|" + f.Resource
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
		if max > 0 && len(out) == max {
			break
		}
	}
	return out
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
