package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// fixWorkerPool is the number of concurrent suggester.Suggest calls during
// `fix plan` / `fix apply`. 3 is a balance between throughput and avoiding
// piling up parallel HTTP 429s on the same Gemini capacity pool. CLI providers
// (gemini-cli, claude-code) carry ~2-3s of subprocess startup overhead each,
// so memory pressure rises linearly with this constant.
const fixWorkerPool = 3

// ── flags ───────────────────────────────────────────────────────────────────

var (
	// shared across plan + apply
	fixProviderFlag string
	fixModelFlag    string
	fixMaxFlag      int
	fixSeverityFlag string
	fixFileFlag     string

	// apply-only
	fixAutoApproveFlag   bool
	fixMaxIterationsFlag int
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
	fixApplyCmd.Flags().IntVar(&fixMaxIterationsFlag, "max-iterations", 5, "Maximum scan→fix iterations (loop stops earlier on convergence or stagnation)")
}

// ── run handlers ────────────────────────────────────────────────────────────

type fixFilter struct {
	findingID string
	severity  string
	file      string
	max       int
}

// fixPlanRecord is the JSON representation of a single fix suggestion.
type fixPlanRecord struct {
	RuleID        string   `json:"rule_id"`
	Severity      string   `json:"severity"`
	Resource      string   `json:"resource"`
	Message       string   `json:"message"`
	File          string   `json:"file,omitempty"`
	HCL           string   `json:"hcl"`
	Explanation   string   `json:"explanation"`
	Prerequisites []string `json:"prerequisites,omitempty"`
	Effort        string   `json:"effort"`
}

func runFixPlan(_ *cobra.Command, _ []string) error {
	filter := fixFilter{
		findingID: "",
		severity:  strings.ToUpper(fixSeverityFlag),
		file:      fixFileFlag,
		max:       fixMaxFlag,
	}
	if outputFormat == "json" {
		return generateAndHandleFixes(filter, func(_ *fix.ApplySession, pending []fix.PendingFix) {
			writeFixPlanJSON(pending)
		})
	}
	return generateAndHandleFixes(filter, func(session *fix.ApplySession, pending []fix.PendingFix) {
		session.Preview(pending)
	})
}

func writeFixPlanJSON(pending []fix.PendingFix) {
	records := make([]fixPlanRecord, 0, len(pending))
	for _, p := range pending {
		r := fixPlanRecord{
			RuleID:        p.Finding.RuleID,
			Severity:      p.Finding.Severity,
			Resource:      p.Finding.Resource,
			Message:       p.Finding.Message,
			HCL:           p.Suggestion.HCL,
			Explanation:   p.Suggestion.Explanation,
			Prerequisites: p.Suggestion.Prerequisites,
			Effort:        p.Suggestion.Effort,
		}
		if p.Location != nil {
			r.File = p.Location.File
		}
		records = append(records, r)
	}

	data, _ := json.MarshalIndent(records, "", "  ")

	if outputDir != "" {
		outPath := outputDir
		if !strings.HasSuffix(outPath, ".json") {
			outPath = filepath.Join(outPath, "fix-plan.json")
		}
		if err := os.WriteFile(outPath, data, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, err)
			return
		}
		fmt.Printf("Written: %s\n", outPath)
		return
	}
	fmt.Println(string(data))
}

// runFixApply runs scan→fix in a loop until HIGH/CRITICAL findings are zeroed,
// stop dropping, or max-iterations is reached. The loop is the default because
// prerequisites added by one fix often introduce new findings (e.g. a fresh KMS
// key that needs a policy) — convergence typically takes 2–4 iterations.
//
// Iteration mode (auto vs interactive) follows --auto-approve.
func runFixApply(cmd *cobra.Command, args []string) error {
	maxIter := fixMaxIterationsFlag
	if maxIter <= 0 {
		maxIter = 5
	}
	prevHigh := -1
	for iter := 1; iter <= maxIter; iter++ {
		if maxIter > 1 {
			fmt.Printf("\n%s ─── Iteration %d/%d ───\n", output.Prefix(), iter, maxIter)
		}

		// Step 1: rescan to see the current state.
		if err := runScan(cmd, []string{}); err != nil {
			return fmt.Errorf("scan in iteration %d: %w", iter, err)
		}

		// Step 2: count HIGH/CRITICAL findings.
		ls, err := history.LoadLastScan(resolveProjectDir())
		if err != nil || ls == nil {
			return fmt.Errorf("could not load scan results in iteration %d", iter)
		}
		high := 0
		for _, f := range ls.Findings {
			if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
				high++
			}
		}
		if maxIter > 1 {
			fmt.Printf("%s iter %d: %d HIGH/CRITICAL finding(s)\n", output.Prefix(), iter, high)
		}

		if high == 0 {
			fmt.Printf("%s ✓ converged: no HIGH/CRITICAL findings remaining.\n", output.Prefix())
			return nil
		}
		if prevHigh != -1 && high >= prevHigh {
			fmt.Printf("%s ⚠ no progress (prev=%d, now=%d) — stopping.\n", output.Prefix(), prevHigh, high)
			return nil
		}
		prevHigh = high

		// Step 3: apply fixes.
		filter := fixFilter{
			severity: strings.ToUpper(fixSeverityFlag),
			file:     fixFileFlag,
			max:      fixMaxFlag,
		}
		if len(args) > 0 {
			filter.findingID = args[0]
		}
		if err := generateAndHandleFixes(filter, func(session *fix.ApplySession, pending []fix.PendingFix) {
			if fixAutoApproveFlag {
				session.ApplyAll(pending)
			} else {
				session.Review(pending)
			}
		}); err != nil {
			return fmt.Errorf("fix apply in iteration %d: %w", iter, err)
		}
	}
	fmt.Printf("%s ⚠ reached max iterations (%d) — re-run if more findings remain.\n", output.Prefix(), maxIter)
	return nil
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
	// CLI-based providers (claude-code, gemini-cli) have higher latency due to
	// subprocess startup + hook execution, so they get longer defaults. Users
	// can override via .terraview.yaml: llm.fix_timeout_seconds, llm.fix_max_retries.
	isCLIProvider := providerName == "claude-code" || providerName == "gemini-cli"
	perCallTimeout := 60
	maxRetries := 1
	if isCLIProvider {
		perCallTimeout = 180
		maxRetries = 2
	}
	if cfg, cfgErr := config.Load(workDir); cfgErr == nil {
		if cfg.LLM.FixTimeoutSeconds > 0 {
			perCallTimeout = cfg.LLM.FixTimeoutSeconds
		} else if cfg.LLM.TimeoutSeconds > perCallTimeout {
			perCallTimeout = cfg.LLM.TimeoutSeconds
		}
		if cfg.LLM.FixMaxRetries > 0 {
			maxRetries = cfg.LLM.FixMaxRetries
		}
	}
	perFindingBudget := perCallTimeout*(maxRetries+1) + 5

	providerCfg := ai.ProviderConfig{
		Model:       modelName,
		APIKey:      resolveAPIKey(providerName),
		Temperature: 0.1,
		MaxTokens:   1024,
		MaxRetries:  maxRetries,
		TimeoutSecs: perCallTimeout,
	}

	globalCtx, cancel := context.WithTimeout(rootCtx,
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

	// Phase 1: generate suggestions (parallel worker pool).
	// Findings are pre-built into jobs serially (file filtering, HCL/context
	// reads), then dispatched to a small pool of workers that call the AI
	// provider concurrently. Output stays labeled by [i/N] so the user can
	// trace progress even though completion order may interleave.
	fmt.Printf("%s Generating %d fix suggestion(s) (concurrency=%d)...\n", output.Prefix(), len(targets), fixWorkerPool)

	type fixJob struct {
		idx        int
		finding    rules.Finding
		req        fix.FixRequest
		loc        *fix.Location
		skipReason string // non-empty → skip without calling AI
	}
	type fixOutcome struct {
		suggestion *fix.FixSuggestion
		loc        *fix.Location
		finding    rules.Finding
		ok         bool
	}

	jobs := make([]fixJob, 0, len(targets))
	for i, f := range targets {
		resourceType := extractType(f.Resource)
		var resourceConfig map[string]interface{}
		if pr, ok := resourceMap[f.Resource]; ok {
			resourceType = pr.typ
			resourceConfig = pr.values
		}
		loc, _ := fix.FindResource(searchDir, f.Resource)
		job := fixJob{idx: i, finding: f, loc: loc}
		if filter.file != "" && !locationMatchesFile(loc, filter.file, searchDir) {
			job.skipReason = "file filter"
			jobs = append(jobs, job)
			continue
		}
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
		if brFlag {
			req.Lang = "pt-BR"
		}
		if loc != nil {
			if lines, err := fix.ReadLines(loc); err == nil {
				req.CurrentHCL = strings.Join(lines, "\n")
			}
			req.FileContext = fix.ReadFileContext(loc, searchDir)
		}
		job.req = req
		jobs = append(jobs, job)
	}

	outcomes := make([]fixOutcome, len(jobs))
	sem := make(chan struct{}, fixWorkerPool)
	var wg sync.WaitGroup
	var printMu sync.Mutex
	total := len(targets)

	// Group eligible jobs (no skipReason) by ResourceAddr so multiple findings
	// on the same resource can be batched into a single AI call. Resources with
	// only one finding still go through the singleton path.
	skippedIdxs := make([]int, 0)
	groups := make(map[string][]int) // resourceAddr → []job index
	groupOrder := make([]string, 0)
	for j, job := range jobs {
		if job.skipReason != "" {
			skippedIdxs = append(skippedIdxs, j)
			continue
		}
		addr := job.finding.Resource
		if _, ok := groups[addr]; !ok {
			groupOrder = append(groupOrder, addr)
		}
		groups[addr] = append(groups[addr], j)
	}

	// Drain skipped jobs first (no AI work).
	for _, j := range skippedIdxs {
		job := jobs[j]
		label := fmt.Sprintf("  [%d/%d] %s on %s...", job.idx+1, total, job.finding.RuleID, job.finding.Resource)
		fmt.Printf("%s ⏩ skipped (%s)\n", label, job.skipReason)
		outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
	}

	for _, addr := range groupOrder {
		idxs := groups[addr]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Build the label set for this group up-front so progress stays readable.
			labelOf := func(j int) string {
				job := jobs[j]
				return fmt.Sprintf("  [%d/%d] %s on %s...", job.idx+1, total, job.finding.RuleID, job.finding.Resource)
			}

			// Allow more time for batch (multiple findings) but cap so a single
			// stuck resource cannot starve the global budget.
			budget := perFindingBudget
			if len(idxs) > 1 {
				budget = perFindingBudget * 2
				if cap := perFindingBudget * len(idxs); cap < budget {
					budget = cap
				}
			}
			findingCtx, findingCancel := context.WithTimeout(globalCtx, time.Duration(budget)*time.Second)
			defer findingCancel()

			if len(idxs) == 1 {
				j := idxs[0]
				job := jobs[j]
				suggestion, err := suggester.Suggest(findingCtx, job.req)
				printMu.Lock()
				defer printMu.Unlock()
				if err != nil {
					if isTimeoutErr(err) {
						fmt.Printf("%s ⏩ skipped (timeout)\n", labelOf(j))
					} else {
						fmt.Printf("%s ✗ %v\n", labelOf(j), err)
					}
					outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
					return
				}
				fmt.Printf("%s ✓\n", labelOf(j))
				outcomes[j] = fixOutcome{suggestion: suggestion, loc: job.loc, finding: job.finding, ok: true}
				return
			}

			// Batch path — N≥2 findings on the same resource.
			reqs := make([]fix.FixRequest, len(idxs))
			for k, j := range idxs {
				reqs[k] = jobs[j].req
			}
			suggestions, err := suggester.SuggestBatch(findingCtx, reqs)
			if err != nil {
				// Fallback: per-finding on batch failure to preserve quality.
				printMu.Lock()
				fmt.Printf("  ⚠ batch failed for %s (%d findings) — falling back per-finding: %v\n", addr, len(idxs), err)
				printMu.Unlock()
				for _, j := range idxs {
					job := jobs[j]
					sugg, sErr := suggester.Suggest(findingCtx, job.req)
					printMu.Lock()
					if sErr != nil {
						if isTimeoutErr(sErr) {
							fmt.Printf("%s ⏩ skipped (timeout)\n", labelOf(j))
						} else {
							fmt.Printf("%s ✗ %v\n", labelOf(j), sErr)
						}
						outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
					} else {
						fmt.Printf("%s ✓\n", labelOf(j))
						outcomes[j] = fixOutcome{suggestion: sugg, loc: job.loc, finding: job.finding, ok: true}
					}
					printMu.Unlock()
				}
				return
			}
			printMu.Lock()
			defer printMu.Unlock()
			for k, j := range idxs {
				job := jobs[j]
				if k < len(suggestions) && suggestions[k] != nil {
					fmt.Printf("%s ✓ (batch×%d)\n", labelOf(j), len(idxs))
					outcomes[j] = fixOutcome{suggestion: suggestions[k], loc: job.loc, finding: job.finding, ok: true}
				} else {
					fmt.Printf("%s ✗ batch missing suggestion\n", labelOf(j))
					outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
				}
			}
		}()
	}
	wg.Wait()

	// Reassemble pending in original target order so downstream display is
	// deterministic regardless of completion order.
	pending := make([]fix.PendingFix, 0, len(jobs))
	for _, oc := range outcomes {
		if !oc.ok {
			continue
		}
		pending = append(pending, fix.PendingFix{
			Finding:    oc.finding,
			Suggestion: oc.suggestion,
			Location:   oc.loc,
			Warnings:   fix.ValidateFix(oc.suggestion),
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
