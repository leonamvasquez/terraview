package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
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
	RuleID             string   `json:"rule_id"`
	Severity           string   `json:"severity"`
	Resource           string   `json:"resource"`
	Message            string   `json:"message"`
	File               string   `json:"file,omitempty"`
	HCL                string   `json:"hcl,omitempty"`
	Explanation        string   `json:"explanation,omitempty"`
	Prerequisites      []string `json:"prerequisites,omitempty"`
	Effort             string   `json:"effort,omitempty"`
	Advisory           bool     `json:"advisory,omitempty"`
	AdvisoryReason     string   `json:"advisory_reason,omitempty"`
	ManualReviewReason string   `json:"manual_review_reason,omitempty"`
	BlastRadius        string   `json:"blast_radius,omitempty"`
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
			RuleID:   p.Finding.RuleID,
			Severity: p.Finding.Severity,
			Resource: p.Finding.Resource,
			Message:  p.Finding.Message,
		}
		if p.Suggestion != nil {
			r.HCL = p.Suggestion.HCL
			r.Explanation = p.Suggestion.Explanation
			r.Prerequisites = p.Suggestion.Prerequisites
			r.Effort = p.Suggestion.Effort
			r.ManualReviewReason = p.Suggestion.ManualReviewReason
			r.BlastRadius = p.Suggestion.BlastRadius
		}
		if p.Advisory != nil {
			r.Advisory = true
			r.AdvisoryReason = p.Advisory.Reason
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
		// runScan returns *ExitError when findings exist (exit 1/2). That's the
		// expected case here — the loop's whole purpose is to react to findings,
		// so unwrap and continue. Only fail on real errors (parser/scanner/IO).
		//
		// stdout is redirected to /dev/null so the user does NOT see the full
		// verdict box / findings tables / scores during a fix loop — those are
		// noise here, the user only cares about applied/failed counts. The
		// scanner spinner (stderr) stays visible so progress is still felt, and
		// the result is persisted to history for the next step to read.
		if err := runScanQuiet(cmd, []string{}); err != nil {
			var exitErr *ExitError
			if !errors.As(err, &exitErr) {
				return fmt.Errorf("scan in iteration %d: %w", iter, err)
			}
		}

		// Step 2: count HIGH/CRITICAL findings.
		ls, err := history.LoadLastScan(resolveProjectDir())
		if err != nil {
			return fmt.Errorf("iter %d: load scan results: %w (try `terraview scan checkov` to verify the scanner is working)", iter, err)
		}
		if ls == nil {
			return fmt.Errorf("iter %d: scan completed but no findings were persisted to history. Verify history is enabled in .terraview.yaml (history.enabled: true) and that the scanner is producing output", iter)
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
			delta := high - prevHigh
			switch {
			case delta > 0:
				fmt.Printf("%s ⚠ regressing (prev=%d, now=%d, +%d new) — stopping. The AI is introducing more findings than it fixes; rerun without --auto-approve to review each change.\n",
					output.Prefix(), prevHigh, high, delta)
			default:
				fmt.Printf("%s ⚠ stalled at %d HIGH/CRITICAL — stopping. Remaining findings need manual review.\n",
					output.Prefix(), high)
			}
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

// runScanQuiet runs runScan with stdout redirected to /dev/null. The scanner
// spinner (stderr) and the persisted history are unaffected — only the loud
// verdict/findings/scores block is suppressed. Used inside the fix-apply loop
// where the user already saw a full scan and now just wants the apply phase.
func runScanQuiet(cmd *cobra.Command, args []string) error {
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		// Fallback: run normally if /dev/null is unavailable.
		return runScan(cmd, args)
	}
	defer devNull.Close()
	original := os.Stdout
	os.Stdout = devNull
	defer func() { os.Stdout = original }()
	return runScan(cmd, args)
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

	// Build project-wide HCL context once. Every fix request gets this so the AI
	// never re-declares an existing data source / variable / provider — the root
	// cause of the iterative-loop "whack-a-mole" where one fix introduces the
	// `Duplicate data ... configuration` error that the next iteration tries
	// (and fails) to clean up.
	projectCtx := fix.BuildProjectContext(searchDir)

	// Phase 1: generate suggestions (parallel worker pool).
	// Output is a single in-place spinner showing live `[done/total]` progress;
	// per-finding success lines are suppressed because at high N (50+) they
	// drown out everything else. Failures and skips are captured into a list
	// printed once after wg.Wait so the user still sees what didn't generate.
	type fixJob struct {
		idx        int
		finding    rules.Finding
		req        fix.FixRequest
		loc        *fix.Location
		skipReason string        // non-empty → skip without calling AI
		advisory   *fix.Advisory // non-nil → pre-classified advisory; AI call is skipped
	}
	type fixOutcome struct {
		suggestion *fix.FixSuggestion
		loc        *fix.Location
		finding    rules.Finding
		advisory   *fix.Advisory
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
		// Pre-classify by static signals (rule catalog + architectural
		// category) before paying for an AI call. Findings that are
		// fundamentally human decisions don't need a generated patch — they
		// just need to surface as advisories.
		if adv := fix.PreClassifyFindingForProject(f, projectDir); adv != nil {
			job.advisory = adv
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
			ProjectContext: projectCtx,
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
	var failuresMu sync.Mutex
	type genFailure struct {
		ruleID, resource, reason string
		skipped                  bool // true → "skipped (reason)"; false → "✗ reason"
	}
	failures := make([]genFailure, 0)
	total := len(targets)
	var doneCount atomic.Int64
	spinner := output.NewSpinner(fmt.Sprintf("Generating fix suggestions [0/%d]", total))
	spinner.Start()
	tick := func() {
		n := doneCount.Add(1)
		spinner.SetMessage(fmt.Sprintf("Generating fix suggestions [%d/%d]", n, total))
	}
	recordFailure := func(job fixJob, reason string, skipped bool) {
		failuresMu.Lock()
		failures = append(failures, genFailure{
			ruleID:   job.finding.RuleID,
			resource: job.finding.Resource,
			reason:   reason,
			skipped:  skipped,
		})
		failuresMu.Unlock()
	}

	// Group eligible jobs (no skipReason, no advisory) by ResourceAddr so
	// multiple findings on the same resource can be batched into a single AI
	// call. Resources with only one finding still go through the singleton
	// path. Pre-classified advisories are drained directly into outcomes
	// without paying for an AI call.
	skippedIdxs := make([]int, 0)
	advisoryIdxs := make([]int, 0)
	groups := make(map[string][]int) // resourceAddr → []job index
	groupOrder := make([]string, 0)
	for j, job := range jobs {
		if job.skipReason != "" {
			skippedIdxs = append(skippedIdxs, j)
			continue
		}
		if job.advisory != nil {
			advisoryIdxs = append(advisoryIdxs, j)
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
		recordFailure(job, job.skipReason, true)
		outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
		tick()
	}

	// Drain advisory jobs — they bypass AI generation and flow directly into
	// pending as advisories. Marked ok=true so they show up downstream.
	for _, j := range advisoryIdxs {
		job := jobs[j]
		outcomes[j] = fixOutcome{
			finding:  job.finding,
			loc:      job.loc,
			advisory: job.advisory,
			ok:       true,
		}
		tick()
	}

	for _, addr := range groupOrder {
		idxs := groups[addr]
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

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
				if err != nil {
					if isTimeoutErr(err) {
						recordFailure(job, "timeout", true)
					} else {
						recordFailure(job, err.Error(), false)
					}
					outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
					tick()
					return
				}
				outcomes[j] = fixOutcome{suggestion: suggestion, loc: job.loc, finding: job.finding, ok: true}
				tick()
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
				for _, j := range idxs {
					job := jobs[j]
					sugg, sErr := suggester.Suggest(findingCtx, job.req)
					if sErr != nil {
						if isTimeoutErr(sErr) {
							recordFailure(job, "timeout", true)
						} else {
							recordFailure(job, sErr.Error(), false)
						}
						outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
					} else {
						outcomes[j] = fixOutcome{suggestion: sugg, loc: job.loc, finding: job.finding, ok: true}
					}
					tick()
				}
				return
			}
			for k, j := range idxs {
				job := jobs[j]
				if k < len(suggestions) && suggestions[k] != nil {
					outcomes[j] = fixOutcome{suggestion: suggestions[k], loc: job.loc, finding: job.finding, ok: true}
				} else {
					recordFailure(job, "batch missing suggestion", false)
					outcomes[j] = fixOutcome{finding: job.finding, loc: job.loc}
				}
				tick()
			}
		}()
	}
	wg.Wait()
	spinner.Stop(len(failures) == 0)

	if len(failures) > 0 {
		fmt.Fprintln(os.Stderr)
		for _, f := range failures {
			marker := "✗"
			if f.skipped {
				marker = "⏩"
			}
			// Truncate noisy multi-line errors to the first line for readability.
			reason := f.reason
			if i := strings.IndexByte(reason, '\n'); i > 0 {
				reason = reason[:i]
			}
			fmt.Fprintf(os.Stderr, "  %s %s on %s — %s\n", marker, f.ruleID, f.resource, reason)
		}
	}

	// Build the dependency graph once so the Classifier can detect when a
	// proposed deletion would orphan inbound references — the most common
	// reason iterative fixes fail with "Reference to undeclared resource".
	graph := topology.BuildGraph(resources)
	classifier := fix.NewClassifierWithProject(graph, projectDir)

	// Reassemble pending in original target order so downstream display is
	// deterministic regardless of completion order. Pre-classified advisories
	// (no suggestion generated) flow through; suggestions get the full
	// Classifier pass to pick up the graph signal on top of catalog/category.
	pending := make([]fix.PendingFix, 0, len(jobs))
	for _, oc := range outcomes {
		if !oc.ok {
			continue
		}
		pf := fix.PendingFix{
			Finding:    oc.finding,
			Suggestion: oc.suggestion,
			Location:   oc.loc,
		}
		if oc.suggestion != nil {
			pf.Warnings = fix.ValidateFix(oc.suggestion)
		}
		switch {
		case oc.advisory != nil:
			pf.Advisory = oc.advisory
		default:
			pf.Advisory = classifier.Classify(pf)
		}
		pending = append(pending, pf)
	}

	if len(pending) == 0 {
		fmt.Printf("\n%s No fix suggestions could be generated.\n\n", output.Prefix())
		return nil
	}

	session := &fix.ApplySession{
		WorkDir:    searchDir,
		ProjectDir: projectDir,
		NoColor:    noColor,
	}
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
