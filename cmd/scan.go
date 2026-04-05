package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"time"

	"encoding/json"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/contextanalysis"
	"github.com/leonamvasquez/terraview/internal/diagram"
	"github.com/leonamvasquez/terraview/internal/fix"
	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/importer"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/normalizer"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/runtime"
	"github.com/leonamvasquez/terraview/internal/sanitizer"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/suppression"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/util"
	"github.com/leonamvasquez/terraview/internal/validator"
)

var (
	// Scan-local flags
	staticOnly        bool // --static: disable AI contextual analysis
	strict            bool
	explainFlag       bool
	diagramFlag       bool
	impactFlag        bool
	explainScoresFlag bool // --explain-scores: show scoring decomposition
	findingsFile      string
	allFlag           bool
	noRedactFlag      bool   // --no-redact: disable sensitive data redaction
	maxResourcesFlag  int    // --max-resources: override AI prompt resource limit (0=auto)
	fixFlag           bool   // --fix: generate AI-powered HCL fix suggestions for CRITICAL/HIGH findings
	fixApplyFlag      bool   // --apply: interactive apply mode — review and patch .tf files in place
	maxFixFlag        int    // --max-fix: max number of findings to generate fixes for (default 5)
	ignoreFile        string // --ignore-file: path to .terraview-ignore suppression file
)

var scanCmd = &cobra.Command{
	Use:   "scan [scanner]",
	Short: "Security scan with AI contextual analysis of a Terraform plan",
	Long: `Analyzes a Terraform plan using security scanners and AI contextual analysis.

By default, terraview runs BOTH the security scanner AND AI-powered contextual
analysis in parallel. The scanner checks individual resources against policy rules;
the AI analyzes cross-resource relationships, architectural patterns, and
dependency risks that static scanners cannot detect.

AI runs automatically when a provider is configured (via .terraview.yaml,
--provider flag, or 'terraview provider use'). Use --static to disable AI
and run only the scanner.

The scanner is specified as a positional argument.
If --plan is not specified, terraview will automatically run:
  terraform init   (if needed)
  terraform plan   (generates plan)
  terraform show   (exports JSON)

Examples:
  terraview scan checkov                       # scanner + AI (default)
  terraview scan checkov --static              # scanner only, no AI
  terraview scan checkov --all                 # everything enabled
  terraview scan checkov --provider gemini     # use specific AI provider
  terraview scan checkov --explain             # scanner + AI + explanation
  terraview scan checkov --diagram             # scanner + AI + diagram
  terraview scan checkov --impact              # scanner + AI + impact analysis
  terraview scan checkov --format compact      # minimal output
  terraview scan checkov --format sarif        # SARIF for CI
  terraview scan checkov --strict              # HIGH returns exit code 2
  terraview scan checkov --findings ext.json   # import external findings
  terraview scan checkov --fix                 # AI fix suggestions (top 5 findings)
  terraview scan checkov --fix --max-fix 10   # AI fix suggestions (up to 10 findings)

Terragrunt:
  terraview scan checkov --terragrunt           # use terragrunt for plan
  terraview scan tfsec --terragrunt -d modules/vpc`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&staticOnly, "static", false, "Static analysis only: disable AI contextual analysis")
	scanCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	scanCmd.Flags().BoolVar(&explainFlag, "explain", false, "Generate AI-powered natural language explanation")
	scanCmd.Flags().BoolVar(&diagramFlag, "diagram", false, "Show ASCII infrastructure diagram")
	scanCmd.Flags().BoolVar(&impactFlag, "impact", false, "Analyze dependency impact of changes")
	scanCmd.Flags().StringVar(&findingsFile, "findings", "", "Import external findings from Checkov/tfsec/Trivy JSON")
	scanCmd.Flags().BoolVar(&explainScoresFlag, "explain-scores", false, "Show detailed score decomposition for audit")
	scanCmd.Flags().BoolVar(&allFlag, "all", false, "Enable all features: explain + diagram + impact")
	scanCmd.Flags().BoolVar(&noRedactFlag, "no-redact", false, "Skip sensitive data redaction (use only with local providers)")
	scanCmd.Flags().IntVar(&maxResourcesFlag, "max-resources", 0, "Max resources included in AI prompt context (0=auto by model)")
	scanCmd.Flags().BoolVar(&fixFlag, "fix", false, "Generate AI-powered HCL fix suggestions for CRITICAL and HIGH findings")
	scanCmd.Flags().BoolVar(&fixApplyFlag, "apply", false, "Interactively review and apply AI fixes directly to .tf files (use with --fix)")
	scanCmd.Flags().IntVar(&maxFixFlag, "max-fix", 5, "Maximum number of findings to generate AI fixes for (used with --fix)")
	scanCmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "Path to suppression file (default: .terraview-ignore in project dir)")
}

func runScan(cmd *cobra.Command, args []string) error {
	// Resolve scanner from positional arg
	scannerName := ""
	if len(args) > 0 {
		scannerName = args[0]
	}

	// --all enables all features
	if allFlag {
		explainFlag = true
		diagramFlag = true
		impactFlag = true
	}

	// If no scanner specified, try auto-select.
	// Skip auto-selection when --findings is already provided with --static:
	// the caller explicitly chose "import external findings, no AI, no scanner".
	if scannerName == "" && !(staticOnly && findingsFile != "") {
		// Load config to check for default scanner
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}
		resolved, _ := scanner.ResolveDefault(cfg.Scanner.Default)
		if resolved != nil {
			scannerName = resolved.Name()
			logVerbose("Auto-selected scanner: %s", scannerName)
		}
	}

	// Validate: must specify at least a scanner or have AI configured
	if scannerName == "" && staticOnly && findingsFile == "" {
		// Show helpful error with installed scanners
		avail := scanner.DefaultManager.Available()
		if len(avail) == 0 {
			return fmt.Errorf("no scanners installed and --static disables AI.\n\nInstall a scanner first:\n  terraview scanners install checkov\n  terraview scanners install --all\n\nOr remove --static to use AI contextual analysis")
		}
		names := make([]string, 0, len(avail))
		for _, s := range avail {
			names = append(names, s.Name())
		}
		return fmt.Errorf("specify a scanner with --static\n\nInstalled scanners:\n  %s\n\nUsage:\n  terraview scan %s --static     # scanner only\n  terraview scan %s               # scanner + AI\n\nSet a default: terraview scanners default %s",
			strings.Join(names, "\n  "), names[0], names[0], names[0])
	}

	// If no scanner and no --static, AI-only mode is valid (if provider available)
	if scannerName == "" && !staticOnly && findingsFile == "" {
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}
		providerAvailable := canResolveAIProvider(cfg)
		if !providerAvailable {
			avail := scanner.DefaultManager.Available()
			if len(avail) == 0 {
				return fmt.Errorf("no scanners installed and no AI provider configured.\n\nGet started:\n  terraview scanners install checkov    # install a scanner\n  terraview provider install ollama     # install local AI\n\nOr configure an AI provider in .terraview.yaml")
			}
			names := make([]string, 0, len(avail))
			for _, s := range avail {
				names = append(names, s.Name())
			}
			return fmt.Errorf("specify a scanner or configure an AI provider\n\nInstalled scanners:\n  %s\n\nUsage:\n  terraview scan %s               # scanner + AI\n  terraview scan %s --static      # scanner only",
				strings.Join(names, "\n  "), names[0], names[0])
		}
	}

	_, exitCode, err := executeReview(scannerName)
	if err != nil {
		return err
	}

	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}

	return nil
}

// reviewConfig holds the resolved configuration for a review pipeline run.
type reviewConfig struct {
	cfg             config.Config
	scannerName     string
	resolvedPlan    string
	resolvedOutput  string
	effectiveAI     bool
	effectiveFormat string

	// Suppression
	ignoreFile string

	// AI settings
	aiProvider     string
	aiModel        string
	aiURL          string
	aiTimeout      int
	aiTemperature  float64
	aiAPIKey       string
	aiMaxResources int
	aiNumCtx       int
}

// cachedAnalysis is the serialized form of an AI context analysis result.
type cachedAnalysis struct {
	Findings []rules.Finding `json:"findings"`
	Summary  string          `json:"summary"`
}

// scanResult holds the output of the parallel scanner + AI phase.
type scanResult struct {
	hardFindings    []rules.Finding
	scannerResult   *scanner.AggregatedResult
	contextFindings []rules.Finding
	contextSummary  string
	pipelineStatus  *aggregator.PipelineStatus
}

// executeReview runs the full review pipeline and returns the plan path, exit code, and any error.
// Pipeline: Parse → [Scanner ‖ AI Context] → Merge → Score → Output
func executeReview(scannerName string) (string, int, error) { //nolint:unparam // planPath used by apply command
	rc, err := resolveReviewConfig(scannerName)
	if err != nil {
		return "", 0, err
	}

	rawPlan, resources, topoGraph, err := parsePlan(rc.resolvedPlan)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	sr, err := runScanners(rc, resources, topoGraph)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	result := mergeAndScore(rc, resources, topoGraph, sr)

	// Auto-record to history — fail-safe, never blocks scan
	recordToHistory(rc, result)

	exitCode, err := renderOutput(rc, result, sr.scannerResult)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	if fixFlag && len(result.Findings) > 0 {
		if fixApplyFlag {
			generateFixesInteractive(rc, result.Findings, resources, rawPlan, maxFixFlag)
		} else {
			generateFixes(rc, result.Findings, resources, rawPlan, maxFixFlag)
		}
	}

	return rc.resolvedPlan, exitCode, nil
}

// generateFixes produces AI-powered HCL fix suggestions for CRITICAL and HIGH findings.
// Capped at 5 fixes per run. Fails gracefully — never blocks the scan exit code.
func generateFixes(rc reviewConfig, findings []rules.Finding, resources []parser.NormalizedResource, rawPlan *parser.TerraformPlan, maxFix int) {
	if maxFix <= 0 {
		maxFix = 5
	}
	// Filter to CRITICAL and HIGH only, deduplicate by rule+resource, deterministic order.
	targets := make([]rules.Finding, 0, len(findings))
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
		targets = append(targets, f)
		if len(targets) == maxFix {
			break
		}
	}
	if len(targets) == 0 {
		return
	}

	// Build resource lookup map and plan index for fix context.
	resourceMap := make(map[string]parser.NormalizedResource, len(resources))
	for _, r := range resources {
		resourceMap[r.Address] = r
	}
	planIndex := fix.BuildIndex(rawPlan, resources)

	// Require an AI provider.
	providerName := rc.aiProvider
	if providerName == "" {
		fmt.Printf("\n%s --fix requires an AI provider. Configure one with: terraview provider list\n", output.Prefix())
		return
	}

	// perCallTimeout: max seconds for a single LLM completion call.
	// perFindingBudget: max seconds for one finding including one internal retry.
	const perCallTimeout = 30
	const perFindingBudget = perCallTimeout*2 + 5 // two calls + overhead

	providerCfg := ai.ProviderConfig{
		Model:       rc.aiModel,
		APIKey:      rc.aiAPIKey,
		BaseURL:     rc.aiURL,
		Temperature: 0.1,
		MaxTokens:   1024,
		MaxRetries:  1,
		TimeoutSecs: perCallTimeout,
	}
	if rc.aiURL != "" && providerName != "ollama" {
		providerCfg.BaseURL = ""
	}

	// Global context covers all findings; each finding also has its own timeout.
	globalCtx, cancel := context.WithTimeout(context.Background(), time.Duration(perFindingBudget*len(targets)+30)*time.Second)
	defer cancel()

	provider, err := ai.NewProvider(globalCtx, providerName, providerCfg)
	if err != nil {
		fmt.Printf("\n%s fix: AI provider unavailable: %v\n", output.Prefix(), err)
		return
	}

	suggester := fix.NewSuggester(provider)

	fmt.Printf("\n%s Generating fix suggestions for %d finding(s)...\n", output.Prefix(), len(targets))

	for _, f := range targets {
		res, ok := resourceMap[f.Resource]
		resourceType := f.Resource
		if idx := strings.Index(f.Resource, "."); idx >= 0 {
			resourceType = f.Resource[:idx]
		}
		var resourceConfig map[string]interface{}
		if ok {
			resourceType = res.Type
			resourceConfig = res.Values
		}

		// Per-finding timeout — prevents one slow finding from starving others.
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

		suggestion, err := suggester.Suggest(findingCtx, req)
		findingCancel()
		if err != nil {
			errMsg := err.Error()
			if strings.Contains(errMsg, "timeout") || strings.Contains(errMsg, "timed out") ||
				strings.Contains(errMsg, "deadline") {
				fmt.Printf("  ⏩ %s on %s — skipped (timed out after %ds; try a faster model)\n",
					f.RuleID, f.Resource, perCallTimeout)
			} else {
				fmt.Printf("  ✗ %s on %s — could not generate fix: %v\n", f.RuleID, f.Resource, err)
			}
			continue
		}

		warnings := fix.ValidateFix(suggestion)
		printFixSuggestion(suggestion, f.Severity, warnings)
	}
}

// generateFixesInteractive runs the same fix generation pipeline as generateFixes
// but then presents each result through an interactive approve/reject session
// that patches .tf files in place (--fix --apply mode).
func generateFixesInteractive(rc reviewConfig, findings []rules.Finding, resources []parser.NormalizedResource, rawPlan *parser.TerraformPlan, maxFix int) {
	if maxFix <= 0 {
		maxFix = 5
	}

	targets := make([]rules.Finding, 0, len(findings))
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
		targets = append(targets, f)
		if len(targets) == maxFix {
			break
		}
	}
	if len(targets) == 0 {
		return
	}

	resourceMap := make(map[string]parser.NormalizedResource, len(resources))
	for _, r := range resources {
		resourceMap[r.Address] = r
	}
	planIndex := fix.BuildIndex(rawPlan, resources)

	providerName := rc.aiProvider
	if providerName == "" {
		fmt.Printf("\n%s --fix --apply requires an AI provider. Configure one with: terraview provider list\n", output.Prefix())
		return
	}

	const perCallTimeout = 30
	const perFindingBudget = perCallTimeout*2 + 5

	providerCfg := ai.ProviderConfig{
		Model:       rc.aiModel,
		APIKey:      rc.aiAPIKey,
		BaseURL:     rc.aiURL,
		Temperature: 0.1,
		MaxTokens:   1024,
		MaxRetries:  1,
		TimeoutSecs: perCallTimeout,
	}

	globalCtx, cancel := context.WithTimeout(context.Background(), time.Duration(perFindingBudget*len(targets)+30)*time.Second)
	defer cancel()

	provider, err := ai.NewProvider(globalCtx, providerName, providerCfg)
	if err != nil {
		fmt.Printf("\n%s fix: AI provider unavailable: %v\n", output.Prefix(), err)
		return
	}

	suggester := fix.NewSuggester(provider)

	fmt.Printf("\n%s Generating %d fix suggestion(s)...\n", output.Prefix(), len(targets))

	// Phase 1: generate all suggestions upfront (batch, with progress).
	pending := make([]fix.PendingFix, 0, len(targets))
	for i, f := range targets {
		fmt.Printf("  [%d/%d] %s on %s... ", i+1, len(targets), f.RuleID, f.Resource)

		res, ok := resourceMap[f.Resource]
		resourceType := f.Resource
		if idx := strings.Index(f.Resource, "."); idx >= 0 {
			resourceType = f.Resource[:idx]
		}
		var resourceConfig map[string]interface{}
		if ok {
			resourceType = res.Type
			resourceConfig = res.Values
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

		suggestion, err := suggester.Suggest(findingCtx, req)
		findingCancel()

		if err != nil {
			if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline") {
				fmt.Printf("⏩ skipped (timeout)\n")
			} else {
				fmt.Printf("✗ %v\n", err)
			}
			continue
		}
		fmt.Printf("✓\n")

		// Locate the resource in .tf files for in-place patching.
		loc, _ := fix.FindResource(workDir, f.Resource)

		pending = append(pending, fix.PendingFix{
			Finding:    f,
			Suggestion: suggestion,
			Location:   loc,
			Warnings:   fix.ValidateFix(suggestion),
		})
	}

	if len(pending) == 0 {
		fmt.Printf("\n%s No fix suggestions could be generated.\n", output.Prefix())
		return
	}

	// Phase 2: interactive review session.
	session := fix.ApplySession{
		WorkDir: workDir,
		NoColor: noColor,
	}
	session.Review(pending)
}

// printFixSuggestion renders a single fix suggestion to stdout, including any
// validation warnings that indicate the fix may need manual review.
func printFixSuggestion(s *fix.FixSuggestion, severity string, warnings []fix.ValidationWarning) {
	fmt.Printf("\n  ▸ %s on %s [%s]\n", s.RuleID, s.Resource, severity)
	if s.Explanation != "" {
		fmt.Printf("    %s\n", s.Explanation)
	}
	fmt.Printf("    Effort: %s\n", s.Effort)

	if len(warnings) > 0 {
		fmt.Println()
		for _, w := range warnings {
			fmt.Printf("    ⚠  %s\n", w.Message)
		}
	}

	if s.HCL != "" {
		fmt.Println()
		for _, line := range strings.Split(s.HCL, "\n") {
			fmt.Printf("    %s\n", line)
		}
	}
	if len(s.Prerequisites) > 0 {
		fmt.Println()
		fmt.Println("    Prerequisites:")
		for _, p := range s.Prerequisites {
			fmt.Printf("      • %s\n", p)
		}
	}
}

// resolveReviewConfig loads config, resolves the plan file, and determines effective settings.
func resolveReviewConfig(scannerName string) (reviewConfig, error) {
	cfg, err := config.Load(workDir)
	if err != nil {
		return reviewConfig{}, fmt.Errorf("config error: %w", err)
	}
	logVerbose("Config loaded from %s", workDir)

	resolvedPlan := planFile
	if resolvedPlan == "" && findingsFile == "" {
		generated, _, err := generatePlan()
		if err != nil {
			return reviewConfig{}, err
		}
		resolvedPlan = generated
	}

	// Resolve effective AI config: CLI flags > config > defaults
	effectiveProvider := cfg.LLM.Provider
	if activeProvider != "" {
		effectiveProvider = activeProvider
	}
	effectiveModel := cfg.LLM.Model
	if activeModel != "" {
		effectiveModel = activeModel
	}
	effectiveURL := cfg.LLM.URL
	if effectiveProvider != "ollama" {
		effectiveURL = ""
	}

	// AI is ON by default unless --static is set.
	// Graceful degradation: if no provider is available, run scanner-only silently.
	effectiveAI := !staticOnly
	if effectiveAI {
		if !canResolveAIProvider(cfg) && activeProvider == "" && activeModel == "" {
			logVerbose("No AI provider configured — running in static mode (scanner only)")
			effectiveAI = false
		}
	}
	if explainFlag {
		effectiveAI = true
	}

	// Resolve output format: CLI flag > config > default
	effectiveFormat := output.FormatPretty
	if cfg.Output.Format != "" {
		effectiveFormat = cfg.Output.Format
	}
	if outputFormat != "" {
		effectiveFormat = outputFormat
	}

	resolvedOutput := outputDir
	if resolvedOutput == "" {
		if effectiveFormat == output.FormatHTML {
			resolvedOutput = "report"
		} else {
			resolvedOutput = workDir
		}
	}

	// Resolve suppress file: flag > default in workDir
	resolvedIgnoreFile := ignoreFile
	if resolvedIgnoreFile == "" {
		resolvedIgnoreFile = filepath.Join(workDir, suppression.DefaultIgnoreFile)
	}

	return reviewConfig{
		cfg:             cfg,
		scannerName:     scannerName,
		resolvedPlan:    resolvedPlan,
		resolvedOutput:  resolvedOutput,
		effectiveAI:     effectiveAI,
		effectiveFormat: effectiveFormat,
		ignoreFile:      resolvedIgnoreFile,
		aiProvider:      effectiveProvider,
		aiModel:         effectiveModel,
		aiURL:           effectiveURL,
		aiTimeout:       cfg.LLM.TimeoutSeconds,
		aiTemperature:   cfg.LLM.Temperature,
		aiAPIKey:        cfg.LLM.APIKey,
		aiMaxResources:  resolveMaxResources(maxResourcesFlag, cfg.LLM.MaxResources),
		aiNumCtx:        cfg.LLM.Ollama.NumCtx,
	}, nil
}

// resolveMaxResources returns the effective max-resources value: flag takes priority over config.
func resolveMaxResources(flagVal, cfgVal int) int {
	if flagVal > 0 {
		return flagVal
	}
	return cfgVal
}

// parsePlan reads and normalizes the Terraform plan, returning the raw plan,
// normalized resources, and the topology graph.
func parsePlan(planPath string) (*parser.TerraformPlan, []parser.NormalizedResource, *topology.Graph, error) {
	logVerbose("Parsing plan: %s", planPath)
	p := parser.NewParser()
	plan, err := p.ParseFile(planPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	logVerbose("Found %d resource changes", len(resources))

	topoGraph := topology.BuildGraph(resources)
	return plan, resources, topoGraph, nil
}

// runScanners executes the security scanner and AI context analysis in parallel.
// Both components degrade gracefully: partial failure produces a partial result with a warning.
func runScanners(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph) (scanResult, error) {
	type scannerOutput struct {
		findings   []rules.Finding
		result     *scanner.AggregatedResult
		err        error
		durationMs int64
	}
	type contextOutput struct {
		findings   []rules.Finding
		summary    string
		err        error
		durationMs int64
	}

	scannerCh := make(chan scannerOutput, 1)
	contextCh := make(chan contextOutput, 1)

	// Pipeline status (populated as components finish)
	ps := &aggregator.PipelineStatus{}

	// Scanner goroutine
	if rc.scannerName != "" {
		go func() {
			start := time.Now()
			resolvedScanner, err := scanner.Resolve(rc.scannerName)
			if err != nil {
				scannerCh <- scannerOutput{err: err, durationMs: time.Since(start).Milliseconds()}
				return
			}

			scanCtx := scanner.ScanContext{
				PlanPath:  rc.resolvedPlan,
				SourceDir: workDir,
				WorkDir:   workDir,
			}

			scanSpinner := output.NewSpinner(fmt.Sprintf("Running scanner: %s...", resolvedScanner.Name()))
			scanSpinner.Start()
			rawResults := scanner.RunAll([]scanner.Scanner{resolvedScanner}, scanCtx)
			aggResult := scanner.Aggregate(rawResults)
			scanSpinner.Stop(true)

			scannerCh <- scannerOutput{
				findings:   aggResult.Findings,
				result:     &aggResult,
				durationMs: time.Since(start).Milliseconds(),
			}
		}()
	} else {
		scannerCh <- scannerOutput{}
		logVerbose("No scanner specified, skipping security scan")
	}

	// AI Context Analysis goroutine (runs in parallel with scanner)
	if rc.effectiveAI {
		go func() {
			start := time.Now()
			ctxFindings, ctxSummary, ctxErr := runCodeContextAnalysis(
				resources, topoGraph,
				rc.aiProvider, rc.aiURL, rc.aiModel,
				rc.aiTimeout, rc.aiTemperature, rc.aiAPIKey,
				rc.aiMaxResources, rc.aiNumCtx, rc.cfg,
				rc.resolvedPlan, rc.scannerName)
			contextCh <- contextOutput{
				findings:   ctxFindings,
				summary:    ctxSummary,
				err:        ctxErr,
				durationMs: time.Since(start).Milliseconds(),
			}
		}()
	} else {
		contextCh <- contextOutput{}
		logVerbose("AI contextual analysis disabled (no provider configured or --static)")
	}

	// Collect scanner results (graceful degradation, non-fatal)
	scanOut := <-scannerCh
	var scannerStatus *aggregator.ComponentStatus
	if rc.scannerName != "" {
		scannerStatus = &aggregator.ComponentStatus{
			Tool:       rc.scannerName,
			DurationMs: scanOut.durationMs,
		}
		if scanOut.err != nil {
			scannerStatus.Status = "failed"
			scannerStatus.Error = scanOut.err.Error()
			fmt.Fprintf(os.Stderr, "%s ⚠ Scanner failed: %v. Showing AI results only (reduced confidence).\n",
				output.Prefix(), scanOut.err)
			logVerbose("Scanner failed (non-fatal): %v", scanOut.err)
		} else {
			scannerStatus.Status = "success"
			if scanOut.result != nil {
				if len(scanOut.result.ScannerStats) > 0 {
					scannerStatus.Version = scanOut.result.ScannerStats[0].Version
				}
				logVerbose("Scanner %s: %d findings (%d raw, %d after dedup)",
					rc.scannerName, len(scanOut.result.Findings), scanOut.result.TotalRaw, scanOut.result.TotalDeduped)
			}
		}
	}
	ps.Scanner = scannerStatus

	// Collect AI results (graceful degradation — errors are warnings)
	ctxOut := <-contextCh
	var contextFindings []rules.Finding
	var contextSummary string
	var aiStatus *aggregator.ComponentStatus
	if rc.effectiveAI {
		aiStatus = &aggregator.ComponentStatus{
			Provider:   rc.aiProvider,
			Model:      rc.aiModel,
			DurationMs: ctxOut.durationMs,
		}
		if ctxOut.err != nil {
			aiStatus.Status = "failed"
			aiStatus.Error = ctxOut.err.Error()
			fmt.Fprintf(os.Stderr, "%s ⚠ AI analysis failed: %v. Showing scanner results only.\n",
				output.Prefix(), ctxOut.err)
			logVerbose("AI analysis failed (non-fatal): %v", ctxOut.err)
		} else {
			aiStatus.Status = "success"
			contextFindings = ctxOut.findings
			contextSummary = ctxOut.summary
			if len(contextFindings) > 0 {
				logVerbose("AI context analysis: %d findings", len(contextFindings))
			}
		}
	}
	ps.AI = aiStatus

	// Determine result completeness
	scannerOK := scannerStatus == nil || scannerStatus.Status == "success"
	aiOK := aiStatus == nil || aiStatus.Status == "success"

	switch {
	case scannerOK && aiOK:
		ps.ResultCompleteness = "complete"
	case scannerOK && !aiOK:
		ps.ResultCompleteness = "partial_scanner_only"
	case !scannerOK && aiOK:
		ps.ResultCompleteness = "partial_ai_only"
	default:
		// Both failed → fatal error
		scanErr := ""
		aiErr := ""
		if scannerStatus != nil {
			scanErr = scannerStatus.Error
		}
		if aiStatus != nil {
			aiErr = aiStatus.Error
		}
		return scanResult{pipelineStatus: ps}, fmt.Errorf(
			"both scanner and AI failed.\n  Scanner: %s\n  AI: %s", scanErr, aiErr)
	}

	// If scanner was not requested, don't consider it a failure
	if rc.scannerName == "" {
		// No scanner → result depends only on AI
		if aiOK || aiStatus == nil {
			ps.ResultCompleteness = "complete"
		}
	}
	if !rc.effectiveAI {
		// No AI → result depends only on scanner
		if scannerOK {
			ps.ResultCompleteness = "complete"
		}
	}

	// Import external findings if specified
	hardFindings := scanOut.findings
	if findingsFile != "" {
		externalFindings, err := importer.Import(findingsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnImportFailed+"\n", output.Prefix(), findingsFile, err)
		} else {
			hardFindings = append(hardFindings, externalFindings...)
			logVerbose("Imported %d external findings from %s", len(externalFindings), findingsFile)
		}
	}

	return scanResult{
		hardFindings:    hardFindings,
		scannerResult:   scanOut.result,
		contextFindings: contextFindings,
		contextSummary:  contextSummary,
		pipelineStatus:  ps,
	}, nil
}

// mergeAndScore deduplicates findings, scores them, and enriches the result with optional analyses.
func mergeAndScore(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph, sr scanResult) aggregator.ReviewResult {
	hardFindings := sr.hardFindings

	// Validate AI findings against the topology graph (discard hallucinations)
	var aiValidationReport *aggregator.AIValidationReport
	validatedAIFindings := sr.contextFindings
	if len(sr.contextFindings) > 0 && topoGraph != nil {
		valid, discarded, report := validator.ValidateAIFindings(sr.contextFindings, topoGraph)
		validatedAIFindings = valid

		// Always build report for quality metrics (not only when discards > 0)
		aiReport := &aggregator.AIValidationReport{
			TotalReceived: report.TotalReceived,
			TotalValid:    report.TotalValid,
			TotalDiscard:  report.TotalDiscard,
		}
		if report.TotalDiscard > 0 {
			fmt.Fprintf(os.Stderr, "%s ⚠ Discarded %d AI findings (hallucinated/invalid)\n",
				output.Prefix(), report.TotalDiscard)
			for _, d := range discarded {
				logVerbose("  ✗ [%s] %s: %s — %s", d.Reason, d.Finding.Resource, d.Finding.Message, d.Detail)
				aiReport.Discarded = append(aiReport.Discarded, aggregator.AIDiscardedFinding{
					Resource: d.Finding.Resource,
					Message:  d.Finding.Message,
					Reason:   string(d.Reason),
					Detail:   d.Detail,
				})
			}
		}
		aiValidationReport = aiReport

		logVerbose("AI validation: %d received, %d valid, %d discarded",
			report.TotalReceived, report.TotalValid, report.TotalDiscard)
	}

	// Merge all findings: scanner + AI context (already validated)
	if len(hardFindings) > 0 || len(validatedAIFindings) > 0 {
		dr := normalizer.Deduplicate(hardFindings, validatedAIFindings)
		hardFindings = dr.Findings
		logVerbose("Dedup: %s", dr.Summary)

		// Attach incremental-value metrics to AI report
		if aiValidationReport != nil {
			aiValidationReport.AIUniqueKept = dr.AIUniqueKept
			aiValidationReport.AIEnriched = dr.AIEnriched
		}
	}

	// Aggregate (with configurable scoring weights)
	sw := rc.cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)
	result := agg.Aggregate(rc.resolvedPlan, len(resources), hardFindings, nil, sr.contextSummary, strict)

	// Attach pipeline status for observability
	result.PipelineStatus = sr.pipelineStatus

	// Attach AI validation report (findings discarded due to hallucination/invalidity)
	result.AIValidation = aiValidationReport

	// Score decomposition for audit (--explain-scores)
	if explainScoresFlag {
		decomp := scorer.Decompose(result.Findings, len(resources))
		result.ScoreDecomposition = &decomp
		logVerbose("Score decomposition computed for %d findings", len(result.Findings))
	}

	// Apply rule filtering from config
	if len(rc.cfg.Rules.DisabledRules) > 0 {
		result.Findings = filterDisabledRules(result.Findings, rc.cfg.Rules.DisabledRules)
		logVerbose("Filtered %d disabled rules from findings", len(rc.cfg.Rules.DisabledRules))
	}

	// Apply .terraview-ignore suppressions
	if ignoreData, err := suppression.Load(rc.ignoreFile); err != nil {
		fmt.Fprintf(os.Stderr, "%s ⚠ Could not load ignore file: %v\n", output.Prefix(), err)
	} else if len(ignoreData.Suppressions) > 0 {
		filtered, suppressedFindings := suppression.Apply(result.Findings, ignoreData)
		result.Findings = filtered
		if len(suppressedFindings) > 0 {
			fmt.Fprintf(os.Stderr, "%s ⊘ Suppressed %d finding(s) via %s\n",
				output.Prefix(), len(suppressedFindings), rc.ignoreFile)
			for _, s := range suppressedFindings {
				reason := s.Reason
				if reason == "" {
					reason = "no reason provided"
				}
				logVerbose("  ⊘ [%s] %s: %s", s.Finding.RuleID, s.Finding.Resource, reason)
			}
		}
	}

	// Meta-analysis: unified cross-tool scoring
	if len(result.Findings) > 0 {
		metaAnalyzer := meta.NewAnalyzer()
		metaResult := metaAnalyzer.Analyze(result.Findings)
		result.MetaAnalysis = metaResult
		logVerbose("Meta-analysis: %s", metaResult.Summary)
	}

	// Generate diagram if requested (deterministic, no AI)
	if diagramFlag {
		gen := diagram.NewGenerator()
		result.Diagram = gen.GenerateWithGraph(resources, topoGraph)
		logVerbose("Infrastructure diagram generated")
	}

	// Analyze impact if requested (deterministic, no AI)
	if impactFlag {
		analyzer := blast.NewAnalyzer()
		blastResult := analyzer.AnalyzeWithGraph(resources, topoGraph)
		result.BlastRadius = blastResult
		logVerbose("Impact analysis: %s", blastResult.Summary)
	}

	return result
}

// renderOutput writes all output files, prints the summary, and returns the exit code.
func renderOutput(rc reviewConfig, result aggregator.ReviewResult, scannerResult *scanner.AggregatedResult) (int, error) {
	langCode := ""
	if brFlag {
		langCode = "pt-BR"
	}
	writer := output.NewWriterWithConfig(output.WriterConfig{
		Format:        rc.effectiveFormat,
		Lang:          langCode,
		Version:       Version,
		ExplainScores: explainScoresFlag,
	})

	switch rc.effectiveFormat {
	case output.FormatHTML:
		if err := os.MkdirAll(rc.resolvedOutput, 0755); err != nil {
			return 0, fmt.Errorf("failed to create output directory: %w", err)
		}
		htmlPath := filepath.Join(rc.resolvedOutput, "review.html")
		if err := writer.WriteHTML(result, htmlPath); err != nil {
			return 0, fmt.Errorf("failed to write HTML: %w", err)
		}
		fmt.Printf("%s HTML report written: %s\n", output.Prefix(), htmlPath)

	case output.FormatJSON:
		jsonPath := filepath.Join(rc.resolvedOutput, "review.json")
		if err := writer.WriteJSON(result, jsonPath); err != nil {
			return 0, fmt.Errorf("failed to write JSON: %w", err)
		}
		logVerbose("Written: %s", jsonPath)

	case output.FormatSARIF:
		jsonPath := filepath.Join(rc.resolvedOutput, "review.json")
		if err := writer.WriteJSON(result, jsonPath); err != nil {
			return 0, fmt.Errorf("failed to write JSON: %w", err)
		}
		logVerbose("Written: %s", jsonPath)
		sarifPath := filepath.Join(rc.resolvedOutput, "review.sarif.json")
		if err := writer.WriteSARIF(result, sarifPath); err != nil {
			return 0, fmt.Errorf("failed to write SARIF: %w", err)
		}
		logVerbose("Written: %s", sarifPath)

	default: // pretty, compact
		jsonPath := filepath.Join(rc.resolvedOutput, "review.json")
		if err := writer.WriteJSON(result, jsonPath); err != nil {
			return 0, fmt.Errorf("failed to write JSON: %w", err)
		}
		logVerbose("Written: %s", jsonPath)
		mdPath := filepath.Join(rc.resolvedOutput, "review.md")
		if err := writer.WriteMarkdown(result, mdPath); err != nil {
			return 0, fmt.Errorf("failed to write Markdown: %w", err)
		}
		logVerbose("Written: %s", mdPath)
	}

	// Print summary
	writer.PrintSummary(result)

	// Print scanner stats if scanners were used
	if scannerResult != nil && rc.effectiveFormat != output.FormatJSON {
		if brFlag {
			fmt.Print(scanner.FormatScannerHeaderBR(*scannerResult))
		} else {
			fmt.Print(scanner.FormatScannerHeader(*scannerResult))
		}
	}

	// Print impact analysis if generated
	if impactFlag && result.BlastRadius != nil {
		fmt.Println()
		fmt.Print(result.BlastRadius.FormatPretty())
	}

	// Apply strict mode: HIGH becomes exit code 2
	exitCode := result.ExitCode
	if strict && exitCode == 1 {
		exitCode = 2
	}

	return exitCode, nil
}

// canResolveAIProvider checks if an AI provider can be resolved from config.
func canResolveAIProvider(cfg config.Config) bool {
	provider := cfg.LLM.Provider
	if provider == "" {
		return false
	}
	return ai.Has(provider)
}

// runCodeContextAnalysis runs AI-powered contextual analysis on resources and topology.
// This analyzes the CODE and RELATIONSHIPS, not scanner findings.
func runCodeContextAnalysis(
	resources []parser.NormalizedResource,
	graph *topology.Graph,
	providerName, url, model string,
	timeoutSecs int, temp float64,
	apiKey string, maxResources, numCtx int,
	cfg config.Config,
	planPath, scannerName string,
) ([]rules.Finding, string, error) {

	logVerbose("AI context analysis: %s (model: %s)", providerName, model)

	// Ollama lifecycle management
	limits := buildResourceLimits(cfg, false)
	var ollamaCleanup func()
	if providerName == "ollama" {
		lc := runtime.NewOllamaLifecycle(limits, url)
		bgCtx := context.Background()
		cleanup, err := lc.Ensure(bgCtx)
		if err != nil {
			return nil, "", fmt.Errorf("ollama unavailable: %w", err)
		}
		ollamaCleanup = cleanup
	}

	// Scale timeout with resource count: base + 3s per resource in the prompt.
	// Large plans through proxy providers (OpenRouter) need more time.
	effectiveResources := len(resources)
	if maxResources > 0 && effectiveResources > maxResources {
		effectiveResources = maxResources
	}
	scaledTimeout := timeoutSecs + effectiveResources*3 + util.ContextTimeoutGraceSecs
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scaledTimeout)*time.Second)
	defer cancel()
	logVerbose("AI timeout: %ds (base %d + %d resources × 3s + %ds grace)",
		scaledTimeout, timeoutSecs, effectiveResources, util.ContextTimeoutGraceSecs)

	// Start resource monitor for Ollama
	var monitor *runtime.Monitor
	if providerName == "ollama" {
		monitor = runtime.NewMonitor(limits, cancel)
		monitor.Start(ctx)
	}

	providerCfg := ai.ProviderConfig{
		Model:        model,
		APIKey:       apiKey,
		BaseURL:      url,
		Temperature:  temp,
		TimeoutSecs:  timeoutSecs,
		MaxTokens:    util.DefaultAnalyzeMaxTokens,
		MaxRetries:   2,
		MaxResources: maxResources,
		NumCtx:       numCtx,
	}

	provider, err := ai.NewProvider(ctx, providerName, providerCfg)
	if err != nil {
		if monitor != nil {
			monitor.Stop()
		}
		if ollamaCleanup != nil {
			ollamaCleanup()
		}
		return nil, "", fmt.Errorf("ai provider %s: %w", providerName, err)
	}

	lang := ""
	if brFlag {
		lang = "pt-BR"
	}

	// Load the context-analysis prompt from prompts directory (if available)
	contextPrompt := ""
	execPath, exErr := os.Executable()
	if exErr == nil {
		promptDir := filepath.Join(filepath.Dir(execPath), "prompts")
		if _, statErr := os.Stat(promptDir); statErr != nil {
			// Fallback: prompts next to working directory
			promptDir = filepath.Join(".", "prompts")
		}
		pl := ai.NewPromptLoader(promptDir)
		if prompts, loadErr := pl.Load(); loadErr == nil {
			contextPrompt = prompts.ContextAnalysis
		}
	}

	analyzer := contextanalysis.NewAnalyzer(provider, lang, contextPrompt, maxResources)

	// ── Sensitive data sanitization ─────────────────────────────────
	// Redact sensitive values (passwords, tokens, ARNs, PEM, etc.)
	// Ollama is local and does not need redaction by default.
	shouldRedact := cfg.LLM.Redact && !noRedactFlag
	if providerName == "ollama" && !cfg.LLM.Redact {
		shouldRedact = false
	}

	if shouldRedact {
		sess := sanitizer.NewSession()
		for i := range resources {
			resources[i].Values = sess.SanitizeMap(resources[i].Values, resources[i].Address+".values")
			if resources[i].BeforeValues != nil {
				resources[i].BeforeValues = sess.SanitizeMap(resources[i].BeforeValues, resources[i].Address+".before_values")
			}
		}
		manifest := sess.Manifest()
		if manifest.Count() > 0 {
			fmt.Fprintf(os.Stderr, "%s ⚠ Redacted %d sensitive values (%d unique) before sending to AI\n",
				output.Prefix(), manifest.Count(), manifest.UniqueCount())
			if cfg.LLM.RedactLog {
				for plac, paths := range manifest.Entries {
					logVerbose("  %s → %v", plac, paths)
				}
			}
		}
	} else {
		logVerbose("Sensitive data redaction disabled")
	}

	// Build cache key based on SHA-256 hash of plan content
	var diskCache *aicache.DiskCache
	var planHash string
	if cfg.LLM.Cache {
		rawPlan, readErr := os.ReadFile(planPath)
		if readErr != nil {
			logVerbose("cache: failed to read plan %s: %v", planPath, readErr)
		} else {
			planHash = aicache.PlanHash(rawPlan)
		}
		ttl := cfg.LLM.CacheTTLHours
		if ttl <= 0 {
			ttl = 24
		}
		diskCache = aicache.NewDiskCache(aicache.DiskCacheDir(), providerName, model, scannerName, ttl)

		if planHash != "" {
			if cached, ok := diskCache.Get(planHash); ok {
				logVerbose("cache hit for AI context analysis (%s/%s, hash=%s)", providerName, model, planHash[:12])
				// Clean up before returning
				if monitor != nil {
					monitor.Stop()
				}
				if ollamaCleanup != nil {
					ollamaCleanup()
				}
				var cachedResult cachedAnalysis
				if err := json.Unmarshal([]byte(cached), &cachedResult); err == nil {
					return cachedResult.Findings, cachedResult.Summary, nil
				}
			}
		}
	}

	displayModel := model
	if providerName != "" && !strings.Contains(model, "/") {
		displayModel = providerName + "/" + model
	}
	aiSpinner := output.NewSpinner(fmt.Sprintf("AI context analysis (%s)...", displayModel))
	aiSpinner.Start()
	result, err := analyzer.Analyze(ctx, resources, graph)
	aiSpinner.Stop(err == nil)

	// Cleanup
	if monitor != nil {
		monitor.Stop()
	}
	if ollamaCleanup != nil {
		ollamaCleanup()
	}

	if err != nil {
		return nil, "", err
	}

	// Store result in disk cache
	if diskCache != nil && planHash != "" {
		cached := cachedAnalysis{Findings: result.Findings, Summary: result.Summary}
		if data, err := json.Marshal(cached); err == nil {
			diskCache.Put(planHash, string(data))
			logVerbose("AI analysis result cached (%s/%s, hash=%s)", providerName, model, planHash[:12])
		}
	}

	if result.ExcludedNoOp > 0 {
		logVerbose("AI context: %d no-op/read resources excluded from analysis", result.ExcludedNoOp)
	}
	logVerbose("AI context (%s/%s): %d findings", providerName, model, len(result.Findings))
	return result.Findings, result.Summary, nil
}

// buildResourceLimits constructs runtime limits from config and safe mode.
func buildResourceLimits(cfg config.Config, safe bool) runtime.ResourceLimits {
	if safe {
		return runtime.SafeResourceLimits()
	}

	limits := runtime.DefaultResourceLimits()

	if cfg.LLM.Ollama.MaxThreads > 0 {
		limits.MaxThreads = cfg.LLM.Ollama.MaxThreads
	}
	if cfg.LLM.Ollama.MaxMemoryMB > 0 {
		limits.MaxMemoryMB = cfg.LLM.Ollama.MaxMemoryMB
	}
	if cfg.LLM.Ollama.MinFreeMemoryMB > 0 {
		limits.MinFreeMemoryMB = cfg.LLM.Ollama.MinFreeMemoryMB
	}

	return limits
}

// filterDisabledRules removes findings whose RuleID matches any disabled rule pattern.
// Supports exact match and prefix match (e.g., "CKV_AWS" disables all Checkov AWS rules).
func filterDisabledRules(findings []rules.Finding, disabled []string) []rules.Finding {
	if len(disabled) == 0 {
		return findings
	}

	disabledSet := make(map[string]bool, len(disabled))
	var prefixes []string
	for _, r := range disabled {
		upper := strings.ToUpper(strings.TrimSpace(r))
		disabledSet[upper] = true
		// Treat entries without underscored suffixes as prefixes
		if !strings.Contains(upper, "_") || strings.HasSuffix(upper, "_") {
			prefixes = append(prefixes, upper)
		}
	}

	filtered := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		id := strings.ToUpper(f.RuleID)
		if disabledSet[id] {
			continue
		}
		skip := false
		for _, prefix := range prefixes {
			if strings.HasPrefix(id, prefix) {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// recordToHistory stores the scan result in the local history database.
// Fail-safe: any error is logged to stderr and silently ignored.
func recordToHistory(rc reviewConfig, result aggregator.ReviewResult) {
	if !rc.cfg.History.Enabled {
		return
	}

	store, err := history.NewStore(history.DefaultDBPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "[history] %v\n", err)
		return
	}
	defer store.Close()

	rec := history.NewRecordFromResult(
		result,
		resolveProjectDir(),
		rc.scannerName,
		rc.aiProvider,
		rc.aiModel,
		0, // duration_ms: populated per-pipeline if needed
		staticOnly,
	)

	if _, err := store.Insert(rec); err != nil {
		fmt.Fprintf(os.Stderr, "[history] %v\n", err)
		return
	}

	// Auto-cleanup if enabled
	if rc.cfg.History.AutoCleanup {
		cleanupCfg := history.CleanupConfig{
			RetentionDays: rc.cfg.History.RetentionDays,
			MaxSizeMB:     rc.cfg.History.MaxSizeMB,
		}
		if removed, err := store.Cleanup(cleanupCfg); err != nil {
			fmt.Fprintf(os.Stderr, "[history] cleanup: %v\n", err)
		} else if removed > 0 {
			logVerbose("History cleanup: removed %d old records", removed)
		}
	}
}
