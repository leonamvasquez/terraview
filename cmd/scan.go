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
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/util"
)

var (
	// Scan-local flags
	staticOnly       bool // --static: disable AI contextual analysis
	strict           bool
	explainFlag      bool
	diagramFlag      bool
	impactFlag       bool
	explainScoresFlag bool // --explain-scores: mostra decomposição do scoring
	findingsFile     string
	allFlag          bool
	noRedactFlag     bool // --no-redact: desabilita redação de dados sensíveis
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

	// If no scanner specified, try auto-select
	if scannerName == "" {
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
}

// executeReview runs the full review pipeline and returns the plan path, exit code, and any error.
// Pipeline: Parse → [Scanner ‖ AI Context] → Merge → Score → Output
func executeReview(scannerName string) (string, int, error) { //nolint:unparam // planPath used by apply command
	rc, err := resolveReviewConfig(scannerName)
	if err != nil {
		return "", 0, err
	}

	resources, topoGraph, err := parsePlan(rc.resolvedPlan)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	sr, err := runScanners(rc, resources, topoGraph)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	result := mergeAndScore(rc, resources, topoGraph, sr)

	exitCode, err := renderOutput(rc, result, sr.scannerResult)
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	return rc.resolvedPlan, exitCode, nil
}

// resolveReviewConfig loads config, resolves the plan file, and determines effective settings.
func resolveReviewConfig(scannerName string) (reviewConfig, error) {
	cfg, err := config.Load(workDir)
	if err != nil {
		return reviewConfig{}, fmt.Errorf("config error: %w", err)
	}
	logVerbose("Config loaded from %s", workDir)

	resolvedPlan := planFile
	if resolvedPlan == "" {
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
		resolvedOutput = workDir
	}

	return reviewConfig{
		cfg:             cfg,
		scannerName:     scannerName,
		resolvedPlan:    resolvedPlan,
		resolvedOutput:  resolvedOutput,
		effectiveAI:     effectiveAI,
		effectiveFormat: effectiveFormat,
		aiProvider:      effectiveProvider,
		aiModel:         effectiveModel,
		aiURL:           effectiveURL,
		aiTimeout:       cfg.LLM.TimeoutSeconds,
		aiTemperature:   cfg.LLM.Temperature,
		aiAPIKey:        cfg.LLM.APIKey,
		aiMaxResources:  cfg.LLM.MaxResources,
		aiNumCtx:        cfg.LLM.Ollama.NumCtx,
	}, nil
}

// parsePlan reads and normalizes the Terraform plan, returning resources and the topology graph.
func parsePlan(planPath string) ([]parser.NormalizedResource, *topology.Graph, error) {
	logVerbose("Parsing plan: %s", planPath)
	p := parser.NewParser()
	plan, err := p.ParseFile(planPath)
	if err != nil {
		return nil, nil, fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	logVerbose("Found %d resource changes", len(resources))

	topoGraph := topology.BuildGraph(resources)
	return resources, topoGraph, nil
}

// runScanners executes the security scanner and AI context analysis in parallel.
func runScanners(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph) (scanResult, error) {
	type scannerOutput struct {
		findings []rules.Finding
		result   *scanner.AggregatedResult
		err      error
	}
	type contextOutput struct {
		findings []rules.Finding
		summary  string
		err      error
	}

	scannerCh := make(chan scannerOutput, 1)
	contextCh := make(chan contextOutput, 1)

	// Scanner goroutine
	if rc.scannerName != "" {
		go func() {
			resolvedScanner, err := scanner.Resolve(rc.scannerName)
			if err != nil {
				scannerCh <- scannerOutput{err: err}
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

			scannerCh <- scannerOutput{findings: aggResult.Findings, result: &aggResult}
		}()
	} else {
		scannerCh <- scannerOutput{}
		logVerbose("No scanner specified, skipping security scan")
	}

	// AI Context Analysis goroutine (runs in parallel with scanner)
	if rc.effectiveAI {
		go func() {
			ctxFindings, ctxSummary, ctxErr := runCodeContextAnalysis(
				resources, topoGraph,
				rc.aiProvider, rc.aiURL, rc.aiModel,
				rc.aiTimeout, rc.aiTemperature, rc.aiAPIKey,
				rc.aiMaxResources, rc.aiNumCtx, rc.cfg)
			contextCh <- contextOutput{findings: ctxFindings, summary: ctxSummary, err: ctxErr}
		}()
	} else {
		contextCh <- contextOutput{}
		logVerbose("AI contextual analysis disabled (no provider configured or --static)")
	}

	// Collect scanner results
	scanOut := <-scannerCh
	if scanOut.err != nil {
		return scanResult{}, fmt.Errorf("scanner error: %w", scanOut.err)
	}
	if scanOut.result != nil {
		logVerbose("Scanner %s: %d findings (%d raw, %d after dedup)",
			rc.scannerName, len(scanOut.result.Findings), scanOut.result.TotalRaw, scanOut.result.TotalDeduped)
	}

	// Collect AI context results (graceful: errors are warnings, not fatal)
	ctxOut := <-contextCh
	var contextFindings []rules.Finding
	var contextSummary string
	if ctxOut.err != nil {
		fmt.Fprintf(os.Stderr, "%s AI context analysis warning: %v\n", output.Prefix(), ctxOut.err)
		logVerbose("AI context analysis failed (non-fatal): %v", ctxOut.err)
	} else {
		contextFindings = ctxOut.findings
		contextSummary = ctxOut.summary
		if len(contextFindings) > 0 {
			logVerbose("AI context analysis: %d findings", len(contextFindings))
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
	}, nil
}

// mergeAndScore deduplicates findings, scores them, and enriches the result with optional analyses.
func mergeAndScore(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph, sr scanResult) aggregator.ReviewResult {
	hardFindings := sr.hardFindings

	// Merge all findings: scanner + AI context
	if len(hardFindings) > 0 || len(sr.contextFindings) > 0 {
		dr := normalizer.Deduplicate(hardFindings, sr.contextFindings)
		hardFindings = dr.Findings
		logVerbose("Dedup: %s", dr.Summary)
	}

	// Aggregate (with configurable scoring weights)
	sw := rc.cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)
	result := agg.Aggregate(rc.resolvedPlan, len(resources), hardFindings, nil, sr.contextSummary, strict)

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

	jsonPath := filepath.Join(rc.resolvedOutput, "review.json")
	if err := writer.WriteJSON(result, jsonPath); err != nil {
		return 0, fmt.Errorf("failed to write JSON: %w", err)
	}
	logVerbose("Written: %s", jsonPath)

	if rc.effectiveFormat == output.FormatSARIF {
		sarifPath := filepath.Join(rc.resolvedOutput, "review.sarif.json")
		if err := writer.WriteSARIF(result, sarifPath); err != nil {
			return 0, fmt.Errorf("failed to write SARIF: %w", err)
		}
		logVerbose("Written: %s", sarifPath)
	}

	if rc.effectiveFormat != output.FormatJSON && rc.effectiveFormat != output.FormatSARIF {
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

	analyzer := contextanalysis.NewAnalyzer(provider, lang, contextPrompt)

	// ── Sanitização de dados sensíveis ─────────────────────────────────
	// Redatar valores sensíveis (passwords, tokens, ARNs, PEM, etc.)
	// antes de enviar os recursos ao provedor de IA.
	// Ollama é local e não precisa de redação por padrão.
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
			fmt.Fprintf(os.Stderr, "%s ⚠ Redatados %d valores sensíveis (%d únicos) antes do envio à IA\n",
				output.Prefix(), manifest.Count(), manifest.UniqueCount())
			if cfg.LLM.RedactLog {
				for plac, paths := range manifest.Entries {
					logVerbose("  %s → %v", plac, paths)
				}
			}
		}
	} else {
		logVerbose("Redação de dados sensíveis desabilitada")
	}

	// Build cache key from resource data + provider + model
	var diskCache *aicache.DiskCache
	var cacheKey string
	if cfg.LLM.Cache {
		resourcesJSON, _ := json.Marshal(resources)
		cacheKey = aicache.AnalysisKey(resourcesJSON, providerName, model)
		ttl := cfg.LLM.CacheTTLHours
		if ttl <= 0 {
			ttl = 24
		}
		diskCache = aicache.NewDiskCache(aicache.DiskCachePath(), providerName, model, ttl)

		if cached, ok := diskCache.Get(cacheKey); ok {
			logVerbose("cache hit for AI context analysis (%s/%s)", providerName, model)
			// Cleanup before returning
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
	if diskCache != nil {
		cached := cachedAnalysis{Findings: result.Findings, Summary: result.Summary}
		if data, err := json.Marshal(cached); err == nil {
			diskCache.Put(cacheKey, string(data))
			logVerbose("cached AI context analysis result (%s/%s)", providerName, model)
		}
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
