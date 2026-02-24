package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/cluster"
	"github.com/leonamvasquez/terraview/internal/clusterai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/diagram"
	"github.com/leonamvasquez/terraview/internal/explain"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/importer"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/normalizer"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/runtime"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var (
	// Scan-local flags
	aiEnabled    bool
	strict       bool
	explainFlag  bool
	diagramFlag  bool
	impactFlag   bool
	findingsFile string
	allFlag      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [scanner]",
	Short: "Security scan and optional AI analysis of a Terraform plan",
	Long: `Analyzes a Terraform plan using a security scanner and/or AI review.

The scanner is specified as a positional argument.
If --plan is not specified, terraview will automatically run:
  terraform init   (if needed)
  terraform plan   (generates plan)
  terraform show   (exports JSON)

Examples:
  terraview scan checkov                       # security scanner only
  terraview scan checkov --ai                  # scanner + AI analysis
  terraview scan --ai                          # AI-only analysis (no scanner)
  terraview scan checkov --all                 # everything enabled
  terraview scan checkov --ai --provider gemini  # Gemini AI
  terraview scan checkov --explain             # scanner + AI explanation
  terraview scan checkov --diagram             # scanner + diagram
  terraview scan checkov --impact              # impact analysis
  terraview scan checkov --format compact      # minimal output
  terraview scan checkov --format sarif        # SARIF for CI
  terraview scan checkov --strict              # HIGH returns exit code 2
  terraview scan checkov --findings ext.json   # import external findings`,
	Args: cobra.MaximumNArgs(1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered semantic review")
	scanCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	scanCmd.Flags().BoolVar(&explainFlag, "explain", false, "Generate AI-powered natural language explanation (implies --ai)")
	scanCmd.Flags().BoolVar(&diagramFlag, "diagram", false, "Show ASCII infrastructure diagram")
	scanCmd.Flags().BoolVar(&impactFlag, "impact", false, "Analyze dependency impact of changes")
	scanCmd.Flags().StringVar(&findingsFile, "findings", "", "Import external findings from Checkov/tfsec/Trivy JSON")
	scanCmd.Flags().BoolVar(&allFlag, "all", false, "Enable all features: explain + diagram + impact")
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
		aiEnabled = true
	}

	// If no scanner specified, try auto-select
	if scannerName == "" {
		// Load config to check for default scanner
		cfg, _ := config.Load(workDir)
		resolved, _ := scanner.ResolveDefault(cfg.Scanner.Default)
		if resolved != nil {
			scannerName = resolved.Name()
			logVerbose("Auto-selected scanner: %s", scannerName)
		}
	}

	// Validate: must specify a scanner or --ai (or both)
	if scannerName == "" && !aiEnabled && !explainFlag && !diagramFlag && findingsFile == "" {
		// Show helpful error with installed scanners
		avail := scanner.DefaultManager.Available()
		if len(avail) == 0 {
			return fmt.Errorf("no scanners installed.\n\nInstall a scanner first:\n  terraview scanners install checkov\n  terraview scanners install tfsec\n  terraview scanners install terrascan\n  terraview scanners install --all\n\nOr use AI-only mode:\n  terraview scan --ai")
		}
		names := make([]string, 0, len(avail))
		for _, s := range avail {
			names = append(names, s.Name())
		}
		return fmt.Errorf("specify a scanner or --ai\n\nInstalled scanners:\n  %s\n\nUsage:\n  terraview scan %s          # security scanner\n  terraview scan %s --ai     # scanner + AI\n  terraview scan --ai             # AI-only\n\nSet a default: terraview scanners default %s",
			strings.Join(names, "\n  "), names[0], names[0], names[0])
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

// executeReview runs the full review pipeline and returns the plan path, exit code, and any error.
func executeReview(scannerName string) (string, int, error) {
	// Load workspace config (.terraview.yaml)
	cfg, err := config.Load(workDir)
	if err != nil {
		return "", 0, fmt.Errorf("config error: %w", err)
	}
	logVerbose("Config loaded from %s", workDir)

	resolvedPlan := planFile

	// If no plan provided, auto-generate from terraform
	if resolvedPlan == "" {
		if err := workspace.Validate(workDir); err != nil {
			return "", 0, err
		}

		executor, err := terraformexec.NewExecutor(workDir)
		if err != nil {
			return "", 0, err
		}

		if executor.NeedsInit() {
			if err := executor.Init(); err != nil {
				return "", 0, err
			}
		}

		generatedPlan, err := executor.Plan()
		if err != nil {
			return "", 0, err
		}
		resolvedPlan = generatedPlan
	}

	// Resolve effective AI config: CLI flags > safe mode > config > defaults
	effectiveProvider := cfg.LLM.Provider
	if aiProvider != "" {
		effectiveProvider = aiProvider
	}
	effectiveModel := cfg.LLM.Model
	if ollamaModel != "" {
		effectiveModel = ollamaModel
	}
	effectiveURL := cfg.LLM.URL
	// When the provider is not ollama, clear the URL so each provider
	// falls back to its own default base URL.
	if effectiveProvider != "ollama" {
		effectiveURL = ""
	}
	effectiveTimeout := cfg.LLM.TimeoutSeconds
	effectiveTemperature := cfg.LLM.Temperature
	// --provider or --model implies --ai
	effectiveAI := aiEnabled || aiProvider != "" || ollamaModel != "" || explainFlag

	// If AI is configured but not active, show info
	if cfg.LLM.Enabled && !effectiveAI {
		logVerbose("AI is configured but not active. Use --ai to enable.")
	}

	// Resolve output format: CLI flag > config > default
	effectiveFormat := output.FormatPretty
	if cfg.Output.Format != "" {
		effectiveFormat = cfg.Output.Format
	}
	if outputFormat != "" {
		effectiveFormat = outputFormat
	}

	// Resolve output directory
	resolvedOutput := outputDir
	if resolvedOutput == "" {
		resolvedOutput = workDir
	}

	// --- Pipeline ---

	// 1. Parse
	logVerbose("Parsing plan: %s", resolvedPlan)
	p := parser.NewParser()
	plan, err := p.ParseFile(resolvedPlan)
	if err != nil {
		return resolvedPlan, 0, fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	summary := p.ExtractResourceSummary(resources)
	logVerbose("Found %d resource changes", len(resources))

	// 2. Scanner-based analysis (primary detection engine)
	var hardFindings []rules.Finding
	var scannerResult *scanner.AggregatedResult

	if scannerName != "" {
		// Run the specified scanner
		resolvedScanner, err := scanner.Resolve(scannerName)
		if err != nil {
			return resolvedPlan, 0, fmt.Errorf("scanner error: %w", err)
		}

		scanCtx := scanner.ScanContext{
			PlanPath:  resolvedPlan,
			SourceDir: workDir,
			WorkDir:   workDir,
		}

		scanSpinner := output.NewSpinner(fmt.Sprintf("Running scanner: %s...", resolvedScanner.Name()))
		scanSpinner.Start()
		rawResults := scanner.RunAll([]scanner.Scanner{resolvedScanner}, scanCtx)
		aggResult := scanner.Aggregate(rawResults)
		scanSpinner.Stop(true)

		scannerResult = &aggResult

		hardFindings = append(hardFindings, aggResult.Findings...)
		logVerbose("Scanner %s: %d findings (%d raw, %d after dedup)",
			resolvedScanner.Name(), len(aggResult.Findings), aggResult.TotalRaw, aggResult.TotalDeduped)
	} else {
		logVerbose("No scanner specified, skipping security scan")
	}

	// 2b. Import external findings if specified (backward compat)
	if findingsFile != "" {
		externalFindings, err := importer.Import(findingsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnImportFailed+"\n", output.Prefix(), findingsFile, err)
		} else {
			hardFindings = append(hardFindings, externalFindings...)
			logVerbose("Imported %d external findings from %s", len(externalFindings), findingsFile)
		}
	}

	// 3. AI review (optional) with lifecycle management
	var aiFindings []rules.Finding
	var aiSummary string
	var clusterCache *clusterai.ClusterCache

	// Build topology graph (used for AI context and other features)
	topoGraph := topology.BuildGraph(resources)

	// 3a. Risk clustering: group scanner findings BEFORE AI to enable cluster-level invocation
	var clusterResult *cluster.ClusterResult
	if len(hardFindings) > 0 {
		builder := cluster.NewBuilder()
		clusterResult = builder.Build(hardFindings)
		if clusterResult.HighRiskClusters > 0 {
			logVerbose("Risk clusters: %d total, %d high-risk", len(clusterResult.Clusters), clusterResult.HighRiskClusters)
		}
	}

	if effectiveAI {
		// Build resource limits from config
		limits := buildResourceLimits(cfg, false)

		// Inject topology context into summary for AI
		topoSummary := make(map[string]interface{})
		for k, v := range summary {
			topoSummary[k] = v
		}
		topoSummary["topology_context"] = topoGraph.FormatContext()
		topoSummary["topology_layers"] = topoGraph.Layers()

		// Cluster-level adaptive AI invocation
		if clusterResult != nil && len(clusterResult.Clusters) > 0 {
			aiFindings, aiSummary, clusterCache = runClusterAIReview(
				clusterResult.Clusters, effectiveProvider, effectiveURL,
				effectiveModel, effectiveTimeout, effectiveTemperature,
				cfg.LLM.APIKey, limits)
		} else {
			logVerbose("No clusters for AI analysis — skipping cluster-level AI")
		}
	} else {
		logVerbose("%s", i18n.T().AISkipped)
	}

	// 3b. (second-opinion removed)
	// 3c. Deduplicate: merge scanner + AI findings (replaces normalizer + resolver)
	if effectiveAI && (len(hardFindings) > 0 || len(aiFindings) > 0) {
		dr := normalizer.Deduplicate(hardFindings, aiFindings)
		hardFindings = dr.Findings
		aiFindings = nil // absorbed into hardFindings via dedup
		aiSummary = ""
		logVerbose("Dedup: %s", dr.Summary)
	}

	// 4. Aggregate (with configurable scoring weights)
	sw := cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)
	result := agg.Aggregate(resolvedPlan, len(resources), hardFindings, aiFindings, aiSummary, strict)

	// 4a. Apply rule filtering from config
	if len(cfg.Rules.DisabledRules) > 0 {
		result.Findings = filterDisabledRules(result.Findings, cfg.Rules.DisabledRules)
		logVerbose("Filtered %d disabled rules from findings", len(cfg.Rules.DisabledRules))
	}

	// 4b2. Meta-analysis: unified cross-tool scoring
	if len(result.Findings) > 0 {
		metaAnalyzer := meta.NewAnalyzer()
		metaResult := metaAnalyzer.Analyze(result.Findings)
		result.MetaAnalysis = metaResult
		logVerbose("Meta-analysis: %s", metaResult.Summary)
	}

	// 4c. Generate diagram if requested (deterministic, no AI)
	if diagramFlag {
		gen := diagram.NewGenerator()
		result.Diagram = gen.GenerateWithGraph(resources, topoGraph)
		logVerbose("Infrastructure diagram generated")
	}

	// 4d. Analyze impact if requested (deterministic, no AI)
	if impactFlag {
		analyzer := blast.NewAnalyzer()
		blastResult := analyzer.AnalyzeWithGraph(resources, topoGraph)
		result.BlastRadius = blastResult
		logVerbose("Impact analysis: %s", blastResult.Summary)
	}

	// 4e. Generate AI explanation if requested (reuses cluster cache — NO additional AI invocation)
	if explainFlag && effectiveAI {
		if clusterCache != nil {
			explainSummary := clusterai.GenerateExplainSummary(clusterCache)
			if explainSummary != "" {
				result.Explanation = &explain.Explanation{
					Summary:   explainSummary,
					RiskLevel: "INFO",
				}
				logVerbose("Explanation generated from cluster cache (no additional AI calls)")
			}
		} else {
			logVerbose("No cluster cache available for --explain")
		}
	}

	// 5. Output
	langCode := ""
	if brFlag {
		langCode = "pt-BR"
	}
	writer := output.NewWriterWithConfig(output.WriterConfig{
		Format: effectiveFormat,
		Lang:   langCode,
	})

	jsonPath := filepath.Join(resolvedOutput, "review.json")
	if err := writer.WriteJSON(result, jsonPath); err != nil {
		return resolvedPlan, 0, fmt.Errorf("failed to write JSON: %w", err)
	}
	logVerbose("Written: %s", jsonPath)

	if effectiveFormat == output.FormatSARIF {
		sarifPath := filepath.Join(resolvedOutput, "review.sarif.json")
		if err := writer.WriteSARIF(result, sarifPath); err != nil {
			return resolvedPlan, 0, fmt.Errorf("failed to write SARIF: %w", err)
		}
		logVerbose("Written: %s", sarifPath)
	}

	if effectiveFormat != output.FormatJSON && effectiveFormat != output.FormatSARIF {
		mdPath := filepath.Join(resolvedOutput, "review.md")
		if err := writer.WriteMarkdown(result, mdPath); err != nil {
			return resolvedPlan, 0, fmt.Errorf("failed to write Markdown: %w", err)
		}
		logVerbose("Written: %s", mdPath)
	}

	// 6. Print summary
	writer.PrintSummary(result)

	// 6a. Print scanner stats if scanners were used
	if scannerResult != nil && effectiveFormat != output.FormatJSON {
		if brFlag {
			fmt.Print(scanner.FormatScannerHeaderBR(*scannerResult))
		} else {
			fmt.Print(scanner.FormatScannerHeader(*scannerResult))
		}
	}

	// (conflict resolution section removed — dedup summary is logged inline)

	// 6c. Print risk clusters if available
	if clusterResult != nil && clusterResult.HighRiskClusters > 0 && effectiveFormat != output.FormatJSON {
		fmt.Println()
		fmt.Print(cluster.FormatClusters(clusterResult))
	}

	// 6d. Print impact analysis if generated
	if impactFlag && result.BlastRadius != nil {
		if br, ok := result.BlastRadius.(*blast.BlastResult); ok {
			fmt.Println()
			fmt.Print(br.FormatPretty())
		}
	}

	// 7. Apply strict mode: HIGH becomes exit code 2
	exitCode := result.ExitCode
	if strict && exitCode == 1 {
		exitCode = 2
	}

	return resolvedPlan, exitCode, nil
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

// runClusterAIReview runs cluster-level adaptive AI invocation.
// Instead of running AI per-resource, groups findings into clusters and runs
// AI per-cluster with adaptive depth (enrichment_only, full_analysis, or skip).
// Returns findings, summary, and the cluster cache for --explain reuse.
func runClusterAIReview(clusters []cluster.RiskCluster,
	providerName, url, model string, timeoutSecs int, temp float64,
	apiKey string, limits runtime.ResourceLimits) ([]rules.Finding, string, *clusterai.ClusterCache) {

	logVerbose("AI provider: %s (model: %s) — cluster-level invocation", providerName, model)

	// Ollama lifecycle management: auto-start and auto-stop
	var ollamaCleanup func()
	if providerName == "ollama" {
		lc := runtime.NewOllamaLifecycle(limits, url)
		bgCtx := context.Background()
		cleanup, err := lc.Ensure(bgCtx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnOllamaUnavail+"\n", output.Prefix(), err)
			return nil, "", nil
		}
		ollamaCleanup = cleanup
	}

	// Create cancellable context for AI execution
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs+30)*time.Second)
	defer cancel()

	// Start resource monitor for Ollama
	var monitor *runtime.Monitor
	if providerName == "ollama" {
		monitor = runtime.NewMonitor(limits, cancel)
		monitor.Start(ctx)
	}

	// Create provider
	providerCfg := ai.ProviderConfig{
		Model:       model,
		APIKey:      apiKey,
		BaseURL:     url,
		Temperature: temp,
		TimeoutSecs: timeoutSecs,
		MaxTokens:   4096,
		MaxRetries:  2,
	}

	provider, err := ai.NewProvider(ctx, providerName, providerCfg)
	if err != nil {
		if monitor != nil {
			monitor.Stop()
		}
		if ollamaCleanup != nil {
			ollamaCleanup()
		}
		fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnAIProviderFailed+"\n", output.Prefix(), providerName, err)
		return nil, "", nil
	}

	// Cluster-level adaptive AI controller
	cache := clusterai.NewClusterCache()
	workers := 4
	if len(clusters) < 4 {
		workers = len(clusters)
	}
	ctrl := clusterai.NewController(provider, cache, workers)

	// Set language if pt-BR
	if brFlag {
		ctrl.SetLang("pt-BR")
	}

	logVerbose("Cluster AI: %d clusters → adaptive invocation (workers=%d)", len(clusters), workers)

	// Run cluster-level AI analysis
	aiSpinner := output.NewSpinner(fmt.Sprintf("AI analyzing %d clusters (%s/%s)...", len(clusters), providerName, model))
	aiSpinner.Start()
	results, stats := ctrl.Run(ctx, clusters)
	aiSpinner.Stop(stats.Errors == 0)

	// Stop monitor and cleanup Ollama process
	if monitor != nil {
		monitor.Stop()
	}
	if ollamaCleanup != nil {
		ollamaCleanup()
	}

	logVerbose("Cluster AI stats: total=%d skipped=%d enriched=%d full=%d cached=%d errors=%d",
		stats.TotalClusters, stats.Skipped, stats.Enriched, stats.FullAnalysis, stats.CacheHits, stats.Errors)

	// Convert cluster results to standard findings
	findings := clusterai.ToFindings(results, clusters, providerName)

	// Build summary from cluster stats
	aiSummary := fmt.Sprintf("Cluster-level AI: %d clusters (%d enriched, %d full, %d skipped, %d cached)",
		stats.TotalClusters, stats.Enriched, stats.FullAnalysis, stats.Skipped, stats.CacheHits)

	logVerbose("AI (%s/%s): %d cluster findings", providerName, model, len(findings))
	return findings, aiSummary, cache
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
