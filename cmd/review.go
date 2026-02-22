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
	"github.com/leonamvasquez/terraview/internal/secondopinion"
	"github.com/leonamvasquez/terraview/internal/smell"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/trend"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var (
	planFile          string
	promptDir         string
	outputDir         string
	ollamaURL         string
	ollamaModel       string
	aiProvider        string
	timeout           int
	temperature       float64
	aiEnabled         bool
	outputFormat      string
	strict            bool
	safeMode          bool
	explainFlag       bool
	diagramFlag       bool
	blastRadiusFlag   bool
	findingsFile      string
	secondOpinionFlag bool
	trendFlag         bool
	smellFlag         bool
	scannerFlag       string
)

var planCmd = &cobra.Command{
	Use:     "plan",
	Aliases: []string{"review"},
	Short:   "Analyze a Terraform plan for security, architecture, and best practices",
	Long: `Analyzes a Terraform plan using a security scanner and optional AI review.

A scanner must be explicitly specified via --scanner.
If --plan is not specified, terraview will automatically run:
  terraform init   (if needed)
  terraform plan   (generates plan)
  terraform show   (exports JSON)

Examples:
  terraview plan --scanner checkov            # use checkov
  terraview plan --scanner tfsec              # use tfsec
  terraview plan --scanner checkov --ai       # scanner + AI analysis
  terraview plan --scanner checkov --plan p.json  # use existing plan
  terraview plan --scanner checkov --ai --provider gemini  # Gemini AI
  terraview plan --scanner checkov --ai --explain  # AI + explanation
  terraview plan --scanner checkov --diagram  # scanner + diagram
  terraview plan --diagram                    # diagram only (no scanner)
  terraview plan --scanner checkov --blast-radius  # blast radius
  terraview plan --scanner checkov --format compact  # minimal output
  terraview plan --scanner checkov --format sarif    # SARIF for CI
  terraview plan --scanner checkov --strict   # HIGH returns exit code 2
  terraview plan --scanner checkov --safe     # safe mode
  terraview plan --findings checkov.json      # import external findings`,
	RunE: runPlan,
}

func init() {
	planCmd.Flags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	planCmd.Flags().StringVar(&promptDir, "prompts", "", "Path to prompts directory")
	planCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for review files")
	planCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama server URL (legacy, prefer --provider)")
	planCmd.Flags().StringVar(&ollamaModel, "model", "", "AI model to use")
	planCmd.Flags().StringVar(&aiProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek)")
	planCmd.Flags().IntVar(&timeout, "timeout", 0, "AI request timeout in seconds")
	planCmd.Flags().Float64Var(&temperature, "temperature", -1, "AI temperature (0.0-1.0)")
	planCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered semantic review")
	planCmd.Flags().StringVar(&outputFormat, "format", "", "Output format: pretty, compact, json, sarif (default pretty)")
	planCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	planCmd.Flags().BoolVar(&safeMode, "safe", false, "Safe mode: light model, reduced threads, stricter resource limits")
	planCmd.Flags().BoolVar(&explainFlag, "explain", false, "Generate AI-powered natural language explanation (implies --ai)")
	planCmd.Flags().BoolVar(&diagramFlag, "diagram", false, "Show ASCII infrastructure diagram")
	planCmd.Flags().BoolVar(&blastRadiusFlag, "blast-radius", false, "Analyze dependency blast radius of changes")
	planCmd.Flags().StringVar(&findingsFile, "findings", "", "Import external findings from Checkov/tfsec/Trivy JSON")
	planCmd.Flags().BoolVar(&secondOpinionFlag, "second-opinion", false, "AI validates scanner findings (implies --ai)")
	planCmd.Flags().BoolVar(&trendFlag, "trend", false, "Track and display score trends over time")
	planCmd.Flags().BoolVar(&smellFlag, "smell", false, "Detect infrastructure design smells")
	planCmd.Flags().StringVar(&scannerFlag, "scanner", "", "Scanner to use: checkov, tfsec, or terrascan")
}

func runPlan(cmd *cobra.Command, args []string) error {
	_, exitCode, err := executeReview()
	if err != nil {
		return err
	}

	if exitCode != 0 {
		return &ExitError{Code: exitCode}
	}

	return nil
}

// executeReview runs the full review pipeline and returns the plan path, exit code, and any error.
func executeReview() (string, int, error) {
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
	if ollamaURL != "" {
		effectiveURL = ollamaURL
	}
	// When the provider is not ollama and no explicit URL was given via flag,
	// clear the URL so each provider falls back to its own default base URL.
	if ollamaURL == "" && effectiveProvider != "ollama" {
		effectiveURL = ""
	}
	effectiveTimeout := cfg.LLM.TimeoutSeconds
	if timeout > 0 {
		effectiveTimeout = timeout
	}
	effectiveTemperature := cfg.LLM.Temperature
	if temperature >= 0 {
		effectiveTemperature = temperature
	}
	// --provider or --model implies --ai
	effectiveAI := aiEnabled || aiProvider != "" || ollamaModel != "" || explainFlag || secondOpinionFlag

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

	// Safe mode overrides
	if safeMode {
		logVerbose("Safe mode enabled: using light model and reduced resources")
		if effectiveProvider == "ollama" && ollamaModel == "" {
			effectiveModel = "llama3.2:3b"
		}
		if timeout == 0 {
			effectiveTimeout = 60
		}
	}

	// Resolve prompts directory
	resolvedPrompts := promptDir
	if resolvedPrompts == "" {
		resolvedPrompts = findBundledDir("prompts")
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

	if scannerFlag != "" {
		// Run the specified scanner
		resolvedScanner, err := scanner.Resolve(scannerFlag)
		if err != nil {
			return resolvedPlan, 0, fmt.Errorf("scanner error: %w", err)
		}

		logVerbose("Running scanner: %s", resolvedScanner.Name())

		scanCtx := scanner.ScanContext{
			PlanPath:  resolvedPlan,
			SourceDir: workDir,
			WorkDir:   workDir,
		}

		rawResults := scanner.RunAll([]scanner.Scanner{resolvedScanner}, scanCtx)
		aggResult := scanner.Aggregate(rawResults)
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
		// Build resource limits from config + safe mode
		limits := buildResourceLimits(cfg, safeMode)

		// Inject topology context into summary for AI
		topoSummary := make(map[string]interface{})
		for k, v := range summary {
			topoSummary[k] = v
		}
		topoSummary["topology_context"] = topoGraph.FormatContext()
		topoSummary["topology_layers"] = topoGraph.Layers()

		// Cluster-level adaptive AI invocation (v0.4.1)
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

	// 3b. Second opinion: AI validates scanner findings
	if secondOpinionFlag && effectiveAI && len(hardFindings) > 0 {
		soCtx, soCancel := context.WithTimeout(context.Background(), time.Duration(effectiveTimeout+30)*time.Second)
		defer soCancel()

		providerCfg := ai.ProviderConfig{
			Model:       effectiveModel,
			APIKey:      cfg.LLM.APIKey,
			BaseURL:     effectiveURL,
			Temperature: effectiveTemperature,
			TimeoutSecs: effectiveTimeout,
			MaxTokens:   4096,
			MaxRetries:  2,
		}

		soProvider, err := ai.NewProvider(soCtx, effectiveProvider, providerCfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnAIProviderUnavail+"\n", output.Prefix(), "--second-opinion", err)
		} else {
			reviewer := secondopinion.NewReviewer(soProvider)
			soResult, err := reviewer.Review(soCtx, hardFindings, resources, topoGraph.FormatContext())
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnSecondOpinionFailed+"\n", output.Prefix(), err)
			} else {
				hardFindings = secondopinion.EnrichFindings(hardFindings, soResult)
				logVerbose("Second opinion: %d agree, %d disputed", soResult.AgreeCount, soResult.DisputeCount)
			}
		}
	}

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

	// 4d. Analyze blast radius if requested (deterministic, no AI)
	if blastRadiusFlag {
		analyzer := blast.NewAnalyzer()
		blastResult := analyzer.AnalyzeWithGraph(resources, topoGraph)
		result.BlastRadius = blastResult
		logVerbose("Blast radius analysis: %s", blastResult.Summary)
	}

	// 4d2. Detect design smells if requested
	if smellFlag {
		detector := smell.NewDetector()
		smellResult := detector.Detect(resources)
		logVerbose("Design smells: %d detected, quality %.1f/10", len(smellResult.Smells), smellResult.QualityScore)
		fmt.Println()
		fmt.Println(smell.FormatSmells(smellResult))
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

	// 4f. Record score trend if requested
	if trendFlag {
		tracker := trend.NewTracker(workDir)
		trendResult, err := tracker.Record(result.Score, len(result.Findings), result.TotalResources, result.SeverityCounts, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s "+i18n.T().WarnTrendFailed+"\n", output.Prefix(), err)
		} else {
			logVerbose("Trend recorded: %s", trendResult.Narrative)
			fmt.Println()
			fmt.Println(trend.FormatTrend(trendResult))
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

	// 6d. Print blast radius if generated
	if blastRadiusFlag && result.BlastRadius != nil {
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

// runClusterAIReview runs cluster-level adaptive AI invocation (v0.4.1).
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
	results, stats := ctrl.Run(ctx, clusters)

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

// findBundledDir looks for a directory relative to the executable, then relative to cwd.
func findBundledDir(dir string) string {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), dir)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		candidate := filepath.Join(homeDir, ".terraview", dir)
		if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
			return candidate
		}
	}

	candidate := dir
	if fi, err := os.Stat(candidate); err == nil && fi.IsDir() {
		return candidate
	}

	return ""
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
