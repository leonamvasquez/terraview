package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/pipeline"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/runtime"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/suppression"
	"github.com/leonamvasquez/terraview/internal/topology"
)

var (
	// Scan-local flags
	staticOnly       bool // --static: disable AI contextual analysis
	strict           bool
	findingsFile     string
	noRedactFlag     bool   // --no-redact: disable sensitive data redaction
	maxResourcesFlag int    // --max-resources: override AI prompt resource limit (0=auto)
	ignoreFile       string // --ignore-file: path to .terraview-ignore suppression file
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
  terraview scan checkov --provider gemini     # use specific AI provider
  terraview scan checkov --format compact      # minimal output
  terraview scan checkov --format sarif        # SARIF for CI
  terraview scan checkov --strict              # HIGH returns exit code 2
  terraview scan checkov --findings ext.json   # import external findings

Related commands:
  terraview explain    # AI natural-language explanation of the infrastructure
  terraview diagram    # ASCII diagram of the topology
  terraview fix        # apply AI-generated fixes to findings
  terraview status     # show findings from the last scan

Terragrunt:
  terraview scan checkov --terragrunt                    # auto-detect terragrunt config
  terraview scan checkov --terragrunt dev.hcl            # use specific config file
  terraview scan checkov --terragrunt terragrunt/prd.hcl # path to config file`,
	Args: func(cmd *cobra.Command, args []string) error {
		// Allow 2 positional args when --terragrunt is "auto" and the extra arg
		// is the config path (NoOptDefVal splits "--terragrunt dev.hcl" into
		// flag="auto" + positional arg "dev.hcl").
		max := 1
		if terragruntFlag == "auto" && len(args) == 2 {
			max = 2
		}
		if len(args) > max {
			return fmt.Errorf("accepts at most 1 arg(s), received %d", len(args))
		}
		return nil
	},
	RunE: runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&staticOnly, "static", false, "Static analysis only: disable AI contextual analysis")
	scanCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	scanCmd.Flags().StringVar(&findingsFile, "findings", "", "Import external findings from Checkov/tfsec/Trivy JSON")
	scanCmd.Flags().BoolVar(&noRedactFlag, "no-redact", false, "Skip sensitive data redaction (use only with local providers)")
	scanCmd.Flags().IntVar(&maxResourcesFlag, "max-resources", 0, "Max resources included in AI prompt context (0=auto by model)")
	scanCmd.Flags().StringVar(&ignoreFile, "ignore-file", "", "Path to suppression file (default: .terraview-ignore in project dir)")

	// pt-BR flag translations (brFlag is set in root.go init which runs before scan.go init)
	if brFlag {
		translateFlags(scanCmd, map[string]string{
			"static":        "Apenas análise estática: desabilitar análise contextual IA",
			"strict":        "Modo estrito: achados HIGH também retornam código de saída 2",
			"findings":      "Importar achados externos de Checkov/tfsec/Trivy JSON",
			"no-redact":     "Desabilitar redação de dados sensíveis (usar apenas com providers locais)",
			"max-resources": "Máximo de recursos incluídos no contexto do prompt IA (0=auto por modelo)",
			"ignore-file":   "Caminho para arquivo de supressão (padrão: .terraview-ignore no diretório do projeto)",
		})
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Handle --terragrunt <file> parsed as extra positional arg due to NoOptDefVal.
	if terragruntFlag == "auto" && len(args) > 1 {
		terragruntFlag = args[len(args)-1]
		args = args[:len(args)-1]
	}

	scannerName := ""
	if len(args) > 0 {
		scannerName = args[0]
	}

	// If no scanner specified, try auto-select.
	if scannerName == "" && !(staticOnly && findingsFile != "") {
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

	// AI-only mode is valid (if provider available)
	if scannerName == "" && !staticOnly && findingsFile == "" {
		cfg, err := config.Load(workDir)
		if err != nil {
			return fmt.Errorf("config error: %w", err)
		}
		providerAvailable := canResolveAIProvider(cfg)
		if !providerAvailable {
			avail := scanner.DefaultManager.Available()
			if len(avail) == 0 {
				return fmt.Errorf("no scanners installed and no AI provider configured.\n\nGet started:\n  terraview scanners install checkov    # install a scanner\n  terraview provider list               # configure an AI provider\n\nOr edit .terraview.yaml directly")
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
// It mirrors a subset of pipeline.Config, using unexported fields so the
// existing cmd-level tests remain a stable public surface. Convert with
// reviewConfig.toPipeline() before invoking the pipeline package.
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

// scanResult holds the output of the parallel scanner + AI phase.
type scanResult struct {
	hardFindings    []rules.Finding
	scannerResult   *scanner.AggregatedResult
	contextFindings []rules.Finding
	contextSummary  string
	pipelineStatus  *aggregator.PipelineStatus
}

// toPipeline converts the CLI-facing reviewConfig plus the current global
// flag state into a pipeline.Config that the reusable Runner can execute.
func (rc reviewConfig) toPipeline() pipeline.Config {
	lang := ""
	if brFlag {
		lang = "pt-BR"
	}
	return pipeline.Config{
		Cfg:             rc.cfg,
		ScannerName:     rc.scannerName,
		PlanPath:        rc.resolvedPlan,
		WorkDir:         workDir,
		EffectiveAI:     rc.effectiveAI,
		EffectiveFormat: rc.effectiveFormat,
		Strict:          strict,
		StaticOnly:      staticOnly,
		NoRedact:        noRedactFlag,
		IgnoreFile:      rc.ignoreFile,
		FindingsFile:    findingsFile,
		AIProvider:      rc.aiProvider,
		AIModel:         rc.aiModel,
		AIURL:           rc.aiURL,
		AITimeoutSecs:   rc.aiTimeout,
		AITemperature:   rc.aiTemperature,
		AIAPIKey:        rc.aiAPIKey,
		AIMaxResources:  rc.aiMaxResources,
		AINumCtx:        rc.aiNumCtx,
		Lang:            lang,
		ShowSpinner:     true,
		Stderr:          os.Stderr,
		ProjectDir:      resolveProjectDir(),
		Verbose:         logVerbose,
	}
}

// executeReview runs the full review pipeline and returns the plan path, exit code, and any error.
// Pipeline: Parse → [Scanner ‖ AI Context] → Merge → Score → Output
func executeReview(scannerName string) (string, int, error) { //nolint:unparam // planPath used by apply command
	rc, err := resolveReviewConfig(scannerName)
	if err != nil {
		return "", 0, err
	}

	runner := pipeline.NewRunner(rc.toPipeline())
	runResult, err := runner.Run(context.Background())
	if err != nil {
		return rc.resolvedPlan, 0, err
	}

	exitCode, err := renderOutput(rc, runResult.Review, runResult.ScannerResult)
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
	return pipeline.ParsePlan(planPath, logVerbose)
}

// runScanners executes the security scanner and AI context analysis in parallel.
// Thin wrapper around pipeline.RunScanPhase that preserves the cmd-level
// reviewConfig/scanResult surface used by the existing test suite.
func runScanners(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph) (scanResult, error) {
	sr, err := pipeline.RunScanPhase(context.Background(), rc.toPipeline(), resources, topoGraph)
	result := scanResult{
		hardFindings:    sr.HardFindings,
		scannerResult:   sr.ScannerResult,
		contextFindings: sr.ContextFindings,
		contextSummary:  sr.ContextSummary,
		pipelineStatus:  sr.PipelineStatus,
	}
	return result, err
}

// mergeAndScore deduplicates findings, scores them, and enriches the result with optional analyses.
func mergeAndScore(rc reviewConfig, resources []parser.NormalizedResource, topoGraph *topology.Graph, sr scanResult) aggregator.ReviewResult {
	psr := pipeline.ScanPhaseResult{
		HardFindings:    sr.hardFindings,
		ScannerResult:   sr.scannerResult,
		ContextFindings: sr.contextFindings,
		ContextSummary:  sr.contextSummary,
		PipelineStatus:  sr.pipelineStatus,
	}
	return pipeline.MergeAndScore(rc.toPipeline(), resources, topoGraph, psr)
}

// renderOutput writes all output files, prints the summary, and returns the exit code.
func renderOutput(rc reviewConfig, result aggregator.ReviewResult, scannerResult *scanner.AggregatedResult) (int, error) {
	langCode := ""
	if brFlag {
		langCode = "pt-BR"
	}
	writer := output.NewWriterWithConfig(output.WriterConfig{
		Format:  rc.effectiveFormat,
		Lang:    langCode,
		Version: Version,
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

// buildResourceLimits constructs runtime limits from config and safe mode.
// Wrapper retained for existing cmd-level tests; delegates to pipeline.
func buildResourceLimits(cfg config.Config, safe bool) runtime.ResourceLimits {
	return pipeline.BuildResourceLimits(cfg, safe)
}

// filterDisabledRules removes findings whose RuleID matches any disabled rule pattern.
// Wrapper retained for existing cmd-level tests; delegates to pipeline.
func filterDisabledRules(findings []rules.Finding, disabled []string) []rules.Finding {
	return pipeline.FilterDisabledRules(findings, disabled)
}
