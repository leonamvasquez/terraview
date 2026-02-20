package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/leonam/terraview/internal/aggregator"
	"github.com/leonam/terraview/internal/ai"
	_ "github.com/leonam/terraview/internal/ai/providers"
	"github.com/leonam/terraview/internal/config"
	"github.com/leonam/terraview/internal/llm"
	"github.com/leonam/terraview/internal/output"
	"github.com/leonam/terraview/internal/parser"
	"github.com/leonam/terraview/internal/rules"
	"github.com/leonam/terraview/internal/runtime"
	"github.com/leonam/terraview/internal/scoring"
	"github.com/leonam/terraview/internal/terraformexec"
	"github.com/leonam/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var (
	planFile    string
	rulesFile   string
	promptDir   string
	outputDir   string
	ollamaURL   string
	ollamaModel string
	aiProvider  string
	timeout     int
	temperature float64
	skipLLM      bool
	outputFormat string
	strict       bool
	safeMode    bool
)

var reviewCmd = &cobra.Command{
	Use:   "review",
	Short: "Review a Terraform plan for security, architecture, and best practices",
	Long: `Analyzes a Terraform plan using deterministic rules and optional AI review.

If --plan is not specified, terraview will automatically run:
  terraform init   (if needed)
  terraform plan   (generates plan)
  terraform show   (exports JSON)

Examples:
  terraview review                              # auto-detect and plan
  terraview review --plan plan.json             # use existing plan
  terraview review --skip-llm                   # hard rules only
  terraview review --provider gemini            # use Gemini AI
  terraview review --format compact             # minimal output
  terraview review --format json                # only write review.json
  terraview review --strict                     # HIGH returns exit code 2
  terraview review --safe                       # safe mode (light model, fewer resources)`,
	RunE: runReview,
}

func init() {
	reviewCmd.Flags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	reviewCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "Path to rules YAML file")
	reviewCmd.Flags().StringVar(&promptDir, "prompts", "", "Path to prompts directory")
	reviewCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for review files")
	reviewCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama server URL (legacy, prefer --provider)")
	reviewCmd.Flags().StringVar(&ollamaModel, "model", "", "AI model to use")
	reviewCmd.Flags().StringVar(&aiProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek)")
	reviewCmd.Flags().IntVar(&timeout, "timeout", 0, "AI request timeout in seconds")
	reviewCmd.Flags().Float64Var(&temperature, "temperature", -1, "AI temperature (0.0-1.0)")
	reviewCmd.Flags().BoolVar(&skipLLM, "skip-llm", false, "Skip AI analysis (hard rules only)")
	reviewCmd.Flags().StringVar(&outputFormat, "format", "", "Output format: pretty, compact, json (default pretty)")
	reviewCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	reviewCmd.Flags().BoolVar(&safeMode, "safe", false, "Safe mode: light model, reduced threads, stricter resource limits")
}

func runReview(cmd *cobra.Command, args []string) error {
	_, exitCode, err := executeReview()
	if err != nil {
		return err
	}

	if exitCode != 0 {
		os.Exit(exitCode)
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
	effectiveTimeout := cfg.LLM.TimeoutSeconds
	if timeout > 0 {
		effectiveTimeout = timeout
	}
	effectiveTemperature := cfg.LLM.Temperature
	if temperature >= 0 {
		effectiveTemperature = temperature
	}
	effectiveSkipLLM := skipLLM || !cfg.LLM.Enabled

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

	// Resolve rules: CLI flag > config rule_packs > default bundled file
	var resolvedRulesPaths []string
	if rulesFile != "" {
		resolvedRulesPaths = []string{rulesFile}
	} else if len(cfg.Rules.RulePacks) > 0 {
		rulesDir := findBundledDir("rules")
		if rulesDir == "" {
			rulesDir = "rules"
		}
		paths, err := rules.ResolveRulePacks(cfg.Rules.RulePacks, rulesDir)
		if err != nil {
			return "", 0, fmt.Errorf("rule packs error: %w", err)
		}
		resolvedRulesPaths = paths
	} else {
		resolvedRulesPaths = []string{findBundledFile("rules", "default-rules.yaml")}
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

	// 2. Hard rules (supports multiple rule files / packs)
	logVerbose("Loading rules from %d source(s)", len(resolvedRulesPaths))
	engine, err := rules.NewEngineFromPaths(resolvedRulesPaths)
	if err != nil {
		return resolvedPlan, 0, fmt.Errorf("rules error: %w", err)
	}

	// Override required tags from config if set
	if len(cfg.Rules.RequiredTags) > 0 {
		engine.SetRequiredTags(cfg.Rules.RequiredTags)
	}

	hardFindings := engine.Evaluate(resources)
	logVerbose("Hard rules: %d findings", len(hardFindings))

	// 3. AI review (optional) with lifecycle management
	var aiFindings []rules.Finding
	var aiSummary string

	if !effectiveSkipLLM {
		// Build resource limits from config + safe mode
		limits := buildResourceLimits(cfg, safeMode)

		aiFindings, aiSummary = runAIReview(resources, summary, resolvedPrompts,
			effectiveProvider, effectiveURL, effectiveModel,
			effectiveTimeout, effectiveTemperature, cfg.LLM.APIKey, limits)
	} else {
		logVerbose("AI analysis skipped")
	}

	// 4. Aggregate (with configurable scoring weights)
	sw := cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)
	result := agg.Aggregate(resolvedPlan, len(resources), hardFindings, aiFindings, aiSummary)

	// 5. Output
	writer := output.NewWriterWithConfig(output.WriterConfig{
		Format: effectiveFormat,
	})

	jsonPath := filepath.Join(resolvedOutput, "review.json")
	if err := writer.WriteJSON(result, jsonPath); err != nil {
		return resolvedPlan, 0, fmt.Errorf("failed to write JSON: %w", err)
	}
	logVerbose("Written: %s", jsonPath)

	if effectiveFormat != output.FormatJSON {
		mdPath := filepath.Join(resolvedOutput, "review.md")
		if err := writer.WriteMarkdown(result, mdPath); err != nil {
			return resolvedPlan, 0, fmt.Errorf("failed to write Markdown: %w", err)
		}
		logVerbose("Written: %s", mdPath)
	}

	// 6. Print summary
	writer.PrintSummary(result)

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

// runAIReview uses the multi-provider AI system with lifecycle management.
func runAIReview(resources []parser.NormalizedResource, summary map[string]interface{},
	promptsDir, providerName, url, model string, timeoutSecs int, temp float64,
	apiKey string, limits runtime.ResourceLimits) ([]rules.Finding, string) {

	logVerbose("AI provider: %s (model: %s)", providerName, model)

	// Load prompts
	if promptsDir == "" {
		fmt.Fprintf(os.Stderr, "[terraview] WARNING: Prompts directory not found. Skipping AI analysis.\n")
		return nil, ""
	}

	loader := llm.NewPromptLoader(promptsDir)
	promptSet, err := loader.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[terraview] WARNING: Failed to load prompts (%v). Skipping AI analysis.\n", err)
		return nil, ""
	}

	// Ollama lifecycle management: auto-start and auto-stop
	var ollamaCleanup func()
	if providerName == "ollama" {
		lc := runtime.NewOllamaLifecycle(limits, url)
		bgCtx := context.Background()
		cleanup, err := lc.Ensure(bgCtx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[terraview] WARNING: Ollama not available (%v). Skipping AI analysis.\n", err)
			return nil, ""
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
		fmt.Fprintf(os.Stderr, "[terraview] WARNING: AI provider %q not available (%v). Skipping AI analysis.\n", providerName, err)
		return nil, ""
	}

	// Build AI request
	req := ai.Request{
		Resources: resources,
		Summary:   summary,
		Prompts: ai.Prompts{
			System:       promptSet.System,
			Security:     promptSet.Security,
			Architecture: promptSet.Architecture,
			Standards:    promptSet.Standards,
		},
	}

	logVerbose("Sending plan to AI (%s) for analysis...", providerName)
	completion, err := provider.Analyze(ctx, req)

	// Stop monitor and cleanup Ollama process
	if monitor != nil {
		monitor.Stop()
	}
	if ollamaCleanup != nil {
		ollamaCleanup()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[terraview] WARNING: AI review failed (%v). Continuing with hard rules only.\n", err)
		return nil, ""
	}

	logVerbose("AI (%s/%s): %d additional findings", completion.Provider, completion.Model, len(completion.Findings))
	return completion.Findings, completion.Summary
}

// findBundledFile looks for a file relative to the executable, then relative to cwd.
func findBundledFile(dir, filename string) string {
	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), dir, filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		candidate := filepath.Join(homeDir, ".terraview", dir, filename)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	candidate := filepath.Join(dir, filename)
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}

	return candidate
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
