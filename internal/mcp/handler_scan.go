package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/contextanalysis"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/normalizer"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/sanitizer"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/util"
	"github.com/leonamvasquez/terraview/internal/validator"
)

type scanArgs struct {
	commonArgs
	Scanner string `json:"scanner"`
	Static  bool   `json:"static"`
}

func handleScan(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args scanArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	logger.Printf("[mcp:scan] arguments received: dir=%q scanner=%q plan=%q static=%v",
		args.Dir, args.Scanner, args.Plan, args.Static)

	_, resources, topoGraph, err := resolvePlan(args.commonArgs, logger)
	if err != nil {
		return ToolsCallResult{}, err
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	cfg, err := config.Load(dir)
	if err != nil {
		cfg = config.DefaultConfig()
		logger.Printf("config load warning: %v, using defaults", err)
	}

	// Resolve plan path for scanner context (mirrors resolvePlan logic)
	planPath := args.Plan
	if planPath == "" {
		candidates := []string{"plan.json", "tfplan.json"}
		for _, c := range candidates {
			candidate := filepath.Join(dir, c)
			if _, err := os.Stat(candidate); err == nil {
				planPath = candidate
				break
			}
		}
	}

	// Validate scanner upfront before launching goroutines
	var resolvedScanner scanner.Scanner
	if args.Scanner != "" {
		resolved, err := scanner.Resolve(args.Scanner)
		if err != nil {
			return ToolsCallResult{}, fmt.Errorf("scanner %q: %w", args.Scanner, err)
		}

		installed, hint := resolved.EnsureInstalled()
		if !installed {
			msg := hint.Default
			if hint.Brew != "" {
				msg = hint.Brew
			}
			return ToolsCallResult{}, fmt.Errorf("scanner %q not installed: %s", args.Scanner, msg)
		}
		resolvedScanner = resolved
	}

	effectiveAI := !args.Static && canResolveAIProviderFromConfig(cfg)

	logger.Printf("[mcp:scan] AI analysis: static=%v provider=%q model=%q effectiveAI=%v",
		args.Static, cfg.LLM.Provider, cfg.LLM.Model, effectiveAI)

	// --- Run scanner and AI in parallel (mirrors CLI behavior) ---
	type scannerOutput struct {
		findings []rules.Finding
		err      error
		durMs    int64
	}
	type aiOutput struct {
		findings []rules.Finding
		err      error
		durMs    int64
	}

	scannerCh := make(chan scannerOutput, 1)
	aiCh := make(chan aiOutput, 1)

	// Scanner goroutine
	if resolvedScanner != nil {
		go func() {
			start := time.Now()
			ctx := scanner.ScanContext{
				PlanPath:  planPath,
				SourceDir: dir,
				WorkDir:   dir,
			}
			logger.Printf("running scanner: %s", resolvedScanner.Name())
			raw := scanner.RunAll([]scanner.Scanner{resolvedScanner}, ctx)
			agg := scanner.Aggregate(raw)
			scannerCh <- scannerOutput{
				findings: agg.Findings,
				durMs:    time.Since(start).Milliseconds(),
			}
		}()
	} else {
		scannerCh <- scannerOutput{}
	}

	// AI goroutine (runs in parallel with scanner)
	if effectiveAI {
		go func() {
			start := time.Now()
			findings, err := runMCPContextAnalysis(resources, topoGraph, cfg, logger)
			aiCh <- aiOutput{
				findings: findings,
				err:      err,
				durMs:    time.Since(start).Milliseconds(),
			}
		}()
	} else {
		aiCh <- aiOutput{}
	}

	// Collect results
	scanOut := <-scannerCh
	aiOut := <-aiCh

	// --- Build pipeline status for observability ---
	ps := &aggregator.PipelineStatus{}

	if resolvedScanner != nil {
		status := &aggregator.ComponentStatus{
			Tool:       args.Scanner,
			DurationMs: scanOut.durMs,
			Status:     "success",
		}
		if scanOut.err != nil {
			status.Status = "failed"
			status.Error = scanOut.err.Error()
		}
		ps.Scanner = status
	}

	if effectiveAI {
		status := &aggregator.ComponentStatus{
			Provider:   cfg.LLM.Provider,
			Model:      cfg.LLM.Model,
			DurationMs: aiOut.durMs,
			Status:     "success",
		}
		if aiOut.err != nil {
			status.Status = "failed"
			status.Error = aiOut.err.Error()
			logger.Printf("[mcp:scan] AI analysis failed (non-fatal): %v", aiOut.err)
		} else {
			logger.Printf("[mcp:scan] AI analysis returned %d findings", len(aiOut.findings))
		}
		ps.AI = status
	}

	// Determine result completeness
	scannerOK := ps.Scanner == nil || ps.Scanner.Status == "success"
	aiOK := ps.AI == nil || ps.AI.Status == "success"
	switch {
	case scannerOK && aiOK:
		ps.ResultCompleteness = "complete"
	case scannerOK && !aiOK:
		ps.ResultCompleteness = "partial_scanner_only"
	case !scannerOK && aiOK:
		ps.ResultCompleteness = "partial_ai_only"
	default:
		ps.ResultCompleteness = "failed"
	}

	hardFindings := scanOut.findings
	contextFindings := aiOut.findings

	// --- Validate AI findings against topology ---
	validatedAIFindings := contextFindings
	if len(contextFindings) > 0 && topoGraph != nil {
		valid, _, report := validator.ValidateAIFindings(contextFindings, topoGraph)
		validatedAIFindings = valid
		if report.TotalDiscard > 0 {
			logger.Printf("[mcp:scan] AI validation: %d valid, %d discarded",
				report.TotalValid, report.TotalDiscard)
		}
	}

	// --- Deduplicate: merge scanner + AI findings ---
	if len(hardFindings) > 0 || len(validatedAIFindings) > 0 {
		dr := normalizer.Deduplicate(hardFindings, validatedAIFindings)
		hardFindings = dr.Findings
	}

	// --- Validate merged findings against topology ---
	if len(hardFindings) > 0 && topoGraph != nil {
		valid, _, report := validator.ValidateAIFindings(hardFindings, topoGraph)
		if report.TotalDiscard > 0 {
			logger.Printf("validated findings: %d valid, %d discarded", report.TotalValid, report.TotalDiscard)
		}
		hardFindings = valid
	}

	// --- Score ---
	sw := cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)

	result := agg.Aggregate(planPath, len(resources), hardFindings, nil, "", false)

	// Attach pipeline status
	result.PipelineStatus = ps

	// Meta-analysis
	if len(result.Findings) > 0 {
		metaAnalyzer := meta.NewAnalyzer()
		result.MetaAnalysis = metaAnalyzer.Analyze(result.Findings)
	}

	return jsonResult(result)
}

// canResolveAIProviderFromConfig checks if an AI provider can be resolved from config.
func canResolveAIProviderFromConfig(cfg config.Config) bool {
	provider := cfg.LLM.Provider
	if provider == "" {
		return false
	}
	return ai.Has(provider)
}

// runMCPContextAnalysis runs AI-powered contextual analysis on resources and topology.
// This mirrors the logic in cmd/scan.go runCodeContextAnalysis but adapted for MCP mode.
func runMCPContextAnalysis(
	resources []parser.NormalizedResource,
	graph *topology.Graph,
	cfg config.Config,
	logger *log.Logger,
) ([]rules.Finding, error) {
	providerName := cfg.LLM.Provider
	model := cfg.LLM.Model
	url := cfg.LLM.URL
	if providerName != "ollama" {
		url = ""
	}

	timeout := cfg.LLM.TimeoutSeconds
	if timeout == 0 {
		timeout = util.DefaultTimeoutSeconds
	}

	temp := cfg.LLM.Temperature
	if temp == 0 {
		temp = 0.2
	}

	logger.Printf("[mcp:scan] AI context analysis: %s (model: %s)", providerName, model)

	// Scale timeout with resource count
	effectiveResources := len(resources)
	maxResources := cfg.LLM.MaxResources
	if maxResources > 0 && effectiveResources > maxResources {
		effectiveResources = maxResources
	}
	scaledTimeout := timeout + effectiveResources*3 + util.ContextTimeoutGraceSecs

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(scaledTimeout)*time.Second)
	defer cancel()

	providerCfg := ai.ProviderConfig{
		Model:        model,
		APIKey:       cfg.LLM.APIKey,
		BaseURL:      url,
		Temperature:  temp,
		TimeoutSecs:  timeout,
		MaxTokens:    util.DefaultAnalyzeMaxTokens,
		MaxRetries:   2,
		MaxResources: maxResources,
		NumCtx:       cfg.LLM.Ollama.NumCtx,
	}

	provider, err := ai.NewProvider(ctx, providerName, providerCfg)
	if err != nil {
		return nil, fmt.Errorf("ai provider %s: %w", providerName, err)
	}

	// Load context-analysis prompt from prompts directory (if available)
	contextPrompt := ""
	execPath, exErr := os.Executable()
	if exErr == nil {
		promptDir := filepath.Join(filepath.Dir(execPath), "prompts")
		if _, statErr := os.Stat(promptDir); statErr != nil {
			promptDir = filepath.Join(".", "prompts")
		}
		pl := ai.NewPromptLoader(promptDir)
		if prompts, loadErr := pl.Load(); loadErr == nil {
			contextPrompt = prompts.ContextAnalysis
		}
	}

	// Sanitize sensitive data before sending to AI
	shouldRedact := cfg.LLM.Redact
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
			logger.Printf("[mcp:scan] redacted %d sensitive values (%d unique) before AI analysis",
				manifest.Count(), manifest.UniqueCount())
		}
	}

	analyzer := contextanalysis.NewAnalyzer(provider, "", contextPrompt, maxResources)

	result, err := analyzer.Analyze(ctx, resources, graph)
	if err != nil {
		return nil, err
	}

	logger.Printf("[mcp:scan] AI context (%s/%s): %d findings", providerName, model, len(result.Findings))
	return result.Findings, nil
}
