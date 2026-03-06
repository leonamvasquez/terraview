package mcp

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/meta"
	"github.com/leonamvasquez/terraview/internal/normalizer"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/scoring"
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

	resources, topoGraph, err := resolvePlan(args.commonArgs, logger)
	if err != nil {
		return ToolsCallResult{}, err
	}

	cfg, err := config.Load(args.Dir)
	if err != nil {
		cfg = config.DefaultConfig()
		logger.Printf("config load warning: %v, using defaults", err)
	}

	// --- Run scanner ---
	var scannerFindings []scanner.ScanResult
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

		dir := args.Dir
		if dir == "" {
			dir = "."
		}
		planPath := args.Plan
		if planPath == "" {
			planPath = fmt.Sprintf("%s/plan.json", dir)
		}

		ctx := scanner.ScanContext{
			PlanPath:  planPath,
			SourceDir: dir,
			WorkDir:   dir,
		}

		logger.Printf("running scanner: %s", resolved.Name())
		scannerFindings = scanner.RunAll([]scanner.Scanner{resolved}, ctx)
	}

	aggResult := scanner.Aggregate(scannerFindings)
	hardFindings := aggResult.Findings

	// --- AI context analysis (skipped in MCP for now, unless !static and provider configured) ---
	// In MCP mode, we run scanner-only by default. AI requires provider configuration
	// and is currently only available when the full CLI pipeline is used.
	// Future: add AI support to MCP handlers when provider resolution is decoupled from cmd.

	// --- Validate and merge ---
	var contextFindings []json.RawMessage // placeholder for future AI integration
	_ = contextFindings

	// --- Score ---
	sw := cfg.Scoring.SeverityWeights
	scorer := scoring.NewScorerWithWeights(sw.Critical, sw.High, sw.Medium, sw.Low)
	agg := aggregator.NewAggregator(scorer)

	// Deduplicate scanner findings (even without AI, dedup normalizes)
	if len(hardFindings) > 0 {
		dr := normalizer.Deduplicate(hardFindings, nil)
		hardFindings = dr.Findings
	}

	// Validate findings against topology if we have them
	if len(hardFindings) > 0 && topoGraph != nil {
		valid, _, report := validator.ValidateAIFindings(hardFindings, topoGraph)
		if report.TotalDiscard > 0 {
			logger.Printf("validated findings: %d valid, %d discarded", report.TotalValid, report.TotalDiscard)
		}
		hardFindings = valid
	}

	result := agg.Aggregate("", len(resources), hardFindings, nil, "", false)

	// Meta-analysis
	if len(result.Findings) > 0 {
		metaAnalyzer := meta.NewAnalyzer()
		result.MetaAnalysis = metaAnalyzer.Analyze(result.Findings)
	}

	return jsonResult(result)
}
