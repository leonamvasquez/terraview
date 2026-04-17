package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/pipeline"
	"github.com/leonamvasquez/terraview/internal/scanner"
)

type scanArgs struct {
	commonArgs
	Scanner string `json:"scanner"`
	Static  bool   `json:"static"`
}

// handleScan runs the full TerraView pipeline via pipeline.Runner so that the
// CLI and MCP entrypoints cannot drift.
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

	// Validate scanner upfront — surfaces clean JSON-RPC error before launching goroutines.
	if args.Scanner != "" {
		resolved, err := scanner.Resolve(args.Scanner)
		if err != nil {
			return ToolsCallResult{}, fmt.Errorf("scanner %q: %w", args.Scanner, err)
		}
		if installed, hint := resolved.EnsureInstalled(); !installed {
			msg := hint.Default
			if hint.Brew != "" {
				msg = hint.Brew
			}
			return ToolsCallResult{}, fmt.Errorf("scanner %q not installed: %s", args.Scanner, msg)
		}
	}

	effectiveAI := !args.Static && canResolveAIProviderFromConfig(cfg)

	logger.Printf("[mcp:scan] AI analysis: static=%v provider=%q model=%q effectiveAI=%v",
		args.Static, cfg.LLM.Provider, cfg.LLM.Model, effectiveAI)

	pipelineCfg := pipeline.Config{
		Cfg:             cfg,
		ScannerName:     args.Scanner,
		PlanPath:        planPath,
		WorkDir:         dir,
		EffectiveAI:     effectiveAI,
		EffectiveFormat: "json",
		AIProvider:      cfg.LLM.Provider,
		AIModel:         cfg.LLM.Model,
		AIURL:           cfg.LLM.URL,
		AITimeoutSecs:   cfg.LLM.TimeoutSeconds,
		AITemperature:   cfg.LLM.Temperature,
		AIAPIKey:        cfg.LLM.APIKey,
		AIMaxResources:  cfg.LLM.MaxResources,
		AINumCtx:        cfg.LLM.Ollama.NumCtx,
		ShowSpinner:     false,
		Stderr:          io.Discard,
		ProjectDir:      dir,
		Verbose: func(format string, a ...any) {
			logger.Printf("[mcp:scan] "+format, a...)
		},
	}

	sr, err := pipeline.RunScanPhase(context.Background(), pipelineCfg, resources, topoGraph)
	if err != nil {
		return ToolsCallResult{}, err
	}

	result := pipeline.MergeAndScore(pipelineCfg, resources, topoGraph, sr)

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
