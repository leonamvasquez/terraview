package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/util"
)

func handleExplain(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args commonArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	_, resources, topoGraph, err := resolvePlan(args, logger)
	if err != nil {
		return ToolsCallResult{}, err
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	cfg, err := config.Load(dir)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("config error: %w", err)
	}

	providerName := cfg.LLM.Provider
	if providerName == "" {
		return ToolsCallResult{}, fmt.Errorf("AI provider required: configure 'llm.provider' in .terraview.yaml")
	}

	model := cfg.LLM.Model
	timeout := cfg.LLM.TimeoutSeconds
	if timeout == 0 {
		timeout = util.DefaultTimeoutSeconds
	}

	url := cfg.LLM.URL
	if providerName != "ollama" && url == util.DefaultOllamaURL {
		url = ""
	}

	temp := cfg.LLM.Temperature
	if temp == 0 {
		temp = util.DefaultExplainTemperature
	}

	providerCfg := ai.ProviderConfig{
		Model:       model,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     url,
		Temperature: temp,
		TimeoutSecs: timeout,
		MaxTokens:   util.DefaultExplainMaxTokens,
		MaxRetries:  2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout+util.ContextTimeoutGraceSecs)*time.Second)
	defer cancel()

	provider, err := ai.NewProvider(ctx, providerName, providerCfg)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("AI provider error: %w", err)
	}

	prompt := buildExplainPrompt(resources, topoGraph)

	req := ai.Request{
		Resources: resources,
		Summary: map[string]interface{}{
			"total_resources":  len(resources),
			"topology_context": topoGraph.FormatContext(),
			"topology_layers":  topoGraph.Layers(),
			"mode":             "explain-infra",
		},
		Prompts: ai.Prompts{
			System: prompt,
		},
	}

	logger.Printf("explain: calling %s/%s", providerName, model)
	completion, err := provider.Analyze(ctx, req)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("AI analysis failed: %w", err)
	}

	return textResult(completion.Summary), nil
}

func buildExplainPrompt(resources []parser.NormalizedResource, topoGraph *topology.Graph) string {
	var sb strings.Builder

	sb.WriteString("You are a senior cloud architect explaining infrastructure to a team.\n\n")
	sb.WriteString("Analyze the following Terraform infrastructure and provide a comprehensive explanation.\n\n")
	sb.WriteString("You MUST respond ONLY with valid JSON in this exact format:\n")
	sb.WriteString(`{
  "findings": [],
  "summary": "{\"overview\":\"...\",\"architecture\":\"...\",\"components\":[{\"resource\":\"...\",\"purpose\":\"...\",\"role\":\"...\"}],\"connections\":[\"...\"],\"patterns\":[\"...\"],\"concerns\":[\"...\"]}"
}`)
	sb.WriteString("\n\nTOPOLOGY:\n")
	sb.WriteString(topoGraph.FormatContext())
	sb.WriteString("\n\nRESOURCES:\n")
	for _, r := range resources {
		sb.WriteString(fmt.Sprintf("- %s (%s) [%s]\n", r.Address, r.Type, r.Action))
	}

	return sb.String()
}
