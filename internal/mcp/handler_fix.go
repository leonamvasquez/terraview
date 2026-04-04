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
	"github.com/leonamvasquez/terraview/internal/fix"
)

type fixArgs struct {
	commonArgs
	RuleID   string `json:"rule_id"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
	Category string `json:"category"`
}

func handleFixSuggest(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args fixArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	if args.RuleID == "" || args.Resource == "" || args.Message == "" {
		return ToolsCallResult{}, fmt.Errorf("rule_id, resource, and message are required")
	}

	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	cfg, err := config.Load(dir)
	if err != nil {
		cfg = config.DefaultConfig()
		logger.Printf("[mcp:fix] config load warning: %v, using defaults", err)
	}

	if cfg.LLM.Provider == "" {
		return ToolsCallResult{}, fmt.Errorf(
			"AI provider not configured — set llm.provider in .terraview.yaml\n" +
				"Run: terraview provider list")
	}

	// Look up the resource's current configuration and build the plan index (best-effort).
	var resourceConfig map[string]interface{}
	var planIndex *fix.PlanIndex
	resourceType := extractResourceType(args.Resource)

	if rawPlan, resources, _, planErr := resolvePlan(args.commonArgs, logger); planErr == nil {
		planIndex = fix.BuildIndex(rawPlan, resources)
		for _, r := range resources {
			if r.Address == args.Resource {
				resourceConfig = r.Values
				resourceType = r.Type
				break
			}
		}
	}

	timeout := 60
	if cfg.LLM.TimeoutSeconds > 0 {
		timeout = cfg.LLM.TimeoutSeconds
	}

	providerCfg := ai.ProviderConfig{
		Model:       cfg.LLM.Model,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     cfg.LLM.URL,
		Temperature: 0.1,
		MaxTokens:   1024,
		MaxRetries:  1,
		TimeoutSecs: timeout,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	provider, err := ai.NewProvider(ctx, cfg.LLM.Provider, providerCfg)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("AI provider %q: %w", cfg.LLM.Provider, err)
	}

	logger.Printf("[mcp:fix] generating fix for %s on %s via %s", args.RuleID, args.Resource, cfg.LLM.Provider)

	suggester := fix.NewSuggester(provider)

	req := fix.FixRequest{
		Finding: fix.FixFinding{
			RuleID:   args.RuleID,
			Severity: args.Severity,
			Message:  args.Message,
			Category: args.Category,
		},
		ResourceAddr:   args.Resource,
		ResourceType:   resourceType,
		ResourceConfig: resourceConfig,
		PlanIndex:      planIndex,
	}

	suggestion, err := suggester.Suggest(ctx, req)
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("fix suggestion failed: %w", err)
	}

	return jsonResult(suggestion)
}

// extractResourceType extracts the resource type from a Terraform address like "aws_s3_bucket.my_bucket".
func extractResourceType(addr string) string {
	parts := strings.SplitN(addr, ".", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return addr
}
