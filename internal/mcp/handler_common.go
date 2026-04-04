package mcp

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// commonArgs are shared fields across all tool arguments.
type commonArgs struct {
	Dir  string `json:"dir"`
	Plan string `json:"plan"`
}

// resolvePlan resolves the plan path and returns the raw plan, normalized
// resources, and topology graph. It requires a pre-generated plan JSON —
// auto-generation (terraform init/plan) is not supported in MCP mode to avoid
// side effects during agent calls.
func resolvePlan(args commonArgs, logger *log.Logger) (*parser.TerraformPlan, []parser.NormalizedResource, *topology.Graph, error) {
	planPath := args.Plan
	dir := args.Dir
	if dir == "" {
		dir = "."
	}

	// If no explicit plan, look for common plan files in the directory
	if planPath == "" {
		candidates := []string{"plan.json", "tfplan.json"}
		for _, c := range candidates {
			candidate := fmt.Sprintf("%s/%s", dir, c)
			if _, err := os.Stat(candidate); err == nil {
				planPath = candidate
				logger.Printf("auto-detected plan: %s", planPath)
				break
			}
		}
	}

	if planPath == "" {
		return nil, nil, nil, fmt.Errorf("no plan file specified and no plan.json found in %s — generate one with: terraform show -json > plan.json", dir)
	}

	if _, err := os.Stat(planPath); err != nil {
		return nil, nil, nil, fmt.Errorf("plan file not found: %s", planPath)
	}

	p := parser.NewParser()
	plan, err := p.ParseFile(planPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	if len(resources) == 0 {
		return nil, nil, nil, fmt.Errorf("no resources found in plan %s", planPath)
	}

	graph := topology.BuildGraph(resources)
	return plan, resources, graph, nil
}

// textResult creates a successful ToolsCallResult with a single text block.
func textResult(text string) ToolsCallResult {
	return ToolsCallResult{
		Content: []ContentBlock{{Type: "text", Text: text}},
	}
}

// jsonResult creates a successful ToolsCallResult with JSON-serialized content.
func jsonResult(v interface{}) (ToolsCallResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ToolsCallResult{}, fmt.Errorf("json marshal: %w", err)
	}
	return textResult(string(data)), nil
}
