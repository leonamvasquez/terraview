package mcp

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/leonamvasquez/terraview/internal/blast"
)

func handleImpact(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args commonArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	_, resources, graph, err := resolvePlan(args, logger)
	if err != nil {
		return ToolsCallResult{}, err
	}

	analyzer := blast.NewAnalyzer()
	result := analyzer.AnalyzeWithGraph(resources, graph)

	logger.Printf("[mcp:impact] resources=%d max_radius=%d impacts=%d",
		len(resources), result.MaxRadius, len(result.Impacts))

	return jsonResult(result)
}
