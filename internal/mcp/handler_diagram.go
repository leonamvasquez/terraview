package mcp

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/leonamvasquez/terraview/internal/diagram"
)

func handleDiagram(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
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

	gen := diagram.NewGenerator()
	ascii := gen.GenerateWithGraph(resources, topoGraph)

	logger.Printf("diagram: generated for %d resources", len(resources))
	return textResult(ascii), nil
}
