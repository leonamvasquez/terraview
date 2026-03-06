package mcp

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/leonamvasquez/terraview/internal/drift"
)

type driftArgs struct {
	commonArgs
	Intelligence bool `json:"intelligence"`
}

// driftResponse is the structured response for the drift tool.
type driftResponse struct {
	Drift        drift.DriftResult         `json:"drift"`
	Intelligence *drift.IntelligenceResult `json:"intelligence,omitempty"`
}

func handleDrift(rawArgs json.RawMessage, logger *log.Logger) (ToolsCallResult, error) {
	var args driftArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return ToolsCallResult{}, fmt.Errorf("invalid arguments: %w", err)
		}
	}

	resources, _, err := resolvePlan(args.commonArgs, logger)
	if err != nil {
		return ToolsCallResult{}, err
	}

	analyzer := drift.NewAnalyzer(nil)
	result := analyzer.Analyze(resources)

	resp := driftResponse{Drift: result}

	if args.Intelligence {
		intelResult := drift.ClassifyDrift(resources, nil)
		resp.Intelligence = intelResult
		logger.Printf("drift: %d changes, intelligence risk=%s", result.TotalChanges, intelResult.RiskLevel)
	} else {
		logger.Printf("drift: %d changes, max_severity=%s", result.TotalChanges, result.MaxSeverity)
	}

	return jsonResult(resp)
}
