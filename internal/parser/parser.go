package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Parser reads and normalizes Terraform plan JSON files.
type Parser struct{}

// NewParser creates a new Parser instance.
func NewParser() *Parser {
	return &Parser{}
}

// ParseFile reads a terraform plan JSON file and returns the parsed plan.
func (p *Parser) ParseFile(path string) (*TerraformPlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read plan file %s: %w", path, err)
	}

	return p.Parse(data)
}

// Parse parses raw JSON bytes into a TerraformPlan.
func (p *Parser) Parse(data []byte) (*TerraformPlan, error) {
	var plan TerraformPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("failed to parse plan JSON: %w", err)
	}

	if len(plan.ResourceChanges) == 0 {
		return nil, fmt.Errorf("plan contains no resource changes")
	}

	return &plan, nil
}

// NormalizeResources converts resource changes into a flat, simplified list
// suitable for rule evaluation and LLM analysis.
func (p *Parser) NormalizeResources(plan *TerraformPlan) []NormalizedResource {
	resources := make([]NormalizedResource, 0, len(plan.ResourceChanges))

	for _, rc := range plan.ResourceChanges {
		action := normalizeAction(rc.Change.Actions)

		values := rc.Change.After
		if values == nil {
			values = make(map[string]interface{})
		}

		nr := NormalizedResource{
			Address:      rc.Address,
			Type:         rc.Type,
			Name:         rc.Name,
			Action:       action,
			Provider:     extractProvider(rc.ProviderName),
			Values:       values,
			BeforeValues: rc.Change.Before,
		}
		resources = append(resources, nr)
	}

	return resources
}

// normalizeAction converts the list of actions into a single human-readable action.
func normalizeAction(actions []string) string {
	if len(actions) == 0 {
		return "no-op"
	}
	if len(actions) == 1 {
		switch actions[0] {
		case "create":
			return "create"
		case "delete":
			return "delete"
		case "read":
			return "read"
		case "no-op":
			return "no-op"
		default:
			return actions[0]
		}
	}
	if len(actions) == 2 {
		if actions[0] == "create" && actions[1] == "delete" {
			return "replace"
		}
		if actions[0] == "delete" && actions[1] == "create" {
			return "replace"
		}
		if actions[0] == "update" || actions[1] == "update" {
			return "update"
		}
	}
	return strings.Join(actions, ",")
}

// extractProvider extracts a short provider name from the full provider path.
func extractProvider(providerName string) string {
	parts := strings.Split(providerName, "/")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return providerName
}

// ExtractResourceSummary creates a concise summary of plan changes for LLM context.
func (p *Parser) ExtractResourceSummary(resources []NormalizedResource) map[string]interface{} {
	summary := map[string]interface{}{
		"total_resources": len(resources),
	}

	actionCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	providerCounts := make(map[string]int)

	for _, r := range resources {
		actionCounts[r.Action]++
		typeCounts[r.Type]++
		providerCounts[r.Provider]++
	}

	summary["actions"] = actionCounts
	summary["resource_types"] = typeCounts
	summary["providers"] = providerCounts

	return summary
}
