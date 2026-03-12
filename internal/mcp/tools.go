package mcp

import "encoding/json"

// AllTools returns the list of all MCP tools provided by terraview.
func AllTools() []ToolDef {
	return []ToolDef{
		{
			Name:        "terraview_scan",
			Description: "Run security scan on Terraform infrastructure. Returns scorecard (0-10) and findings.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":     { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"scanner": { "type": "string", "enum": ["checkov", "tfsec", "terrascan"], "description": "Security scanner to use." },
					"plan":    { "type": "string", "description": "Path to pre-generated plan JSON." },
					"static":  { "type": "boolean", "default": false, "description": "Run scanner only, disable AI contextual analysis." }
				}
			}`),
		},
		{
			Name:        "terraview_explain",
			Description: "Natural language explanation of Terraform infrastructure. Requires AI provider.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to pre-generated plan JSON." }
				}
			}`),
		},
		{
			Name:        "terraview_diagram",
			Description: "ASCII infrastructure diagram. No AI required.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to pre-generated plan JSON." }
				}
			}`),
		},
		{
			Name:        "terraview_drift",
			Description: "Detect and classify infrastructure drift by risk.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":          { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan":         { "type": "string", "description": "Path to pre-generated plan JSON." },
					"intelligence": { "type": "boolean", "default": false, "description": "Enable advanced drift classification and risk scoring." }
				}
			}`),
		},
		{
			Name:        "terraview_history",
			Description: "Query scan history for a Terraform project. Returns past scan records with scores and finding counts.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":   { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"limit": { "type": "integer", "description": "Maximum number of records to return.", "default": 10 },
					"since": { "type": "string", "description": "Only return scans after this date (YYYY-MM-DD)." }
				}
			}`),
		},
		{
			Name:        "terraview_history_trend",
			Description: "Score trends over time for a Terraform project. Shows direction and deltas for security metrics.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":   { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"limit": { "type": "integer", "description": "Maximum number of records to analyze.", "default": 20 }
				}
			}`),
		},
		{
			Name:        "terraview_history_compare",
			Description: "Compare two scan records side by side. Shows score deltas and metric changes.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":    { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"before": { "type": "integer", "description": "Scan ID for the older scan. If omitted with after, compares the 2 most recent scans." },
					"after":  { "type": "integer", "description": "Scan ID for the newer scan. If omitted with before, compares the 2 most recent scans." }
				}
			}`),
		},
		{
			Name:        "terraview_impact",
			Description: "Blast radius and dependency impact analysis. Shows how changes propagate through infrastructure.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to pre-generated plan JSON." }
				}
			}`),
		},
		{
			Name:        "terraview_cache",
			Description: "AI cache status and management. View cache stats or clear cached AI analysis results.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"action": { "type": "string", "enum": ["status", "clear"], "description": "Cache action to perform.", "default": "status" }
				}
			}`),
		},
		{
			Name:        "terraview_scanners",
			Description: "List available security scanners and their installation status.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
		{
			Name:        "terraview_version",
			Description: "Show terraview version and environment information.",
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
		},
	}
}

// LookupTool returns the tool definition for the given name, or nil.
func LookupTool(name string) *ToolDef {
	for _, t := range AllTools() {
		if t.Name == name {
			return &t
		}
	}
	return nil
}
