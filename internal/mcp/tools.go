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
