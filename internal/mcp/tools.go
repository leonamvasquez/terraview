package mcp

import "encoding/json"

// AllTools returns the list of all MCP tools provided by terraview.
func AllTools() []ToolDef {
	return []ToolDef{
		{
			Name: "terraview_scan",
			Description: `Security scan of a Terraform plan. Runs a static security scanner (checkov/tfsec/terrascan) and AI contextual analysis in parallel, then merges, deduplicates, and scores the findings.

Prerequisites: A Terraform plan JSON must exist. Generate it with:
  terraform plan -out=tfplan && terraform show -json tfplan > plan.json

Output: JSON with:
  - score (0–10, higher is safer)
  - verdict: "SAFE" or "NOT SAFE"
  - findings[]: severity, resource, message, category, source
  - meta_analysis.unified_score and meta_analysis.correlations (resources flagged by multiple tools — highest confidence)
  - pipeline_status: which components ran and whether they succeeded

Workflow guidance:
  - Use scanner "checkov" for broad IaC coverage. Leave static: false (default) to also run AI cross-resource analysis.
  - CRITICAL findings → block the change and report to the user.
  - HIGH-only findings → report with recommended fixes; don't block.
  - Check meta_analysis.correlations first — multi-tool agreement = highest confidence findings.
  - If no scanner is installed, call terraview_scanners first to diagnose.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":     { "type": "string", "description": "Terraform workspace directory. Defaults to current directory.", "default": "." },
					"scanner": { "type": "string", "enum": ["checkov", "tfsec", "terrascan"], "description": "Security scanner to use. If omitted, uses the default configured scanner." },
					"plan":    { "type": "string", "description": "Path to a pre-generated plan JSON. If omitted, looks for plan.json or tfplan.json in dir." },
					"static":  { "type": "boolean", "default": false, "description": "Run scanner only. Set true to skip AI contextual analysis (faster, no API calls)." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  true, // AI provider API call
			},
		},
		{
			Name: "terraview_explain",
			Description: `AI-powered natural language explanation of Terraform infrastructure. Describes what each resource does, how resources connect, and the overall architecture pattern.

Prerequisites:
  - An AI provider must be configured in .terraview.yaml (llm.provider + llm.api_key).
  - A Terraform plan JSON must exist.

Output: JSON with:
  - overview: one-paragraph summary of the infrastructure
  - architecture: description of the architectural pattern (e.g., "3-tier VPC with private subnets")
  - components[]: per-resource purpose and role
  - connections[]: how resources relate to each other
  - patterns[]: recognized architecture patterns
  - concerns[]: non-security observations (cost, complexity)

Use this tool when asked to: explain what infrastructure a plan will create, summarize a plan before review, or generate architecture documentation.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to a pre-generated plan JSON." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:  true,
				OpenWorldHint: true, // AI provider API call
			},
		},
		{
			Name: "terraview_diagram",
			Description: `Deterministic ASCII infrastructure diagram from a Terraform plan. No AI or network access required. Groups resources into layered network topology: VPC → subnets → service tiers. AWS only.

Prerequisites: A plan JSON must exist (plan.json or tfplan.json in dir, or pass plan explicitly).

Output: ASCII text diagram showing the infrastructure layout. Can be pasted directly into PR comments, issue descriptions, or documentation.

Use when asked to: visualize what infrastructure will be created, show the network topology, or generate a diagram for documentation. For GCP or Azure resources, this tool currently returns no output (AWS-only).`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to a pre-generated plan JSON." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
				OpenWorldHint:  false, // fully deterministic, no external calls
			},
		},
		{
			Name: "terraview_drift",
			Description: `Detect and classify infrastructure drift — differences between Terraform state and actual cloud resources. Classifies each change by risk level.

Prerequisites: Valid Terraform workspace with initialized state (terraform init must have been run). If passing plan, it must be a pre-generated plan JSON (not a binary planfile).

Output: JSON with drift items, each with:
  - resource: the drifted resource address
  - risk: CRITICAL / HIGH / MEDIUM / LOW
  - change_type: created / updated / deleted outside Terraform
  - detail: what changed

With intelligence: true, also classifies each drift item as "intentional" (matches recent apply patterns) or "suspicious" (unexpected).

Use when asked to: check if infrastructure was modified outside Terraform, detect configuration drift before a release, or audit unplanned changes.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":          { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan":         { "type": "string", "description": "Path to a pre-generated plan JSON." },
					"intelligence": { "type": "boolean", "default": false, "description": "Enable advanced drift classification: intentional vs suspicious changes, risk scoring." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:  true,
				OpenWorldHint: true, // runs terraform plan which contacts cloud provider
			},
		},
		{
			Name: "terraview_history",
			Description: `Query the local SQLite scan history for a Terraform project. Every terraview_scan call stores results automatically — no extra configuration needed.

Output: Array of past scans ordered by most recent, each with:
  - id: scan record ID (use with terraview_history_compare)
  - timestamp: when the scan ran
  - score: security score at the time (0–10)
  - findings_by_severity: counts of CRITICAL/HIGH/MEDIUM/LOW findings
  - plan_file: which plan was scanned

Use to: show security posture over time, find when a score degraded, list recent scans, or get scan IDs for comparison.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":   { "type": "string", "description": "Terraform workspace directory (used to scope history to this project).", "default": "." },
					"limit": { "type": "integer", "description": "Maximum number of records to return.", "default": 10 },
					"since": { "type": "string", "description": "Only return scans after this date. Format: YYYY-MM-DD or relative (7d, 30d)." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name: "terraview_history_trend",
			Description: `Score trend analysis for a Terraform project's scan history. Shows whether the security posture is improving, degrading, or stable over time.

Output: JSON with:
  - direction: "improving" | "degrading" | "stable"
  - score_delta: change from oldest to newest in the window
  - data_points[]: (timestamp, score) pairs for sparkline rendering
  - finding_trend: changes in critical/high/medium finding counts

Use to: answer "is this project getting more or less secure over time?", detect regressions across multiple scans, or summarize security posture trends for a report.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":   { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"limit": { "type": "integer", "description": "Number of most recent scans to include in trend analysis.", "default": 20 }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name: "terraview_history_compare",
			Description: `Compare two specific scan records side by side. Shows score deltas and what findings appeared or were resolved between scans.

Output: JSON diff with:
  - score_before / score_after: security scores for each scan
  - score_delta: positive = improved, negative = degraded
  - new_findings[]: findings present in "after" but not in "before"
  - resolved_findings[]: findings present in "before" but not in "after"
  - finding_count_delta: changes per severity

If before/after are omitted, compares the two most recent scans automatically.

Use to: measure security impact of a specific Terraform change, show what improved or regressed between two points, or validate that a fix actually resolved a finding.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":    { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"before": { "type": "integer", "description": "Scan ID for the older scan. Get IDs from terraview_history." },
					"after":  { "type": "integer", "description": "Scan ID for the newer scan. If both omitted, compares the 2 most recent scans." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name: "terraview_impact",
			Description: `Blast radius and dependency impact analysis. Shows how changed resources propagate through the infrastructure dependency graph.

Prerequisites: A plan JSON must exist.

Output: Impact report with:
  - changed_resources[]: resources being modified in this plan
  - impact_graph: for each changed resource, its downstream dependents and impact depth
  - blast_radius_score: 0–10, higher = more resources affected
  - high_impact_resources[]: resources whose change affects the most dependents

Use when asked: how many resources are affected by changing X, what is the risk of modifying a shared VPC/subnet/security group, or which resources depend on a specific module output.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"dir":  { "type": "string", "description": "Terraform workspace directory.", "default": "." },
					"plan": { "type": "string", "description": "Path to a pre-generated plan JSON." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name: "terraview_cache",
			Description: `Manage the AI response cache. The cache stores AI analysis results keyed by plan SHA-256 hash to avoid redundant API calls on repeated scans of the same plan.

Actions:
  - status (default): Show cache directory, entry count, total size, and oldest/newest entry timestamps.
  - clear: Delete all cached entries. Use when switching AI providers, changing the AI model, or when cached results may be stale after major infrastructure updates.

Important: "clear" is irreversible. Deleted entries will be regenerated (with API cost) on the next scan.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {
					"action": { "type": "string", "enum": ["status", "clear"], "description": "Action to perform: 'status' to view stats, 'clear' to delete all cached entries.", "default": "status" }
				}
			}`),
			Annotations: &ToolAnnotations{
				// Not read-only: "clear" action is destructive
				DestructiveHint: true,
				OpenWorldHint:   false,
			},
		},
		{
			Name: "terraview_scanners",
			Description: `List available security scanners and their installation status. Shows which scanners (checkov, tfsec, terrascan) are installed, their versions, where they are installed, and install hints for missing ones.

Output: List of scanners with status (installed/missing), version, install location, and platform-specific install commands.

Use to: check prerequisites before calling terraview_scan with a specific scanner, diagnose "scanner not found" errors, or determine which scanner to recommend for a given environment.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
		},
		{
			Name: "terraview_fix_suggest",
			Description: `Generate a concrete Terraform HCL fix for a specific security finding from a terraview_scan result. Uses the configured AI provider to produce a minimal, targeted remediation.

Prerequisites:
  - An AI provider must be configured in .terraview.yaml (llm.provider).
  - rule_id, resource, and message are required (copy them directly from a terraview_scan finding).
  - Optionally pass dir/plan so the tool can look up the resource's current configuration and produce a more precise fix.

Output: JSON with:
  - hcl: the corrected Terraform resource block (complete, valid HCL)
  - explanation: one sentence describing what changed and why it fixes the issue
  - prerequisites: additional resources or IAM permissions required (if any)
  - effort: "low" | "medium" | "high"

Workflow:
  1. Call terraview_scan to get findings
  2. For each CRITICAL or HIGH finding, call terraview_fix_suggest with the finding fields
  3. Present the hcl fix to the user with the explanation
  4. If prerequisites is non-empty, inform the user what else needs to be created or configured`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"required": ["rule_id", "resource", "message"],
				"properties": {
					"dir":      { "type": "string", "description": "Terraform workspace directory. Used to load config and look up the resource in the plan.", "default": "." },
					"plan":     { "type": "string", "description": "Path to pre-generated plan JSON. If provided, the tool reads the resource's current configuration to produce a more precise fix." },
					"rule_id":  { "type": "string", "description": "Rule ID from the finding (e.g. CKV_AWS_158, AI-CLA-SEC). Copy exactly from terraview_scan output." },
					"resource": { "type": "string", "description": "Terraform resource address (e.g. aws_cloudwatch_log_group.ecs). Copy exactly from terraview_scan output." },
					"message":  { "type": "string", "description": "Finding message from terraview_scan. Provides context for the AI to understand what needs fixing." },
					"severity": { "type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], "description": "Finding severity from terraview_scan." },
					"category": { "type": "string", "description": "Finding category from terraview_scan (e.g. security, compliance, reliability)." }
				}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:  true,
				OpenWorldHint: true, // AI provider API call
			},
		},
		{
			Name: "terraview_version",
			Description: `Show terraview version, Go runtime version, and environment information (OS, architecture, build date).

Use to: confirm the installed version when troubleshooting, verify the environment meets requirements, or include version info in bug reports.`,
			InputSchema: json.RawMessage(`{
				"type": "object",
				"properties": {}
			}`),
			Annotations: &ToolAnnotations{
				ReadOnlyHint:   true,
				IdempotentHint: true,
			},
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
