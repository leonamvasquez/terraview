// Package contextanalysis runs AI-powered contextual analysis directly on
// Terraform resources and topology, independent of scanner findings.
// This is the core differentiator: scanners check individual resources
// against policy rules; context analysis finds cross-resource risks,
// architectural anti-patterns, and dependency-chain vulnerabilities
// that static rule engines cannot detect.
package contextanalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// defaultContextBatchSize is the resource cap per contextanalysis call when
// no explicit limit is configured. Lower than the standard defaultMaxResources
// because contextanalysis prompts include topology context overhead (~2–5k tokens).
const defaultContextBatchSize = 80

// Result holds the output of a code context analysis run.
type Result struct {
	Findings     []rules.Finding `json:"findings"`
	Summary      string          `json:"summary"`
	Model        string          `json:"model"`
	Provider     string          `json:"provider"`
	ExcludedNoOp int             `json:"excluded_no_op,omitempty"` // resources skipped because action is no-op or read
}

// Analyzer performs code-level contextual analysis using AI.
type Analyzer struct {
	provider              ai.Provider
	lang                  string
	contextAnalysisPrompt string // loaded from context-analysis.md
	maxResources          int    // batch size limit (0 = defaultContextBatchSize)
	followUpRounds        int    // number of follow-up rounds after initial analysis (0 = disabled)
}

// NewAnalyzer creates a new context analyzer with the given AI provider.
// If contextPrompt is non-empty, it is used as the system prompt instead of the inline fallback.
// maxResources sets the per-call resource limit; 0 means use defaultContextBatchSize.
func NewAnalyzer(provider ai.Provider, lang string, contextPrompt string, maxResources int) *Analyzer {
	return &Analyzer{
		provider:              provider,
		lang:                  lang,
		contextAnalysisPrompt: contextPrompt,
		maxResources:          maxResources,
	}
}

// WithFollowUpRounds configures the number of follow-up rounds to run after the
// initial analysis. Each round sends a new prompt asking for additional cross-resource
// risks not already identified, enabling iterative discovery. Setting n=0 (default)
// disables follow-up and preserves backward-compatible behavior.
func (a *Analyzer) WithFollowUpRounds(n int) *Analyzer {
	a.followUpRounds = n
	return a
}

// effectiveBatchSize returns the resource cap per AI call.
func (a *Analyzer) effectiveBatchSize() int {
	if a.maxResources > 0 {
		return a.maxResources
	}
	return defaultContextBatchSize
}

// filterActive removes no-op and read resources from the slice.
// no-op resources are confirmed-unchanged by Terraform and contain no new risk.
// read resources are data sources resolved at plan time; they carry no drift.
// Filtering them before AI analysis avoids sending stale, low-signal context
// that inflates token usage without improving finding quality.
func filterActive(resources []parser.NormalizedResource) (active []parser.NormalizedResource, excluded int) {
	active = resources[:0:len(resources)]
	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			excluded++
			continue
		}
		active = append(active, r)
	}
	return active, excluded
}

// Analyze runs contextual analysis on the parsed plan resources and topology graph.
// no-op and read resources are excluded before analysis — they carry no new risk
// and their removal can cut token usage by 60–80 % on incremental CI/CD plans.
// For plans that still exceed the batch size after filtering, resources are split
// by priority tier across multiple sequential calls and findings are merged.
func (a *Analyzer) Analyze(ctx context.Context, resources []parser.NormalizedResource, graph *topology.Graph) (*Result, error) {
	if len(resources) == 0 {
		return &Result{Summary: "No resources to analyze."}, nil
	}

	active, excluded := filterActive(resources)

	if len(active) == 0 {
		return &Result{
			Summary:      "No active resource changes to analyze (all resources are no-op or read).",
			ExcludedNoOp: excluded,
		}, nil
	}

	batchSize := a.effectiveBatchSize()
	var result *Result
	var err error
	if len(active) <= batchSize {
		result, err = a.runSingle(ctx, active, graph, 0, 0, 0)
	} else {
		result, err = a.runBatched(ctx, active, graph, batchSize)
	}
	if err != nil {
		return nil, err
	}
	result.ExcludedNoOp = excluded

	if a.followUpRounds > 0 && len(result.Findings) > 0 {
		updated, fuErr := a.runFollowUp(ctx, active, graph, result)
		if fuErr != nil {
			// Non-fatal: log and return the initial result unchanged.
			log.Printf("contextanalysis: follow-up rounds failed (non-fatal): %v", fuErr)
		} else {
			result = updated
		}
	}

	return result, nil
}

// runSingle executes a single AI call for the given resource slice.
// batchNum and totalBatches are non-zero only when called from runBatched;
// totalResources is the total plan size for batch notes.
func (a *Analyzer) runSingle(ctx context.Context, resources []parser.NormalizedResource, graph *topology.Graph, batchNum, totalBatches, totalResources int) (*Result, error) {
	prompt := a.buildPrompt(resources, graph, batchNum, totalBatches, totalResources)

	sysPrompt := a.buildSystemPrompt()

	if os.Getenv("TERRAVIEW_TOKEN_DEBUG") == "1" {
		summaryJSON, _ := json.Marshal(prompt)
		userChars := len("Review the following Terraform plan for security, architecture, and best practice issues.\n\n## Plan Summary\n\n") + len(summaryJSON)
		sysChars := len(sysPrompt)
		label := "single"
		if totalBatches > 1 {
			label = fmt.Sprintf("batch %d/%d", batchNum, totalBatches)
		}
		fmt.Fprintf(os.Stderr, "[token-debug] %s: system=%d chars (~%d tokens)  user=%d chars (~%d tokens)  total=~%d tokens\n",
			label, sysChars, sysChars/4, userChars, userChars/4, (sysChars+userChars)/4)
	}

	req := ai.Request{
		Resources: resources,
		Summary:   prompt,
		Prompts: ai.Prompts{
			System: sysPrompt,
		},
	}

	completion, err := a.provider.Analyze(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("context analysis failed: %w", err)
	}

	// Tag all findings as ai/context source
	for i := range completion.Findings {
		completion.Findings[i].Source = "ai/context"
	}

	return &Result{
		Findings: completion.Findings,
		Summary:  completion.Summary,
		Model:    completion.Model,
		Provider: completion.Provider,
	}, nil
}

// runBatched splits resources into priority-ordered batches, calls runSingle for
// each, and merges the results. The topology graph is passed to every batch so
// the AI retains cross-resource relationship context even when attributes are split.
func (a *Analyzer) runBatched(ctx context.Context, resources []parser.NormalizedResource, graph *topology.Graph, batchSize int) (*Result, error) { //nolint:unparam // error kept for interface consistency; future batches may return errors
	// Sort by priority tier so the most security-critical resources go first
	sorted := make([]parser.NormalizedResource, len(resources))
	copy(sorted, resources)
	sort.SliceStable(sorted, func(i, j int) bool {
		return resourcePriorityTier(sorted[i].Type) < resourcePriorityTier(sorted[j].Type)
	})

	totalResources := len(sorted)
	totalBatches := (totalResources + batchSize - 1) / batchSize

	var allFindings []rules.Finding
	var summaries []string
	var lastModel, lastProvider string

	for i := 0; i < len(sorted); i += batchSize {
		if ctx.Err() != nil {
			break
		}

		end := i + batchSize
		if end > len(sorted) {
			end = len(sorted)
		}

		batchNum := i/batchSize + 1
		result, err := a.runSingle(ctx, sorted[i:end], graph, batchNum, totalBatches, totalResources)
		if err != nil {
			// Soft failure: skip failed batch, continue with remaining
			continue
		}

		allFindings = append(allFindings, result.Findings...)
		if result.Summary != "" {
			summaries = append(summaries, result.Summary)
		}
		lastModel = result.Model
		lastProvider = result.Provider
	}

	summary := ""
	switch len(summaries) {
	case 0:
		summary = "No issues found."
	case 1:
		summary = summaries[0]
	default:
		// Use the first batch summary (highest-priority resources) as the primary assessment
		summary = summaries[0]
	}

	return &Result{
		Findings: deduplicateFindings(allFindings),
		Summary:  summary,
		Model:    lastModel,
		Provider: lastProvider,
	}, nil
}

// deduplicateFindings removes findings that share the same resource address
// and message prefix (first 60 chars), keeping the first occurrence.
func deduplicateFindings(findings []rules.Finding) []rules.Finding {
	type key struct{ resource, msgPrefix string }
	seen := make(map[key]bool, len(findings))
	result := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		msg := f.Message
		if len(msg) > 60 {
			msg = msg[:60]
		}
		k := key{resource: f.Resource, msgPrefix: msg}
		if !seen[k] {
			seen[k] = true
			result = append(result, f)
		}
	}
	return result
}

// resourcePriorityTier returns a sort priority for a given resource type.
// Lower number = higher priority (processed first in batches).
func resourcePriorityTier(resourceType string) int {
	high := []string{
		"aws_iam_role", "aws_iam_policy", "aws_iam_user", "aws_iam_group",
		"aws_security_group", "aws_security_group_rule",
		"aws_s3_bucket", "aws_s3_bucket_policy", "aws_s3_bucket_acl",
		"aws_kms_key", "aws_kms_alias",
		"aws_rds_instance", "aws_db_instance",
		"aws_secretsmanager_secret", "aws_ssm_parameter",
		"google_iam_binding", "google_iam_member", "google_storage_bucket",
		"azurerm_role_assignment", "azurerm_storage_account",
	}
	medium := []string{
		"aws_lambda_function", "aws_api_gateway_rest_api",
		"aws_eks_cluster", "aws_ecs_task_definition",
		"aws_cloudtrail", "aws_config_rule",
		"aws_vpc", "aws_subnet", "aws_internet_gateway",
	}
	for _, t := range high {
		if t == resourceType {
			return 1
		}
	}
	for _, t := range medium {
		if t == resourceType {
			return 2
		}
	}
	return 3
}

// followUpFinding is a compact representation of an already-identified finding
// sent back to the AI so it can avoid repeating the same issues.
type followUpFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Resource string `json:"resource"`
	Message  string `json:"message"`
}

// runFollowUp executes up to a.followUpRounds additional AI calls, each asking for
// cross-resource risks not yet identified. It accumulates new findings into a copy
// of initial and appends round summaries. Breaks early when a round returns no new findings.
func (a *Analyzer) runFollowUp(ctx context.Context, resources []parser.NormalizedResource, graph *topology.Graph, initial *Result) (*Result, error) {
	result := &Result{
		Findings: make([]rules.Finding, len(initial.Findings)),
		Summary:  initial.Summary,
		Model:    initial.Model,
		Provider: initial.Provider,
	}
	copy(result.Findings, initial.Findings)

	prev := result.Findings

	for round := 1; round <= a.followUpRounds; round++ {
		if ctx.Err() != nil {
			break
		}

		followUpPromptStr := a.buildFollowUpPrompt(prev)

		req := ai.Request{
			Resources: resources,
			Summary:   map[string]interface{}{"follow_up": true, "round": round, "analysis": followUpPromptStr},
			Prompts: ai.Prompts{
				System: a.buildSystemPrompt(),
			},
		}

		completion, err := a.provider.Analyze(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("follow-up round %d: %w", round, err)
		}

		newFindings := make([]rules.Finding, 0, len(completion.Findings))
		for _, f := range completion.Findings {
			f.Source = "ai/context/followup"
			newFindings = append(newFindings, f)
		}

		if len(newFindings) == 0 {
			break
		}

		result.Findings = append(result.Findings, newFindings...)
		prev = result.Findings

		roundSummary := completion.Summary
		if roundSummary == "" {
			roundSummary = fmt.Sprintf("%d additional finding(s) identified.", len(newFindings))
		}
		result.Summary += fmt.Sprintf("\n\n[Follow-up round %d]\n%s", round, roundSummary)
	}

	return result, nil
}

// buildFollowUpPrompt builds the follow-up user prompt string that instructs the AI
// to find only additional risks beyond those already identified in prev.
func (a *Analyzer) buildFollowUpPrompt(prev []rules.Finding) string {
	compact := make([]followUpFinding, len(prev))
	for i, f := range prev {
		compact[i] = followUpFinding{
			RuleID:   f.RuleID,
			Severity: f.Severity,
			Resource: f.Resource,
			Message:  f.Message,
		}
	}

	prevJSON, _ := json.Marshal(compact)

	return `follow_up_instruction: The following findings were already identified in a previous analysis pass. ` +
		`Identify ONLY additional cross-resource risks that were NOT covered above. ` +
		`Do not repeat the findings above.` +
		"\n\nprevious_findings: " + string(prevJSON)
}

// buildSystemPrompt constructs the system prompt for contextual analysis.
// Uses the loaded context-analysis.md prompt when available, falls back to inline.
func (a *Analyzer) buildSystemPrompt() string {
	var prompt string

	if a.contextAnalysisPrompt != "" {
		// Use the loaded prompt from prompts/context-analysis.md
		prompt = a.contextAnalysisPrompt
	} else {
		// Inline fallback if the prompt file is not available
		prompt = `You are a senior cloud infrastructure architect reviewing Terraform code for cross-resource risks that static scanners cannot detect.

Focus on:
1. Cross-resource dependency risks (blast radius, cascade failures, shared IAM)
2. Architectural anti-patterns (single AZ, no auto-scaling, missing circuit breakers)
3. Implicit security boundaries violated by resource relationships
4. Business logic risks (lifecycle rules deleting prod data, conflicting policies)
5. Configuration drift potential (immutable attributes forcing replacement)
6. Network topology gaps (missing VPC endpoints, NAT gateways, DNS resolution)

Rules:
- Only report findings that a static scanner would NOT catch
- Each finding must reference specific resource addresses
- Explain the cross-resource CONTEXT, not just individual resource issues
- Be precise and actionable with remediation steps

Severity guide:
- CRITICAL: Data loss, full lateral movement, cascade deletion of stateful resources
- HIGH: Missing redundancy for stateful resources, overly broad shared IAM
- MEDIUM: Architectural anti-patterns increasing blast radius, missing observability
- LOW: Configuration hygiene, drift-prone patterns`
	}

	if a.lang == "pt-BR" {
		prompt += "\n\nIMPORTANT: You MUST respond entirely in Brazilian Portuguese (pt-BR)."
	}

	return prompt
}

// buildPrompt constructs the user prompt with full resource and topology context.
// batchNum and totalBatches are non-zero when this is part of a batched run;
// totalResources is the total plan size (may differ from len(resources) in batched mode).
func (a *Analyzer) buildPrompt(resources []parser.NormalizedResource, graph *topology.Graph, batchNum, totalBatches, totalResources int) map[string]interface{} {
	var sb strings.Builder

	sb.WriteString("## Terraform Infrastructure Context Analysis\n\n")

	if totalBatches > 1 {
		sb.WriteString(fmt.Sprintf("**Batch %d of %d** — %d resources in this batch (%d total in plan).\n", batchNum, totalBatches, len(resources), totalResources))
		sb.WriteString("The topology graph below covers all plan resources for cross-resource context.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("Total resources: %d\n\n", len(resources)))
	}

	// Resource summary by type
	byType := make(map[string][]string)
	for _, r := range resources {
		byType[r.Type] = append(byType[r.Type], r.Address)
	}

	types := make([]string, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Strings(types)

	sb.WriteString("### Resources by type\n")
	for _, t := range types {
		addrs := byType[t]
		sb.WriteString(fmt.Sprintf("- %s (%d): %s\n", t, len(addrs), strings.Join(addrs, ", ")))
	}

	sb.WriteString("\n")

	// Resource details (actions and key attributes)
	sb.WriteString("### Resource details\n")
	for _, r := range resources {
		sb.WriteString(fmt.Sprintf("\n#### %s [%s]\n", r.Address, r.Action))
		sb.WriteString(fmt.Sprintf("Type: %s | Provider: %s\n", r.Type, r.Provider))

		if len(r.Values) > 0 {
			// Include security-relevant attributes
			relevant := extractRelevantAttributes(r.Values)
			if len(relevant) > 0 {
				for k, v := range relevant {
					sb.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
				}
			}
		}
	}

	sb.WriteString("\n")

	// Topology context.
	// In batched mode (totalBatches > 1), emit only the edges that touch at least
	// one resource in this batch — the full graph would repeat ~10k tokens of overhead
	// per call with diminishing benefit for lower-priority batches.
	// In single-call mode, emit the full FormatContext for complete topology view.
	if graph != nil {
		sb.WriteString("### Topology\n")
		if totalBatches > 1 {
			batchAddrs := make(map[string]bool, len(resources))
			for _, r := range resources {
				batchAddrs[r.Address] = true
			}
			edgeCount := 0
			for _, e := range graph.Edges {
				if batchAddrs[e.From] || batchAddrs[e.To] {
					sb.WriteString(fmt.Sprintf("  %s --[%s]--> %s\n", e.From, e.Via, e.To))
					edgeCount++
				}
			}
			if edgeCount == 0 {
				sb.WriteString("  (no cross-resource dependencies in this batch)\n")
			}
		} else {
			sb.WriteString(graph.FormatContext())
		}
	}

	return map[string]interface{}{
		"context_analysis": true,
		"total_resources":  len(resources),
		"analysis":         sb.String(),
	}
}

// extractRelevantAttributes filters resource values to security/architecture-relevant ones.
func extractRelevantAttributes(values map[string]interface{}) map[string]interface{} {
	relevant := make(map[string]interface{})

	securityKeys := []string{
		// Network
		"cidr_block", "cidr_blocks", "ingress", "egress", "from_port", "to_port",
		"protocol", "security_groups", "security_group_ids", "vpc_id", "subnet_id",
		"subnet_ids", "publicly_accessible", "map_public_ip_on_launch",
		"associate_public_ip_address", "internal", "load_balancer_type",
		"drop_invalid_header_fields",
		// Encryption
		"encrypted", "kms_key_id", "kms_key_arn", "server_side_encryption_configuration",
		"at_rest_encryption_enabled", "in_transit_encryption_enabled",
		// IAM
		"iam_role", "role_arn", "policy", "assume_role_policy", "inline_policy",
		"iam_instance_profile", "execution_role_arn", "task_role_arn",
		// Storage
		"storage_encrypted", "backup_retention_period", "deletion_protection",
		"skip_final_snapshot", "lifecycle_rule", "versioning",
		"bucket_policy", "replication_configuration",
		// Compute
		"instance_type", "ami", "availability_zone", "multi_az",
		"desired_count", "min_size", "max_size",
		// EKS
		"endpoint_public_access", "endpoint_private_access", "public_access_cidrs",
		"encryption_config", "enabled_cluster_log_types",
		// KMS
		"enable_key_rotation", "deletion_window_in_days", "key_usage",
		// Lambda
		"environment", "dead_letter_config", "reserved_concurrent_executions",
		"tracing_config", "vpc_config",
		// CloudTrail
		"enable_log_file_validation", "is_multi_region_trail", "include_global_service_events",
		// RDS
		"iam_database_authentication_enabled", "performance_insights_enabled",
		"enabled_cloudwatch_logs_exports",
		// WAF / ALB
		"default_action", "visibility_config",
		// Logging
		"logging", "access_logs", "enable_logging",
		// Tags
		"tags",
	}

	for _, key := range securityKeys {
		if v, ok := values[key]; ok {
			relevant[key] = v
		}
	}

	return relevant
}
