// Package contextanalysis runs AI-powered contextual analysis directly on
// Terraform resources and topology, independent of scanner findings.
// This is the core differentiator: scanners check individual resources
// against policy rules; context analysis finds cross-resource risks,
// architectural anti-patterns, and dependency-chain vulnerabilities
// that static rule engines cannot detect.
package contextanalysis

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// Result holds the output of a code context analysis run.
type Result struct {
	Findings []rules.Finding `json:"findings"`
	Summary  string          `json:"summary"`
	Model    string          `json:"model"`
	Provider string          `json:"provider"`
}

// Analyzer performs code-level contextual analysis using AI.
type Analyzer struct {
	provider              ai.Provider
	lang                  string
	contextAnalysisPrompt string // loaded from context-analysis.md
}

// NewAnalyzer creates a new context analyzer with the given AI provider.
// If contextPrompt is non-empty, it is used as the system prompt instead of the inline fallback.
func NewAnalyzer(provider ai.Provider, lang string, contextPrompt string) *Analyzer {
	return &Analyzer{
		provider:              provider,
		lang:                  lang,
		contextAnalysisPrompt: contextPrompt,
	}
}

// Analyze runs contextual analysis on the parsed plan resources and topology graph.
// Unlike cluster-level AI (which re-examines scanner findings), this analyzes the
// RESOURCES and their RELATIONSHIPS directly to find issues scanners miss.
func (a *Analyzer) Analyze(ctx context.Context, resources []parser.NormalizedResource, graph *topology.Graph) (*Result, error) {
	if len(resources) == 0 {
		return &Result{Summary: "No resources to analyze."}, nil
	}

	prompt := a.buildPrompt(resources, graph)

	req := ai.Request{
		Resources: resources,
		Summary:   prompt,
		Prompts: ai.Prompts{
			System: a.buildSystemPrompt(),
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
func (a *Analyzer) buildPrompt(resources []parser.NormalizedResource, graph *topology.Graph) map[string]interface{} {
	var sb strings.Builder

	sb.WriteString("## Terraform Infrastructure Context Analysis\n\n")
	sb.WriteString(fmt.Sprintf("Total resources: %d\n\n", len(resources)))

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

	// Topology context
	if graph != nil {
		sb.WriteString("### Topology\n")
		sb.WriteString(graph.FormatContext())
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
		"associate_public_ip_address",
		// Encryption
		"encrypted", "kms_key_id", "kms_key_arn", "server_side_encryption_configuration",
		"at_rest_encryption_enabled", "in_transit_encryption_enabled",
		// IAM
		"iam_role", "role_arn", "policy", "assume_role_policy", "inline_policy",
		"iam_instance_profile", "execution_role_arn", "task_role_arn",
		// Storage
		"storage_encrypted", "backup_retention_period", "deletion_protection",
		"skip_final_snapshot", "lifecycle_rule", "versioning",
		// Compute
		"instance_type", "ami", "availability_zone", "multi_az",
		"desired_count", "min_size", "max_size",
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
