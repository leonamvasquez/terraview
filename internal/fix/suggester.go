package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
)

const systemPrompt = `You are a Terraform security expert specialized in IaC remediation.
Given a security finding and resource context from a Terraform plan, generate a minimal HCL fix.

Respond ONLY with a JSON object — no markdown, no code fences, no text outside JSON:
{
  "hcl": "<corrected resource block as valid Terraform HCL>",
  "explanation": "<one sentence: what attribute changed and why it fixes the security issue>",
  "prerequisites": ["<full HCL block for any new resource required, e.g. aws_kms_key>"],
  "effort": "<low|medium|high>"
}

## STRICT RULES — violating any rule makes the fix unusable

### References (most important)
- If plan_context.plan_resources lists existing resources of the required type, use the FIRST address as the reference (e.g. aws_kms_key.main.arn)
- If plan_context.canonical_name is provided, use it EXACTLY as the name for the new resource (e.g. resource "aws_kms_key" "ecs" { })
- If plan_context.resolved_references provides a value for an attribute (rest_api_id, resource_id, vpc_id, subnet_ids, etc.), copy that value EXACTLY into the fix
- NEVER invent resource names — only use names from plan_context or derived from canonical_name

### Forbidden patterns — any of these causes terraform apply to fail
- Placeholder strings: "example_*", "YOUR_*", "PLACEHOLDER_*", "your-*", "<attribute_name>", "REPLACE_WITH_*"
- Fake account IDs: "111122223333", "123456789012", "000000000000", "ACCOUNT_ID"
- Fake ARNs: any arn:aws: string with REGION, ACCOUNT_ID, or "your-" in it
- String-quoted Terraform references: DO NOT write "aws_kms_key.main.arn" (quoted) — write aws_kms_key.main.arn (unquoted reference)

### HCL syntax rules
- NEVER use ''' triple-quote heredoc — use jsonencode() for JSON content in container_definitions
- NEVER write block attributes as lists: settings = [{ ... }] is WRONG → use settings { ... } block form
- Resource blocks must have type and name labels: resource "aws_kms_key" "ecs" { ... }
- Do not include terraform{}, provider{}, variable{}, or data{} blocks

### Scope
- Make the MINIMUM change required — do not add unrelated attributes
- effort: "low" = change/add one attribute, "medium" = add a resource reference, "high" = significant restructure`

// Suggester generates HCL fix suggestions using an AI provider.
type Suggester struct {
	provider ai.Provider
}

// NewSuggester creates a Suggester backed by the given AI provider.
func NewSuggester(provider ai.Provider) *Suggester {
	return &Suggester{provider: provider}
}

// Suggest generates a fix suggestion for the given finding and resource configuration.
// On timeout, it retries once with a truncated config to reduce token usage.
func (s *Suggester) Suggest(ctx context.Context, req FixRequest) (*FixSuggestion, error) {
	user := buildUserMessage(req)

	text, err := s.provider.Complete(ctx, systemPrompt, user)
	if err != nil {
		// Retry once with truncated config if the error looks like a timeout
		// or token overflow — smaller payload usually succeeds.
		if isRetryableError(err) && len(req.ResourceConfig) > 0 {
			req.ResourceConfig = TruncateConfig(req.ResourceConfig, req.Finding.RuleID)
			user = buildUserMessage(req)
			text, err = s.provider.Complete(ctx, systemPrompt, user)
		}
		if err != nil {
			return nil, fmt.Errorf("fix suggestion failed: %w", err)
		}
	}

	suggestion, parseErr := parseFixResponse(text, req)
	if parseErr != nil {
		return nil, parseErr
	}

	return suggestion, nil
}

// isRetryableError returns true for errors that are likely caused by payload size
// (timeouts, context-length exceeded).
func isRetryableError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "timed out") ||
		strings.Contains(msg, "context length") ||
		strings.Contains(msg, "too long") ||
		strings.Contains(msg, "max_tokens")
}

// planContext is the structured plan information sent to the AI to eliminate
// invented resource names and placeholder values.
type planContext struct {
	// PlanResources lists all resources of the required type that exist in the plan.
	// e.g. {"aws_kms_key": ["aws_kms_key.main", "aws_kms_key.logs"]}
	PlanResources map[string][]string `json:"plan_resources,omitempty"`

	// ResolvedReferences maps attribute names to their resolved Terraform reference
	// as extracted from the plan's Configuration.Expressions.
	// e.g. {"rest_api_id": "aws_api_gateway_rest_api.main.id"}
	ResolvedReferences map[string]string `json:"resolved_references,omitempty"`

	// CanonicalName is the deterministic name to use when creating a new required
	// resource. Only set when PlanResources shows zero existing resources of that type.
	// e.g. "aws_kms_key.ecs"
	CanonicalName string `json:"canonical_name,omitempty"`

	// RequiredNewResource is the Terraform type that must be created.
	// e.g. "aws_kms_key"
	RequiredNewResource string `json:"required_new_resource,omitempty"`
}

// buildUserMessage serializes the fix request context into a structured JSON
// user message, including plan context when a PlanIndex is available.
func buildUserMessage(req FixRequest) string {
	type payload struct {
		Finding struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			Category string `json:"category"`
		} `json:"finding"`
		ResourceType  string                 `json:"resource_type"`
		ResourceAddr  string                 `json:"resource_addr"`
		CurrentConfig map[string]interface{} `json:"current_config,omitempty"`
		PlanContext   *planContext           `json:"plan_context,omitempty"`
	}

	var p payload
	p.Finding.RuleID = req.Finding.RuleID
	p.Finding.Severity = req.Finding.Severity
	p.Finding.Message = req.Finding.Message
	p.Finding.Category = req.Finding.Category
	p.ResourceType = req.ResourceType
	p.ResourceAddr = req.ResourceAddr

	// Always truncate config to relevant attributes for this rule.
	p.CurrentConfig = TruncateConfig(req.ResourceConfig, req.Finding.RuleID)

	// Build plan context from the index when available.
	if req.PlanIndex != nil {
		ctx := buildPlanContext(req)
		if ctx != nil {
			p.PlanContext = ctx
		}
	}

	data, _ := json.MarshalIndent(p, "", "  ")
	return string(data)
}

// buildPlanContext constructs the planContext section of the user message using
// the PlanIndex attached to the request.
func buildPlanContext(req FixRequest) *planContext {
	idx := req.PlanIndex
	ctx := &planContext{}

	populated := false

	// Resolved attribute references (rest_api_id, resource_id, etc.)
	if resolved := idx.ResolvedRefs(req.ResourceAddr); len(resolved) > 0 {
		ctx.ResolvedReferences = resolved
		populated = true
	}

	// Required resource type for this rule
	requiredType := RequiredResourceType(req.Finding.RuleID)
	if requiredType != "" {
		ctx.RequiredNewResource = requiredType
		existing := idx.ResourcesOfType(requiredType)
		ctx.PlanResources = map[string][]string{
			requiredType: existing,
		}
		// Canonical name: only needed when no existing resource exists
		if len(existing) == 0 {
			ctx.CanonicalName = CanonicalResourceName(req.ResourceAddr, requiredType)
		}
		populated = true
	}

	if !populated {
		return nil
	}
	return ctx
}

// parseFixResponse extracts the FixSuggestion from the AI response text.
func parseFixResponse(text string, req FixRequest) (*FixSuggestion, error) {
	cleaned := extractJSON(text)

	var raw struct {
		HCL           string   `json:"hcl"`
		Explanation   string   `json:"explanation"`
		Prerequisites []string `json:"prerequisites"`
		Effort        string   `json:"effort"`
	}
	if err := json.Unmarshal([]byte(cleaned), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse fix response as JSON: %w (raw: %s)", err, truncate(text, 200))
	}
	if raw.HCL == "" {
		return nil, fmt.Errorf("fix response missing hcl field")
	}

	effort := raw.Effort
	if effort != "low" && effort != "medium" && effort != "high" {
		effort = "medium"
	}

	return &FixSuggestion{
		RuleID:        req.Finding.RuleID,
		Resource:      req.ResourceAddr,
		HCL:           raw.HCL,
		Explanation:   raw.Explanation,
		Prerequisites: raw.Prerequisites,
		Effort:        effort,
	}, nil
}

// extractJSON strips markdown code fences and extracts the first JSON object.
func extractJSON(text string) string {
	text = strings.TrimSpace(text)

	if idx := strings.Index(text, "```json"); idx >= 0 {
		text = text[idx+7:]
		if end := strings.Index(text, "```"); end >= 0 {
			text = text[:end]
		}
	} else if idx := strings.Index(text, "```"); idx >= 0 {
		text = text[idx+3:]
		if end := strings.Index(text, "```"); end >= 0 {
			text = text[:end]
		}
	}

	start := strings.Index(text, "{")
	end := strings.LastIndex(text, "}")
	if start >= 0 && end > start {
		return strings.TrimSpace(text[start : end+1])
	}
	return strings.TrimSpace(text)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
