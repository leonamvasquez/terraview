package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/ai"
)

const systemPrompt = `You are a Terraform security expert specialized in IaC remediation.
You will receive a security finding and the ACTUAL HCL SOURCE CODE of the affected resource as it exists in the .tf file.

Your task: produce the MINIMUM change to the source HCL that fixes the finding.

Respond ONLY with a JSON object — no markdown, no code fences, no text outside JSON:
{
  "hcl": "<the complete corrected resource block — must be valid Terraform HCL>",
  "explanation": "<one sentence: what changed and why it fixes the issue>",
  "prerequisites": ["<full HCL block for any NEW resource that must be created — omit if nothing new is needed>"],
  "effort": "<low|medium|high>"
}

## GOLDEN RULE: preserve the source, patch the minimum

When current_hcl is provided:
- Start from that exact source code — do NOT rewrite or restructure it
- Preserve every existing attribute, reference, variable (var.X), local (local.Y), expression, and comment
- Only add or change the single attribute or block needed to fix the finding
- Keep the same indentation style and spacing as the original

## References — never invent, always reuse

- If file_context lists a resource of the required type (e.g. aws_kms_key), reference it: aws_kms_key.NAME.arn
- If plan_context.plan_resources lists an existing resource, use its address as the reference
- If plan_context.resolved_references gives a value for an attribute, copy it EXACTLY
- If plan_context.canonical_name is set, use it as the name for the new resource
- NEVER invent resource names, account IDs, ARNs, or placeholder values

## Forbidden patterns — any of these causes terraform apply to fail

- Placeholder strings: "example_*", "YOUR_*", "PLACEHOLDER_*", "your-*", "<attr>", "REPLACE_WITH_*"
- Fake account IDs: "111122223333", "123456789012", "000000000000", "ACCOUNT_ID"
- Fake ARNs: arn:aws: with REGION, ACCOUNT_ID, or "your-" anywhere in it
- String-quoted Terraform references: WRONG: kms_key_id = "aws_kms_key.main.arn" / RIGHT: kms_key_id = aws_kms_key.main.arn

## Schema whitelist — never invent attributes

If the user message contains "valid_attributes" for the resource type, every
top-level argument or nested block name in the generated HCL MUST appear in
that list. Common hallucinations to avoid:
- "web_acl_arn" on aws_lb (WAF needs a separate aws_wafv2_web_acl_association resource)
- "encryption" on aws_s3_bucket (use aws_s3_bucket_server_side_encryption_configuration)
- "logging" on aws_s3_bucket (use aws_s3_bucket_logging)
- "versioning" on aws_s3_bucket (use aws_s3_bucket_versioning)
- "acl" on aws_s3_bucket (use aws_s3_bucket_acl)
If a remediation requires a feature not in valid_attributes, emit a separate
prerequisite resource block instead of inventing an argument.

## HCL syntax rules

- Use jsonencode({}) for JSON — never heredoc with raw JSON (heredoc braces break block detection)
- Never write blocks as lists: logging_config = [{ ... }] is WRONG → logging_config { ... }
- Resource blocks must have both type and name: resource "aws_kms_key" "my_key" { ... }
- Do not emit terraform{}, provider{}, variable{}, output{}, or data{} blocks in "hcl"
- Prerequisites must be complete, standalone resource blocks that terraform validate will accept

## Prerequisites rules

- Only emit a prerequisite when the resource truly does not exist anywhere in the project
- file_context shows all other resources in the same file — check it before creating a new resource
- If an existing resource of the needed type is listed, reference it instead of creating a new one

## Effort guide

- low: add/change one attribute (e.g. enable_key_rotation = true)
- medium: add a reference to another resource (e.g. kms_key_id = aws_kms_key.main.arn)
- high: add a nested block or restructure (e.g. server_side_encryption_configuration { ... })`

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

	sys := systemPrompt
	if req.Lang == "pt-BR" {
		sys += "\n\nIMPORTANT: Respond entirely in Brazilian Portuguese (pt-BR). The \"explanation\" field must be in Portuguese."
	}

	text, err := s.provider.Complete(ctx, sys, user)
	if err != nil {
		// Retry once with truncated config if the error looks like a timeout
		// or token overflow — smaller payload usually succeeds.
		if isRetryableError(err) && len(req.ResourceConfig) > 0 {
			req.ResourceConfig = TruncateConfig(req.ResourceConfig, req.Finding.RuleID)
			user = buildUserMessage(req)
			text, err = s.provider.Complete(ctx, sys, user)
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
// user message. When CurrentHCL is set it becomes the primary context; the
// plan-JSON config is included as secondary fallback only.
func buildUserMessage(req FixRequest) string {
	type payload struct {
		Finding struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
			Message  string `json:"message"`
			Category string `json:"category"`
		} `json:"finding"`
		ResourceType    string                 `json:"resource_type"`
		ResourceAddr    string                 `json:"resource_addr"`
		CurrentHCL      string                 `json:"current_hcl,omitempty"`
		FileContext     string                 `json:"file_context,omitempty"`
		CurrentConfig   map[string]interface{} `json:"current_config,omitempty"`
		PlanContext     *planContext           `json:"plan_context,omitempty"`
		ValidAttributes []string               `json:"valid_attributes,omitempty"`
	}

	var p payload
	p.Finding.RuleID = req.Finding.RuleID
	p.Finding.Severity = req.Finding.Severity
	p.Finding.Message = req.Finding.Message
	p.Finding.Category = req.Finding.Category
	p.ResourceType = req.ResourceType
	p.ResourceAddr = req.ResourceAddr

	// Primary: actual HCL source (variables and references preserved).
	p.CurrentHCL = req.CurrentHCL
	p.FileContext = req.FileContext

	// Secondary: truncated plan-JSON config (resolved values, useful when HCL not available).
	if req.CurrentHCL == "" {
		p.CurrentConfig = TruncateConfig(req.ResourceConfig, req.Finding.RuleID)
	}

	// Curated whitelist of top-level attributes for the target resource type
	// (only set for types in our schema map). The AI must not emit arguments
	// outside this list — a post-flight check rejects fixes that violate it.
	if attrs := KnownAttributes(req.ResourceType); len(attrs) > 0 {
		p.ValidAttributes = attrs
	}

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
