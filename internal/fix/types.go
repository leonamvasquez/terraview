package fix

// FixRequest contains the context needed to generate a Terraform HCL fix suggestion.
type FixRequest struct {
	Finding        FixFinding             `json:"finding"`
	ResourceAddr   string                 `json:"resource_addr"`
	ResourceType   string                 `json:"resource_type"`
	ResourceConfig map[string]interface{} `json:"resource_config,omitempty"`

	// CurrentHCL is the actual HCL source of the resource block as it appears in
	// the .tf file (variables, locals, and references preserved). When set, the AI
	// uses this as the authoritative baseline and makes the minimal change to it
	// instead of reconstructing the block from scratch using plan-JSON values.
	CurrentHCL string `json:"current_hcl,omitempty"`

	// FileContext contains the HCL of up to fileContextMaxLines surrounding lines
	// from the same .tf file. Used to understand naming conventions, existing
	// references, and avoid generating duplicate resources.
	FileContext string `json:"file_context,omitempty"`

	// PlanIndex provides the full resource index of the Terraform plan.
	// When set, the suggester uses it to resolve real resource references
	// and generate canonical names instead of inventing placeholders.
	// Not serialized — used internally to build the AI user message.
	PlanIndex *PlanIndex `json:"-"`

	// Lang sets the response language. "pt-BR" instructs the AI to respond in
	// Brazilian Portuguese. Empty means English (default).
	Lang string `json:"-"`
}

// FixFinding is the security finding that needs remediation.
type FixFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Category string `json:"category"`
}

// FixSuggestion is the AI-generated remediation for a security finding.
type FixSuggestion struct {
	RuleID        string   `json:"rule_id"`
	Resource      string   `json:"resource"`
	HCL           string   `json:"hcl"`
	Explanation   string   `json:"explanation"`
	Prerequisites []string `json:"prerequisites,omitempty"`
	Effort        string   `json:"effort"` // "low" | "medium" | "high"
}
