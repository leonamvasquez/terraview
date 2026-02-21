package rules

// Severity levels for findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Category classifies the domain of a finding.
const (
	CategorySecurity        = "security"
	CategoryCompliance      = "compliance"
	CategoryBestPractice    = "best-practice"
	CategoryMaintainability = "maintainability"
	CategoryReliability     = "reliability"
)

// Finding represents a single issue detected by a scanner or LLM analysis.
type Finding struct {
	RuleID      string `json:"rule_id" yaml:"rule_id"`
	Severity    string `json:"severity" yaml:"severity"`
	Category    string `json:"category" yaml:"category"`
	Resource    string `json:"resource" yaml:"resource"`
	Message     string `json:"message" yaml:"message"`
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Source      string `json:"source" yaml:"source"` // "hard-rule" or "llm"
}
