package rules

import "github.com/leonamvasquez/terraview/internal/parser"

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

// Finding represents a single issue detected by a rule or LLM analysis.
type Finding struct {
	RuleID      string `json:"rule_id" yaml:"rule_id"`
	Severity    string `json:"severity" yaml:"severity"`
	Category    string `json:"category" yaml:"category"`
	Resource    string `json:"resource" yaml:"resource"`
	Message     string `json:"message" yaml:"message"`
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty"`
	Source      string `json:"source" yaml:"source"` // "hard-rule" or "llm"
}

// RuleDefinition represents a single rule loaded from YAML.
type RuleDefinition struct {
	ID                string             `yaml:"id"`
	Name              string             `yaml:"name"`
	Description       string             `yaml:"description"`
	Severity          string             `yaml:"severity"`
	Category          string             `yaml:"category"`
	Remediation       string             `yaml:"remediation"`
	Enabled           bool               `yaml:"enabled"`
	Targets           []string           `yaml:"targets"` // resource types this rule applies to
	Conditions        []Condition        `yaml:"conditions"`
	CompanionExcludes []CompanionExclude `yaml:"companion_excludes,omitempty"`
}

// CompanionExclude defines a companion resource type that, when present in the plan,
// suppresses a finding for the target resource (e.g., aws_s3_bucket_versioning for BP001).
type CompanionExclude struct {
	ResourceType string `yaml:"resource_type"`
	NameField    string `yaml:"name_field"` // field in companion that references the bucket (e.g., "bucket")
}

// Condition defines a single check within a rule.
type Condition struct {
	Field    string      `yaml:"field"`
	Operator string      `yaml:"operator"` // equals, not_equals, contains, not_contains, exists, not_exists, matches, in_list
	Value    interface{} `yaml:"value,omitempty"`
}

// RulesConfig is the top-level YAML structure for rules files.
type RulesConfig struct {
	Version               string           `yaml:"version"`
	RequiredTags          []string         `yaml:"required_tags,omitempty"`
	TaggableResourceTypes []string         `yaml:"taggable_resource_types,omitempty"`
	CriticalResourceTypes []string         `yaml:"critical_resource_types,omitempty"`
	Rules                 []RuleDefinition `yaml:"rules"`
}

// Rule is the interface that all rule evaluators must implement.
type Rule interface {
	ID() string
	Evaluate(resource parser.NormalizedResource, allResources []parser.NormalizedResource) []Finding
}
