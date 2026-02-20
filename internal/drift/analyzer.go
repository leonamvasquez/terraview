package drift

import (
	"fmt"
	"strings"

	"github.com/leonam/terraview/internal/parser"
	"github.com/leonam/terraview/internal/rules"
)

// DriftResult holds the analysis of infrastructure drift.
type DriftResult struct {
	TotalChanges    int             `json:"total_changes"`
	Creates         int             `json:"creates"`
	Updates         int             `json:"updates"`
	Deletes         int             `json:"deletes"`
	Replaces        int             `json:"replaces"`
	Findings        []rules.Finding `json:"findings"`
	MaxSeverity     string          `json:"max_severity"`
	ExitCode        int             `json:"exit_code"`
	Summary         string          `json:"summary"`
	AffectedTypes   []string        `json:"affected_types"`
}

// Analyzer evaluates drift risk from a terraform plan.
type Analyzer struct {
	criticalTypes []string
}

// NewAnalyzer creates a new drift analyzer.
// criticalTypes defines resource types considered high-risk for drift.
func NewAnalyzer(criticalTypes []string) *Analyzer {
	if len(criticalTypes) == 0 {
		criticalTypes = defaultCriticalTypes
	}
	return &Analyzer{criticalTypes: criticalTypes}
}

var defaultCriticalTypes = []string{
	"aws_db_instance",
	"aws_rds_cluster",
	"aws_dynamodb_table",
	"aws_s3_bucket",
	"aws_elasticache_cluster",
	"aws_efs_file_system",
	"aws_kinesis_stream",
	"aws_iam_role",
	"aws_iam_policy",
	"aws_vpc",
	"aws_subnet",
	"aws_route_table",
	"aws_security_group",
	"aws_kms_key",
	"aws_lambda_function",
	"aws_ecs_service",
	"aws_eks_cluster",
}

// Analyze evaluates drift risk from normalized resources.
func (a *Analyzer) Analyze(resources []parser.NormalizedResource) DriftResult {
	result := DriftResult{
		TotalChanges: 0,
	}

	typeSet := make(map[string]bool)

	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			continue
		}

		result.TotalChanges++
		typeSet[r.Type] = true

		switch r.Action {
		case "create":
			result.Creates++
		case "update":
			result.Updates++
		case "delete":
			result.Deletes++
			result.Findings = append(result.Findings, a.evaluateDelete(r)...)
		case "replace":
			result.Replaces++
			result.Findings = append(result.Findings, a.evaluateReplace(r)...)
		}

		// Evaluate drift risk for all changes
		result.Findings = append(result.Findings, a.evaluateDriftRisk(r)...)
	}

	for t := range typeSet {
		result.AffectedTypes = append(result.AffectedTypes, t)
	}

	result.MaxSeverity = computeMaxSeverity(result.Findings)
	result.ExitCode = computeDriftExitCode(result.MaxSeverity)
	result.Summary = a.buildSummary(result)

	return result
}

func (a *Analyzer) evaluateDelete(r parser.NormalizedResource) []rules.Finding {
	var findings []rules.Finding

	if a.isCriticalType(r.Type) {
		findings = append(findings, rules.Finding{
			RuleID:      "DRIFT-DEL",
			Severity:    rules.SeverityCritical,
			Category:    rules.CategoryReliability,
			Resource:    r.Address,
			Message:     fmt.Sprintf("Drift detected: critical resource %s is being deleted. This may indicate unauthorized infrastructure changes.", r.Address),
			Remediation: "Investigate why this resource drifted. Check for manual changes in the AWS console or other tools.",
			Source:      "drift",
		})
	} else {
		findings = append(findings, rules.Finding{
			RuleID:      "DRIFT-DEL",
			Severity:    rules.SeverityHigh,
			Category:    rules.CategoryReliability,
			Resource:    r.Address,
			Message:     fmt.Sprintf("Drift detected: resource %s is being deleted.", r.Address),
			Remediation: "Review the deletion and ensure it is intentional.",
			Source:      "drift",
		})
	}

	return findings
}

func (a *Analyzer) evaluateReplace(r parser.NormalizedResource) []rules.Finding {
	severity := rules.SeverityHigh
	if a.isCriticalType(r.Type) {
		severity = rules.SeverityCritical
	}

	return []rules.Finding{{
		RuleID:      "DRIFT-RPL",
		Severity:    severity,
		Category:    rules.CategoryReliability,
		Resource:    r.Address,
		Message:     fmt.Sprintf("Drift detected: resource %s will be replaced (destroy + recreate). This may cause downtime.", r.Address),
		Remediation: "Investigate the cause. Consider using lifecycle create_before_destroy to minimize disruption.",
		Source:      "drift",
	}}
}

func (a *Analyzer) evaluateDriftRisk(r parser.NormalizedResource) []rules.Finding {
	var findings []rules.Finding

	// Detect security-sensitive drift
	if r.Action == "update" || r.Action == "create" {
		if isSecurityResource(r.Type) {
			findings = append(findings, rules.Finding{
				RuleID:      "DRIFT-SEC",
				Severity:    rules.SeverityHigh,
				Category:    rules.CategorySecurity,
				Resource:    r.Address,
				Message:     fmt.Sprintf("Drift in security-related resource %s (%s). Review for potential security implications.", r.Address, r.Action),
				Remediation: "Verify the change does not weaken security posture. Check IAM policies, security groups, and encryption settings.",
				Source:      "drift",
			})
		}
	}

	return findings
}

func (a *Analyzer) isCriticalType(resourceType string) bool {
	for _, ct := range a.criticalTypes {
		if ct == resourceType {
			return true
		}
	}
	return false
}

func isSecurityResource(resourceType string) bool {
	securityPrefixes := []string{
		"aws_iam_",
		"aws_security_group",
		"aws_kms_",
		"aws_acm_",
		"aws_waf",
		"aws_shield",
		"aws_guardduty",
	}
	for _, prefix := range securityPrefixes {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

func computeMaxSeverity(findings []rules.Finding) string {
	if len(findings) == 0 {
		return "NONE"
	}

	order := map[string]int{
		rules.SeverityCritical: 0,
		rules.SeverityHigh:     1,
		rules.SeverityMedium:   2,
		rules.SeverityLow:      3,
		rules.SeverityInfo:     4,
	}

	max := rules.SeverityInfo
	for _, f := range findings {
		if order[f.Severity] < order[max] {
			max = f.Severity
		}
	}
	return max
}

func computeDriftExitCode(maxSeverity string) int {
	switch maxSeverity {
	case rules.SeverityCritical:
		return 2
	case rules.SeverityHigh:
		return 1
	default:
		return 0
	}
}

func (a *Analyzer) buildSummary(result DriftResult) string {
	if result.TotalChanges == 0 {
		return "No infrastructure drift detected. State is in sync."
	}

	parts := []string{}
	if result.Creates > 0 {
		parts = append(parts, fmt.Sprintf("%d create", result.Creates))
	}
	if result.Updates > 0 {
		parts = append(parts, fmt.Sprintf("%d update", result.Updates))
	}
	if result.Deletes > 0 {
		parts = append(parts, fmt.Sprintf("%d delete", result.Deletes))
	}
	if result.Replaces > 0 {
		parts = append(parts, fmt.Sprintf("%d replace", result.Replaces))
	}

	summary := fmt.Sprintf("Drift detected: %d changes (%s).", result.TotalChanges, strings.Join(parts, ", "))

	if result.MaxSeverity == rules.SeverityCritical {
		summary += " CRITICAL drift requires immediate attention."
	} else if result.MaxSeverity == rules.SeverityHigh {
		summary += " HIGH risk drift should be investigated."
	}

	return summary
}
