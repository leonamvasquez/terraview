package scanner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// AggregatedResult holds the combined output from all scanners.
type AggregatedResult struct {
	Findings      []rules.Finding `json:"findings"`
	ScannerStats  []ScannerStat   `json:"scanner_stats"`
	TotalRaw      int             `json:"total_raw"`     // before dedup
	TotalDeduped  int             `json:"total_deduped"` // after dedup
	ScannersUsed  []string        `json:"scanners_used"`
	ScannersError []string        `json:"scanners_error"`
}

// ScannerStat tracks per-scanner statistics.
type ScannerStat struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Findings int    `json:"findings"`
	Error    string `json:"error,omitempty"`
}

// Aggregate combines results from multiple scanners, deduplicates, and normalizes.
func Aggregate(results []ScanResult) AggregatedResult {
	var allFindings []rules.Finding
	var stats []ScannerStat
	var used, errored []string

	for _, r := range results {
		stat := ScannerStat{
			Name:     r.Scanner,
			Version:  r.Version,
			Findings: len(r.Findings),
		}
		if r.Error != nil {
			stat.Error = r.Error.Error()
			errored = append(errored, r.Scanner)
		} else {
			used = append(used, r.Scanner)
			allFindings = append(allFindings, r.Findings...)
		}
		stats = append(stats, stat)
	}

	totalRaw := len(allFindings)
	deduped := deduplicateFindings(allFindings)
	sortBySeverity(deduped)

	return AggregatedResult{
		Findings:      deduped,
		ScannerStats:  stats,
		TotalRaw:      totalRaw,
		TotalDeduped:  len(deduped),
		ScannersUsed:  used,
		ScannersError: errored,
	}
}

// FormatScannerHeader returns a formatted string showing which scanners ran.
func FormatScannerHeader(result AggregatedResult) string {
	var sb strings.Builder

	sb.WriteString("  Scanners: ")
	for i, stat := range result.ScannerStats {
		if i > 0 {
			sb.WriteString(" | ")
		}
		if stat.Error != "" {
			sb.WriteString(fmt.Sprintf("%s (error)", stat.Name))
		} else {
			sb.WriteString(fmt.Sprintf("%s (%d findings)", stat.Name, stat.Findings))
		}
	}
	sb.WriteString("\n")

	if result.TotalRaw != result.TotalDeduped {
		sb.WriteString(fmt.Sprintf("  Dedup: %d → %d findings (-%d duplicates)\n",
			result.TotalRaw, result.TotalDeduped, result.TotalRaw-result.TotalDeduped))
	}

	return sb.String()
}

// FormatScannerHeaderBR returns the header in Brazilian Portuguese.
func FormatScannerHeaderBR(result AggregatedResult) string {
	var sb strings.Builder

	sb.WriteString("  Scanners: ")
	for i, stat := range result.ScannerStats {
		if i > 0 {
			sb.WriteString(" | ")
		}
		if stat.Error != "" {
			sb.WriteString(fmt.Sprintf("%s (erro)", stat.Name))
		} else {
			sb.WriteString(fmt.Sprintf("%s (%d achados)", stat.Name, stat.Findings))
		}
	}
	sb.WriteString("\n")

	if result.TotalRaw != result.TotalDeduped {
		sb.WriteString(fmt.Sprintf("  Dedup: %d → %d achados (-%d duplicados)\n",
			result.TotalRaw, result.TotalDeduped, result.TotalRaw-result.TotalDeduped))
	}

	return sb.String()
}

// deduplicateFindings removes findings that match on the same resource + similar rule.
// When multiple scanners find the same issue, keep the one with the highest severity
// and enrich the source field to show all scanners that found it.
func deduplicateFindings(findings []rules.Finding) []rules.Finding {
	type dedupKey struct {
		resource string
		ruleNorm string
	}

	seen := make(map[dedupKey]*rules.Finding)
	var order []dedupKey

	for i := range findings {
		f := findings[i]
		key := dedupKey{
			resource: normalizeResource(f.Resource),
			ruleNorm: normalizeRuleID(f.RuleID, f.Message),
		}

		existing, exists := seen[key]
		if !exists {
			seen[key] = &f
			order = append(order, key)
		} else {
			// Keep higher severity
			if severityRank(f.Severity) > severityRank(existing.Severity) {
				existing.Severity = f.Severity
			}
			// Merge remediation if the existing one is empty
			if existing.Remediation == "" && f.Remediation != "" {
				existing.Remediation = f.Remediation
			}
			// Track which scanners found this
			if !strings.Contains(existing.Source, extractScannerName(f.Source)) {
				existing.Source += "+" + extractScannerName(f.Source)
			}
		}
	}

	result := make([]rules.Finding, 0, len(order))
	for _, key := range order {
		result = append(result, *seen[key])
	}
	return result
}

// normalizeResource strips file paths and line numbers for comparison.
func normalizeResource(r string) string {
	r = strings.TrimSpace(r)
	// Remove line number references
	if idx := strings.LastIndex(r, ":"); idx > 0 {
		// Only strip if what follows looks like a line number
		after := r[idx+1:]
		isDigit := true
		for _, c := range after {
			if c < '0' || c > '9' {
				isDigit = false
				break
			}
		}
		if isDigit && len(after) > 0 {
			r = r[:idx]
		}
	}
	return strings.ToLower(r)
}

// normalizeRuleID creates a comparable key from different scanner rule IDs.
// Maps known equivalent rules across scanners.
func normalizeRuleID(ruleID, message string) string {
	id := strings.ToUpper(ruleID)

	// Extract the core check type from the message for cross-tool matching
	msg := strings.ToLower(message)

	// Known cross-scanner mappings for common checks
	switch {
	case strings.Contains(msg, "encryption at rest") || strings.Contains(msg, "encrypt") && strings.Contains(msg, "rest"):
		return "ENCRYPT_REST:" + extractResourceType(msg)
	case strings.Contains(msg, "encryption in transit") || strings.Contains(msg, "encrypt") && strings.Contains(msg, "transit"):
		return "ENCRYPT_TRANSIT:" + extractResourceType(msg)
	case strings.Contains(msg, "public") && strings.Contains(msg, "access"):
		return "PUBLIC_ACCESS:" + extractResourceType(msg)
	case strings.Contains(msg, "logging") || strings.Contains(msg, "log") && strings.Contains(msg, "enabl"):
		return "LOGGING:" + extractResourceType(msg)
	case strings.Contains(msg, "ssh") && strings.Contains(msg, "0.0.0.0"):
		return "SSH_OPEN"
	case strings.Contains(msg, "wildcard") && strings.Contains(msg, "iam"):
		return "IAM_WILDCARD"
	}

	return id
}

// extractResourceType tries to identify the AWS resource type from a message.
func extractResourceType(msg string) string {
	resourceTypes := []string{
		"s3", "rds", "ec2", "iam", "elb", "alb", "ecs", "eks", "lambda",
		"dynamodb", "sqs", "sns", "cloudfront", "elasticsearch", "opensearch",
		"redshift", "elasticache", "kms", "cloudtrail", "cloudwatch", "ecr",
		"neptune", "docdb", "msk", "kinesis", "efs", "dax", "mq", "sagemaker",
		"api gateway", "apigateway", "glue", "codebuild", "waf", "emr",
	}
	for _, rt := range resourceTypes {
		if strings.Contains(msg, rt) {
			return rt
		}
	}
	return "unknown"
}

// extractScannerName gets the scanner name from a source string like "scanner:checkov".
func extractScannerName(source string) string {
	parts := strings.SplitN(source, ":", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return source
}

func severityRank(s string) int {
	switch s {
	case rules.SeverityCritical:
		return 5
	case rules.SeverityHigh:
		return 4
	case rules.SeverityMedium:
		return 3
	case rules.SeverityLow:
		return 2
	case rules.SeverityInfo:
		return 1
	default:
		return 0
	}
}

func sortBySeverity(findings []rules.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
}
