package drift

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// DriftClassification categorizes drift as intentional or suspicious.
type DriftClassification string

const (
	ClassIntentional DriftClassification = "intentional"
	ClassSuspicious  DriftClassification = "suspicious"
	ClassUnknown     DriftClassification = "unknown"
)

// DriftItem represents a single drifted resource with classification and risk.
type DriftItem struct {
	Resource       string              `json:"resource"`
	ResourceType   string              `json:"resource_type"`
	Action         string              `json:"action"`
	Classification DriftClassification `json:"classification"`
	RiskScore      float64             `json:"risk_score"`
	RiskFactors    []string            `json:"risk_factors"`
	ChangedFields  []string            `json:"changed_fields,omitempty"`
}

// IntelligenceResult extends DriftResult with classification and risk data.
type IntelligenceResult struct {
	Items            []DriftItem `json:"items"`
	OverallRisk      float64     `json:"overall_risk"`
	RiskLevel        string      `json:"risk_level"`
	SuspiciousCount  int         `json:"suspicious_count"`
	IntentionalCount int         `json:"intentional_count"`
	Narrative        string      `json:"narrative,omitempty"`
	Recommendations  []string    `json:"recommendations"`
}

// ClassifyDrift analyzes resources and classifies each change.
func ClassifyDrift(resources []parser.NormalizedResource, criticalTypes []string) *IntelligenceResult {
	result := &IntelligenceResult{}
	criticalSet := make(map[string]bool)
	for _, ct := range criticalTypes {
		criticalSet[ct] = true
	}

	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			continue
		}

		item := DriftItem{
			Resource:     r.Address,
			ResourceType: r.Type,
			Action:       r.Action,
		}

		// Detect changed fields from values diff
		item.ChangedFields = detectChangedFields(r)

		// Classify and score
		item.RiskScore, item.RiskFactors = computeItemRisk(r, criticalSet)
		item.Classification = classifyItem(r, item.ChangedFields, criticalSet)

		result.Items = append(result.Items, item)

		switch item.Classification {
		case ClassSuspicious:
			result.SuspiciousCount++
		case ClassIntentional:
			result.IntentionalCount++
		}
	}

	// Sort by risk score descending
	sort.Slice(result.Items, func(i, j int) bool {
		return result.Items[i].RiskScore > result.Items[j].RiskScore
	})

	// Overall risk
	result.OverallRisk = computeOverallRisk(result.Items)
	result.RiskLevel = riskLevelLabel(result.OverallRisk)
	result.Recommendations = buildRecommendations(result)

	return result
}

func detectChangedFields(r parser.NormalizedResource) []string {
	if r.BeforeValues == nil || r.Values == nil {
		return nil
	}

	var changed []string

	for key, afterVal := range r.Values {
		beforeVal, exists := r.BeforeValues[key]
		if !exists || fmt.Sprintf("%v", beforeVal) != fmt.Sprintf("%v", afterVal) {
			changed = append(changed, key)
		}
	}

	// Check for removed fields
	for key := range r.BeforeValues {
		if _, exists := r.Values[key]; !exists {
			changed = append(changed, key+" (removed)")
		}
	}

	sort.Strings(changed)
	return changed
}

func computeItemRisk(r parser.NormalizedResource, criticalSet map[string]bool) (float64, []string) {
	score := 0.0
	var factors []string

	// Action-based risk
	switch r.Action {
	case "delete":
		score += 4.0
		factors = append(factors, "resource deletion")
	case "replace":
		score += 3.5
		factors = append(factors, "resource replacement (destroy+recreate)")
	case "update":
		score += 1.5
		factors = append(factors, "in-place update")
	case "create":
		score += 0.5
		factors = append(factors, "new resource")
	}

	// Critical type boost
	if criticalSet[r.Type] {
		score += 2.0
		factors = append(factors, "critical resource type")
	}

	// Security resource boost
	if isSecurityResource(r.Type) {
		score += 2.5
		factors = append(factors, "security-sensitive resource")
	}

	// Data resource boost
	if isDataResource(r.Type) {
		score += 1.5
		factors = append(factors, "data/storage resource")
	}

	// Network resource
	if isNetworkResource(r.Type) {
		score += 1.0
		factors = append(factors, "network resource")
	}

	// Cap at 10
	if score > 10.0 {
		score = 10.0
	}

	return score, factors
}

func classifyItem(r parser.NormalizedResource, changedFields []string, criticalSet map[string]bool) DriftClassification {
	// Deletions of critical resources are suspicious
	if r.Action == "delete" && criticalSet[r.Type] {
		return ClassSuspicious
	}

	// Replacements are suspicious
	if r.Action == "replace" {
		return ClassSuspicious
	}

	// Security resource changes are suspicious
	if isSecurityResource(r.Type) && (r.Action == "update" || r.Action == "delete") {
		return ClassSuspicious
	}

	// Check for sensitive field changes
	for _, field := range changedFields {
		if isSensitiveField(field) {
			return ClassSuspicious
		}
	}

	// Creates are usually intentional
	if r.Action == "create" {
		return ClassIntentional
	}

	// Tag-only or description-only updates are intentional
	if r.Action == "update" && allFieldsAreCosmetic(changedFields) {
		return ClassIntentional
	}

	return ClassUnknown
}

func isSensitiveField(field string) bool {
	sensitive := []string{
		"policy", "iam", "role", "permission",
		"cidr", "ingress", "egress", "security_group",
		"encryption", "kms", "password", "secret",
		"public", "acl", "bucket_policy",
	}
	lower := strings.ToLower(field)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

func allFieldsAreCosmetic(fields []string) bool {
	if len(fields) == 0 {
		return false
	}
	cosmetic := map[string]bool{
		"tags": true, "tags_all": true, "description": true, "name_prefix": true,
	}
	for _, f := range fields {
		if !cosmetic[f] {
			return false
		}
	}
	return true
}

func isDataResource(resourceType string) bool {
	prefixes := []string{
		"aws_db_", "aws_rds_", "aws_dynamodb_", "aws_s3_",
		"aws_elasticache_", "aws_efs_", "aws_kinesis_",
		"aws_redshift_", "aws_docdb_", "aws_neptune_",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(resourceType, p) {
			return true
		}
	}
	return false
}

func isNetworkResource(resourceType string) bool {
	prefixes := []string{
		"aws_vpc", "aws_subnet", "aws_route",
		"aws_nat_gateway", "aws_internet_gateway",
		"aws_network_", "aws_lb", "aws_alb", "aws_elb",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(resourceType, p) {
			return true
		}
	}
	return false
}

func computeOverallRisk(items []DriftItem) float64 {
	if len(items) == 0 {
		return 0
	}
	total := 0.0
	maxRisk := 0.0
	for _, item := range items {
		total += item.RiskScore
		if item.RiskScore > maxRisk {
			maxRisk = item.RiskScore
		}
	}
	// Weighted: 60% max risk, 40% average
	avg := total / float64(len(items))
	return maxRisk*0.6 + avg*0.4
}

func riskLevelLabel(risk float64) string {
	switch {
	case risk >= 7.0:
		return "CRITICAL"
	case risk >= 5.0:
		return "HIGH"
	case risk >= 3.0:
		return "MEDIUM"
	case risk >= 1.0:
		return "LOW"
	default:
		return "NONE"
	}
}

func buildRecommendations(result *IntelligenceResult) []string {
	var recs []string

	if result.SuspiciousCount > 0 {
		recs = append(recs, fmt.Sprintf("Investigate %d suspicious drift items — possible unauthorized changes.", result.SuspiciousCount))
	}

	hasSecDrift := false
	hasDataDrift := false
	for _, item := range result.Items {
		if isSecurityResource(item.ResourceType) {
			hasSecDrift = true
		}
		if isDataResource(item.ResourceType) {
			hasDataDrift = true
		}
	}

	if hasSecDrift {
		recs = append(recs, "Security-related drift detected. Audit IAM policies and security group rules.")
	}
	if hasDataDrift {
		recs = append(recs, "Data resource drift detected. Verify backup and encryption settings before applying.")
	}

	if result.OverallRisk >= 5.0 {
		recs = append(recs, "Consider running 'terraform plan' in a staging environment first.")
	}

	if len(recs) == 0 {
		recs = append(recs, "No high-risk drift detected. Changes appear safe to apply.")
	}

	return recs
}

// FormatNarrative generates a human-readable drift narrative.
func FormatNarrative(result *IntelligenceResult) string {
	if len(result.Items) == 0 {
		return "No drift detected. Infrastructure state is in sync."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Drift Intelligence Report: %d changes detected (risk: %s, score: %.1f/10)\n\n",
		len(result.Items), result.RiskLevel, result.OverallRisk))

	if result.SuspiciousCount > 0 {
		sb.WriteString(fmt.Sprintf("WARNING: %d suspicious changes require investigation.\n\n", result.SuspiciousCount))
	}

	// Group by classification
	groups := map[DriftClassification][]DriftItem{
		ClassSuspicious:  {},
		ClassIntentional: {},
		ClassUnknown:     {},
	}
	for _, item := range result.Items {
		groups[item.Classification] = append(groups[item.Classification], item)
	}

	if len(groups[ClassSuspicious]) > 0 {
		sb.WriteString("SUSPICIOUS CHANGES:\n")
		for _, item := range groups[ClassSuspicious] {
			sb.WriteString(fmt.Sprintf("  - [%.1f] %s (%s) — %s\n", item.RiskScore, item.Resource, item.Action, strings.Join(item.RiskFactors, ", ")))
		}
		sb.WriteString("\n")
	}

	if len(groups[ClassUnknown]) > 0 {
		sb.WriteString("UNCLASSIFIED CHANGES:\n")
		for _, item := range groups[ClassUnknown] {
			sb.WriteString(fmt.Sprintf("  - [%.1f] %s (%s) — %s\n", item.RiskScore, item.Resource, item.Action, strings.Join(item.RiskFactors, ", ")))
		}
		sb.WriteString("\n")
	}

	if len(groups[ClassIntentional]) > 0 {
		sb.WriteString("INTENTIONAL CHANGES:\n")
		for _, item := range groups[ClassIntentional] {
			sb.WriteString(fmt.Sprintf("  - [%.1f] %s (%s)\n", item.RiskScore, item.Resource, item.Action))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("RECOMMENDATIONS:\n")
	for _, rec := range result.Recommendations {
		sb.WriteString(fmt.Sprintf("  - %s\n", rec))
	}

	return sb.String()
}
