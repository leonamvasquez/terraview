// Package feature extracts normalized semantic features from terraform resources.
// It is provider-agnostic and works with AWS, Azure, and GCP resources.
package feature

import (
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// ResourceFeatures holds the extracted semantic features for a single resource.
type ResourceFeatures struct {
	ResourceID        string   `json:"resource_id"`
	Provider          string   `json:"provider"`
	ResourceType      string   `json:"resource_type"`
	NetworkExposure   int      `json:"network_exposure"`
	EncryptionRisk    int      `json:"encryption_risk"`
	IdentityRisk      int      `json:"identity_risk"`
	GovernanceRisk    int      `json:"governance_risk"`
	ObservabilityRisk int      `json:"observability_risk"`
	Flags             []string `json:"flags"`
}

// TotalRisk returns the sum of all risk axes (0-15).
func (rf *ResourceFeatures) TotalRisk() int {
	return rf.NetworkExposure + rf.EncryptionRisk + rf.IdentityRisk +
		rf.GovernanceRisk + rf.ObservabilityRisk
}

// Extractor extracts semantic features from normalized resources.
type Extractor struct{}

// NewExtractor creates a new feature extractor.
func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract processes a slice of resources and returns features for each. O(n).
func (e *Extractor) Extract(resources []parser.NormalizedResource) []ResourceFeatures {
	result := make([]ResourceFeatures, 0, len(resources))
	for i := range resources {
		result = append(result, e.extractOne(&resources[i]))
	}
	return result
}

func (e *Extractor) extractOne(r *parser.NormalizedResource) ResourceFeatures {
	rf := ResourceFeatures{
		ResourceID:   r.Address,
		Provider:     detectProvider(r.Provider, r.Type),
		ResourceType: r.Type,
	}

	vals := r.Values
	if vals == nil {
		vals = map[string]interface{}{}
	}

	rf.NetworkExposure = e.scoreNetwork(r.Type, vals)
	rf.EncryptionRisk = e.scoreEncryption(r.Type, vals)
	rf.IdentityRisk = e.scoreIdentity(r.Type, vals)
	rf.GovernanceRisk = e.scoreGovernance(r.Type, vals)
	rf.ObservabilityRisk = e.scoreObservability(r.Type, vals)
	rf.Flags = e.extractFlags(r.Type, vals)

	sort.Strings(rf.Flags)
	return rf
}

func detectProvider(provider, resourceType string) string {
	p := strings.ToLower(provider)
	rt := strings.ToLower(resourceType)

	switch {
	case strings.Contains(p, "aws") || strings.HasPrefix(rt, "aws_"):
		return "aws"
	case strings.Contains(p, "azurerm") || strings.HasPrefix(rt, "azurerm_"):
		return "azure"
	case strings.Contains(p, "google") || strings.HasPrefix(rt, "google_"):
		return "gcp"
	default:
		if idx := strings.Index(rt, "_"); idx > 0 {
			return rt[:idx]
		}
		return "unknown"
	}
}

func (e *Extractor) scoreNetwork(resType string, vals map[string]interface{}) int {
	rt := strings.ToLower(resType)
	score := 0

	if isNetworkResource(rt) {
		score = 1
	}

	if hasTruthyKey(vals, "publicly_accessible") ||
		hasTruthyKey(vals, "public_access") ||
		hasTruthyKey(vals, "public_network_access_enabled") ||
		hasTruthyKey(vals, "associate_public_ip_address") {
		score = maxInt(score, 2)
	}

	if hasWildcardCIDR(vals) {
		score = 3
	}

	if hasPublicACL(vals) {
		score = 3
	}

	return score
}

func (e *Extractor) scoreEncryption(resType string, vals map[string]interface{}) int {
	rt := strings.ToLower(resType)
	score := 0

	if needsEncryption(rt) {
		score = 1

		if hasFalsyKey(vals, "encrypted") ||
			hasFalsyKey(vals, "encryption_at_rest") ||
			hasFalsyKey(vals, "storage_encrypted") {
			score = 3
		}

		if !hasNonEmptyKey(vals, "kms_key_id") &&
			!hasNonEmptyKey(vals, "kms_key_arn") &&
			!hasNonEmptyKey(vals, "customer_managed_key_id") &&
			!hasNonEmptyKey(vals, "cmk_key_vault_key_id") {
			score = maxInt(score, 2)
		}

		if hasTruthyKey(vals, "encrypted") ||
			hasTruthyKey(vals, "storage_encrypted") ||
			hasTruthyKey(vals, "encryption_at_rest") {
			score = maxInt(score-1, 0)
		}
	}

	return score
}

func (e *Extractor) scoreIdentity(resType string, vals map[string]interface{}) int {
	rt := strings.ToLower(resType)
	score := 0

	if isIdentityResource(rt) {
		score = 1

		if hasWildcardPolicy(vals) {
			score = 3
		}

		if hasWildcardAssumeRole(vals) {
			score = maxInt(score, 2)
		}
	}

	return score
}

func (e *Extractor) scoreGovernance(_ string, vals map[string]interface{}) int {
	score := 0

	if !hasNonEmptyKey(vals, "tags") && !hasNonEmptyKey(vals, "labels") {
		score = 1
	}

	if hasTruthyKey(vals, "skip_final_snapshot") {
		score = maxInt(score, 2)
	}

	if hasFalsyKey(vals, "deletion_protection") ||
		hasFalsyKey(vals, "prevent_destroy") {
		score = maxInt(score, 2)
	}

	return score
}

func (e *Extractor) scoreObservability(resType string, vals map[string]interface{}) int {
	rt := strings.ToLower(resType)
	score := 0

	if needsMonitoring(rt) {
		score = 1

		if hasFalsyKey(vals, "logging") ||
			hasFalsyKey(vals, "access_logs") ||
			hasFalsyKey(vals, "enhanced_monitoring_enabled") {
			score = 2
		}

		if !hasPositiveIntKey(vals, "retention_in_days") &&
			!hasPositiveIntKey(vals, "backup_retention_period") {
			if isLoggingResource(rt) || isDatabaseResource(rt) {
				score = maxInt(score, 2)
			}
		}
	}

	return score
}

func (e *Extractor) extractFlags(resType string, vals map[string]interface{}) []string {
	var flags []string
	rt := strings.ToLower(resType)

	if hasTruthyKey(vals, "publicly_accessible") || hasPublicACL(vals) {
		flags = append(flags, "public-access")
	}
	if hasWildcardCIDR(vals) {
		flags = append(flags, "wildcard-cidr")
	}
	if hasWildcardPolicy(vals) {
		flags = append(flags, "wildcard-policy")
	}
	if !hasNonEmptyKey(vals, "tags") && !hasNonEmptyKey(vals, "labels") {
		flags = append(flags, "no-tags")
	}
	if hasTruthyKey(vals, "skip_final_snapshot") {
		flags = append(flags, "skip-final-snapshot")
	}
	if needsEncryption(rt) && hasFalsyKey(vals, "encrypted") {
		flags = append(flags, "unencrypted")
	}
	if needsEncryption(rt) && !hasNonEmptyKey(vals, "kms_key_id") && !hasNonEmptyKey(vals, "kms_key_arn") {
		flags = append(flags, "no-kms")
	}
	if hasTruthyKey(vals, "associate_public_ip_address") {
		flags = append(flags, "public-ip")
	}
	if hasFalsyKey(vals, "multi_az") {
		flags = append(flags, "single-az")
	}
	if !hasPositiveIntKey(vals, "retention_in_days") && isLoggingResource(rt) {
		flags = append(flags, "no-retention")
	}
	if hasFalsyKey(vals, "versioning") || hasVersioningDisabled(vals) {
		flags = append(flags, "no-versioning")
	}

	return flags
}

func isNetworkResource(rt string) bool {
	keywords := []string{"security_group", "firewall", "network", "subnet",
		"lb", "load_balancer", "cdn", "cloudfront", "gateway", "endpoint",
		"waf", "proxy", "vpn"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func needsEncryption(rt string) bool {
	keywords := []string{"db", "database", "rds", "storage", "disk", "volume",
		"bucket", "blob", "s3", "ebs", "snapshot", "backup", "kms",
		"secret", "sql", "cosmos", "dynamo", "bigtable", "spanner"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func isIdentityResource(rt string) bool {
	keywords := []string{"iam", "role", "policy", "identity", "service_account",
		"access", "permission", "principal", "user", "group"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func needsMonitoring(rt string) bool {
	keywords := []string{"instance", "db", "database", "cluster", "server",
		"function", "lambda", "container", "vm", "compute", "app_service",
		"cloud_run", "log", "bucket", "storage"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func isLoggingResource(rt string) bool {
	keywords := []string{"log_group", "log_analytics", "logging", "monitor"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func isDatabaseResource(rt string) bool {
	keywords := []string{"db_instance", "rds", "sql", "database", "cosmos",
		"dynamo", "bigtable", "spanner", "cloudsql"}
	for _, kw := range keywords {
		if strings.Contains(rt, kw) {
			return true
		}
	}
	return false
}

func hasTruthyKey(vals map[string]interface{}, key string) bool {
	v, ok := vals[key]
	if !ok {
		return false
	}
	switch tv := v.(type) {
	case bool:
		return tv
	case string:
		return tv == "true" || tv == "1" || tv == "yes"
	case float64:
		return tv != 0
	}
	return false
}

func hasFalsyKey(vals map[string]interface{}, key string) bool {
	v, ok := vals[key]
	if !ok {
		return false
	}
	switch tv := v.(type) {
	case bool:
		return !tv
	case string:
		return tv == "false" || tv == "0" || tv == "no"
	case float64:
		return tv == 0
	}
	return false
}

func hasNonEmptyKey(vals map[string]interface{}, key string) bool {
	v, ok := vals[key]
	if !ok {
		return false
	}
	switch tv := v.(type) {
	case string:
		return tv != ""
	case map[string]interface{}:
		return len(tv) > 0
	case []interface{}:
		return len(tv) > 0
	case nil:
		return false
	}
	return true
}

func hasPositiveIntKey(vals map[string]interface{}, key string) bool {
	v, ok := vals[key]
	if !ok {
		return false
	}
	switch tv := v.(type) {
	case float64:
		return tv > 0
	case int:
		return tv > 0
	}
	return false
}

func hasWildcardCIDR(vals map[string]interface{}) bool {
	return containsStringAnywhere(vals, "0.0.0.0/0") ||
		containsStringAnywhere(vals, "::/0")
}

func hasPublicACL(vals map[string]interface{}) bool {
	return containsStringAnywhere(vals, "public-read") ||
		containsStringAnywhere(vals, "public-read-write") ||
		containsStringAnywhere(vals, "public") ||
		hasTruthyKey(vals, "public_access")
}

func hasWildcardPolicy(vals map[string]interface{}) bool {
	if containsStringAnywhere(vals, "\"Action\":\"*\"") ||
		containsStringAnywhere(vals, "\"Action\": \"*\"") ||
		containsStringAnywhere(vals, "\"actions\":[\"*\"]") {
		return true
	}
	if p, ok := vals["policy"]; ok {
		if ps, ok := p.(string); ok {
			return strings.Contains(ps, "\"*\"") && strings.Contains(ps, "Action")
		}
	}
	return false
}

func hasWildcardAssumeRole(vals map[string]interface{}) bool {
	if p, ok := vals["assume_role_policy"]; ok {
		if ps, ok := p.(string); ok {
			return strings.Contains(ps, "\"*\"") && strings.Contains(ps, "Principal")
		}
	}
	return false
}

func hasVersioningDisabled(vals map[string]interface{}) bool {
	if v, ok := vals["versioning"]; ok {
		if vm, ok := v.(map[string]interface{}); ok {
			return hasFalsyKey(vm, "enabled")
		}
	}
	return false
}

func containsStringAnywhere(vals map[string]interface{}, target string) bool {
	target = strings.ToLower(target)
	return searchValue(vals, target)
}

func searchValue(v interface{}, target string) bool {
	switch tv := v.(type) {
	case string:
		return strings.Contains(strings.ToLower(tv), target)
	case map[string]interface{}:
		for _, val := range tv {
			if searchValue(val, target) {
				return true
			}
		}
	case []interface{}:
		for _, item := range tv {
			if searchValue(item, target) {
				return true
			}
		}
	}
	return false
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
