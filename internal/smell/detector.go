package smell

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// SmellType categorizes design smells.
type SmellType string

const (
	SmellHardcodedValues  SmellType = "hardcoded-values"
	SmellNoTags           SmellType = "missing-tags"
	SmellSingleAZ         SmellType = "single-az"
	SmellNoEncryption     SmellType = "no-encryption"
	SmellOverlyPermissive SmellType = "overly-permissive"
	SmellNoBackup         SmellType = "no-backup"
	SmellMonolith         SmellType = "monolith-risk"
	SmellNoModules        SmellType = "no-modules"
	SmellResourceSprawl   SmellType = "resource-sprawl"
	SmellNamingInconsist  SmellType = "naming-inconsistency"
)

// Smell represents a detected design smell.
type Smell struct {
	Type       SmellType `json:"type"`
	Severity   string    `json:"severity"`
	Resource   string    `json:"resource,omitempty"`
	Message    string    `json:"message"`
	Suggestion string    `json:"suggestion"`
	Category   string    `json:"category"`
}

// DetectorResult is the result of the design smell analysis.
type DetectorResult struct {
	Smells       []Smell  `json:"smells"`
	QualityScore float64  `json:"quality_score"`
	QualityLevel string   `json:"quality_level"`
	TopConcerns  []string `json:"top_concerns"`
	Summary      string   `json:"summary"`
}

// Detector analyzes Terraform resources for design smells.
type Detector struct{}

// NewDetector creates a new Design Smell Detector.
func NewDetector() *Detector {
	return &Detector{}
}

// Detect analyzes resources for architectural design smells.
func (d *Detector) Detect(resources []parser.NormalizedResource) *DetectorResult {
	result := &DetectorResult{}

	result.Smells = append(result.Smells, d.checkTags(resources)...)
	result.Smells = append(result.Smells, d.checkEncryption(resources)...)
	result.Smells = append(result.Smells, d.checkPermissions(resources)...)
	result.Smells = append(result.Smells, d.checkHA(resources)...)
	result.Smells = append(result.Smells, d.checkNaming(resources)...)
	result.Smells = append(result.Smells, d.checkSprawl(resources)...)
	result.Smells = append(result.Smells, d.checkHardcodedValues(resources)...)
	result.Smells = append(result.Smells, d.checkBackup(resources)...)
	result.Smells = append(result.Smells, d.checkModuleUsage(resources)...)

	// Sort by severity
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(result.Smells, func(i, j int) bool {
		return sevOrder[result.Smells[i].Severity] < sevOrder[result.Smells[j].Severity]
	})

	result.QualityScore = computeQualityScore(result.Smells, len(resources))
	result.QualityLevel = qualityLevel(result.QualityScore)
	result.TopConcerns = topConcerns(result.Smells)
	result.Summary = buildSmellSummary(result)

	return result
}

func (d *Detector) checkTags(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	taggable := map[string]bool{
		// AWS
		"aws_instance": true, "aws_s3_bucket": true, "aws_db_instance": true,
		"aws_vpc": true, "aws_subnet": true, "aws_security_group": true,
		"aws_lambda_function": true, "aws_ecs_service": true,
		"aws_eks_cluster": true, "aws_rds_cluster": true,
		// Azure
		"azurerm_resource_group": true, "azurerm_virtual_network": true,
		"azurerm_subnet": true, "azurerm_virtual_machine": true,
		"azurerm_linux_virtual_machine": true, "azurerm_windows_virtual_machine": true,
		"azurerm_storage_account": true, "azurerm_sql_server": true,
		"azurerm_kubernetes_cluster": true, "azurerm_function_app": true,
		// GCP
		"google_compute_instance": true, "google_storage_bucket": true,
		"google_sql_database_instance": true, "google_container_cluster": true,
		"google_compute_network": true, "google_cloud_run_service": true,
	}

	for _, r := range resources {
		if !taggable[r.Type] {
			continue
		}
		if r.Values == nil {
			continue
		}
		tags, hasTags := r.Values["tags"]
		if !hasTags || tags == nil {
			smells = append(smells, Smell{
				Type:       SmellNoTags,
				Severity:   "MEDIUM",
				Resource:   r.Address,
				Message:    fmt.Sprintf("Resource %s has no tags. Tags are essential for cost tracking, ownership, and compliance.", r.Address),
				Suggestion: "Add tags: Name, Environment, Team, CostCenter at minimum.",
				Category:   "best-practice",
			})
		}
	}
	return smells
}

func (d *Detector) checkEncryption(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	encryptable := []string{
		// AWS
		"aws_s3_bucket", "aws_db_instance", "aws_rds_cluster",
		"aws_ebs_volume", "aws_efs_file_system", "aws_dynamodb_table",
		// Azure
		"azurerm_storage_account", "azurerm_sql_database", "azurerm_mssql_database",
		"azurerm_managed_disk", "azurerm_cosmosdb_account",
		// GCP
		"google_storage_bucket", "google_sql_database_instance",
		"google_compute_disk", "google_bigquery_dataset",
	}

	for _, r := range resources {
		if !containsStr(encryptable, r.Type) || r.Values == nil {
			continue
		}
		_, hasEncrypt := r.Values["encrypted"]
		_, hasKMS := r.Values["kms_key_id"]
		_, hasStorageEnc := r.Values["storage_encrypted"]
		_, hasAzureEnc := r.Values["enable_blob_encryption"]
		_, hasAzureHTTPS := r.Values["enable_https_traffic_only"]
		_, hasGCPEnc := r.Values["encryption"]
		if !hasEncrypt && !hasKMS && !hasStorageEnc && !hasAzureEnc && !hasAzureHTTPS && !hasGCPEnc {
			smells = append(smells, Smell{
				Type:       SmellNoEncryption,
				Severity:   "HIGH",
				Resource:   r.Address,
				Message:    fmt.Sprintf("Resource %s may not have encryption configured.", r.Address),
				Suggestion: "Enable encryption at rest using cloud-native KMS or default encryption.",
				Category:   "security",
			})
		}
	}
	return smells
}

func (d *Detector) checkPermissions(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	for _, r := range resources {
		if r.Values == nil {
			continue
		}
		// Check for overly permissive security groups / NSGs / firewalls
		if r.Type == "aws_security_group" || r.Type == "aws_security_group_rule" {
			if cidr, ok := r.Values["cidr_blocks"]; ok {
				if cidrStr := fmt.Sprintf("%v", cidr); strings.Contains(cidrStr, "0.0.0.0/0") {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "HIGH",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s allows traffic from 0.0.0.0/0 (entire internet).", r.Address),
						Suggestion: "Restrict CIDR blocks to known IP ranges or use VPN/private access.",
						Category:   "security",
					})
				}
			}
		}
		// Azure NSG: check for wildcard source
		if r.Type == "azurerm_network_security_rule" || r.Type == "azurerm_network_security_group" {
			if src, ok := r.Values["source_address_prefix"]; ok {
				srcStr := fmt.Sprintf("%v", src)
				if srcStr == "*" || srcStr == "0.0.0.0/0" || srcStr == "Internet" {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "HIGH",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s allows traffic from %s (entire internet).", r.Address, srcStr),
						Suggestion: "Restrict source_address_prefix to known IP ranges or service tags.",
						Category:   "security",
					})
				}
			}
		}
		// GCP firewall: check for 0.0.0.0/0 source range
		if r.Type == "google_compute_firewall" {
			if ranges, ok := r.Values["source_ranges"]; ok {
				if rangeStr := fmt.Sprintf("%v", ranges); strings.Contains(rangeStr, "0.0.0.0/0") {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "HIGH",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s allows traffic from 0.0.0.0/0 (entire internet).", r.Address),
						Suggestion: "Restrict source_ranges to known IP ranges or service accounts.",
						Category:   "security",
					})
				}
			}
		}
		// Check for wildcard IAM (AWS + Azure + GCP)
		if strings.HasPrefix(r.Type, "aws_iam_") {
			if policy, ok := r.Values["policy"]; ok {
				policyStr := fmt.Sprintf("%v", policy)
				if strings.Contains(policyStr, "\"*\"") && strings.Contains(policyStr, "\"Action\"") {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "CRITICAL",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s may have wildcard (*) IAM permissions.", r.Address),
						Suggestion: "Follow least-privilege principle. Use specific actions and resource ARNs.",
						Category:   "security",
					})
				}
			}
		}
		// Azure role assignment with broad scope
		if r.Type == "azurerm_role_assignment" {
			if scope, ok := r.Values["scope"]; ok {
				scopeStr := fmt.Sprintf("%v", scope)
				if scopeStr == "/" || strings.HasPrefix(scopeStr, "/subscriptions/") && strings.Count(scopeStr, "/") <= 2 {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "HIGH",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s has a broad role assignment scope.", r.Address),
						Suggestion: "Scope role assignments to specific resource groups rather than the subscription level.",
						Category:   "security",
					})
				}
			}
		}
		// GCP IAM with broad role
		if strings.HasPrefix(r.Type, "google_project_iam_") || r.Type == "google_project_iam_member" {
			if role, ok := r.Values["role"]; ok {
				roleStr := fmt.Sprintf("%v", role)
				if roleStr == "roles/owner" || roleStr == "roles/editor" {
					smells = append(smells, Smell{
						Type:       SmellOverlyPermissive,
						Severity:   "HIGH",
						Resource:   r.Address,
						Message:    fmt.Sprintf("Resource %s uses broad role %s.", r.Address, roleStr),
						Suggestion: "Use more specific roles instead of Owner/Editor. Follow least-privilege principle.",
						Category:   "security",
					})
				}
			}
		}
	}
	return smells
}

func (d *Detector) checkHA(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	azResources := 0
	azSet := make(map[string]bool)
	for _, r := range resources {
		if r.Values == nil {
			continue
		}
		// AWS availability_zone
		if az, ok := r.Values["availability_zone"]; ok {
			azResources++
			azSet[fmt.Sprintf("%v", az)] = true
		}
		// Azure zones
		if zones, ok := r.Values["zones"]; ok {
			azResources++
			azSet[fmt.Sprintf("%v", zones)] = true
		}
		// GCP zone
		if zone, ok := r.Values["zone"]; ok {
			azResources++
			azSet[fmt.Sprintf("%v", zone)] = true
		}
	}
	if azResources > 2 && len(azSet) == 1 {
		smells = append(smells, Smell{
			Type:       SmellSingleAZ,
			Severity:   "HIGH",
			Resource:   "",
			Message:    fmt.Sprintf("All %d resources with AZ configuration are in a single availability zone.", azResources),
			Suggestion: "Distribute resources across multiple AZs for high availability.",
			Category:   "reliability",
		})
	}
	return smells
}

func (d *Detector) checkNaming(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	hasUnderscore := 0
	hasDash := 0
	for _, r := range resources {
		if strings.Contains(r.Name, "_") {
			hasUnderscore++
		}
		if strings.Contains(r.Name, "-") {
			hasDash++
		}
	}
	if hasUnderscore > 0 && hasDash > 0 && len(resources) > 3 {
		smells = append(smells, Smell{
			Type:       SmellNamingInconsist,
			Severity:   "LOW",
			Resource:   "",
			Message:    fmt.Sprintf("Mixed naming conventions: %d resources use underscores, %d use dashes.", hasUnderscore, hasDash),
			Suggestion: "Adopt a consistent naming convention (e.g., snake_case or kebab-case).",
			Category:   "best-practice",
		})
	}
	return smells
}

func (d *Detector) checkSprawl(resources []parser.NormalizedResource) []Smell {
	var smells []Smell
	typeCounts := make(map[string]int)
	for _, r := range resources {
		typeCounts[r.Type]++
	}
	if len(typeCounts) > 15 {
		smells = append(smells, Smell{
			Type:       SmellResourceSprawl,
			Severity:   "MEDIUM",
			Resource:   "",
			Message:    fmt.Sprintf("Resource sprawl detected: %d different resource types in a single plan.", len(typeCounts)),
			Suggestion: "Consider splitting into modules or separate Terraform workspaces.",
			Category:   "best-practice",
		})
	}
	return smells
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// checkHardcodedValues detects secrets, IPs, and credentials hardcoded in resource values.
func (d *Detector) checkHardcodedValues(resources []parser.NormalizedResource) []Smell {
	var smells []Smell

	sensitiveFields := []string{
		"password", "secret", "api_key", "access_key", "secret_key",
		"private_key", "token", "credentials", "connection_string",
	}

	for _, r := range resources {
		if r.Values == nil {
			continue
		}
		for _, field := range sensitiveFields {
			if val, ok := r.Values[field]; ok {
				valStr := fmt.Sprintf("%v", val)
				// Skip empty, variable references, and placeholder values
				if valStr == "" || valStr == "<nil>" || strings.HasPrefix(valStr, "var.") || strings.HasPrefix(valStr, "data.") {
					continue
				}
				smells = append(smells, Smell{
					Type:       SmellHardcodedValues,
					Severity:   "CRITICAL",
					Resource:   r.Address,
					Message:    fmt.Sprintf("Resource %s has a hardcoded sensitive value in field %q.", r.Address, field),
					Suggestion: "Use variables, SSM Parameter Store, Secrets Manager, or Vault for sensitive values.",
					Category:   "security",
				})
			}
		}
	}
	return smells
}

// checkBackup detects database and storage resources without backup configuration.
func (d *Detector) checkBackup(resources []parser.NormalizedResource) []Smell {
	var smells []Smell

	backupChecks := map[string][]string{
		// AWS
		"aws_db_instance":     {"backup_retention_period"},
		"aws_rds_cluster":     {"backup_retention_period"},
		"aws_dynamodb_table":  {"point_in_time_recovery"},
		"aws_efs_file_system": {"lifecycle_policy"},
		// Azure
		"azurerm_mssql_database":   {"short_term_retention_policy"},
		"azurerm_cosmosdb_account": {"backup"},
		"azurerm_storage_account":  {"blob_properties"},
		// GCP
		"google_sql_database_instance": {"settings"},
	}

	for _, r := range resources {
		fields, ok := backupChecks[r.Type]
		if !ok || r.Values == nil {
			continue
		}
		hasBackup := false
		for _, field := range fields {
			if _, exists := r.Values[field]; exists {
				hasBackup = true
				break
			}
		}
		if !hasBackup {
			smells = append(smells, Smell{
				Type:       SmellNoBackup,
				Severity:   "HIGH",
				Resource:   r.Address,
				Message:    fmt.Sprintf("Resource %s has no backup configuration.", r.Address),
				Suggestion: "Enable automated backups with appropriate retention periods for data protection.",
				Category:   "reliability",
			})
		}
	}
	return smells
}

// checkModuleUsage detects large plans without module organization (monolith risk).
func (d *Detector) checkModuleUsage(resources []parser.NormalizedResource) []Smell {
	var smells []Smell

	// Count non-module resources (no "module." prefix in address)
	rootResources := 0
	for _, r := range resources {
		if !strings.HasPrefix(r.Address, "module.") {
			rootResources++
		}
	}

	totalResources := len(resources)

	// Monolith risk: too many resources at root level without modules
	if rootResources > 20 && totalResources > 0 {
		moduleRatio := float64(totalResources-rootResources) / float64(totalResources)
		if moduleRatio < 0.3 {
			smells = append(smells, Smell{
				Type:       SmellMonolith,
				Severity:   "MEDIUM",
				Resource:   "",
				Message:    fmt.Sprintf("Monolith risk: %d resources at root level with only %.0f%% in modules.", rootResources, moduleRatio*100),
				Suggestion: "Break infrastructure into reusable modules for better maintainability and testing.",
				Category:   "best-practice",
			})
		}
	}

	// No modules at all with significant resource count
	if totalResources > 10 && rootResources == totalResources {
		smells = append(smells, Smell{
			Type:       SmellNoModules,
			Severity:   "LOW",
			Resource:   "",
			Message:    fmt.Sprintf("All %d resources are defined at root level with no module usage.", totalResources),
			Suggestion: "Consider organizing related resources into Terraform modules for reusability.",
			Category:   "best-practice",
		})
	}

	return smells
}

func computeQualityScore(smells []Smell, _ int) float64 {
	if len(smells) == 0 {
		return 10.0
	}
	penalty := 0.0
	weights := map[string]float64{"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3, "INFO": 0.0}
	for _, s := range smells {
		if w, ok := weights[s.Severity]; ok {
			penalty += w
		}
	}
	score := 10.0 - penalty
	if score < 0 {
		score = 0
	}
	return score
}

func qualityLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "EXCELLENT"
	case score >= 7.0:
		return "GOOD"
	case score >= 5.0:
		return "FAIR"
	case score >= 3.0:
		return "POOR"
	default:
		return "CRITICAL"
	}
}

func topConcerns(smells []Smell) []string {
	catCount := make(map[string]int)
	for _, s := range smells {
		catCount[s.Category]++
	}
	var concerns []string
	for cat, count := range catCount {
		concerns = append(concerns, fmt.Sprintf("%s (%d issues)", cat, count))
	}
	sort.Strings(concerns)
	return concerns
}

func buildSmellSummary(result *DetectorResult) string {
	if len(result.Smells) == 0 {
		return "No design smells detected. Architecture quality is excellent."
	}
	return fmt.Sprintf("Detected %d design smells. Quality: %s (%.1f/10). Top concerns: %s.",
		len(result.Smells), result.QualityLevel, result.QualityScore,
		strings.Join(result.TopConcerns, ", "))
}

// FormatSmells produces a human-readable smell report.
func FormatSmells(result *DetectorResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Design Smell Report — Quality: %s (%.1f/10)\n\n",
		result.QualityLevel, result.QualityScore))

	if len(result.Smells) == 0 {
		sb.WriteString("No design smells detected.\n")
		return sb.String()
	}

	for _, s := range result.Smells {
		resource := s.Resource
		if resource == "" {
			resource = "(global)"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s — %s\n", s.Severity, string(s.Type), resource))
		sb.WriteString(fmt.Sprintf("  %s\n", s.Message))
		sb.WriteString(fmt.Sprintf("  Suggestion: %s\n\n", s.Suggestion))
	}

	sb.WriteString(fmt.Sprintf("Summary: %s\n", result.Summary))
	return sb.String()
}
