// Package builtin provides a standalone, zero-dependency security scanner
// implemented in pure Go. It evaluates 43 CKV_AWS rules directly against
// a parsed Terraform plan, requiring no external binaries.
package builtin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// CheckFn evaluates a single rule against one resource. Returns a finding
// if the rule fires, or nil if the resource passes.
type CheckFn func(r parser.NormalizedResource) *rules.Finding

// Rule pairs a check function with its metadata.
type Rule struct {
	ID       string
	Severity string
	Category string
	Check    CheckFn
}

// All returns the full set of built-in CKV_AWS rules.
func All() []Rule {
	return allRules
}

// Scan parses planPath and evaluates all built-in rules, returning findings.
func Scan(planPath string) ([]rules.Finding, error) {
	data, err := os.ReadFile(planPath)
	if err != nil {
		return nil, fmt.Errorf("builtin scanner: read plan: %w", err)
	}

	var plan parser.TerraformPlan
	if err := json.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("builtin scanner: parse plan: %w", err)
	}

	p := parser.NewParser()
	resources := p.NormalizeResources(&plan)

	var findings []rules.Finding
	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" || r.Action == "delete" {
			continue
		}
		for _, rule := range allRules {
			if f := rule.Check(r); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func strVal(v map[string]interface{}, key string) string {
	if v == nil {
		return ""
	}
	if s, ok := v[key].(string); ok {
		return s
	}
	return ""
}

func boolVal(v map[string]interface{}, key string) bool {
	if v == nil {
		return false
	}
	switch b := v[key].(type) {
	case bool:
		return b
	case float64:
		return b != 0
	}
	return false
}

func isList(v map[string]interface{}, key string) bool {
	if v == nil {
		return false
	}
	arr, ok := v[key].([]interface{})
	return ok && len(arr) > 0
}

func finding(r parser.NormalizedResource, ruleID, severity, category, msg, remediation string) *rules.Finding {
	// Use the pt-BR message when available and the locale is active.
	if i18n.IsBR() {
		if translated, ok := messagesPTBR[ruleID]; ok {
			msg = translated
		}
	}
	return &rules.Finding{
		RuleID:      ruleID,
		Severity:    severity,
		Category:    category,
		Resource:    r.Address,
		Message:     msg,
		Remediation: remediation,
		Source:      "builtin",
	}
}

// ---------------------------------------------------------------------------
// Rule definitions
// ---------------------------------------------------------------------------

var allRules = []Rule{
	// ---- S3 ----------------------------------------------------------------
	{
		ID: "CKV_AWS_18", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_s3_bucket" {
				return nil
			}
			if !isList(r.Values, "logging") {
				return finding(r, "CKV_AWS_18", rules.SeverityMedium, rules.CategorySecurity,
					"S3 bucket does not have access logging enabled",
					"Add a logging { target_bucket = ... } block to the aws_s3_bucket resource.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_19", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_s3_bucket" {
				return nil
			}
			if !isList(r.Values, "server_side_encryption_configuration") {
				return finding(r, "CKV_AWS_19", rules.SeverityHigh, rules.CategorySecurity,
					"S3 bucket does not have server-side encryption enabled",
					"Add a server_side_encryption_configuration block with AES256 or aws:kms.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_20", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_s3_bucket" {
				return nil
			}
			acl := strVal(r.Values, "acl")
			if strings.Contains(acl, "public") {
				return finding(r, "CKV_AWS_20", rules.SeverityHigh, rules.CategorySecurity,
					fmt.Sprintf("S3 bucket has a public ACL (%q)", acl),
					"Remove the public ACL and use aws_s3_bucket_public_access_block instead.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_21", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_s3_bucket" {
				return nil
			}
			if !isList(r.Values, "versioning") {
				return finding(r, "CKV_AWS_21", rules.SeverityMedium, rules.CategorySecurity,
					"S3 bucket does not have versioning enabled",
					"Add versioning { enabled = true } to the aws_s3_bucket resource.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_57", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_s3_bucket_public_access_block" {
				return nil
			}
			if !boolVal(r.Values, "block_public_acls") || !boolVal(r.Values, "block_public_policy") ||
				!boolVal(r.Values, "ignore_public_acls") || !boolVal(r.Values, "restrict_public_buckets") {
				return finding(r, "CKV_AWS_57", rules.SeverityHigh, rules.CategorySecurity,
					"S3 public access block does not block all public access",
					"Set block_public_acls, block_public_policy, ignore_public_acls, and restrict_public_buckets to true.")
			}
			return nil
		},
	},
	// ---- RDS ---------------------------------------------------------------
	{
		ID: "CKV_AWS_16", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_db_instance" {
				return nil
			}
			ret, ok := r.Values["backup_retention_period"]
			if !ok {
				return finding(r, "CKV_AWS_16", rules.SeverityMedium, rules.CategorySecurity,
					"RDS instance has no backup retention period configured",
					"Set backup_retention_period to a value >= 7 days.")
			}
			if n, ok := ret.(float64); ok && n == 0 {
				return finding(r, "CKV_AWS_16", rules.SeverityMedium, rules.CategorySecurity,
					"RDS instance backup retention period is 0 (backups disabled)",
					"Set backup_retention_period to a value >= 7 days.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_23", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_db_instance" {
				return nil
			}
			if !boolVal(r.Values, "storage_encrypted") {
				return finding(r, "CKV_AWS_23", rules.SeverityHigh, rules.CategorySecurity,
					"RDS instance storage is not encrypted",
					"Set storage_encrypted = true and optionally specify kms_key_id.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_24", Severity: rules.SeverityHigh, Category: rules.CategoryReliability,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_db_instance" {
				return nil
			}
			if !boolVal(r.Values, "multi_az") {
				return finding(r, "CKV_AWS_24", rules.SeverityHigh, rules.CategoryReliability,
					"RDS instance is not configured for Multi-AZ deployment",
					"Set multi_az = true for production databases to enable automatic failover.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_25", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_db_instance" {
				return nil
			}
			if boolVal(r.Values, "publicly_accessible") {
				return finding(r, "CKV_AWS_25", rules.SeverityHigh, rules.CategorySecurity,
					"RDS instance is publicly accessible",
					"Set publicly_accessible = false and use a VPC security group for access control.")
			}
			return nil
		},
	},
	// ---- EC2 ---------------------------------------------------------------
	{
		ID: "CKV_AWS_79", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_instance" {
				return nil
			}
			opts, ok := r.Values["metadata_options"].([]interface{})
			if !ok || len(opts) == 0 {
				return finding(r, "CKV_AWS_79", rules.SeverityHigh, rules.CategorySecurity,
					"EC2 instance does not enforce IMDSv2 (metadata_options not configured)",
					"Add metadata_options { http_tokens = \"required\" http_endpoint = \"enabled\" }.")
			}
			if m, ok := opts[0].(map[string]interface{}); ok {
				if strVal(m, "http_tokens") != "required" {
					return finding(r, "CKV_AWS_79", rules.SeverityHigh, rules.CategorySecurity,
						"EC2 instance allows IMDSv1 (http_tokens is not \"required\")",
						"Set metadata_options { http_tokens = \"required\" } to enforce IMDSv2.")
				}
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_88", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_instance" {
				return nil
			}
			if boolVal(r.Values, "associate_public_ip_address") {
				return finding(r, "CKV_AWS_88", rules.SeverityMedium, rules.CategorySecurity,
					"EC2 instance has a public IP address associated",
					"Set associate_public_ip_address = false and use a NAT gateway for outbound access.")
			}
			return nil
		},
	},
	// ---- Security Groups ---------------------------------------------------
	{
		ID: "CKV_AWS_63", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			return checkOpenPort(r, "CKV_AWS_63", 22, "SSH")
		},
	},
	{
		ID: "CKV_AWS_64", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			return checkOpenPort(r, "CKV_AWS_64", 3389, "RDP")
		},
	},
	// ---- Lambda ------------------------------------------------------------
	{
		ID: "CKV_AWS_92", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_lambda_function" {
				return nil
			}
			if !isList(r.Values, "dead_letter_config") {
				return finding(r, "CKV_AWS_92", rules.SeverityMedium, rules.CategorySecurity,
					"Lambda function has no dead letter queue configured",
					"Add dead_letter_config { target_arn = aws_sqs_queue.dlq.arn } to capture failed invocations.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_117", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_lambda_function" {
				return nil
			}
			if !isList(r.Values, "vpc_config") {
				return finding(r, "CKV_AWS_117", rules.SeverityMedium, rules.CategorySecurity,
					"Lambda function is not deployed inside a VPC",
					"Add vpc_config { subnet_ids = [...] security_group_ids = [...] } to restrict network access.")
			}
			return nil
		},
	},
	// ---- CloudFront --------------------------------------------------------
	{
		ID: "CKV_AWS_91", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_cloudfront_distribution" {
				return nil
			}
			cert, ok := r.Values["viewer_certificate"].([]interface{})
			if !ok || len(cert) == 0 {
				return nil
			}
			if m, ok := cert[0].(map[string]interface{}); ok {
				if boolVal(m, "cloudfront_default_certificate") {
					return finding(r, "CKV_AWS_91", rules.SeverityMedium, rules.CategorySecurity,
						"CloudFront distribution uses the default CloudFront certificate (no custom TLS)",
						"Configure a custom ACM certificate in viewer_certificate and set minimum_protocol_version = TLSv1.2_2021.")
				}
			}
			return nil
		},
	},
	// ---- DynamoDB ----------------------------------------------------------
	{
		ID: "CKV_AWS_119", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_dynamodb_table" {
				return nil
			}
			pitr, ok := r.Values["point_in_time_recovery"].([]interface{})
			if !ok || len(pitr) == 0 {
				return finding(r, "CKV_AWS_119", rules.SeverityMedium, rules.CategorySecurity,
					"DynamoDB table does not have point-in-time recovery enabled",
					"Add point_in_time_recovery { enabled = true } to the aws_dynamodb_table resource.")
			}
			if m, ok := pitr[0].(map[string]interface{}); ok {
				if !boolVal(m, "enabled") {
					return finding(r, "CKV_AWS_119", rules.SeverityMedium, rules.CategorySecurity,
						"DynamoDB table point-in-time recovery is disabled",
						"Set point_in_time_recovery { enabled = true }.")
				}
			}
			return nil
		},
	},
	// ---- ElastiCache -------------------------------------------------------
	{
		ID: "CKV_AWS_28", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_elasticache_replication_group" {
				return nil
			}
			if !boolVal(r.Values, "transit_encryption_enabled") {
				return finding(r, "CKV_AWS_28", rules.SeverityHigh, rules.CategorySecurity,
					"ElastiCache replication group does not have in-transit encryption enabled",
					"Set transit_encryption_enabled = true.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_31", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_elasticache_replication_group" {
				return nil
			}
			if !boolVal(r.Values, "at_rest_encryption_enabled") {
				return finding(r, "CKV_AWS_31", rules.SeverityHigh, rules.CategorySecurity,
					"ElastiCache replication group does not have at-rest encryption enabled",
					"Set at_rest_encryption_enabled = true.")
			}
			return nil
		},
	},
	// ---- CloudWatch --------------------------------------------------------
	{
		ID: "CKV_AWS_158", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_cloudwatch_log_group" {
				return nil
			}
			if strVal(r.Values, "kms_key_id") == "" {
				return finding(r, "CKV_AWS_158", rules.SeverityMedium, rules.CategorySecurity,
					"CloudWatch log group is not encrypted with a KMS key",
					"Set kms_key_id = aws_kms_key.<name>.arn on the aws_cloudwatch_log_group resource.")
			}
			return nil
		},
	},
	// ---- EKS ---------------------------------------------------------------
	{
		ID: "CKV_AWS_58", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_eks_cluster" {
				return nil
			}
			enc, ok := r.Values["encryption_config"].([]interface{})
			if !ok || len(enc) == 0 {
				return finding(r, "CKV_AWS_58", rules.SeverityHigh, rules.CategorySecurity,
					"EKS cluster does not have secrets encryption configured",
					"Add an encryption_config block with provider.key_arn and resources = [\"secrets\"].")
			}
			m, ok := enc[0].(map[string]interface{})
			if !ok {
				return finding(r, "CKV_AWS_58", rules.SeverityHigh, rules.CategorySecurity,
					"EKS cluster does not have secrets encryption configured",
					"Add an encryption_config block with provider.key_arn and resources = [\"secrets\"].")
			}
			// Verify resources list contains "secrets"
			hasSecrets := false
			if resList, ok := m["resources"].([]interface{}); ok {
				for _, res := range resList {
					if s, ok := res.(string); ok && s == "secrets" {
						hasSecrets = true
						break
					}
				}
			}
			// Verify provider key_arn is non-empty
			hasKeyARN := false
			if provList, ok := m["provider"].([]interface{}); ok && len(provList) > 0 {
				if pm, ok := provList[0].(map[string]interface{}); ok {
					hasKeyARN = strVal(pm, "key_arn") != ""
				}
			}
			if !hasSecrets || !hasKeyARN {
				return finding(r, "CKV_AWS_58", rules.SeverityHigh, rules.CategorySecurity,
					"EKS cluster encryption_config is missing key_arn or does not encrypt secrets",
					"Ensure encryption_config has provider.key_arn set and resources includes \"secrets\".")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_39", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_eks_cluster" {
				return nil
			}
			vpc, ok := r.Values["vpc_config"].([]interface{})
			if !ok || len(vpc) == 0 {
				return nil
			}
			m, ok := vpc[0].(map[string]interface{})
			if !ok {
				return nil
			}
			if !boolVal(m, "endpoint_public_access") {
				return nil
			}
			// Public access enabled — check CIDRs
			cidrs, ok := m["public_access_cidrs"].([]interface{})
			if !ok || len(cidrs) == 0 {
				return finding(r, "CKV_AWS_39", rules.SeverityHigh, rules.CategorySecurity,
					"EKS cluster API endpoint is publicly accessible with no CIDR restrictions",
					"Set endpoint_public_access = false or restrict public_access_cidrs to trusted CIDRs.")
			}
			for _, c := range cidrs {
				if s, ok := c.(string); ok && (s == "0.0.0.0/0" || s == "::/0") {
					return finding(r, "CKV_AWS_39", rules.SeverityHigh, rules.CategorySecurity,
						"EKS cluster API endpoint is publicly accessible from any IP (0.0.0.0/0)",
						"Set endpoint_public_access = false or restrict public_access_cidrs to trusted CIDRs.")
				}
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_37", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_eks_cluster" {
				return nil
			}
			logTypes, ok := r.Values["enabled_cluster_log_types"].([]interface{})
			if !ok {
				return finding(r, "CKV_AWS_37", rules.SeverityMedium, rules.CategorySecurity,
					"EKS cluster does not have api and audit logging enabled",
					"Set enabled_cluster_log_types to include \"api\" and \"audit\".")
			}
			hasAPI, hasAudit := false, false
			for _, lt := range logTypes {
				if s, ok := lt.(string); ok {
					switch s {
					case "api":
						hasAPI = true
					case "audit":
						hasAudit = true
					}
				}
			}
			if !hasAPI || !hasAudit {
				return finding(r, "CKV_AWS_37", rules.SeverityMedium, rules.CategorySecurity,
					"EKS cluster does not have api and audit logging enabled",
					"Set enabled_cluster_log_types to include \"api\" and \"audit\".")
			}
			return nil
		},
	},
	// ---- ECS ---------------------------------------------------------------
	{
		ID: "CKV_AWS_97", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_ecs_task_definition" {
				return nil
			}
			if strVal(r.Values, "network_mode") == "host" {
				return finding(r, "CKV_AWS_97", rules.SeverityHigh, rules.CategorySecurity,
					"ECS task definition uses host network mode",
					"Set network_mode to \"awsvpc\" or \"bridge\" instead of \"host\".")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_336", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_ecs_task_definition" {
				return nil
			}
			// container_definitions may be a raw JSON string or a slice
			containsSecretKey := func(raw string) bool {
				return strings.Contains(raw, "AWS_ACCESS_KEY_ID") ||
					strings.Contains(raw, "AWS_SECRET_ACCESS_KEY")
			}
			switch v := r.Values["container_definitions"].(type) {
			case string:
				if containsSecretKey(v) {
					return finding(r, "CKV_AWS_336", rules.SeverityCritical, rules.CategorySecurity,
						"ECS task definition container_definitions contains AWS credential environment variables",
						"Remove AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from container env vars; use IAM roles instead.")
				}
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok && containsSecretKey(s) {
						return finding(r, "CKV_AWS_336", rules.SeverityCritical, rules.CategorySecurity,
							"ECS task definition container_definitions contains AWS credential environment variables",
							"Remove AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY from container env vars; use IAM roles instead.")
					}
				}
			}
			return nil
		},
	},
	// ---- ECR ---------------------------------------------------------------
	{
		ID: "CKV_AWS_32", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_ecr_repository" {
				return nil
			}
			scanCfg, ok := r.Values["image_scanning_configuration"].([]interface{})
			if !ok || len(scanCfg) == 0 {
				return finding(r, "CKV_AWS_32", rules.SeverityMedium, rules.CategorySecurity,
					"ECR repository does not have image scanning on push enabled",
					"Add image_scanning_configuration { scan_on_push = true } to the aws_ecr_repository resource.")
			}
			if m, ok := scanCfg[0].(map[string]interface{}); ok {
				if !boolVal(m, "scan_on_push") {
					return finding(r, "CKV_AWS_32", rules.SeverityMedium, rules.CategorySecurity,
						"ECR repository does not have image scanning on push enabled",
						"Set scan_on_push = true inside image_scanning_configuration.")
				}
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_136", Severity: rules.SeverityLow, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_ecr_repository" {
				return nil
			}
			if strVal(r.Values, "image_tag_mutability") != "IMMUTABLE" {
				return finding(r, "CKV_AWS_136", rules.SeverityLow, rules.CategorySecurity,
					"ECR repository allows mutable image tags",
					"Set image_tag_mutability = \"IMMUTABLE\" to prevent tag overwriting.")
			}
			return nil
		},
	},
	// ---- SQS ---------------------------------------------------------------
	{
		ID: "CKV_AWS_27", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_sqs_queue" {
				return nil
			}
			if strVal(r.Values, "kms_master_key_id") == "" && !boolVal(r.Values, "sqs_managed_sse_enabled") {
				return finding(r, "CKV_AWS_27", rules.SeverityMedium, rules.CategorySecurity,
					"SQS queue is not encrypted at rest",
					"Set kms_master_key_id or enable sqs_managed_sse_enabled = true.")
			}
			return nil
		},
	},
	// ---- SNS ---------------------------------------------------------------
	{
		ID: "CKV_AWS_26", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_sns_topic" {
				return nil
			}
			if strVal(r.Values, "kms_master_key_id") == "" {
				return finding(r, "CKV_AWS_26", rules.SeverityMedium, rules.CategorySecurity,
					"SNS topic is not encrypted with a KMS key",
					"Set kms_master_key_id on the aws_sns_topic resource.")
			}
			return nil
		},
	},
	// ---- Secrets Manager ---------------------------------------------------
	{
		ID: "CKV_AWS_149", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_secretsmanager_secret" {
				return nil
			}
			if strVal(r.Values, "kms_key_id") == "" {
				return finding(r, "CKV_AWS_149", rules.SeverityMedium, rules.CategorySecurity,
					"Secrets Manager secret is not encrypted with a customer-managed KMS key",
					"Set kms_key_id on the aws_secretsmanager_secret resource.")
			}
			return nil
		},
	},
	// ---- CloudTrail --------------------------------------------------------
	{
		ID: "CKV_AWS_35", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_cloudtrail" {
				return nil
			}
			if strVal(r.Values, "kms_key_id") == "" {
				return finding(r, "CKV_AWS_35", rules.SeverityHigh, rules.CategorySecurity,
					"CloudTrail trail is not encrypted with a KMS key",
					"Set kms_key_id on the aws_cloudtrail resource.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_36", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_cloudtrail" {
				return nil
			}
			if !boolVal(r.Values, "enable_log_file_validation") {
				return finding(r, "CKV_AWS_36", rules.SeverityMedium, rules.CategorySecurity,
					"CloudTrail trail does not have log file validation enabled",
					"Set enable_log_file_validation = true on the aws_cloudtrail resource.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_67", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_cloudtrail" {
				return nil
			}
			if strVal(r.Values, "s3_bucket_name") == "" {
				return finding(r, "CKV_AWS_67", rules.SeverityMedium, rules.CategorySecurity,
					"CloudTrail trail does not have an S3 bucket configured for log storage",
					"Set s3_bucket_name on the aws_cloudtrail resource.")
			}
			return nil
		},
	},
	// ---- IAM ---------------------------------------------------------------
	{
		ID: "CKV_AWS_40", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_iam_user_policy" {
				return nil
			}
			// Inline user policies are unconditionally flagged.
			return finding(r, "CKV_AWS_40", rules.SeverityMedium, rules.CategorySecurity,
				"IAM inline policy attached directly to a user",
				"Attach policies to IAM groups or roles instead of directly to users.")
		},
	},
	{
		ID: "CKV_AWS_60", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_iam_policy" {
				return nil
			}
			if hasWildcardAdminStatement(strVal(r.Values, "policy")) {
				return finding(r, "CKV_AWS_60", rules.SeverityCritical, rules.CategorySecurity,
					"IAM policy grants wildcard admin permissions (Action=* + Resource=*)",
					"Restrict the policy to the minimum required actions and resources.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_62", Severity: rules.SeverityCritical, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_iam_role_policy" {
				return nil
			}
			if hasWildcardAdminStatement(strVal(r.Values, "policy")) {
				return finding(r, "CKV_AWS_62", rules.SeverityCritical, rules.CategorySecurity,
					"IAM role inline policy grants wildcard admin permissions (Action=* + Resource=*)",
					"Restrict the policy to the minimum required actions and resources.")
			}
			return nil
		},
	},
	// ---- OpenSearch / Elasticsearch ----------------------------------------
	{
		ID: "CKV_AWS_84", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_opensearch_domain" && r.Type != "aws_elasticsearch_domain" {
				return nil
			}
			logOpts, ok := r.Values["log_publishing_options"].([]interface{})
			if !ok || len(logOpts) == 0 {
				return finding(r, "CKV_AWS_84", rules.SeverityMedium, rules.CategorySecurity,
					"OpenSearch/Elasticsearch domain does not have AUDIT_LOGS publishing enabled",
					"Add a log_publishing_options block with log_type = \"AUDIT_LOGS\" and enabled = true.")
			}
			for _, item := range logOpts {
				m, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				if strVal(m, "log_type") == "AUDIT_LOGS" {
					enabled, hasKey := m["enabled"]
					// enabled defaults to true when not set; only fail if explicitly false
					if !hasKey {
						return nil
					}
					if b, ok := enabled.(bool); ok && !b {
						break
					}
					return nil
				}
			}
			return finding(r, "CKV_AWS_84", rules.SeverityMedium, rules.CategorySecurity,
				"OpenSearch/Elasticsearch domain does not have AUDIT_LOGS publishing enabled",
				"Add a log_publishing_options block with log_type = \"AUDIT_LOGS\" and enabled = true.")
		},
	},
	{
		ID: "CKV_AWS_137", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_opensearch_domain" && r.Type != "aws_elasticsearch_domain" {
				return nil
			}
			ear, ok := r.Values["encrypt_at_rest"].([]interface{})
			if !ok || len(ear) == 0 {
				return finding(r, "CKV_AWS_137", rules.SeverityHigh, rules.CategorySecurity,
					"OpenSearch/Elasticsearch domain does not have encryption at rest enabled",
					"Add encrypt_at_rest { enabled = true } to the domain resource.")
			}
			if m, ok := ear[0].(map[string]interface{}); ok {
				if !boolVal(m, "enabled") {
					return finding(r, "CKV_AWS_137", rules.SeverityHigh, rules.CategorySecurity,
						"OpenSearch/Elasticsearch domain does not have encryption at rest enabled",
						"Set encrypt_at_rest { enabled = true }.")
				}
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_148", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_opensearch_domain" && r.Type != "aws_elasticsearch_domain" {
				return nil
			}
			policy := strVal(r.Values, "access_policies")
			if policy == "" {
				return nil
			}
			// Detect open principal without a Condition block.
			// A policy with Principal:* or Principal:{AWS:*} AND no Condition is dangerous.
			hasOpenPrincipal := strings.Contains(policy, `"Principal":"*"`) ||
				strings.Contains(policy, `"Principal": "*"`) ||
				strings.Contains(policy, `"AWS":"*"`) ||
				strings.Contains(policy, `"AWS": "*"`)
			hasCondition := strings.Contains(policy, `"Condition"`)
			if hasOpenPrincipal && !hasCondition {
				return finding(r, "CKV_AWS_148", rules.SeverityHigh, rules.CategorySecurity,
					"OpenSearch/Elasticsearch domain access policy allows unrestricted principal (*)",
					"Restrict access_policies to specific principals or add a Condition block.")
			}
			return nil
		},
	},
	// ---- RDS Cluster -------------------------------------------------------
	{
		ID: "CKV_AWS_96", Severity: rules.SeverityMedium, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_rds_cluster" {
				return nil
			}
			if !boolVal(r.Values, "iam_database_authentication_enabled") {
				return finding(r, "CKV_AWS_96", rules.SeverityMedium, rules.CategorySecurity,
					"RDS cluster does not have IAM database authentication enabled",
					"Set iam_database_authentication_enabled = true on the aws_rds_cluster resource.")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_162", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_rds_cluster" {
				return nil
			}
			if !boolVal(r.Values, "storage_encrypted") {
				return finding(r, "CKV_AWS_162", rules.SeverityHigh, rules.CategorySecurity,
					"RDS cluster storage is not encrypted",
					"Set storage_encrypted = true on the aws_rds_cluster resource.")
			}
			return nil
		},
	},
	// ---- MSK ---------------------------------------------------------------
	{
		ID: "CKV_AWS_80", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_msk_cluster" {
				return nil
			}
			encInfo, ok := r.Values["encryption_info"].([]interface{})
			if !ok || len(encInfo) == 0 {
				return finding(r, "CKV_AWS_80", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have in-transit encryption configured",
					"Set encryption_info.encryption_in_transit.client_broker to \"TLS\" or \"TLS_PLAINTEXT\".")
			}
			m, ok := encInfo[0].(map[string]interface{})
			if !ok {
				return finding(r, "CKV_AWS_80", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have in-transit encryption configured",
					"Set encryption_info.encryption_in_transit.client_broker to \"TLS\" or \"TLS_PLAINTEXT\".")
			}
			inTransit, ok := m["encryption_in_transit"].([]interface{})
			if !ok || len(inTransit) == 0 {
				return finding(r, "CKV_AWS_80", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have in-transit encryption configured",
					"Set encryption_info.encryption_in_transit.client_broker to \"TLS\" or \"TLS_PLAINTEXT\".")
			}
			itm, ok := inTransit[0].(map[string]interface{})
			if !ok {
				return finding(r, "CKV_AWS_80", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster in-transit encryption is not properly configured",
					"Set client_broker to \"TLS\" or \"TLS_PLAINTEXT\".")
			}
			if strVal(itm, "client_broker") == "PLAINTEXT" {
				return finding(r, "CKV_AWS_80", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster in-transit encryption client_broker is set to PLAINTEXT",
					"Set client_broker to \"TLS\" or \"TLS_PLAINTEXT\".")
			}
			return nil
		},
	},
	{
		ID: "CKV_AWS_81", Severity: rules.SeverityHigh, Category: rules.CategorySecurity,
		Check: func(r parser.NormalizedResource) *rules.Finding {
			if r.Type != "aws_msk_cluster" {
				return nil
			}
			encInfo, ok := r.Values["encryption_info"].([]interface{})
			if !ok || len(encInfo) == 0 {
				return finding(r, "CKV_AWS_81", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have at-rest encryption with a KMS key",
					"Set encryption_info.encryption_at_rest.data_volume_kms_key_id.")
			}
			m, ok := encInfo[0].(map[string]interface{})
			if !ok {
				return finding(r, "CKV_AWS_81", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have at-rest encryption with a KMS key",
					"Set encryption_info.encryption_at_rest.data_volume_kms_key_id.")
			}
			encAtRest, ok := m["encryption_at_rest"].([]interface{})
			if !ok || len(encAtRest) == 0 {
				return finding(r, "CKV_AWS_81", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have at-rest encryption with a KMS key",
					"Set encryption_info.encryption_at_rest.data_volume_kms_key_id.")
			}
			earm, ok := encAtRest[0].(map[string]interface{})
			if !ok || strVal(earm, "data_volume_kms_key_id") == "" {
				return finding(r, "CKV_AWS_81", rules.SeverityHigh, rules.CategorySecurity,
					"MSK cluster does not have at-rest encryption with a KMS key",
					"Set encryption_info.encryption_at_rest.data_volume_kms_key_id.")
			}
			return nil
		},
	},
}

// hasWildcardAdminStatement returns true when a JSON IAM policy document contains
// at least one statement with Effect=Allow, Action=* (or ["*"]), Resource=* (or ["*"]).
// The check is intentionally permissive — string-contains — to avoid a full JSON
// decode in the hot path while still catching the most dangerous patterns.
func hasWildcardAdminStatement(policyJSON string) bool {
	if !strings.Contains(policyJSON, `"Allow"`) {
		return false
	}
	hasWildcardAction := strings.Contains(policyJSON, `"Action":"*"`) ||
		strings.Contains(policyJSON, `"Action":["*"]`) ||
		strings.Contains(policyJSON, `"Action": "*"`) ||
		strings.Contains(policyJSON, `"Action": ["*"]`)
	hasWildcardResource := strings.Contains(policyJSON, `"Resource":"*"`) ||
		strings.Contains(policyJSON, `"Resource":["*"]`) ||
		strings.Contains(policyJSON, `"Resource": "*"`) ||
		strings.Contains(policyJSON, `"Resource": ["*"]`)
	return hasWildcardAction && hasWildcardResource
}

// checkOpenPort checks whether an aws_security_group or aws_security_group_rule
// allows unrestricted inbound access on the given port.
func checkOpenPort(r parser.NormalizedResource, ruleID string, port int, proto string) *rules.Finding {
	if r.Type != "aws_security_group" && r.Type != "aws_security_group_rule" {
		return nil
	}

	check := func(ingress interface{}) bool {
		m, ok := ingress.(map[string]interface{})
		if !ok {
			return false
		}
		// Port range check
		from, _ := m["from_port"].(float64)
		to, _ := m["to_port"].(float64)
		if !(float64(port) >= from && float64(port) <= to) {
			return false
		}
		// CIDR check
		for _, k := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
			if cidrs, ok := m[k].([]interface{}); ok {
				for _, c := range cidrs {
					if s, ok := c.(string); ok && (s == "0.0.0.0/0" || s == "::/0") {
						return true
					}
				}
			}
		}
		return false
	}

	// aws_security_group has an "ingress" list
	if r.Type == "aws_security_group" {
		ingresses, ok := r.Values["ingress"].([]interface{})
		if !ok {
			return nil
		}
		for _, ing := range ingresses {
			if check(ing) {
				return finding(r, ruleID, rules.SeverityHigh, rules.CategorySecurity,
					fmt.Sprintf("Security group allows unrestricted %s access (port %d) from the internet", proto, port),
					fmt.Sprintf("Restrict the %s ingress rule to specific trusted CIDR ranges instead of 0.0.0.0/0.", proto))
			}
		}
		return nil
	}

	// aws_security_group_rule with type = "ingress"
	if strVal(r.Values, "type") == "ingress" && check(r.Values) {
		return finding(r, ruleID, rules.SeverityHigh, rules.CategorySecurity,
			fmt.Sprintf("Security group rule allows unrestricted %s access (port %d) from the internet", proto, port),
			fmt.Sprintf("Restrict the %s ingress rule to specific trusted CIDR ranges instead of 0.0.0.0/0.", proto))
	}
	return nil
}
