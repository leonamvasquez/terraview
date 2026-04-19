// Package builtin provides a standalone, zero-dependency security scanner
// implemented in pure Go. It evaluates 20 CKV_AWS rules directly against
// a parsed Terraform plan, requiring no external binaries.
package builtin

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
