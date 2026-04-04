package fix

import "strings"

// ruleRequiredResources maps a Checkov/tfsec rule ID to the Terraform resource type
// that must be created (or referenced) to remediate it.
// Used to look up existing resources in the plan before the AI invents names.
var ruleRequiredResources = map[string]string{
	// Encryption — KMS
	"CKV_AWS_7":   "aws_kms_key", // CloudTrail KMS
	"CKV_AWS_18":  "aws_kms_key", // S3 bucket KMS
	"CKV_AWS_19":  "aws_kms_key", // SQS KMS
	"CKV_AWS_26":  "aws_kms_key", // SNS KMS
	"CKV_AWS_76":  "aws_kms_key", // Kinesis KMS
	"CKV_AWS_135": "aws_kms_key", // OpenSearch KMS
	"CKV_AWS_136": "aws_kms_key", // ECR KMS
	"CKV_AWS_158": "aws_kms_key", // CloudWatch log group KMS
	"CKV_AWS_163": "aws_kms_key", // EFS KMS
	"CKV_AWS_189": "aws_kms_key", // EBS default KMS
	"CKV_AWS_211": "aws_kms_key", // MSK KMS
	"CKV_AWS_219": "aws_kms_key", // DocDB KMS
	"CKV_AWS_227": "aws_kms_key", // RDS KMS
	"CKV_AWS_259": "aws_kms_key", // Secrets Manager KMS

	// API Gateway request validation
	"CKV2_AWS_53": "aws_api_gateway_request_validator",

	// API Gateway client certificate
	"CKV2_AWS_51": "aws_api_gateway_client_certificate",

	// CloudFront origin access
	"CKV_AWS_86": "aws_cloudfront_origin_access_identity",

	// WAF
	"CKV2_AWS_31": "aws_wafv2_web_acl",
	"CKV_AWS_192": "aws_wafv2_web_acl",
}

// ruleRelevantAttrs maps a rule ID to the subset of resource attributes that
// are meaningful for generating a fix. Used to truncate large current_config
// payloads before sending to the AI provider (Sprint 4).
var ruleRelevantAttrs = map[string][]string{
	"CKV_AWS_7":   {"kms_key_id", "name", "s3_bucket_name"},
	"CKV_AWS_18":  {"server_side_encryption_configuration", "bucket"},
	"CKV_AWS_19":  {"kms_master_key_id", "name"},
	"CKV_AWS_26":  {"kms_master_key_id", "name"},
	"CKV_AWS_51":  {"image_tag_mutability", "name"},
	"CKV_AWS_59":  {"rest_api_id", "resource_id", "http_method", "authorization", "api_key_required"},
	"CKV_AWS_86":  {"default_cache_behavior", "origin"},
	"CKV_AWS_120": {"stage_name", "cache_cluster_enabled", "cache_cluster_size", "rest_api_id"},
	"CKV_AWS_136": {"encryption_configuration", "name", "image_tag_mutability"},
	"CKV_AWS_158": {"kms_key_id", "name", "retention_in_days"},
	"CKV_AWS_225": {"method_path", "stage_name", "settings"},
	"CKV_AWS_338": {"retention_in_days", "name", "kms_key_id"},
	"CKV_AWS_336": {"container_definitions", "family", "requires_compatibilities"},
	"CKV2_AWS_51": {"stage_name", "client_certificate_id", "rest_api_id"},
	"CKV2_AWS_53": {"rest_api_id", "resource_id", "http_method", "authorization", "request_validator_id", "api_key_required"},
	"CKV2_AWS_71": {"domain_name", "subject_alternative_names", "domain_validation_options", "validation_method", "tags"},
}

// RequiredResourceType returns the Terraform resource type that must exist or be
// created to remediate the given rule. Returns "" if the rule has no known dependency.
func RequiredResourceType(ruleID string) string {
	return ruleRequiredResources[ruleID]
}

// RelevantAttributes returns the subset of resource config attributes relevant
// for fixing the given rule. Returns nil if no specific knowledge is available
// (in which case the caller should apply a generic truncation).
func RelevantAttributes(ruleID string) []string {
	return ruleRelevantAttrs[ruleID]
}

// CanonicalResourceName derives a deterministic Terraform resource name for a
// new resource that needs to be created to satisfy a fix dependency.
//
// The convention is:  <new_resource_type>.<logical_name_of_source>
//
// Examples:
//
//	("aws_cloudwatch_log_group.ecs",  "aws_kms_key")                    → "aws_kms_key.ecs"
//	("aws_api_gateway_method.proxy",  "aws_api_gateway_request_validator") → "aws_api_gateway_request_validator.proxy"
//	("module.vpc.aws_s3_bucket.logs", "aws_kms_key")                   → "aws_kms_key.logs"
func CanonicalResourceName(sourceAddr, newType string) string {
	// Take the last segment of the address (handles module paths).
	parts := strings.Split(sourceAddr, ".")
	logicalName := "default"
	if len(parts) >= 2 {
		logicalName = parts[len(parts)-1]
	}
	return newType + "." + logicalName
}

// TruncateConfig reduces a resource configuration map to the attributes most
// relevant to the given rule, protecting against AI provider token limit errors.
//
// If the rule has no specific knowledge, a generic cap of maxGenericAttrs
// non-nil attributes is applied.
func TruncateConfig(config map[string]interface{}, ruleID string) map[string]interface{} {
	if len(config) == 0 {
		return config
	}

	relevant := RelevantAttributes(ruleID)
	if len(relevant) > 0 {
		return keepAttrs(config, relevant)
	}

	return truncateGeneric(config, maxGenericAttrs)
}

const maxGenericAttrs = 20

// keepAttrs returns a new map containing only the listed attributes (if non-nil).
func keepAttrs(config map[string]interface{}, keys []string) map[string]interface{} {
	result := make(map[string]interface{}, len(keys))
	for _, k := range keys {
		if v, ok := config[k]; ok && v != nil {
			result[k] = v
		}
	}
	// If nothing survived (all were nil), fall back to the generic truncation
	// so the AI still has some context.
	if len(result) == 0 {
		return truncateGeneric(config, maxGenericAttrs)
	}
	return result
}

// truncateGeneric keeps up to max non-nil attributes from an arbitrary config map.
func truncateGeneric(config map[string]interface{}, max int) map[string]interface{} {
	result := make(map[string]interface{}, max)
	for k, v := range config {
		if v == nil {
			continue
		}
		result[k] = v
		if len(result) >= max {
			break
		}
	}
	return result
}
