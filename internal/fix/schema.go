package fix

import (
	"fmt"
	"sort"
	"strings"
)

// resourceSchemas is a curated whitelist of valid top-level attributes and
// nested block names for the AWS resource types most often touched by fix
// suggestions. The list is intentionally narrow: only types where AI
// hallucinations have caused real failures (e.g. inventing `web_acl_arn` on
// `aws_lb`, where WAF association is a separate `aws_wafv2_web_acl_association`
// resource) — for unknown types we fall through and accept anything.
//
// Source: HashiCorp Terraform AWS provider docs, 2026.
var resourceSchemas = map[string]map[string]struct{}{
	"aws_s3_bucket": setOf(
		"bucket", "bucket_prefix", "force_destroy", "object_lock_enabled", "tags", "tags_all",
		// Legacy attributes (AWS provider <v4) — still accepted, but modern fixes
		// should prefer the dedicated resources (aws_s3_bucket_versioning, etc.).
		"acl", "versioning", "logging", "policy", "website", "cors_rule", "lifecycle_rule",
		"replication_configuration", "server_side_encryption_configuration", "object_lock_configuration",
		"acceleration_status", "request_payer", "grant",
	),
	"aws_kms_key": setOf(
		"description", "key_usage", "customer_master_key_spec", "policy", "deletion_window_in_days",
		"is_enabled", "enable_key_rotation", "rotation_period_in_days", "multi_region", "tags", "tags_all",
		"bypass_policy_lockout_safety_check", "custom_key_store_id", "xks_key_id",
	),
	"aws_kms_alias": setOf(
		"name", "name_prefix", "target_key_id",
	),
	"aws_iam_role": setOf(
		"name", "name_prefix", "path", "description", "assume_role_policy", "max_session_duration",
		"permissions_boundary", "force_detach_policies", "managed_policy_arns", "inline_policy", "tags", "tags_all",
	),
	"aws_iam_policy": setOf(
		"name", "name_prefix", "path", "description", "policy", "tags", "tags_all",
	),
	"aws_iam_role_policy": setOf(
		"name", "name_prefix", "policy", "role",
	),
	"aws_lambda_function": setOf(
		"function_name", "role", "handler", "runtime", "filename", "source_code_hash",
		"s3_bucket", "s3_key", "s3_object_version", "image_uri", "package_type", "image_config",
		"description", "environment", "ephemeral_storage", "kms_key_arn", "memory_size", "publish",
		"reserved_concurrent_executions", "timeout", "architectures", "code_signing_config_arn",
		"dead_letter_config", "file_system_config", "layers", "logging_config", "snap_start",
		"tracing_config", "vpc_config", "tags", "tags_all", "skip_destroy", "replace_security_groups_on_destroy",
		"replacement_security_group_ids",
	),
	"aws_lb": setOf(
		"name", "name_prefix", "internal", "load_balancer_type", "security_groups", "subnet_mapping",
		"subnets", "idle_timeout", "connection_logs", "access_logs", "enable_deletion_protection",
		"enable_cross_zone_load_balancing", "enable_http2", "enable_waf_fail_open", "ip_address_type",
		"customer_owned_ipv4_pool", "drop_invalid_header_fields", "preserve_host_header",
		"desync_mitigation_mode", "enforce_security_group_inbound_rules_on_private_link_traffic",
		"client_keep_alive", "dns_record_client_routing_policy", "xff_header_processing_mode",
		"tags", "tags_all", "enable_xff_client_port", "enable_zonal_shift", "enable_tls_version_and_cipher_suite_headers",
	),
	"aws_security_group": setOf(
		"name", "name_prefix", "description", "vpc_id", "ingress", "egress",
		"revoke_rules_on_delete", "tags", "tags_all",
	),
	"aws_ecs_task_definition": setOf(
		"family", "container_definitions", "cpu", "memory", "execution_role_arn", "task_role_arn",
		"network_mode", "ipc_mode", "pid_mode", "requires_compatibilities", "runtime_platform",
		"placement_constraints", "proxy_configuration", "volume", "ephemeral_storage", "inference_accelerator",
		"skip_destroy", "track_latest", "tags", "tags_all",
	),
	"aws_ecs_service": setOf(
		"name", "cluster", "task_definition", "desired_count", "launch_type", "capacity_provider_strategy",
		"deployment_circuit_breaker", "deployment_controller", "deployment_maximum_percent",
		"deployment_minimum_healthy_percent", "enable_ecs_managed_tags", "enable_execute_command",
		"force_new_deployment", "health_check_grace_period_seconds", "iam_role", "load_balancer",
		"network_configuration", "ordered_placement_strategy", "placement_constraints", "platform_version",
		"propagate_tags", "scheduling_strategy", "service_connect_configuration", "service_registries",
		"tags", "tags_all", "triggers", "wait_for_steady_state", "alarms", "force_delete", "availability_zone_rebalancing",
		"sigint_signal_supported", "volume_configuration", "vpc_lattice_configurations",
	),
	"aws_db_instance": setOf(
		"identifier", "identifier_prefix", "allocated_storage", "max_allocated_storage", "storage_type",
		"storage_throughput", "iops", "engine", "engine_version", "instance_class", "username", "password",
		"manage_master_user_password", "master_user_secret_kms_key_id", "db_name", "db_subnet_group_name",
		"parameter_group_name", "option_group_name", "vpc_security_group_ids", "publicly_accessible",
		"availability_zone", "multi_az", "backup_retention_period", "backup_window", "maintenance_window",
		"copy_tags_to_snapshot", "deletion_protection", "skip_final_snapshot", "final_snapshot_identifier",
		"storage_encrypted", "kms_key_id", "iam_database_authentication_enabled", "performance_insights_enabled",
		"performance_insights_kms_key_id", "performance_insights_retention_period", "monitoring_interval",
		"monitoring_role_arn", "enabled_cloudwatch_logs_exports", "auto_minor_version_upgrade",
		"allow_major_version_upgrade", "apply_immediately", "ca_cert_identifier", "character_set_name",
		"db_subnet_group_name", "delete_automated_backups", "domain", "domain_iam_role_name", "license_model",
		"nchar_character_set_name", "network_type", "port", "replicate_source_db", "restore_to_point_in_time",
		"s3_import", "snapshot_identifier", "tags", "tags_all", "timeouts", "timezone", "blue_green_update",
		"replica_mode", "custom_iam_instance_profile", "engine_lifecycle_support", "manage_master_user_password",
		"db_cluster_snapshot_identifier",
	),
	"aws_dynamodb_table": setOf(
		"name", "billing_mode", "hash_key", "range_key", "read_capacity", "write_capacity",
		"attribute", "ttl", "local_secondary_index", "global_secondary_index", "stream_enabled",
		"stream_view_type", "server_side_encryption", "point_in_time_recovery", "import_table",
		"replica", "restore_date_time", "restore_source_name", "restore_to_latest_time",
		"deletion_protection_enabled", "table_class", "tags", "tags_all", "timeouts", "on_demand_throughput",
		"warm_throughput",
	),
	"aws_ecr_repository": setOf(
		"name", "image_tag_mutability", "encryption_configuration", "image_scanning_configuration",
		"force_delete", "tags", "tags_all", "timeouts",
	),
	"aws_sns_topic": setOf(
		"name", "name_prefix", "display_name", "policy", "delivery_policy", "application_success_feedback_role_arn",
		"application_success_feedback_sample_rate", "application_failure_feedback_role_arn",
		"http_success_feedback_role_arn", "http_success_feedback_sample_rate", "http_failure_feedback_role_arn",
		"kms_master_key_id", "signature_version", "tracing_config", "fifo_topic", "archive_policy",
		"content_based_deduplication", "lambda_success_feedback_role_arn", "lambda_success_feedback_sample_rate",
		"lambda_failure_feedback_role_arn", "sqs_success_feedback_role_arn", "sqs_success_feedback_sample_rate",
		"sqs_failure_feedback_role_arn", "firehose_success_feedback_role_arn",
		"firehose_success_feedback_sample_rate", "firehose_failure_feedback_role_arn", "tags", "tags_all",
		"fifo_throughput_scope",
	),
	"aws_sqs_queue": setOf(
		"name", "name_prefix", "delay_seconds", "max_message_size", "message_retention_seconds",
		"receive_wait_time_seconds", "visibility_timeout_seconds", "policy", "redrive_policy",
		"redrive_allow_policy", "fifo_queue", "content_based_deduplication", "kms_master_key_id",
		"kms_data_key_reuse_period_seconds", "sqs_managed_sse_enabled", "deduplication_scope",
		"fifo_throughput_limit", "tags", "tags_all",
	),
	"aws_cloudtrail": setOf(
		"name", "s3_bucket_name", "s3_key_prefix", "cloud_watch_logs_role_arn", "cloud_watch_logs_group_arn",
		"enable_logging", "include_global_service_events", "is_multi_region_trail", "is_organization_trail",
		"sns_topic_name", "enable_log_file_validation", "kms_key_id", "advanced_event_selector",
		"event_selector", "insight_selector", "tags", "tags_all",
	),
	"aws_cloudwatch_log_group": setOf(
		"name", "name_prefix", "retention_in_days", "kms_key_id", "log_group_class", "skip_destroy",
		"tags", "tags_all",
	),
}

func setOf(items ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(items))
	for _, it := range items {
		m[it] = struct{}{}
	}
	return m
}

// KnownAttributes returns the curated set of valid top-level attributes for the
// given resource type. Returns nil if the type is not in the schema map — in
// that case validation is skipped (permissive default).
func KnownAttributes(resourceType string) []string {
	s, ok := resourceSchemas[resourceType]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// extractTopLevelAttrs scans an HCL resource block and returns the set of
// top-level attribute identifiers and nested block names (depth 1 inside the
// outer `resource "TYPE" "NAME" { ... }`). String/comment/heredoc-aware.
//
// Identifiers found by detecting either `name =` (attribute) or `name {`
// (block) on lines where the brace depth (relative to the resource block) is 1.
func extractTopLevelAttrs(hcl string) []string {
	var out []string
	seen := make(map[string]struct{})

	depth := 0
	heredocMarker := ""
	lines := strings.Split(hcl, "\n")

	for _, line := range lines {
		// Heredoc handling
		if heredocMarker != "" {
			if strings.TrimSpace(line) == heredocMarker {
				heredocMarker = ""
			}
			continue
		}
		if idx := strings.Index(line, "<<"); idx >= 0 {
			marker := strings.TrimSpace(line[idx+2:])
			marker = strings.TrimPrefix(marker, "-")
			if h := strings.IndexByte(marker, '#'); h >= 0 {
				marker = strings.TrimSpace(marker[:h])
			}
			if marker != "" && !strings.ContainsAny(marker, " \t{\"") {
				heredocMarker = marker
			}
		}

		// At depth==1 (inside the resource block, before any nested block),
		// detect `ident = ...` or `ident {`.
		if depth == 1 {
			if name := identAtLineStart(line); name != "" {
				if _, ok := seen[name]; !ok {
					seen[name] = struct{}{}
					out = append(out, name)
				}
			}
		}
		depth += countBraces(line)
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

// identAtLineStart extracts the attribute or block identifier from a line of
// the form `<spaces><ident>(<spaces>)?(=|{)...`. Returns empty if not found.
func identAtLineStart(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return ""
	}
	end := 0
	for end < len(trimmed) {
		ch := trimmed[end]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			end++
			continue
		}
		break
	}
	if end == 0 {
		return ""
	}
	ident := trimmed[:end]
	rest := strings.TrimLeft(trimmed[end:], " \t")
	if strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "{") {
		// Skip the literal `resource` token from the outer header line.
		if ident == "resource" {
			return ""
		}
		return ident
	}
	return ""
}

// extractResourceTypeFromHCL returns the resource type from the first
// `resource "TYPE" "NAME" {` line in hcl, or "" if the block header is missing.
func extractResourceTypeFromHCL(hcl string) string {
	for _, line := range strings.Split(hcl, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "resource ") {
			continue
		}
		// resource "TYPE" "NAME" {
		first := strings.IndexByte(t, '"')
		if first < 0 {
			return ""
		}
		second := strings.IndexByte(t[first+1:], '"')
		if second < 0 {
			return ""
		}
		return t[first+1 : first+1+second]
	}
	return ""
}

// ValidateAttributes verifies that every top-level attribute or block in the
// generated HCL exists in the curated schema for resourceType. Returns nil if
// the resource type is unknown (permissive) or if every attribute is valid.
//
// On unknown attributes, returns a descriptive error listing them — used as a
// pre-flight check to reject AI-hallucinated attributes (e.g. `web_acl_arn`
// on `aws_lb`) before they corrupt the .tf file.
func ValidateAttributes(hcl, resourceType string) error {
	whitelist, ok := resourceSchemas[resourceType]
	if !ok {
		return nil
	}
	attrs := extractTopLevelAttrs(hcl)
	var unknown []string
	for _, a := range attrs {
		if _, ok := whitelist[a]; !ok {
			unknown = append(unknown, a)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	return fmt.Errorf("HCL gerado contém atributos inválidos para %s: %s — provavelmente alucinação do AI",
		resourceType, strings.Join(unknown, ", "))
}
