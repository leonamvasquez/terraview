package contextanalysis

// genericFallbackKeys are universally relevant attributes emitted for every
// resource regardless of type. They cover tags, encryption, IAM and network
// basics so resource types absent from relevantKeysByType (e.g. aws_appsync_*,
// new providers) never lose security/architecture context silently.
var genericFallbackKeys = []string{
	// Tags / governance
	"tags",
	// Encryption (universal)
	"encrypted", "kms_key_id", "kms_key_arn",
	// IAM (universal)
	"policy", "role_arn",
	// Network (universal)
	"vpc_id", "subnet_id", "security_group_ids",
	// Logging (universal)
	"logging",
}

// relevantKeysByType maps a Terraform resource type to the
// security/architecture-relevant attribute keys to include in the AI prompt.
// Tightens token usage by ~30–50 % vs the old flat whitelist (an aws_iam_role
// no longer carries multi_az/backup_retention_period that never apply).
//
// Coverage mirrors internal/feature/type_registry.go entries plus a few extras.
// Types absent from this map fall through to genericFallbackKeys only.
var relevantKeysByType = map[string][]string{
	// ── Compute ────────────────────────────────────────────────────────
	"aws_instance": {
		"instance_type", "ami", "availability_zone",
		"associate_public_ip_address", "iam_instance_profile",
		"security_groups", "subnet_id", "monitoring",
	},
	"aws_launch_template": {
		"instance_type", "image_id", "iam_instance_profile",
		"vpc_security_group_ids", "user_data",
	},
	"aws_autoscaling_group": {
		"min_size", "max_size", "desired_capacity",
		"availability_zones", "vpc_zone_identifier", "health_check_type",
	},

	// ── Containers / Serverless ────────────────────────────────────────
	"aws_ecs_cluster":         {"setting", "configuration"},
	"aws_ecs_service":         {"desired_count", "launch_type", "network_configuration", "load_balancer"},
	"aws_ecs_task_definition": {"network_mode", "execution_role_arn", "task_role_arn", "container_definitions"},
	"aws_ecr_repository":      {"image_tag_mutability", "image_scanning_configuration", "encryption_configuration"},
	"aws_lambda_function": {
		"runtime", "environment", "vpc_config", "tracing_config",
		"dead_letter_config", "reserved_concurrent_executions", "execution_role_arn",
	},
	"aws_lambda_permission": {"action", "principal", "source_arn", "function_name"},

	// ── Kubernetes (EKS) ───────────────────────────────────────────────
	"aws_eks_cluster": {
		"version", "endpoint_public_access", "endpoint_private_access",
		"public_access_cidrs", "encryption_config", "enabled_cluster_log_types",
		"vpc_config",
	},
	"aws_eks_node_group":      {"instance_types", "scaling_config", "subnet_ids", "remote_access"},
	"aws_eks_fargate_profile": {"selector", "subnet_ids", "pod_execution_role_arn"},

	// ── Storage ────────────────────────────────────────────────────────
	"aws_s3_bucket": {
		"acl", "versioning", "server_side_encryption_configuration",
		"lifecycle_rule", "replication_configuration", "logging",
		"website", "cors_rule", "object_lock_configuration",
	},
	"aws_s3_bucket_public_access_block": {
		"block_public_acls", "block_public_policy",
		"ignore_public_acls", "restrict_public_buckets",
	},
	"aws_s3_bucket_policy": {"policy"},
	"aws_s3_bucket_acl":    {"acl"},
	"aws_ebs_volume":       {"size", "type", "encrypted", "kms_key_id", "availability_zone"},
	"aws_efs_file_system":  {"encrypted", "performance_mode", "lifecycle_policy"},
	"aws_glacier_vault":    {"access_policy", "notification"},

	// ── Database ───────────────────────────────────────────────────────
	"aws_db_instance": {
		"engine", "engine_version", "instance_class", "publicly_accessible",
		"storage_encrypted", "kms_key_id", "backup_retention_period",
		"multi_az", "deletion_protection", "skip_final_snapshot",
		"iam_database_authentication_enabled", "performance_insights_enabled",
		"enabled_cloudwatch_logs_exports", "vpc_security_group_ids",
	},
	"aws_rds_cluster": {
		"engine", "engine_version", "storage_encrypted", "kms_key_id",
		"backup_retention_period", "deletion_protection", "skip_final_snapshot",
		"iam_database_authentication_enabled", "enabled_cloudwatch_logs_exports",
		"vpc_security_group_ids",
	},
	"aws_rds_cluster_instance":          {"engine", "instance_class", "publicly_accessible", "performance_insights_enabled"},
	"aws_dynamodb_table":                {"billing_mode", "server_side_encryption", "point_in_time_recovery", "stream_enabled"},
	"aws_elasticache_cluster":           {"engine", "engine_version", "node_type", "num_cache_nodes", "at_rest_encryption_enabled", "transit_encryption_enabled"},
	"aws_elasticache_replication_group": {"engine", "engine_version", "at_rest_encryption_enabled", "transit_encryption_enabled", "auth_token", "automatic_failover_enabled"},
	"aws_redshift_cluster":              {"node_type", "publicly_accessible", "encrypted", "kms_key_id", "logging", "enhanced_vpc_routing"},
	"aws_neptune_cluster":               {"storage_encrypted", "kms_key_id", "backup_retention_period", "iam_database_authentication_enabled"},
	"aws_docdb_cluster":                 {"storage_encrypted", "kms_key_id", "backup_retention_period", "enabled_cloudwatch_logs_exports"},

	// ── Messaging ──────────────────────────────────────────────────────
	"aws_sqs_queue":                        {"kms_master_key_id", "fifo_queue", "visibility_timeout_seconds", "redrive_policy"},
	"aws_sns_topic":                        {"kms_master_key_id", "delivery_policy"},
	"aws_kinesis_stream":                   {"shard_count", "encryption_type", "kms_key_id", "retention_period"},
	"aws_kinesis_firehose_delivery_stream": {"destination", "server_side_encryption", "extended_s3_configuration"},
	"aws_msk_cluster":                      {"kafka_version", "encryption_info", "client_authentication", "logging_info", "broker_node_group_info"},
	"aws_mq_broker":                        {"engine_type", "publicly_accessible", "encryption_options", "logs"},

	// ── Search / Analytics ─────────────────────────────────────────────
	"aws_opensearch_domain":     {"engine_version", "encrypt_at_rest", "node_to_node_encryption", "domain_endpoint_options", "vpc_options", "log_publishing_options"},
	"aws_elasticsearch_domain":  {"elasticsearch_version", "encrypt_at_rest", "node_to_node_encryption", "domain_endpoint_options", "vpc_options"},
	"aws_athena_workgroup":      {"configuration", "state"},
	"aws_glue_catalog_database": {"location_uri", "parameters"},

	// ── Networking ─────────────────────────────────────────────────────
	"aws_vpc":                       {"cidr_block", "enable_dns_support", "enable_dns_hostnames", "instance_tenancy"},
	"aws_subnet":                    {"cidr_block", "availability_zone", "map_public_ip_on_launch", "vpc_id"},
	"aws_security_group":            {"vpc_id", "ingress", "egress", "name"},
	"aws_security_group_rule":       {"type", "from_port", "to_port", "protocol", "cidr_blocks", "source_security_group_id", "security_group_id"},
	"aws_lb":                        {"load_balancer_type", "internal", "security_groups", "subnets", "drop_invalid_header_fields", "access_logs"},
	"aws_alb":                       {"load_balancer_type", "internal", "security_groups", "subnets", "drop_invalid_header_fields", "access_logs"},
	"aws_lb_listener":               {"protocol", "port", "ssl_policy", "certificate_arn", "default_action"},
	"aws_cloudfront_distribution":   {"default_cache_behavior", "viewer_certificate", "logging_config", "web_acl_id", "restrictions"},
	"aws_wafv2_web_acl":             {"default_action", "visibility_config", "rule"},
	"aws_vpc_endpoint":              {"service_name", "vpc_endpoint_type", "policy", "private_dns_enabled"},
	"aws_nat_gateway":               {"subnet_id", "connectivity_type"},
	"aws_internet_gateway":          {"vpc_id"},
	"aws_transit_gateway":           {"auto_accept_shared_attachments", "default_route_table_association", "default_route_table_propagation", "dns_support"},
	"aws_network_firewall_firewall": {"firewall_policy_arn", "subnet_mapping", "delete_protection"},

	// ── Identity (IAM) ─────────────────────────────────────────────────
	"aws_iam_role": {
		"assume_role_policy", "inline_policy", "managed_policy_arns",
		"max_session_duration", "permissions_boundary",
	},
	"aws_iam_policy":           {"policy", "name"},
	"aws_iam_user":             {"name", "force_destroy", "permissions_boundary"},
	"aws_iam_user_policy":      {"policy", "user"},
	"aws_iam_role_policy":      {"policy", "role"},
	"aws_iam_instance_profile": {"role"},
	"aws_iam_group":            {"name", "path"},
	"aws_iam_access_key":       {"user", "status"},

	// ── Secrets / KMS / SSM ────────────────────────────────────────────
	"aws_secretsmanager_secret": {"kms_key_id", "rotation_rules", "policy", "recovery_window_in_days"},
	"aws_kms_key":               {"enable_key_rotation", "deletion_window_in_days", "key_usage", "policy", "multi_region"},
	"aws_kms_alias":             {"target_key_id", "name"},
	"aws_ssm_parameter":         {"type", "tier", "key_id"},

	// ── Observability ──────────────────────────────────────────────────
	"aws_cloudwatch_log_group":          {"retention_in_days", "kms_key_id"},
	"aws_cloudwatch_metric_alarm":       {"alarm_actions", "comparison_operator", "evaluation_periods", "metric_name", "threshold"},
	"aws_cloudtrail":                    {"is_multi_region_trail", "include_global_service_events", "enable_log_file_validation", "kms_key_id", "s3_bucket_name", "event_selector"},
	"aws_config_configuration_recorder": {"recording_group", "role_arn"},
	"aws_guardduty_detector":            {"enable", "finding_publishing_frequency", "datasources"},

	// ── API Gateway ────────────────────────────────────────────────────
	"aws_api_gateway_rest_api": {"endpoint_configuration", "policy", "minimum_compression_size"},
	"aws_apigatewayv2_api":     {"protocol_type", "cors_configuration", "route_selection_expression"},

	// ── ML ─────────────────────────────────────────────────────────────
	"aws_sagemaker_endpoint":          {"endpoint_config_name", "kms_key_arn"},
	"aws_sagemaker_notebook_instance": {"instance_type", "kms_key_id", "direct_internet_access", "root_access"},

	// ── Backup / DR ────────────────────────────────────────────────────
	"aws_backup_vault": {"kms_key_arn"},
	"aws_backup_plan":  {"rule"},

	// ── GCP / Azure (minimal — fallback handles the rest) ──────────────
	"google_storage_bucket":   {"location", "uniform_bucket_level_access", "encryption", "logging", "versioning"},
	"google_iam_binding":      {"role", "members"},
	"google_iam_member":       {"role", "member"},
	"azurerm_storage_account": {"account_tier", "account_replication_type", "enable_https_traffic_only", "min_tls_version", "allow_nested_items_to_be_public"},
	"azurerm_role_assignment": {"role_definition_name", "principal_id", "scope"},
}

// extractRelevantAttributesForType returns the values map filtered to the keys
// that matter for the given resource type, merged with the universal fallback.
// Types unknown to relevantKeysByType still get the fallback so unmapped
// providers (e.g. aws_appsync_*) never reach the AI without context.
func extractRelevantAttributesForType(resourceType string, values map[string]interface{}) map[string]interface{} {
	if len(values) == 0 {
		return map[string]interface{}{}
	}

	relevant := make(map[string]interface{})
	seen := make(map[string]bool, len(genericFallbackKeys)+8)

	emit := func(key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		if v, ok := values[key]; ok {
			relevant[key] = v
		}
	}

	if perType, ok := relevantKeysByType[resourceType]; ok {
		for _, k := range perType {
			emit(k)
		}
	}
	for _, k := range genericFallbackKeys {
		emit(k)
	}

	return relevant
}
