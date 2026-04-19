package diagram

import "strings"

// ContainmentNode represents a resource or container in the hierarchy tree.
type ContainmentNode struct {
	Address  string
	Type     string
	Label    string
	Action   string
	Children []*ContainmentNode
}

// Connection represents a dependency arrow between two service groups.
type Connection struct {
	From  string // service/group label
	To    string // service/group label
	Via   string // relationship description
	Label string // human-readable label
}

// AggregatedGroup represents a service-level group (e.g. "S3" with 8 buckets).
type AggregatedGroup struct {
	Service      string   // service name: "S3", "IAM", etc.
	Type         string   // primary resource type
	Label        string   // display label (set by aggregator)
	PrimaryCount int      // count of primary resources (e.g. aws_s3_bucket)
	TotalCount   int      // count of all resources (primary + sub-resources)
	Action       string   // dominant action (create, mixed, etc.)
	Addresses    []string // all resource addresses in this group
	VPCAddress   string   // VPC this group belongs to (multi-VPC support)
}

// SubnetSummary holds the count of subnets per tier inside the VPC.
type SubnetSummary struct {
	Public      int
	Firewall    int
	Management  int
	PrivateApp  int
	PrivateData int
	Private     int // generic private (no tier detected)
}

// TopoLayer represents an architectural layer in the topological diagram.
type TopoLayer struct {
	Name          string             // layer display name
	Order         int                // rendering order (top to bottom)
	Groups        []*AggregatedGroup // aggregated service groups in this layer
	IsVPC         bool               // whether this layer represents the VPC boundary
	VPCAddress    string             // resource address of the VPC (for multi-VPC support)
	SubnetSummary *SubnetSummary     // subnet count summary (only if IsVPC)
	NetworkGroups []*AggregatedGroup // Network box groups inside VPC
	ComputeGroups []*AggregatedGroup // Compute box groups inside VPC
	DataGroups    []*AggregatedGroup // Data box groups inside VPC
}

// TopoResult holds the complete resolved topology for rendering.
type TopoResult struct {
	Provider         string
	Title            string
	Lang             string // output language; "pt-BR" switches titles to Brazilian Portuguese
	Layers           []*TopoLayer
	Connections      []*Connection
	SubnetPlacements map[string]string   // service group label → subnet tier
	ConfigRefs       map[string][]string // resource address → referenced addresses (from plan configuration)
	SGCrossRefs      []SGCrossRef        // security group cross-references from configuration
}

// --- Service Grouping Maps ---

// serviceGrouping maps each resource type to its service group name.
// Sub-resources collapse into their parent service.
var serviceGrouping = map[string]string{
	// S3
	"aws_s3_bucket":            "S3",
	"aws_s3_bucket_versioning": "S3",
	"aws_s3_bucket_policy":     "S3",
	"aws_s3_bucket_server_side_encryption_configuration": "S3",
	"aws_s3_bucket_lifecycle_configuration":              "S3",
	"aws_s3_bucket_public_access_block":                  "S3",
	"aws_s3_bucket_replication_configuration":            "S3",
	"aws_s3_bucket_intelligent_tiering_configuration":    "S3",
	"aws_s3_bucket_object_lock_configuration":            "S3",
	"aws_s3_bucket_logging":                              "S3",
	"aws_s3_bucket_cors_configuration":                   "S3",
	"aws_s3_bucket_notification":                         "S3",
	"aws_s3_bucket_acl":                                  "S3",
	"aws_s3_bucket_website_configuration":                "S3",
	"aws_s3_bucket_ownership_controls":                   "S3",
	"aws_s3_bucket_metric":                               "S3",
	"aws_s3_bucket_analytics_configuration":              "S3",
	"aws_s3_bucket_request_payment_configuration":        "S3",
	"aws_s3_object":                                      "S3",

	// IAM
	"aws_iam_role":                    "IAM",
	"aws_iam_policy":                  "IAM",
	"aws_iam_role_policy":             "IAM",
	"aws_iam_role_policy_attachment":  "IAM",
	"aws_iam_instance_profile":        "IAM",
	"aws_iam_user":                    "IAM",
	"aws_iam_group":                   "IAM",
	"aws_iam_group_policy":            "IAM",
	"aws_iam_group_policy_attachment": "IAM",
	"aws_iam_group_membership":        "IAM",
	"aws_iam_user_policy":             "IAM",
	"aws_iam_user_policy_attachment":  "IAM",
	"aws_iam_openid_connect_provider": "IAM",
	"aws_iam_account_password_policy": "IAM",
	"aws_iam_service_linked_role":     "IAM",
	"aws_iam_access_key":              "IAM",
	"aws_iam_policy_document":         "IAM",
	"aws_iam_server_certificate":      "IAM",

	// CloudWatch
	"aws_cloudwatch_log_group":               "CloudWatch",
	"aws_cloudwatch_log_resource_policy":     "CloudWatch",
	"aws_cloudwatch_log_metric_filter":       "CloudWatch",
	"aws_cloudwatch_log_subscription_filter": "CloudWatch",
	"aws_cloudwatch_metric_alarm":            "CloudWatch",
	// EventBridge (formerly CloudWatch Events)
	"aws_cloudwatch_event_rule":       "EventBridge",
	"aws_cloudwatch_event_target":     "EventBridge",
	"aws_cloudwatch_event_bus":        "EventBridge",
	"aws_eventbridge_rule":            "EventBridge",
	"aws_eventbridge_bus":             "EventBridge",
	"aws_eventbridge_pipe":            "EventBridge",
	"aws_eventbridge_connection":      "EventBridge",
	"aws_eventbridge_api_destination": "EventBridge",
	"aws_eventbridge_target":          "EventBridge",
	"aws_scheduler_schedule":          "EventBridge",
	"aws_scheduler_schedule_group":    "EventBridge",
	"aws_cloudwatch_dashboard":        "CloudWatch",
	"aws_cloudwatch_composite_alarm":  "CloudWatch",

	// KMS
	"aws_kms_key":   "KMS",
	"aws_kms_alias": "KMS",
	"aws_kms_grant": "KMS",

	// SNS
	"aws_sns_topic":              "SNS",
	"aws_sns_topic_policy":       "SNS",
	"aws_sns_topic_subscription": "SNS",

	// SQS
	"aws_sqs_queue":                      "SQS",
	"aws_sqs_queue_policy":               "SQS",
	"aws_sqs_queue_redrive_policy":       "SQS",
	"aws_sqs_queue_redrive_allow_policy": "SQS",

	// Route 53
	"aws_route53_zone":         "Route 53",
	"aws_route53_record":       "Route 53",
	"aws_route53_health_check": "Route 53",

	// Secrets Manager
	"aws_secretsmanager_secret":          "Secrets Manager",
	"aws_secretsmanager_secret_version":  "Secrets Manager",
	"aws_secretsmanager_secret_policy":   "Secrets Manager",
	"aws_secretsmanager_secret_rotation": "Secrets Manager",

	// SSM
	"aws_ssm_parameter":                 "SSM Parameter Store",
	"aws_ssm_maintenance_window":        "SSM",
	"aws_ssm_maintenance_window_target": "SSM",
	"aws_ssm_maintenance_window_task":   "SSM",
	"aws_ssm_document":                  "SSM",
	"aws_ssm_association":               "SSM",

	// ECR
	"aws_ecr_repository":                "ECR",
	"aws_ecr_lifecycle_policy":          "ECR",
	"aws_ecr_repository_policy":         "ECR",
	"aws_ecr_replication_configuration": "ECR",

	// Load Balancer
	"aws_lb":                         "Load Balancer",
	"aws_alb":                        "Load Balancer",
	"aws_lb_listener":                "Load Balancer",
	"aws_alb_listener":               "Load Balancer",
	"aws_lb_listener_rule":           "Load Balancer",
	"aws_alb_listener_rule":          "Load Balancer",
	"aws_lb_target_group":            "Load Balancer",
	"aws_alb_target_group":           "Load Balancer",
	"aws_lb_target_group_attachment": "Load Balancer",

	// Security Group
	"aws_security_group":                  "Security Group",
	"aws_security_group_rule":             "Security Group",
	"aws_vpc_security_group_ingress_rule": "Security Group",
	"aws_vpc_security_group_egress_rule":  "Security Group",

	// EKS (keep expanded — architecturally significant)
	"aws_eks_cluster":                  "EKS Cluster",
	"aws_eks_node_group":               "EKS Node Group",
	"aws_eks_addon":                    "EKS Addon",
	"aws_eks_fargate_profile":          "EKS Fargate",
	"aws_eks_identity_provider_config": "EKS",

	// ECS
	"aws_ecs_cluster":                    "ECS Cluster",
	"aws_ecs_service":                    "ECS",
	"aws_ecs_task_definition":            "ECS",
	"aws_ecs_capacity_provider":          "ECS",
	"aws_ecs_cluster_capacity_providers": "ECS",

	// RDS
	"aws_rds_cluster":                   "Aurora RDS",
	"aws_rds_cluster_instance":          "Aurora RDS",
	"aws_rds_cluster_parameter_group":   "Aurora RDS",
	"aws_rds_cluster_endpoint":          "Aurora RDS",
	"aws_db_instance":                   "RDS Instance",
	"aws_db_parameter_group":            "RDS Instance",
	"aws_db_option_group":               "RDS Instance",
	"aws_db_subnet_group":               "RDS Subnet Group",
	"aws_db_proxy":                      "RDS Proxy",
	"aws_db_proxy_default_target_group": "RDS Proxy",
	"aws_db_proxy_target":               "RDS Proxy",

	// DynamoDB
	"aws_dynamodb_table":                         "DynamoDB",
	"aws_dynamodb_table_item":                    "DynamoDB",
	"aws_dynamodb_global_table":                  "DynamoDB",
	"aws_dynamodb_kinesis_streaming_destination": "DynamoDB",

	// ElastiCache
	"aws_elasticache_cluster":           "ElastiCache",
	"aws_elasticache_replication_group": "ElastiCache",
	"aws_elasticache_subnet_group":      "ElastiCache",
	"aws_elasticache_parameter_group":   "ElastiCache",

	// CloudFront
	"aws_cloudfront_distribution":            "CloudFront",
	"aws_cloudfront_origin_access_identity":  "CloudFront",
	"aws_cloudfront_origin_access_control":   "CloudFront",
	"aws_cloudfront_cache_policy":            "CloudFront",
	"aws_cloudfront_function":                "CloudFront",
	"aws_cloudfront_response_headers_policy": "CloudFront",

	// WAF
	"aws_wafv2_web_acl":                       "WAF",
	"aws_wafv2_web_acl_association":           "WAF",
	"aws_wafv2_ip_set":                        "WAF",
	"aws_wafv2_rule_group":                    "WAF",
	"aws_wafv2_web_acl_logging_configuration": "WAF",

	// ACM
	"aws_acm_certificate":            "ACM",
	"aws_acm_certificate_validation": "ACM",

	// Lambda
	"aws_lambda_function":                       "Lambda",
	"aws_lambda_permission":                     "Lambda",
	"aws_lambda_event_source_mapping":           "Lambda",
	"aws_lambda_layer_version":                  "Lambda",
	"aws_lambda_alias":                          "Lambda",
	"aws_lambda_provisioned_concurrency_config": "Lambda",
	"aws_lambda_function_event_invoke_config":   "Lambda",

	// VPN/Transit
	"aws_vpn_connection":                              "VPN",
	"aws_vpn_gateway":                                 "VPN",
	"aws_customer_gateway":                            "VPN",
	"aws_transit_gateway":                             "Transit Gateway",
	"aws_transit_gateway_attachment":                  "Transit Gateway",
	"aws_transit_gateway_route_table":                 "Transit Gateway",
	"aws_transit_gateway_route":                       "Transit Gateway",
	"aws_ec2_transit_gateway":                         "Transit Gateway",
	"aws_ec2_transit_gateway_vpc_attachment":          "Transit Gateway",
	"aws_ec2_transit_gateway_route":                   "Transit Gateway",
	"aws_ec2_transit_gateway_route_table":             "Transit Gateway",
	"aws_ec2_transit_gateway_route_table_association": "Transit Gateway",
	"aws_ec2_transit_gateway_route_table_propagation": "Transit Gateway",

	// CodePipeline/Build/Deploy
	"aws_codepipeline":                "CodePipeline",
	"aws_codebuild_project":           "CodeBuild",
	"aws_codedeploy_app":              "CodeDeploy",
	"aws_codedeploy_deployment_group": "CodeDeploy",

	// Backup
	"aws_backup_vault":     "Backup",
	"aws_backup_plan":      "Backup",
	"aws_backup_selection": "Backup",

	// CloudTrail
	"aws_cloudtrail": "CloudTrail",

	// Config
	"aws_config_configuration_recorder":        "AWS Config",
	"aws_config_delivery_channel":              "AWS Config",
	"aws_config_config_rule":                   "AWS Config",
	"aws_config_configuration_recorder_status": "AWS Config",

	// GuardDuty
	"aws_guardduty_detector":                   "GuardDuty",
	"aws_guardduty_member":                     "GuardDuty",
	"aws_guardduty_organization_admin_account": "GuardDuty",

	// Kinesis
	"aws_kinesis_stream":                   "Kinesis",
	"aws_kinesis_firehose_delivery_stream": "Kinesis Firehose",

	// Step Functions
	"aws_sfn_state_machine": "Step Functions",

	// Auto Scaling (collapse together including launch template)
	"aws_autoscaling_group":     "Auto Scaling",
	"aws_autoscaling_policy":    "Auto Scaling",
	"aws_autoscaling_schedule":  "Auto Scaling",
	"aws_autoscaling_group_tag": "Auto Scaling",
	"aws_appautoscaling_target": "Auto Scaling",
	"aws_appautoscaling_policy": "Auto Scaling",
	"aws_launch_template":       "Auto Scaling",

	// EC2
	"aws_instance":   "EC2 Instance",
	"aws_eip":        "Elastic IP",
	"aws_ebs_volume": "EBS Volume",
	"aws_key_pair":   "EC2 Key Pair",
	"aws_ami":        "AMI",
	"aws_ami_copy":   "AMI",

	// VPC core
	"aws_vpc":                     "VPC",
	"aws_subnet":                  "Subnet",
	"aws_internet_gateway":        "Internet Gateway",
	"aws_nat_gateway":             "NAT Gateway",
	"aws_route_table":             "Route Table",
	"aws_route_table_association": "Route Table",
	"aws_route":                   "Route Table",
	"aws_network_acl":             "Network ACL",
	"aws_network_acl_rule":        "Network ACL",
	"aws_vpc_endpoint":            "VPC Endpoint",
	"aws_vpc_endpoint_service":    "PrivateLink",
	"aws_vpc_peering_connection":  "VPC Peering",
	"aws_vpc_flow_log":            "VPC Flow Log",
	"aws_network_interface":       "ENI",
	"aws_eip_association":         "Elastic IP",

	// API Gateway
	"aws_api_gateway_rest_api":             "API Gateway",
	"aws_api_gateway_resource":             "API Gateway",
	"aws_api_gateway_method":               "API Gateway",
	"aws_api_gateway_integration":          "API Gateway",
	"aws_api_gateway_deployment":           "API Gateway",
	"aws_api_gateway_stage":                "API Gateway",
	"aws_api_gateway_authorizer":           "API Gateway",
	"aws_api_gateway_api_key":              "API Gateway",
	"aws_api_gateway_usage_plan":           "API Gateway",
	"aws_api_gateway_usage_plan_key":       "API Gateway",
	"aws_api_gateway_method_settings":      "API Gateway",
	"aws_api_gateway_vpc_link":             "API Gateway",
	"aws_api_gateway_method_response":      "API Gateway",
	"aws_api_gateway_integration_response": "API Gateway",
	"aws_apigatewayv2_api":                 "API Gateway",
	"aws_apigatewayv2_stage":               "API Gateway",
	"aws_apigatewayv2_route":               "API Gateway",
	"aws_apigatewayv2_integration":         "API Gateway",
	"aws_apigatewayv2_deployment":          "API Gateway",
	"aws_apigatewayv2_domain_name":         "API Gateway",
	"aws_apigatewayv2_api_mapping":         "API Gateway",
	"aws_apigatewayv2_authorizer":          "API Gateway",
	"aws_apigatewayv2_vpc_link":            "API Gateway",

	// Network Firewall
	"aws_networkfirewall_firewall":              "Network Firewall",
	"aws_networkfirewall_firewall_policy":       "Network Firewall",
	"aws_networkfirewall_rule_group":            "Network Firewall",
	"aws_networkfirewall_logging_configuration": "Network Firewall",

	// Prometheus + Grafana
	"aws_prometheus_workspace":            "Prometheus",
	"aws_prometheus_rule_group_namespace": "Prometheus",
	"aws_grafana_workspace":               "Grafana",

	// SecurityHub
	"aws_securityhub_account":                "SecurityHub",
	"aws_securityhub_standards_subscription": "SecurityHub",

	// Synthetics
	"aws_synthetics_canary": "Synthetics",

	// EFS
	"aws_efs_file_system":        "EFS",
	"aws_efs_mount_target":       "EFS",
	"aws_efs_access_point":       "EFS",
	"aws_efs_backup_policy":      "EFS",
	"aws_efs_file_system_policy": "EFS",

	// OpenSearch
	"aws_opensearch_domain":        "OpenSearch",
	"aws_opensearch_domain_policy": "OpenSearch",

	// Service Discovery
	"aws_service_discovery_private_dns_namespace": "Service Discovery",
	"aws_service_discovery_service":               "Service Discovery",

	// Misc
	"aws_macie2_account": "Macie",
}

// primaryTypes are resource types whose count is displayed.
// Sub-resources (versioning, policy attachments) are NOT primary.
var primaryTypes = map[string]bool{
	"aws_s3_bucket":                               true,
	"aws_iam_role":                                true,
	"aws_iam_policy":                              true,
	"aws_iam_user":                                true,
	"aws_cloudwatch_log_group":                    true,
	"aws_cloudwatch_metric_alarm":                 true,
	"aws_cloudwatch_event_rule":                   true,
	"aws_cloudwatch_event_bus":                    true,
	"aws_eventbridge_bus":                         true,
	"aws_kms_key":                                 true,
	"aws_sns_topic":                               true,
	"aws_sqs_queue":                               true,
	"aws_route53_zone":                            true,
	"aws_route53_record":                          true,
	"aws_secretsmanager_secret":                   true,
	"aws_ssm_parameter":                           true,
	"aws_ecr_repository":                          true,
	"aws_lb":                                      true,
	"aws_alb":                                     true,
	"aws_lb_target_group":                         true,
	"aws_alb_target_group":                        true,
	"aws_security_group":                          true,
	"aws_eks_cluster":                             true,
	"aws_eks_node_group":                          true,
	"aws_eks_addon":                               true,
	"aws_eks_fargate_profile":                     true,
	"aws_ecs_cluster":                             true,
	"aws_ecs_service":                             true,
	"aws_ecs_task_definition":                     true,
	"aws_rds_cluster":                             true,
	"aws_rds_cluster_instance":                    true,
	"aws_db_instance":                             true,
	"aws_db_subnet_group":                         true,
	"aws_dynamodb_table":                          true,
	"aws_elasticache_cluster":                     true,
	"aws_elasticache_replication_group":           true,
	"aws_cloudfront_distribution":                 true,
	"aws_wafv2_web_acl":                           true,
	"aws_acm_certificate":                         true,
	"aws_lambda_function":                         true,
	"aws_instance":                                true,
	"aws_autoscaling_group":                       true,
	"aws_launch_template":                         true,
	"aws_codepipeline":                            true,
	"aws_codebuild_project":                       true,
	"aws_vpc":                                     true,
	"aws_subnet":                                  true,
	"aws_internet_gateway":                        true,
	"aws_nat_gateway":                             true,
	"aws_route_table":                             true,
	"aws_vpc_endpoint":                            true,
	"aws_transit_gateway":                         true,
	"aws_vpn_connection":                          true,
	"aws_cloudtrail":                              true,
	"aws_kinesis_stream":                          true,
	"aws_kinesis_firehose_delivery_stream":        true,
	"aws_sfn_state_machine":                       true,
	"aws_backup_vault":                            true,
	"aws_guardduty_detector":                      true,
	"aws_db_proxy":                                true,
	"aws_api_gateway_rest_api":                    true,
	"aws_apigatewayv2_api":                        true,
	"aws_networkfirewall_firewall":                true,
	"aws_opensearch_domain":                       true,
	"aws_efs_file_system":                         true,
	"aws_service_discovery_private_dns_namespace": true,
	"aws_vpc_peering_connection":                  true,
	"aws_vpc_endpoint_service":                    true,
	"aws_vpn_gateway":                             true,
	"aws_customer_gateway":                        true,
	"aws_ec2_transit_gateway":                     true,
}

// topoLayerByType maps resource types to their VPC inner layer classification.
// Resources with a VPC-layer classification render inside the VPC boundary.
// Resources without an entry here go to top-level layers (Edge, Ingress, Supporting, etc.)
var topoLayerByType = map[string]string{
	// Network (VPC internals)
	"aws_vpc":                                         "Network",
	"aws_subnet":                                      "Network",
	"aws_internet_gateway":                            "Network",
	"aws_nat_gateway":                                 "Network",
	"aws_route_table":                                 "Network",
	"aws_route_table_association":                     "Network",
	"aws_route":                                       "Network",
	"aws_network_acl":                                 "Network",
	"aws_network_acl_rule":                            "Network",
	"aws_vpc_endpoint":                                "Network",
	"aws_vpc_flow_log":                                "Network",
	"aws_network_interface":                           "Network",
	"aws_eip":                                         "Network",
	"aws_eip_association":                             "Network",
	"aws_security_group":                              "Network",
	"aws_security_group_rule":                         "Network",
	"aws_vpc_security_group_ingress_rule":             "Network",
	"aws_vpc_security_group_egress_rule":              "Network",
	"aws_networkfirewall_firewall":                    "Compute",
	"aws_networkfirewall_firewall_policy":             "Compute",
	"aws_networkfirewall_rule_group":                  "Compute",
	"aws_transit_gateway":                             "Network",
	"aws_transit_gateway_attachment":                  "Network",
	"aws_transit_gateway_route_table":                 "Network",
	"aws_transit_gateway_route":                       "Network",
	"aws_ec2_transit_gateway":                         "Network",
	"aws_ec2_transit_gateway_vpc_attachment":          "Network",
	"aws_ec2_transit_gateway_route":                   "Network",
	"aws_ec2_transit_gateway_route_table":             "Network",
	"aws_db_subnet_group":                             "Network",
	"aws_elasticache_subnet_group":                    "Network",
	"aws_vpc_peering_connection":                      "Network",
	"aws_vpc_endpoint_service":                        "Network",
	"aws_networkfirewall_logging_configuration":       "Compute",
	"aws_ec2_transit_gateway_route_table_association": "Network",
	"aws_ec2_transit_gateway_route_table_propagation": "Network",
	"aws_vpn_connection":                              "Network",
	"aws_vpn_gateway":                                 "Network",
	"aws_customer_gateway":                            "Network",

	// Compute
	"aws_eks_cluster":                             "Compute",
	"aws_eks_node_group":                          "Compute",
	"aws_eks_addon":                               "Compute",
	"aws_eks_fargate_profile":                     "Compute",
	"aws_eks_identity_provider_config":            "Compute",
	"aws_ecs_cluster":                             "Compute",
	"aws_ecs_service":                             "Compute",
	"aws_ecs_task_definition":                     "Compute",
	"aws_ecs_capacity_provider":                   "Compute",
	"aws_lambda_function":                         "Compute",
	"aws_lambda_permission":                       "Compute",
	"aws_lambda_event_source_mapping":             "Compute",
	"aws_lambda_provisioned_concurrency_config":   "Compute",
	"aws_lambda_function_event_invoke_config":     "Compute",
	"aws_lambda_layer_version":                    "Compute",
	"aws_lambda_alias":                            "Compute",
	"aws_instance":                                "Compute",
	"aws_autoscaling_group":                       "Compute",
	"aws_autoscaling_policy":                      "Compute",
	"aws_autoscaling_schedule":                    "Compute",
	"aws_appautoscaling_target":                   "Compute",
	"aws_appautoscaling_policy":                   "Compute",
	"aws_launch_template":                         "Compute",
	"aws_autoscaling_group_tag":                   "Compute",
	"aws_lb":                                      "Compute",
	"aws_alb":                                     "Compute",
	"aws_lb_listener":                             "Compute",
	"aws_alb_listener":                            "Compute",
	"aws_lb_listener_rule":                        "Compute",
	"aws_alb_listener_rule":                       "Compute",
	"aws_lb_target_group":                         "Compute",
	"aws_alb_target_group":                        "Compute",
	"aws_lb_target_group_attachment":              "Compute",
	"aws_ecs_cluster_capacity_providers":          "Compute",
	"aws_service_discovery_private_dns_namespace": "Compute",
	"aws_service_discovery_service":               "Compute",
	"aws_key_pair":                                "Compute",
	"aws_ami":                                     "Compute",
	"aws_ami_copy":                                "Compute",
	"aws_ebs_volume":                              "Compute",

	// Data
	"aws_rds_cluster":                            "Data",
	"aws_rds_cluster_instance":                   "Data",
	"aws_rds_cluster_parameter_group":            "Data",
	"aws_rds_cluster_endpoint":                   "Data",
	"aws_db_instance":                            "Data",
	"aws_db_parameter_group":                     "Data",
	"aws_db_option_group":                        "Data",
	"aws_db_proxy":                               "Data",
	"aws_db_proxy_default_target_group":          "Data",
	"aws_db_proxy_target":                        "Data",
	"aws_dynamodb_table":                         "Data",
	"aws_dynamodb_table_item":                    "Data",
	"aws_dynamodb_global_table":                  "Data",
	"aws_dynamodb_kinesis_streaming_destination": "Data",
	"aws_elasticache_cluster":                    "Data",
	"aws_elasticache_replication_group":          "Data",
	"aws_elasticache_parameter_group":            "Data",
	"aws_opensearch_domain":                      "Data",
	"aws_opensearch_domain_policy":               "Data",
	"aws_kinesis_stream":                         "Data",
	"aws_kinesis_firehose_delivery_stream":       "Data",
	"aws_efs_file_system":                        "Data",
	"aws_efs_mount_target":                       "Data",
	"aws_efs_access_point":                       "Data",
	"aws_efs_backup_policy":                      "Data",
	"aws_efs_file_system_policy":                 "Data",
}

// typeHierarchy maps child resource types to their parent type for containment.
// When explicit references aren't found, this provides type-based nesting.
var typeHierarchy = map[string]string{
	"aws_subnet":                   "aws_vpc",
	"aws_security_group":           "aws_vpc",
	"aws_security_group_rule":      "aws_vpc",
	"aws_route_table":              "aws_vpc",
	"aws_route_table_association":  "aws_vpc",
	"aws_route":                    "aws_vpc",
	"aws_internet_gateway":         "aws_vpc",
	"aws_nat_gateway":              "aws_vpc",
	"aws_network_acl":              "aws_vpc",
	"aws_network_acl_rule":         "aws_vpc",
	"aws_vpc_endpoint":             "aws_vpc",
	"aws_vpc_flow_log":             "aws_vpc",
	"aws_network_interface":        "aws_vpc",
	"aws_db_subnet_group":          "aws_vpc",
	"aws_elasticache_subnet_group": "aws_vpc",

	"aws_eks_node_group":               "aws_eks_cluster",
	"aws_eks_addon":                    "aws_eks_cluster",
	"aws_eks_fargate_profile":          "aws_eks_cluster",
	"aws_eks_identity_provider_config": "aws_eks_cluster",

	"aws_ecs_service":                    "aws_ecs_cluster",
	"aws_ecs_capacity_provider":          "aws_ecs_cluster",
	"aws_ecs_task_definition":            "aws_ecs_cluster",
	"aws_ecs_cluster_capacity_providers": "aws_ecs_cluster",

	"aws_autoscaling_schedule":  "aws_autoscaling_group",
	"aws_autoscaling_group_tag": "aws_autoscaling_group",
	"aws_appautoscaling_policy": "aws_appautoscaling_target",
	"aws_appautoscaling_target": "aws_ecs_service",

	"aws_efs_access_point":       "aws_efs_file_system",
	"aws_efs_backup_policy":      "aws_efs_file_system",
	"aws_efs_file_system_policy": "aws_efs_file_system",
	"aws_efs_mount_target":       "aws_efs_file_system",

	"aws_service_discovery_service": "aws_service_discovery_private_dns_namespace",

	"aws_lb_listener":                "aws_lb",
	"aws_alb_listener":               "aws_lb",
	"aws_lb_listener_rule":           "aws_lb",
	"aws_alb_listener_rule":          "aws_lb",
	"aws_lb_target_group":            "aws_lb",
	"aws_alb_target_group":           "aws_lb",
	"aws_lb_target_group_attachment": "aws_lb",

	"aws_route53_record":       "aws_route53_zone",
	"aws_route53_health_check": "aws_route53_zone",

	"aws_cloudwatch_event_target":            "aws_cloudwatch_event_rule",
	"aws_cloudwatch_log_metric_filter":       "aws_cloudwatch_log_group",
	"aws_cloudwatch_log_subscription_filter": "aws_cloudwatch_log_group",
}

// inferredConnectionRules are connections implied by coexistence of resource types.
var inferredConnectionRules = []struct {
	FromType string
	ToType   string
	Label    string
}{
	{"aws_lb_target_group", "aws_eks_node_group", "targets"},
	{"aws_lb_target_group", "aws_instance", "targets"},
	{"aws_lb_target_group", "aws_ecs_service", "targets"},
	{"aws_lb_target_group", "aws_lambda_function", "targets"},
	{"aws_route53_record", "aws_lb", "alias"},
	{"aws_route53_record", "aws_cloudfront_distribution", "alias"},
	{"aws_cloudfront_distribution", "aws_s3_bucket", "origin"},
	// CloudFront→LB handled by configRefs-based connections to avoid picking wrong ALB in multi-VPC.
	{"aws_cloudwatch_metric_alarm", "aws_sns_topic", "alarm_actions"},
	{"aws_lambda_function", "aws_sqs_queue", "event_source"},
	{"aws_lambda_function", "aws_dynamodb_table", "event_source"},
	{"aws_lambda_function", "aws_s3_bucket", "trigger"},
	{"aws_codepipeline", "aws_codebuild_project", "stage"},
	{"aws_codebuild_project", "aws_ecr_repository", "build_output"},
	{"aws_vpc_flow_log", "aws_s3_bucket", "destination"},
	{"aws_vpc_flow_log", "aws_cloudwatch_log_group", "destination"},
	{"aws_cloudtrail", "aws_s3_bucket", "s3_bucket"},
	{"aws_config_delivery_channel", "aws_s3_bucket", "s3_bucket"},
	{"aws_kinesis_firehose_delivery_stream", "aws_s3_bucket", "destination"},
	{"aws_backup_selection", "aws_backup_vault", "vault"},
	{"aws_db_proxy", "aws_rds_cluster", "target"},
	{"aws_db_proxy", "aws_db_instance", "target"},
	{"aws_elasticache_replication_group", "aws_elasticache_subnet_group", "subnet"},
	// WAF associations handled by annotation logic using configRefs (not inferred rules)
	// to avoid false positives from type-coexistence matching.
	{"aws_ecs_service", "aws_lb_target_group", "load_balancer"},
	{"aws_eks_cluster", "aws_security_group", "cluster_sg"},
	{"aws_autoscaling_group", "aws_launch_template", "template"},
	{"aws_instance", "aws_security_group", "security_groups"},
	{"aws_api_gateway_vpc_link", "aws_lb", "target"},
}

// containmentFields are topology edge "via" values that indicate parent-child nesting.
var containmentFields = map[string]bool{
	"vpc_id":     true,
	"subnet_id":  true,
	"subnet_ids": true,
}

// isContainmentEdge returns true if the edge represents a parent-child relationship.
func isContainmentEdge(via string) bool {
	return containmentFields[via]
}

// servicePrefixGroup maps common AWS resource type prefixes to their service
// group name. Used as a fallback when the exact type is not in serviceGrouping,
// ensuring new/unknown subtypes still group with their parent service.
var servicePrefixGroup = []struct {
	prefix  string
	service string
}{
	{"aws_cloudwatch_", "CloudWatch"},
	{"aws_s3_", "S3"},
	{"aws_iam_", "IAM"},
	{"aws_wafv2_", "WAF"},
	{"aws_config_", "AWS Config"},
	{"aws_backup_", "Backup"},
	{"aws_codepipeline", "CodePipeline"},
	{"aws_codebuild_", "CodeBuild"},
	{"aws_codecommit_", "CodeCommit"},
	{"aws_kms_", "KMS"},
	{"aws_sns_", "SNS"},
	{"aws_sqs_", "SQS"},
	{"aws_ecr_", "ECR"},
	{"aws_ssm_", "SSM"},
	{"aws_secretsmanager_", "Secrets Manager"},
	{"aws_route53_", "Route 53"},
	{"aws_cloudfront_", "CloudFront"},
	{"aws_eks_", "EKS Cluster"},
	{"aws_ecs_", "ECS"},
	{"aws_lambda_", "Lambda"},
	{"aws_dynamodb_", "DynamoDB"},
	{"aws_rds_", "Aurora RDS"},
	{"aws_db_", "Aurora RDS"},
	{"aws_elasticache_", "ElastiCache"},
	{"aws_kinesis_", "Kinesis"},
	{"aws_guardduty_", "GuardDuty"},
	{"aws_securityhub_", "SecurityHub"},
	{"aws_cloudtrail", "CloudTrail"},
	{"aws_xray_", "X-Ray Sampling"},
	{"aws_synthetics_", "Synthetics"},
	{"aws_prometheus_", "Prometheus"},
	{"aws_grafana_", "Grafana"},
	{"aws_sfn_", "Step Functions"},
	{"aws_codedeploy_", "CodeDeploy"},
}

// getServiceGroup returns the service group name for a resource type.
// Falls back to prefix matching, then serviceLabels friendly name, then the raw type.
func getServiceGroup(resType string) string {
	if svc, ok := serviceGrouping[resType]; ok {
		return svc
	}
	// Prefix-based fallback ensures unknown subtypes group with their service
	for _, pg := range servicePrefixGroup {
		if strings.HasPrefix(resType, pg.prefix) {
			return pg.service
		}
	}
	if label, ok := serviceLabels[resType]; ok {
		return label
	}
	return resType
}

// isPrimaryType returns true if this resource type counts as a "primary" resource.
func isPrimaryType(resType string) bool {
	return primaryTypes[resType]
}

// getTopoVPCLayer returns the VPC inner layer for a resource type.
// Returns "" if the resource should NOT go inside the VPC.
func getTopoVPCLayer(resType string) string {
	if layer, ok := topoLayerByType[resType]; ok {
		return layer
	}
	return ""
}

// classifySubnetTier determines the tier from a subnet address/name.
func classifySubnetTier(address string) string {
	lower := strings.ToLower(address)
	switch {
	case strings.Contains(lower, "public"):
		return "public"
	case strings.Contains(lower, "firewall"):
		return "firewall"
	case strings.Contains(lower, "mgmt") || strings.Contains(lower, "management"):
		return "management"
	case strings.Contains(lower, "private_app") || strings.Contains(lower, "app"):
		return "private_app"
	case strings.Contains(lower, "private_data") || strings.Contains(lower, "data"):
		return "private_data"
	default:
		return "private"
	}
}

// defaultSubnetPlacement maps service group names to their default subnet tier.
// Used to place service nodes inside the correct subnet container in the VPC.
var defaultSubnetPlacement = map[string]string{
	// Public subnet resources
	"Load Balancer": "public", // default for internet-facing; internal LBs override to private_app
	"ALB":           "public", // split: public application load balancer
	"NLB":           "public", // split: public network load balancer

	// Private app subnet resources (internal load balancers)
	"ALB Internal": "private_app", // split: internal application load balancer
	"NLB Internal": "private_app", // split: internal network load balancer

	// Management subnet resources
	"Bastion Host": "management",

	// EKS autoscaler tags (private_app alongside EKS Cluster)
	"EKS Autoscaler": "private_app",

	// Private app subnet resources (compute)
	"EKS Cluster":     "private_app",
	"EKS Node Group":  "private_app",
	"EKS Addon":       "private_app",
	"EKS Fargate":     "private_app",
	"ECS Cluster":     "private_app",
	"ECS":             "private_app",
	"Lambda":          "private_app",
	"Auto Scaling":    "private_app",
	"Launch Template": "private_app",
	"EC2 Instance":    "private_app",

	// Private data subnet resources
	"Aurora RDS":       "private_data",
	"RDS Instance":     "private_data",
	"RDS Proxy":        "private_data",
	"ElastiCache":      "private_data",
	"DynamoDB":         "private_data",
	"OpenSearch":       "private_data",
	"Kinesis":          "private_data",
	"Kinesis Firehose": "private_data",
	"EFS":              "private_data",

	// Private app subnet resources (service mesh)
	"Service Discovery": "private_app",

	// VPC-level resources (not in any specific subnet)
	"Security Group":     "vpc_level",
	"Route Table":        "vpc_level",
	"Network ACL":        "vpc_level",
	"VPC Endpoint":       "vpc_level",
	"PrivateLink":        "vpc_level",
	"VPC Peering":        "vpc_level",
	"VPN":                "vpc_level",
	"VPC Flow Log":       "vpc_level",
	"Network Firewall":   "firewall",
	"Transit Gateway":    "vpc_level",
	"ENI":                "vpc_level",
	"RDS Subnet Group":   "vpc_level",
	"ElastiCache Subnet": "vpc_level",
}

// subnetTierOrder defines the rendering order of subnet tiers (top to bottom).
var subnetTierOrder = []string{"public", "firewall", "management", "private_app", "private", "private_data"}

// getDefaultSubnetPlacement returns the default subnet tier for a service.
func getDefaultSubnetPlacement(service string) string {
	if tier, ok := defaultSubnetPlacement[service]; ok {
		return tier
	}
	return "vpc_level"
}
