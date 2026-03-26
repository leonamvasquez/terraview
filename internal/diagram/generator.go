package diagram

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// Layer represents a logical infrastructure layer.
type Layer struct {
	Name      string
	Order     int
	Resources []ResourceEntry
}

// ResourceEntry represents a resource in the diagram.
type ResourceEntry struct {
	Address string
	Type    string
	Action  string
	Label   string // friendly display name
}

// Generator creates ASCII infrastructure diagrams from Terraform plan resources.
type Generator struct {
	// Mode controls the diagram style:
	//   "topo" — topological diagram with connections, nesting, and aggregation
	//   "flat" or "" — original flat layer-based diagram (default for backward compat)
	Mode string
	// ConfigRefs maps resource addresses to their configuration references.
	// Used in multi-VPC scenarios to resolve VPC assignment from Terraform expressions.
	ConfigRefs map[string][]string
	// SGCrossRefs holds security group cross-references extracted from the configuration.
	SGCrossRefs []SGCrossRef
}

// NewGenerator creates a new diagram Generator with the default (flat) mode.
func NewGenerator() *Generator {
	return &Generator{}
}

// NewTopoGenerator creates a Generator in topological mode.
func NewTopoGenerator() *Generator {
	return &Generator{Mode: "topo"}
}

// Generate produces an ASCII infrastructure diagram from normalized resources.
// Uses the topology graph (if provided) to render connections between resources.
func (g *Generator) Generate(resources []parser.NormalizedResource) string {
	return g.GenerateWithGraph(resources, nil)
}

// GenerateWithGraph produces an ASCII infrastructure diagram
// using the topology graph for dependency-aware layout.
// In "topo" mode, renders a topological diagram with connections, nesting, and aggregation.
// In "flat" mode (default), renders the original layer-based diagram.
func (g *Generator) GenerateWithGraph(resources []parser.NormalizedResource, graph *topology.Graph) string {
	if len(resources) == 0 {
		return "Infrastructure Diagram\n" +
			"======================\n\n" +
			"  (no resource changes)\n"
	}

	// Filter out no-op/read resources
	var active []parser.NormalizedResource
	for _, r := range resources {
		if r.Action != "no-op" && r.Action != "read" {
			active = append(active, r)
		}
	}
	if len(active) == 0 {
		return "Infrastructure Diagram\n" +
			"======================\n\n" +
			"  (no resource changes)\n"
	}

	// Topological mode: resolve hierarchy, aggregate, render
	if g.Mode == "topo" {
		result := ResolveTopology(active, graph, g.ConfigRefs)
		result.SGCrossRefs = g.SGCrossRefs
		AggregateTopoResult(result)
		return RenderTopoResult(result)
	}

	// Flat mode (default): original layer-based rendering
	provider := detectProvider(active)
	layers := g.buildLayers(active)

	var edges map[string][]string
	if graph != nil {
		edges = buildEdgeMap(graph)
	}

	return g.renderElaborate(layers, edges, provider)
}

type layerDef struct {
	name  string
	order int
	icon  string
}

var layerDefs = map[string]layerDef{
	"Internet":   {name: "Internet", order: 0, icon: "☁"},
	"DNS":        {name: "DNS & CDN", order: 1, icon: "🌐"},
	"Access":     {name: "Load Balancing", order: 2, icon: "⚖"},
	"Network":    {name: "Network", order: 3, icon: "🔌"},
	"Compute":    {name: "Compute", order: 4, icon: "⚙"},
	"Data":       {name: "Data & Storage", order: 5, icon: "💾"},
	"Messaging":  {name: "Messaging & Events", order: 6, icon: "📨"},
	"IAM":        {name: "IAM", order: 7, icon: "👤"},
	"Security":   {name: "Security", order: 8, icon: "🔒"},
	"Secrets":    {name: "Secrets & Config", order: 9, icon: "🔑"},
	"CICD":       {name: "CI/CD & Registry", order: 10, icon: "🚀"},
	"Monitoring": {name: "Monitoring & Observability", order: 11, icon: "📊"},
	"Other":      {name: "Other", order: 12, icon: "📦"},
}

var layerMapping = map[string]string{
	// DNS & CDN
	"aws_route53_record":                    "DNS",
	"aws_route53_zone":                      "DNS",
	"aws_route53_health_check":              "DNS",
	"aws_route53_resolver_endpoint":         "DNS",
	"aws_route53_resolver_rule":             "DNS",
	"aws_cloudfront_distribution":           "DNS",
	"aws_cloudfront_origin_access_control":  "DNS",
	"aws_cloudfront_origin_access_identity": "DNS",
	"aws_cloudfront_cache_policy":           "DNS",
	"aws_cloudfront_function":               "DNS",

	// Access / Load Balancing
	"aws_lb":                         "Access",
	"aws_alb":                        "Access",
	"aws_lb_listener":                "Access",
	"aws_lb_listener_rule":           "Access",
	"aws_lb_target_group":            "Access",
	"aws_lb_target_group_attachment": "Access",
	"aws_api_gateway_rest_api":       "Access",
	"aws_api_gateway_resource":       "Access",
	"aws_api_gateway_method":         "Access",
	"aws_api_gateway_integration":    "Access",
	"aws_api_gateway_deployment":     "Access",
	"aws_api_gateway_stage":          "Access",
	"aws_apigatewayv2_api":           "Access",
	"aws_apigatewayv2_stage":         "Access",
	"aws_apigatewayv2_route":         "Access",
	"aws_apigatewayv2_integration":   "Access",
	"azurerm_lb":                     "Access",
	"google_compute_forwarding_rule": "Access",

	// Network Layer
	"aws_vpc":                          "Network",
	"aws_subnet":                       "Network",
	"aws_internet_gateway":             "Network",
	"aws_nat_gateway":                  "Network",
	"aws_route_table":                  "Network",
	"aws_route_table_association":      "Network",
	"aws_route":                        "Network",
	"aws_eip":                          "Network",
	"aws_vpc_peering_connection":       "Network",
	"aws_network_interface":            "Network",
	"aws_vpc_endpoint":                 "Network",
	"aws_vpc_endpoint_service":         "Network",
	"aws_vpc_dhcp_options":             "Network",
	"aws_vpc_dhcp_options_association": "Network",
	"aws_dx_connection":                "Network",
	"aws_dx_gateway":                   "Network",
	"aws_vpn_connection":               "Network",
	"aws_vpn_gateway":                  "Network",
	"aws_customer_gateway":             "Network",
	"aws_transit_gateway":              "Network",
	"aws_transit_gateway_attachment":   "Network",
	"aws_network_acl":                  "Network",
	"aws_network_acl_rule":             "Network",
	"azurerm_virtual_network":          "Network",
	"azurerm_subnet":                   "Network",
	"google_compute_network":           "Network",
	"google_compute_subnetwork":        "Network",

	// Compute Layer
	"aws_instance":                    "Compute",
	"aws_launch_template":             "Compute",
	"aws_autoscaling_group":           "Compute",
	"aws_autoscaling_policy":          "Compute",
	"aws_appautoscaling_target":       "Compute",
	"aws_appautoscaling_policy":       "Compute",
	"aws_ecs_cluster":                 "Compute",
	"aws_ecs_service":                 "Compute",
	"aws_ecs_task_definition":         "Compute",
	"aws_eks_cluster":                 "Compute",
	"aws_eks_node_group":              "Compute",
	"aws_eks_addon":                   "Compute",
	"aws_eks_fargate_profile":         "Compute",
	"aws_lambda_function":             "Compute",
	"aws_lambda_permission":           "Compute",
	"aws_lambda_layer_version":        "Compute",
	"aws_lambda_event_source_mapping": "Compute",
	"aws_batch_compute_environment":   "Compute",
	"aws_batch_job_definition":        "Compute",
	"aws_batch_job_queue":             "Compute",
	"aws_lightsail_instance":          "Compute",
	"aws_spot_instance_request":       "Compute",
	"azurerm_virtual_machine":         "Compute",
	"azurerm_linux_virtual_machine":   "Compute",
	"google_compute_instance":         "Compute",

	// Data & Storage Layer
	"aws_db_instance":                                    "Data",
	"aws_db_subnet_group":                                "Data",
	"aws_db_parameter_group":                             "Data",
	"aws_db_option_group":                                "Data",
	"aws_rds_cluster":                                    "Data",
	"aws_rds_cluster_instance":                           "Data",
	"aws_rds_cluster_parameter_group":                    "Data",
	"aws_dynamodb_table":                                 "Data",
	"aws_dynamodb_global_table":                          "Data",
	"aws_elasticache_cluster":                            "Data",
	"aws_elasticache_replication_group":                  "Data",
	"aws_elasticache_subnet_group":                       "Data",
	"aws_elasticache_parameter_group":                    "Data",
	"aws_s3_bucket":                                      "Data",
	"aws_s3_bucket_versioning":                           "Data",
	"aws_s3_bucket_server_side_encryption_configuration": "Data",
	"aws_s3_bucket_public_access_block":                  "Data",
	"aws_s3_bucket_policy":                               "Data",
	"aws_s3_bucket_lifecycle_configuration":              "Data",
	"aws_s3_bucket_logging":                              "Data",
	"aws_s3_bucket_cors_configuration":                   "Data",
	"aws_s3_bucket_notification":                         "Data",
	"aws_s3_bucket_object":                               "Data",
	"aws_s3_object":                                      "Data",
	"aws_ebs_volume":                                     "Data",
	"aws_ebs_snapshot":                                   "Data",
	"aws_efs_file_system":                                "Data",
	"aws_efs_mount_target":                               "Data",
	"aws_efs_access_point":                               "Data",
	"aws_redshift_cluster":                               "Data",
	"aws_elasticsearch_domain":                           "Data",
	"aws_opensearch_domain":                              "Data",
	"aws_kinesis_stream":                                 "Data",
	"aws_kinesis_firehose_delivery_stream":               "Data",
	"aws_glue_catalog_database":                          "Data",
	"aws_glue_catalog_table":                             "Data",
	"aws_glue_crawler":                                   "Data",
	"aws_glue_job":                                       "Data",
	"aws_athena_workgroup":                               "Data",
	"aws_backup_vault":                                   "Data",
	"aws_backup_plan":                                    "Data",
	"azurerm_storage_account":                            "Data",
	"google_storage_bucket":                              "Data",
	"google_sql_database_instance":                       "Data",

	// Messaging & Events Layer
	"aws_sqs_queue":               "Messaging",
	"aws_sqs_queue_policy":        "Messaging",
	"aws_sns_topic":               "Messaging",
	"aws_sns_topic_subscription":  "Messaging",
	"aws_sns_topic_policy":        "Messaging",
	"aws_eventbridge_rule":        "Messaging",
	"aws_cloudwatch_event_rule":   "Messaging",
	"aws_cloudwatch_event_target": "Messaging",
	"aws_ses_domain_identity":     "Messaging",
	"aws_ses_email_identity":      "Messaging",
	"aws_msk_cluster":             "Messaging",
	"aws_mq_broker":               "Messaging",
	"aws_sfn_state_machine":       "Messaging",
	"aws_sfn_activity":            "Messaging",

	// IAM Layer
	"aws_iam_role":                    "IAM",
	"aws_iam_policy":                  "IAM",
	"aws_iam_role_policy":             "IAM",
	"aws_iam_role_policy_attachment":  "IAM",
	"aws_iam_policy_attachment":       "IAM",
	"aws_iam_instance_profile":        "IAM",
	"aws_iam_user":                    "IAM",
	"aws_iam_user_policy":             "IAM",
	"aws_iam_user_policy_attachment":  "IAM",
	"aws_iam_group":                   "IAM",
	"aws_iam_group_policy":            "IAM",
	"aws_iam_group_membership":        "IAM",
	"aws_iam_access_key":              "IAM",
	"aws_iam_openid_connect_provider": "IAM",
	"aws_iam_saml_provider":           "IAM",
	"aws_iam_service_linked_role":     "IAM",

	// Security Layer
	"aws_security_group":              "Security",
	"aws_security_group_rule":         "Security",
	"aws_kms_key":                     "Security",
	"aws_kms_alias":                   "Security",
	"aws_kms_grant":                   "Security",
	"aws_acm_certificate":             "Security",
	"aws_acm_certificate_validation":  "Security",
	"aws_waf_web_acl":                 "Security",
	"aws_wafv2_web_acl":               "Security",
	"aws_wafv2_web_acl_association":   "Security",
	"aws_wafv2_ip_set":                "Security",
	"aws_wafv2_rule_group":            "Security",
	"aws_shield_protection":           "Security",
	"aws_guardduty_detector":          "Security",
	"aws_inspector_assessment_target": "Security",
	"aws_macie2_account":              "Security",
	"azurerm_network_security_group":  "Security",
	"google_compute_firewall":         "Security",

	// Secrets & Config Layer
	"aws_ssm_parameter":                   "Secrets",
	"aws_ssm_document":                    "Secrets",
	"aws_ssm_association":                 "Secrets",
	"aws_ssm_maintenance_window":          "Secrets",
	"aws_secretsmanager_secret":           "Secrets",
	"aws_secretsmanager_secret_version":   "Secrets",
	"aws_appconfig_application":           "Secrets",
	"aws_appconfig_environment":           "Secrets",
	"aws_appconfig_configuration_profile": "Secrets",

	// CI/CD & Registry Layer
	"aws_ecr_repository":                 "CICD",
	"aws_ecr_lifecycle_policy":           "CICD",
	"aws_ecr_repository_policy":          "CICD",
	"aws_codebuild_project":              "CICD",
	"aws_codepipeline":                   "CICD",
	"aws_codedeploy_app":                 "CICD",
	"aws_codedeploy_deployment_group":    "CICD",
	"aws_codecommit_repository":          "CICD",
	"aws_codeartifact_repository":        "CICD",
	"aws_codestarconnections_connection": "CICD",

	// Monitoring & Observability Layer
	"aws_cloudwatch_log_group":          "Monitoring",
	"aws_cloudwatch_log_stream":         "Monitoring",
	"aws_cloudwatch_log_metric_filter":  "Monitoring",
	"aws_cloudwatch_metric_alarm":       "Monitoring",
	"aws_cloudwatch_dashboard":          "Monitoring",
	"aws_cloudwatch_composite_alarm":    "Monitoring",
	"aws_cloudtrail":                    "Monitoring",
	"aws_flow_log":                      "Monitoring",
	"aws_config_configuration_recorder": "Monitoring",
	"aws_config_config_rule":            "Monitoring",
	"aws_config_delivery_channel":       "Monitoring",
	"aws_xray_sampling_rule":            "Monitoring",
	"aws_budgets_budget":                "Monitoring",
}

var serviceLabels = map[string]string{
	// AWS — Network
	"aws_vpc":                        "Amazon VPC",
	"aws_subnet":                     "Subnet",
	"aws_internet_gateway":           "Internet Gateway",
	"aws_nat_gateway":                "NAT Gateway",
	"aws_route_table":                "Route Table",
	"aws_route_table_association":    "Route Assoc.",
	"aws_route":                      "Route",
	"aws_eip":                        "Elastic IP",
	"aws_vpc_peering_connection":     "VPC Peering",
	"aws_network_interface":          "Network Interface",
	"aws_vpc_endpoint":               "VPC Endpoint",
	"aws_vpc_endpoint_service":       "VPC Endpoint Svc",
	"aws_vpc_dhcp_options":           "DHCP Options",
	"aws_dx_connection":              "Direct Connect",
	"aws_dx_gateway":                 "DX Gateway",
	"aws_vpn_connection":             "VPN Connection",
	"aws_vpn_gateway":                "VPN Gateway",
	"aws_customer_gateway":           "Customer Gateway",
	"aws_transit_gateway":            "Transit Gateway",
	"aws_transit_gateway_attachment": "TGW Attachment",
	"aws_network_acl":                "Network ACL",
	"aws_network_acl_rule":           "NACL Rule",

	// AWS — DNS & CDN
	"aws_route53_zone":                      "Amazon Route 53",
	"aws_route53_record":                    "Route 53 Record",
	"aws_route53_health_check":              "Route 53 Health Check",
	"aws_route53_resolver_endpoint":         "Route 53 Resolver",
	"aws_cloudfront_distribution":           "Amazon CloudFront",
	"aws_cloudfront_origin_access_control":  "CloudFront OAC",
	"aws_cloudfront_origin_access_identity": "CloudFront OAI",
	"aws_cloudfront_cache_policy":           "CloudFront Cache Policy",
	"aws_cloudfront_function":               "CloudFront Function",

	// AWS — Load Balancing & API
	"aws_lb":                         "Application LB",
	"aws_alb":                        "Application LB",
	"aws_lb_listener":                "LB Listener",
	"aws_lb_listener_rule":           "LB Listener Rule",
	"aws_lb_target_group":            "LB Target Group",
	"aws_lb_target_group_attachment": "TG Attachment",
	"aws_api_gateway_rest_api":       "API Gateway",
	"aws_api_gateway_resource":       "API GW Resource",
	"aws_api_gateway_method":         "API GW Method",
	"aws_api_gateway_integration":    "API GW Integration",
	"aws_api_gateway_deployment":     "API GW Deployment",
	"aws_api_gateway_stage":          "API GW Stage",
	"aws_apigatewayv2_api":           "API Gateway v2",
	"aws_apigatewayv2_stage":         "API GW v2 Stage",
	"aws_apigatewayv2_route":         "API GW v2 Route",
	"aws_apigatewayv2_integration":   "API GW v2 Integration",

	// AWS — Compute
	"aws_instance":                    "EC2 Instance",
	"aws_launch_template":             "Launch Template",
	"aws_autoscaling_group":           "Auto Scaling Group",
	"aws_autoscaling_policy":          "Auto Scaling Policy",
	"aws_appautoscaling_target":       "App Auto Scaling Target",
	"aws_appautoscaling_policy":       "App Auto Scaling Policy",
	"aws_ecs_cluster":                 "ECS Cluster",
	"aws_ecs_service":                 "ECS Service",
	"aws_ecs_task_definition":         "ECS Task Definition",
	"aws_eks_cluster":                 "EKS Cluster",
	"aws_eks_node_group":              "EKS Node Group",
	"aws_eks_addon":                   "EKS Add-on",
	"aws_eks_fargate_profile":         "EKS Fargate Profile",
	"aws_lambda_function":             "Lambda Function",
	"aws_lambda_permission":           "Lambda Permission",
	"aws_lambda_layer_version":        "Lambda Layer",
	"aws_lambda_event_source_mapping": "Lambda Event Source",
	"aws_batch_compute_environment":   "Batch Compute Env",
	"aws_batch_job_definition":        "Batch Job Definition",
	"aws_batch_job_queue":             "Batch Job Queue",
	"aws_lightsail_instance":          "Lightsail Instance",
	"aws_spot_instance_request":       "Spot Instance",

	// AWS — Data & Storage
	"aws_db_instance":                                    "Amazon RDS",
	"aws_db_subnet_group":                                "DB Subnet Group",
	"aws_db_parameter_group":                             "DB Parameter Group",
	"aws_db_option_group":                                "DB Option Group",
	"aws_rds_cluster":                                    "RDS Cluster",
	"aws_rds_cluster_instance":                           "RDS Instance",
	"aws_rds_cluster_parameter_group":                    "RDS Param Group",
	"aws_dynamodb_table":                                 "DynamoDB Table",
	"aws_dynamodb_global_table":                          "DynamoDB Global",
	"aws_elasticache_cluster":                            "ElastiCache",
	"aws_elasticache_replication_group":                  "ElastiCache Redis",
	"aws_elasticache_subnet_group":                       "ElastiCache Subnet",
	"aws_elasticache_parameter_group":                    "ElastiCache Params",
	"aws_s3_bucket":                                      "Amazon S3",
	"aws_s3_bucket_versioning":                           "S3 Versioning",
	"aws_s3_bucket_server_side_encryption_configuration": "S3 Encryption",
	"aws_s3_bucket_public_access_block":                  "S3 Access Block",
	"aws_s3_bucket_policy":                               "S3 Bucket Policy",
	"aws_s3_bucket_lifecycle_configuration":              "S3 Lifecycle",
	"aws_s3_bucket_logging":                              "S3 Logging",
	"aws_s3_bucket_cors_configuration":                   "S3 CORS",
	"aws_s3_bucket_notification":                         "S3 Notification",
	"aws_s3_bucket_object":                               "S3 Object",
	"aws_s3_object":                                      "S3 Object",
	"aws_ebs_volume":                                     "EBS Volume",
	"aws_ebs_snapshot":                                   "EBS Snapshot",
	"aws_efs_file_system":                                "Amazon EFS",
	"aws_efs_mount_target":                               "EFS Mount Target",
	"aws_efs_access_point":                               "EFS Access Point",
	"aws_redshift_cluster":                               "Amazon Redshift",
	"aws_elasticsearch_domain":                           "Elasticsearch",
	"aws_opensearch_domain":                              "OpenSearch",
	"aws_kinesis_stream":                                 "Kinesis Stream",
	"aws_kinesis_firehose_delivery_stream":               "Kinesis Firehose",
	"aws_glue_catalog_database":                          "Glue Database",
	"aws_glue_catalog_table":                             "Glue Table",
	"aws_glue_crawler":                                   "Glue Crawler",
	"aws_glue_job":                                       "Glue Job",
	"aws_athena_workgroup":                               "Athena Workgroup",
	"aws_backup_vault":                                   "Backup Vault",
	"aws_backup_plan":                                    "Backup Plan",

	// AWS — Messaging & Events
	"aws_sqs_queue":               "Amazon SQS",
	"aws_sqs_queue_policy":        "SQS Policy",
	"aws_sns_topic":               "Amazon SNS",
	"aws_sns_topic_subscription":  "SNS Subscription",
	"aws_sns_topic_policy":        "SNS Policy",
	"aws_eventbridge_rule":        "EventBridge Rule",
	"aws_cloudwatch_event_rule":   "EventBridge Rule",
	"aws_cloudwatch_event_target": "EventBridge Target",
	"aws_ses_domain_identity":     "SES Domain",
	"aws_ses_email_identity":      "SES Email",
	"aws_msk_cluster":             "Amazon MSK",
	"aws_mq_broker":               "Amazon MQ",
	"aws_sfn_state_machine":       "Step Functions",
	"aws_sfn_activity":            "Step Functions Activity",

	// AWS — IAM
	"aws_iam_role":                    "IAM Role",
	"aws_iam_policy":                  "IAM Policy",
	"aws_iam_role_policy":             "IAM Role Policy",
	"aws_iam_role_policy_attachment":  "IAM Attachment",
	"aws_iam_policy_attachment":       "IAM Attachment",
	"aws_iam_instance_profile":        "Instance Profile",
	"aws_iam_user":                    "IAM User",
	"aws_iam_user_policy":             "IAM User Policy",
	"aws_iam_user_policy_attachment":  "IAM User Attachment",
	"aws_iam_group":                   "IAM Group",
	"aws_iam_group_policy":            "IAM Group Policy",
	"aws_iam_group_membership":        "IAM Group Membership",
	"aws_iam_access_key":              "IAM Access Key",
	"aws_iam_openid_connect_provider": "OIDC Provider",
	"aws_iam_saml_provider":           "SAML Provider",
	"aws_iam_service_linked_role":     "Service-Linked Role",

	// AWS — Security
	"aws_security_group":              "Security Group",
	"aws_security_group_rule":         "SG Rule",
	"aws_kms_key":                     "KMS Key",
	"aws_kms_alias":                   "KMS Alias",
	"aws_kms_grant":                   "KMS Grant",
	"aws_acm_certificate":             "ACM Certificate",
	"aws_acm_certificate_validation":  "ACM Validation",
	"aws_waf_web_acl":                 "WAF ACL",
	"aws_wafv2_web_acl":               "WAF v2 ACL",
	"aws_wafv2_web_acl_association":   "WAF Association",
	"aws_wafv2_ip_set":                "WAF IP Set",
	"aws_wafv2_rule_group":            "WAF Rule Group",
	"aws_shield_protection":           "AWS Shield",
	"aws_guardduty_detector":          "GuardDuty",
	"aws_inspector_assessment_target": "Inspector",
	"aws_macie2_account":              "Amazon Macie",

	// AWS — Secrets & Config
	"aws_ssm_parameter":                   "SSM Parameter",
	"aws_ssm_document":                    "SSM Document",
	"aws_ssm_association":                 "SSM Association",
	"aws_ssm_maintenance_window":          "SSM Maintenance Window",
	"aws_secretsmanager_secret":           "Secrets Manager",
	"aws_secretsmanager_secret_version":   "Secret Version",
	"aws_appconfig_application":           "AppConfig App",
	"aws_appconfig_environment":           "AppConfig Env",
	"aws_appconfig_configuration_profile": "AppConfig Profile",

	// AWS — CI/CD & Registry
	"aws_ecr_repository":                 "ECR Repository",
	"aws_ecr_lifecycle_policy":           "ECR Lifecycle",
	"aws_ecr_repository_policy":          "ECR Policy",
	"aws_codebuild_project":              "CodeBuild Project",
	"aws_codepipeline":                   "CodePipeline",
	"aws_codedeploy_app":                 "CodeDeploy App",
	"aws_codedeploy_deployment_group":    "CodeDeploy Group",
	"aws_codecommit_repository":          "CodeCommit Repo",
	"aws_codeartifact_repository":        "CodeArtifact Repo",
	"aws_codestarconnections_connection": "CodeStar Connection",

	// AWS — Monitoring & Observability
	"aws_cloudwatch_log_group":          "CloudWatch Logs",
	"aws_cloudwatch_log_stream":         "CW Log Stream",
	"aws_cloudwatch_log_metric_filter":  "CW Metric Filter",
	"aws_cloudwatch_metric_alarm":       "CloudWatch Alarm",
	"aws_cloudwatch_dashboard":          "CW Dashboard",
	"aws_cloudwatch_composite_alarm":    "CW Composite Alarm",
	"aws_cloudtrail":                    "CloudTrail",
	"aws_flow_log":                      "VPC Flow Log",
	"aws_config_configuration_recorder": "AWS Config",
	"aws_config_config_rule":            "Config Rule",
	"aws_config_delivery_channel":       "Config Channel",
	"aws_xray_sampling_rule":            "X-Ray Sampling",
	"aws_budgets_budget":                "AWS Budget",

	// Azure
	"azurerm_virtual_network":        "Virtual Network",
	"azurerm_subnet":                 "Subnet",
	"azurerm_virtual_machine":        "Virtual Machine",
	"azurerm_linux_virtual_machine":  "Linux VM",
	"azurerm_storage_account":        "Storage Account",
	"azurerm_lb":                     "Load Balancer",
	"azurerm_network_security_group": "Network SG",

	// GCP
	"google_compute_instance":      "Compute Instance",
	"google_compute_network":       "VPC Network",
	"google_compute_subnetwork":    "Subnetwork",
	"google_compute_firewall":      "Firewall Rule",
	"google_storage_bucket":        "Cloud Storage",
	"google_sql_database_instance": "Cloud SQL",
}

func getLayer(resourceType string) string {
	if layer, ok := layerMapping[resourceType]; ok {
		return layer
	}

	parts := strings.Split(resourceType, "_")
	if len(parts) >= 2 {
		// Check data-related keywords FIRST so "rds_cluster" → Data, not Compute.
		switch {
		case containsPart(parts, "db") || containsPart(parts, "rds") || containsPart(parts, "database") ||
			containsPart(parts, "dynamodb") || containsPart(parts, "elasticache") ||
			containsPart(parts, "storage") || containsPart(parts, "bucket") || containsPart(parts, "s3") ||
			containsPart(parts, "efs") || containsPart(parts, "redshift") || containsPart(parts, "kinesis") ||
			containsPart(parts, "glue") || containsPart(parts, "athena") || containsPart(parts, "backup") ||
			containsPart(parts, "opensearch") || containsPart(parts, "elasticsearch"):
			return "Data"
		case containsPart(parts, "sqs") || containsPart(parts, "sns") || containsPart(parts, "eventbridge") ||
			containsPart(parts, "ses") || containsPart(parts, "msk") || containsPart(parts, "mq") ||
			containsPart(parts, "sfn"):
			return "Messaging"
		case containsPart(parts, "cloudfront") || containsPart(parts, "route53") || containsPart(parts, "dns"):
			return "DNS"
		case containsPart(parts, "lb") || containsPart(parts, "alb") || containsPart(parts, "gateway"):
			return "Access"
		case containsPart(parts, "iam"):
			return "IAM"
		case containsPart(parts, "security") || containsPart(parts, "kms") ||
			containsPart(parts, "firewall") || containsPart(parts, "waf") || containsPart(parts, "acm") ||
			containsPart(parts, "guardduty") || containsPart(parts, "shield") || containsPart(parts, "macie") ||
			containsPart(parts, "inspector"):
			return "Security"
		case containsPart(parts, "ssm") || containsPart(parts, "secretsmanager") || containsPart(parts, "appconfig"):
			return "Secrets"
		case containsPart(parts, "ecr") || containsPart(parts, "codebuild") || containsPart(parts, "codepipeline") ||
			containsPart(parts, "codedeploy") || containsPart(parts, "codecommit") || containsPart(parts, "codeartifact"):
			return "CICD"
		case containsPart(parts, "cloudwatch") || containsPart(parts, "log") || containsPart(parts, "alarm") ||
			containsPart(parts, "monitor") || containsPart(parts, "cloudtrail") || containsPart(parts, "config") ||
			containsPart(parts, "xray") || containsPart(parts, "budgets"):
			return "Monitoring"
		case containsPart(parts, "vpc") || containsPart(parts, "subnet") || containsPart(parts, "network") ||
			containsPart(parts, "route") || containsPart(parts, "eip") || containsPart(parts, "nat") ||
			containsPart(parts, "transit") || containsPart(parts, "vpn") || containsPart(parts, "dx"):
			return "Network"
		case containsPart(parts, "instance") || containsPart(parts, "cluster") || containsPart(parts, "lambda") ||
			containsPart(parts, "ecs") || containsPart(parts, "eks") || containsPart(parts, "autoscaling") ||
			containsPart(parts, "batch") || containsPart(parts, "lightsail"):
			return "Compute"
		}
	}

	return "Other"
}

func containsPart(parts []string, target string) bool {
	for _, p := range parts {
		if p == target {
			return true
		}
	}
	return false
}

func actionIcon(action string) string {
	switch action {
	case "create":
		return "[+]"
	case "update":
		return "[~]"
	case "delete":
		return "[-]"
	case "replace":
		return "[!]"
	default:
		return "[ ]"
	}
}

func getLabel(resType, address string) string {
	if label, ok := serviceLabels[resType]; ok {
		// Append the resource name for disambiguation
		parts := strings.SplitN(address, ".", 2)
		if len(parts) == 2 {
			return label + " (" + parts[1] + ")"
		}
		return label
	}
	return address
}

func runeLen(s string) int {
	return utf8.RuneCountInString(s)
}

func detectProvider(resources []parser.NormalizedResource) string {
	for _, r := range resources {
		t := strings.ToLower(r.Type)
		if strings.HasPrefix(t, "aws_") {
			return "aws"
		}
		if strings.HasPrefix(t, "azurerm_") {
			return "azure"
		}
		if strings.HasPrefix(t, "google_") {
			return "gcp"
		}
	}
	return "unknown"
}

func providerTitle(provider string) string {
	switch provider {
	case "aws":
		return "AWS"
	case "azure":
		return "Azure"
	case "gcp":
		return "Google Cloud"
	default:
		return "Cloud"
	}
}

func buildEdgeMap(graph *topology.Graph) map[string][]string {
	edges := make(map[string][]string)
	for _, e := range graph.Edges {
		edges[e.From] = append(edges[e.From], e.To)
	}
	return edges
}

func (g *Generator) buildLayers(resources []parser.NormalizedResource) []Layer {
	layerMap := make(map[string]*Layer)

	for _, r := range resources {
		layerName := getLayer(r.Type)
		layer, exists := layerMap[layerName]
		if !exists {
			def, ok := layerDefs[layerName]
			if !ok {
				def = layerDefs["Other"]
			}
			layer = &Layer{
				Name:  layerName,
				Order: def.order,
			}
			layerMap[layerName] = layer
		}

		layer.Resources = append(layer.Resources, ResourceEntry{
			Address: r.Address,
			Type:    r.Type,
			Action:  r.Action,
			Label:   getLabel(r.Type, r.Address),
		})
	}

	layers := make([]Layer, 0, len(layerMap))
	for _, l := range layerMap {
		layers = append(layers, *l)
	}

	sort.Slice(layers, func(i, j int) bool {
		return layers[i].Order < layers[j].Order
	})

	return layers
}

const (
	boxMinWidth   = 40
	maxBoxWidth   = 70
	diagramWidth  = 100
	connectorChar = "│"
	arrowDown     = "▼"
	cornerTL      = "┌"
	cornerTR      = "┐"
	cornerBL      = "└"
	cornerBR      = "┘"
	horizLine     = "─"
	teeDown       = "┬"
	teeUp         = "┴"
	vertLine      = "│"
)

func (g *Generator) renderElaborate(layers []Layer, edges map[string][]string, provider string) string {
	var sb strings.Builder

	title := fmt.Sprintf("Infrastructure Diagram — %s", providerTitle(provider))
	sb.WriteString(fmt.Sprintf("\n%s\n", centerText(title, diagramWidth)))
	sb.WriteString(fmt.Sprintf("%s\n\n", centerText(strings.Repeat("═", len(title)), diagramWidth)))

	// Determine if there are network-related resources that suggest a VPC boundary
	hasVPC := false
	var vpcLayers []Layer
	var outsideLayers []Layer

	for _, layer := range layers {
		switch layer.Name {
		case "Network", "Compute", "Data":
			vpcLayers = append(vpcLayers, layer)
			if layer.Name == "Network" {
				hasVPC = true
			}
		default:
			outsideLayers = append(outsideLayers, layer)
		}
	}

	// If no VPC, treat everything as outside layers
	if !hasVPC {
		outsideLayers = layers
		vpcLayers = nil
	}

	// Render Internet entry point
	sb.WriteString(renderCenteredBox("Internet", diagramWidth))
	sb.WriteString(renderCenteredConnector(diagramWidth))

	// Render outside-VPC layers (DNS, Access, Security, Monitoring)
	for _, layer := range outsideLayers {
		g.renderLayerBoxes(&sb, layer, edges)
		sb.WriteString(renderCenteredConnector(diagramWidth))
	}

	// Render VPC boundary if applicable
	if len(vpcLayers) > 0 {
		g.renderVPCSection(&sb, vpcLayers, edges, provider)
	}

	// Legend
	sb.WriteString("\n")
	sb.WriteString(centerText("[+] create  [~] update  [-] delete  [!] replace", diagramWidth))
	sb.WriteString("\n")

	return sb.String()
}

func (g *Generator) renderLayerBoxes(sb *strings.Builder, layer Layer, edges map[string][]string) { //nolint:unparam // edges reserved for future connection rendering
	def, ok := layerDefs[layer.Name]
	if !ok {
		def = layerDefs["Other"]
	}

	if len(layer.Resources) <= 2 {
		// Single centered box with all resources
		g.renderSingleLayerBox(sb, def.name, layer.Resources)
	} else {
		// Split into two columns
		mid := (len(layer.Resources) + 1) / 2
		left := layer.Resources[:mid]
		right := layer.Resources[mid:]
		g.renderDualColumnBox(sb, def.name, left, right)
	}
}

func (g *Generator) renderSingleLayerBox(sb *strings.Builder, title string, resources []ResourceEntry) {
	// Calculate box width (using rune count for proper Unicode alignment)
	maxContent := runeLen(title) + 4
	for _, r := range resources {
		line := fmt.Sprintf(" %s %s ", actionIcon(r.Action), r.Label)
		if runeLen(line) > maxContent {
			maxContent = runeLen(line)
		}
	}
	boxWidth := maxContent + 4
	if boxWidth < boxMinWidth {
		boxWidth = boxMinWidth
	}
	if boxWidth > maxBoxWidth {
		boxWidth = maxBoxWidth
	}

	// Centered box
	pad := (diagramWidth - boxWidth) / 2
	prefix := strings.Repeat(" ", pad)

	// Top border
	sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, cornerTL, strings.Repeat(horizLine, boxWidth-2), cornerTR))

	// Title
	titlePad := boxWidth - 4 - runeLen(title)
	if titlePad < 0 {
		titlePad = 0
	}
	sb.WriteString(fmt.Sprintf("%s%s  %s%s%s\n", prefix, vertLine, title, strings.Repeat(" ", titlePad), vertLine))

	// Separator
	sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, vertLine, strings.Repeat(horizLine, boxWidth-2), vertLine))

	// Resources
	for _, r := range resources {
		label := r.Label
		if runeLen(label) > boxWidth-8 {
			runes := []rune(label)
			label = string(runes[:boxWidth-11]) + "..."
		}
		line := fmt.Sprintf("%s %s", actionIcon(r.Action), label)
		linePad := boxWidth - 4 - runeLen(line)
		if linePad < 0 {
			linePad = 0
		}
		sb.WriteString(fmt.Sprintf("%s%s  %s%s%s\n", prefix, vertLine, line, strings.Repeat(" ", linePad), vertLine))
	}

	// Bottom border
	sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, cornerBL, strings.Repeat(horizLine, boxWidth-2), cornerBR))
}

func (g *Generator) renderDualColumnBox(sb *strings.Builder, title string, left, right []ResourceEntry) {
	// Title spanning both columns
	totalWidth := diagramWidth - 4
	titlePad := totalWidth - runeLen(title) - 1
	if titlePad < 0 {
		titlePad = 0
	}

	sb.WriteString(fmt.Sprintf("  %s%s%s\n", cornerTL, strings.Repeat(horizLine, totalWidth), cornerTR))
	sb.WriteString(fmt.Sprintf("  %s %s%s%s\n", vertLine, title, strings.Repeat(" ", titlePad), vertLine))
	sb.WriteString(fmt.Sprintf("  %s%s%s\n", vertLine, strings.Repeat(horizLine, totalWidth), vertLine))

	// Dual columns
	maxRows := len(left)
	if len(right) > maxRows {
		maxRows = len(right)
	}

	halfWidth := (totalWidth - 3) / 2 // -3 for " │ " separator

	for i := 0; i < maxRows; i++ {
		var leftStr, rightStr string
		if i < len(left) {
			leftStr = fmt.Sprintf("%s %s", actionIcon(left[i].Action), left[i].Label)
		}
		if i < len(right) {
			rightStr = fmt.Sprintf("%s %s", actionIcon(right[i].Action), right[i].Label)
		}

		if runeLen(leftStr) > halfWidth-1 {
			runes := []rune(leftStr)
			leftStr = string(runes[:halfWidth-4]) + "..."
		}
		if runeLen(rightStr) > halfWidth-1 {
			runes := []rune(rightStr)
			rightStr = string(runes[:halfWidth-4]) + "..."
		}

		lPad := halfWidth - runeLen(leftStr)
		rPad := halfWidth - runeLen(rightStr)
		if lPad < 0 {
			lPad = 0
		}
		if rPad < 0 {
			rPad = 0
		}

		sb.WriteString(fmt.Sprintf("  %s %s%s %s %s%s%s\n",
			vertLine, leftStr, strings.Repeat(" ", lPad),
			vertLine, rightStr, strings.Repeat(" ", rPad), vertLine))
	}

	sb.WriteString(fmt.Sprintf("  %s%s%s\n", cornerBL, strings.Repeat(horizLine, totalWidth), cornerBR))
}

func (g *Generator) renderVPCSection(sb *strings.Builder, layers []Layer, edges map[string][]string, provider string) { //nolint:unparam // edges reserved for future connection rendering
	vpcLabel := "VPC"
	if provider == "azure" {
		vpcLabel = "Virtual Network"
	} else if provider == "gcp" {
		vpcLabel = "VPC Network"
	}

	totalWidth := diagramWidth - 4
	vpcTitlePad := totalWidth - runeLen(vpcLabel) - 1
	if vpcTitlePad < 0 {
		vpcTitlePad = 0
	}

	// VPC top border (double lines)
	sb.WriteString(fmt.Sprintf("  ╔%s╗\n", strings.Repeat("═", totalWidth)))
	sb.WriteString(fmt.Sprintf("  ║ %s%s║\n", vpcLabel, strings.Repeat(" ", vpcTitlePad)))
	sb.WriteString(fmt.Sprintf("  ║%s║\n", strings.Repeat(" ", totalWidth)))

	// Render each layer inside VPC
	for i, layer := range layers {
		def, ok := layerDefs[layer.Name]
		if !ok {
			def = layerDefs["Other"]
		}
		g.renderInnerLayer(sb, def.name, layer.Resources, totalWidth)

		if i < len(layers)-1 {
			// Connector inside VPC
			center := totalWidth / 2
			sb.WriteString(fmt.Sprintf("  ║%s%s%s║\n", strings.Repeat(" ", center), connectorChar, strings.Repeat(" ", totalWidth-center-1)))
			sb.WriteString(fmt.Sprintf("  ║%s%s%s║\n", strings.Repeat(" ", center), arrowDown, strings.Repeat(" ", totalWidth-center-1)))
		}
	}

	sb.WriteString(fmt.Sprintf("  ║%s║\n", strings.Repeat(" ", totalWidth)))
	sb.WriteString(fmt.Sprintf("  ╚%s╝\n", strings.Repeat("═", totalWidth)))
}

func (g *Generator) renderInnerLayer(sb *strings.Builder, title string, resources []ResourceEntry, outerWidth int) {
	innerWidth := outerWidth - 6

	if len(resources) <= 2 {
		g.renderInnerSingleBox(sb, title, resources, outerWidth, innerWidth)
	} else {
		g.renderInnerDualBox(sb, title, resources, outerWidth, innerWidth)
	}
}

func (g *Generator) renderInnerSingleBox(sb *strings.Builder, title string, resources []ResourceEntry, outerWidth, innerWidth int) {
	boxWidth := innerWidth
	if boxWidth > maxBoxWidth {
		boxWidth = maxBoxWidth
	}
	innerPad := (outerWidth - boxWidth) / 2

	prefix := fmt.Sprintf("  ║%s", strings.Repeat(" ", innerPad))
	suffix := func(visualLen int) string {
		remaining := outerWidth - innerPad - visualLen
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("%s║", strings.Repeat(" ", remaining))
	}

	// Top border — visual width = boxWidth (1 + boxWidth-2 + 1)
	topLine := fmt.Sprintf("%s%s%s", cornerTL, strings.Repeat(horizLine, boxWidth-2), cornerTR)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, topLine, suffix(boxWidth)))

	// Title — visual width = boxWidth (1 + 2 + titleLen + pad + 1)
	tPad := boxWidth - 4 - runeLen(title)
	if tPad < 0 {
		tPad = 0
	}
	titleLine := fmt.Sprintf("%s  %s%s%s", vertLine, title, strings.Repeat(" ", tPad), vertLine)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, titleLine, suffix(boxWidth)))

	// Separator
	sepLine := fmt.Sprintf("%s%s%s", vertLine, strings.Repeat(horizLine, boxWidth-2), vertLine)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, sepLine, suffix(boxWidth)))

	// Resources
	for _, r := range resources {
		label := r.Label
		if runeLen(label) > boxWidth-8 {
			runes := []rune(label)
			label = string(runes[:boxWidth-11]) + "..."
		}
		line := fmt.Sprintf("%s %s", actionIcon(r.Action), label)
		lPad := boxWidth - 4 - runeLen(line)
		if lPad < 0 {
			lPad = 0
		}
		resLine := fmt.Sprintf("%s  %s%s%s", vertLine, line, strings.Repeat(" ", lPad), vertLine)
		sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, resLine, suffix(boxWidth)))
	}

	// Bottom border
	botLine := fmt.Sprintf("%s%s%s", cornerBL, strings.Repeat(horizLine, boxWidth-2), cornerBR)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, botLine, suffix(boxWidth)))
}

func (g *Generator) renderInnerDualBox(sb *strings.Builder, title string, resources []ResourceEntry, outerWidth, innerWidth int) {
	// Split into left/right
	mid := (len(resources) + 1) / 2
	left := resources[:mid]
	right := resources[mid:]

	colWidth := (innerWidth - 5) / 2 // -5 for spaces and separator
	if colWidth < 15 {
		colWidth = 15
	}

	// The total inner box width (visual chars)
	// Row = │ + space + colWidth + │ + space + colWidth + │ = colWidth*2 + 5
	boxWidth := colWidth*2 + 5
	innerPad := (outerWidth - boxWidth) / 2

	prefix := fmt.Sprintf("  ║%s", strings.Repeat(" ", innerPad))
	suffix := func(visualLen int) string {
		remaining := outerWidth - innerPad - visualLen
		if remaining < 0 {
			remaining = 0
		}
		return fmt.Sprintf("%s║", strings.Repeat(" ", remaining))
	}

	// Top border — visual width = boxWidth
	topLine := fmt.Sprintf("%s%s%s", cornerTL, strings.Repeat(horizLine, boxWidth-2), cornerTR)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, topLine, suffix(boxWidth)))

	// Title — visual width = boxWidth
	tPad := boxWidth - 4 - runeLen(title)
	if tPad < 0 {
		tPad = 0
	}
	titleLine := fmt.Sprintf("%s  %s%s%s", vertLine, title, strings.Repeat(" ", tPad), vertLine)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, titleLine, suffix(boxWidth)))

	// Separator — visual width = boxWidth
	sepLine := fmt.Sprintf("%s%s%s", vertLine, strings.Repeat(horizLine, boxWidth-2), vertLine)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, sepLine, suffix(boxWidth)))

	// Dual columns
	maxRows := len(left)
	if len(right) > maxRows {
		maxRows = len(right)
	}

	for i := 0; i < maxRows; i++ {
		var leftStr, rightStr string
		if i < len(left) {
			leftStr = fmt.Sprintf("%s %s", actionIcon(left[i].Action), left[i].Label)
		}
		if i < len(right) {
			rightStr = fmt.Sprintf("%s %s", actionIcon(right[i].Action), right[i].Label)
		}

		if runeLen(leftStr) > colWidth-1 {
			runes := []rune(leftStr)
			leftStr = string(runes[:colWidth-4]) + "..."
		}
		if runeLen(rightStr) > colWidth-1 {
			runes := []rune(rightStr)
			rightStr = string(runes[:colWidth-4]) + "..."
		}

		lp := colWidth - runeLen(leftStr)
		rp := colWidth - runeLen(rightStr)
		if lp < 0 {
			lp = 0
		}
		if rp < 0 {
			rp = 0
		}

		rowLine := fmt.Sprintf("%s %s%s%s %s%s%s",
			vertLine, leftStr, strings.Repeat(" ", lp),
			vertLine, rightStr, strings.Repeat(" ", rp), vertLine)
		sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, rowLine, suffix(boxWidth)))
	}

	// Bottom border
	botLine := fmt.Sprintf("%s%s%s", cornerBL, strings.Repeat(horizLine, boxWidth-2), cornerBR)
	sb.WriteString(fmt.Sprintf("%s%s%s\n", prefix, botLine, suffix(boxWidth)))
}

func centerText(text string, width int) string {
	if runeLen(text) >= width {
		return text
	}
	pad := (width - runeLen(text)) / 2
	return strings.Repeat(" ", pad) + text
}

func renderCenteredBox(label string, totalWidth int) string {
	boxWidth := runeLen(label) + 6
	pad := (totalWidth - boxWidth) / 2
	prefix := strings.Repeat(" ", pad)

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, cornerTL, strings.Repeat(horizLine, boxWidth-2), cornerTR))
	titlePad := boxWidth - 4 - runeLen(label)
	if titlePad < 0 {
		titlePad = 0
	}
	sb.WriteString(fmt.Sprintf("%s%s  %s%s%s\n", prefix, vertLine, label, strings.Repeat(" ", titlePad), vertLine))
	sb.WriteString(fmt.Sprintf("%s%s%s%s\n", prefix, cornerBL, strings.Repeat(horizLine, boxWidth-2), cornerBR))
	return sb.String()
}

func renderCenteredConnector(totalWidth int) string {
	center := totalWidth / 2
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s%s\n", strings.Repeat(" ", center), connectorChar))
	sb.WriteString(fmt.Sprintf("%s%s\n", strings.Repeat(" ", center), arrowDown))
	return sb.String()
}
