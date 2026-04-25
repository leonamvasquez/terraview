package feature

type typeProfile struct {
	network, encryption, identity, governance, observability int
}

var typeRegistry = map[string]typeProfile{
	// Compute
	"aws_instance":          {2, 1, 1, 1, 2},
	"aws_launch_template":   {1, 1, 1, 1, 1},
	"aws_autoscaling_group": {1, 0, 1, 1, 2},
	// Containers
	"aws_ecs_cluster":         {1, 1, 1, 1, 2},
	"aws_ecs_service":         {2, 1, 1, 1, 2},
	"aws_ecs_task_definition": {1, 2, 2, 1, 1},
	"aws_ecr_repository":      {0, 1, 2, 1, 1},
	// Kubernetes
	"aws_eks_cluster":         {3, 2, 2, 2, 2},
	"aws_eks_node_group":      {2, 1, 1, 1, 1},
	"aws_eks_fargate_profile": {1, 1, 2, 1, 1},
	// Serverless
	"aws_lambda_function":   {1, 1, 2, 1, 2},
	"aws_lambda_permission": {0, 0, 3, 1, 0},
	// Storage
	"aws_s3_bucket":                     {2, 2, 2, 2, 2},
	"aws_s3_bucket_public_access_block": {3, 0, 0, 1, 0},
	"aws_ebs_volume":                    {0, 3, 0, 1, 1},
	"aws_efs_file_system":               {1, 2, 0, 1, 1},
	"aws_glacier_vault":                 {0, 2, 2, 1, 0},
	// Database
	"aws_db_instance":                   {2, 2, 1, 2, 2},
	"aws_rds_cluster":                   {2, 2, 1, 2, 2},
	"aws_rds_cluster_instance":          {2, 2, 1, 1, 2},
	"aws_dynamodb_table":                {0, 2, 1, 2, 1},
	"aws_elasticache_cluster":           {1, 2, 0, 1, 1},
	"aws_elasticache_replication_group": {1, 2, 0, 1, 1},
	"aws_redshift_cluster":              {2, 2, 1, 2, 2},
	"aws_neptune_cluster":               {2, 2, 1, 2, 1},
	"aws_docdb_cluster":                 {2, 2, 1, 2, 1},
	// Messaging
	"aws_sqs_queue":                        {0, 2, 2, 1, 1},
	"aws_sns_topic":                        {1, 2, 2, 1, 1},
	"aws_kinesis_stream":                   {0, 2, 1, 1, 2},
	"aws_kinesis_firehose_delivery_stream": {0, 2, 1, 1, 2},
	"aws_msk_cluster":                      {2, 2, 1, 1, 2},
	"aws_mq_broker":                        {2, 2, 1, 1, 1},
	"aws_eventbridge_bus":                  {0, 1, 2, 1, 1},
	// Search/Analytics
	"aws_opensearch_domain":     {2, 2, 2, 1, 2},
	"aws_elasticsearch_domain":  {2, 2, 2, 1, 2},
	"aws_athena_workgroup":      {0, 2, 1, 1, 1},
	"aws_glue_catalog_database": {0, 1, 2, 1, 1},
	// Networking
	"aws_vpc":                       {3, 0, 0, 1, 1},
	"aws_subnet":                    {2, 0, 0, 1, 0},
	"aws_security_group":            {3, 0, 0, 1, 0},
	"aws_security_group_rule":       {3, 0, 0, 1, 0},
	"aws_lb":                        {3, 1, 0, 1, 2},
	"aws_alb":                       {3, 1, 0, 1, 2},
	"aws_lb_listener":               {3, 1, 0, 1, 1},
	"aws_cloudfront_distribution":   {3, 1, 0, 1, 2},
	"aws_wafv2_web_acl":             {3, 0, 0, 1, 1},
	"aws_vpc_endpoint":              {2, 0, 1, 1, 0},
	"aws_nat_gateway":               {2, 0, 0, 1, 0},
	"aws_internet_gateway":          {3, 0, 0, 1, 0},
	"aws_transit_gateway":           {2, 0, 0, 1, 0},
	"aws_network_firewall_firewall": {3, 1, 0, 1, 2},
	// Identity
	"aws_iam_role":             {0, 0, 3, 1, 0},
	"aws_iam_policy":           {0, 0, 3, 1, 0},
	"aws_iam_user":             {0, 0, 3, 1, 0},
	"aws_iam_user_policy":      {0, 0, 3, 1, 0},
	"aws_iam_role_policy":      {0, 0, 3, 1, 0},
	"aws_iam_instance_profile": {0, 0, 2, 1, 0},
	// Secrets/KMS
	"aws_secretsmanager_secret": {0, 3, 2, 1, 1},
	"aws_kms_key":               {0, 3, 2, 2, 1},
	"aws_ssm_parameter":         {0, 2, 1, 1, 0},
	// Observability
	"aws_cloudwatch_log_group":          {0, 2, 0, 2, 3},
	"aws_cloudwatch_metric_alarm":       {0, 0, 0, 1, 2},
	"aws_cloudtrail":                    {0, 2, 1, 3, 3},
	"aws_config_configuration_recorder": {0, 1, 1, 3, 2},
	"aws_guardduty_detector":            {0, 0, 0, 2, 3},
	// API Gateway
	"aws_api_gateway_rest_api": {2, 1, 2, 1, 2},
	"aws_apigatewayv2_api":     {2, 1, 2, 1, 2},
	// ML
	"aws_sagemaker_endpoint":          {2, 2, 1, 1, 2},
	"aws_sagemaker_notebook_instance": {1, 2, 1, 1, 1},
	// Backup/DR
	"aws_backup_vault": {0, 2, 1, 2, 1},
	"aws_backup_plan":  {0, 0, 0, 2, 1},
}

func lookupProfile(resourceType string) (typeProfile, bool) {
	p, ok := typeRegistry[resourceType]
	return p, ok
}
