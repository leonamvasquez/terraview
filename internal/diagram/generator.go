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
type Generator struct{}

// NewGenerator creates a new diagram Generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// Generate produces an ASCII infrastructure diagram from normalized resources.
// Uses the topology graph (if provided) to render connections between resources.
func (g *Generator) Generate(resources []parser.NormalizedResource) string {
	return g.GenerateWithGraph(resources, nil)
}

// GenerateWithGraph produces an elaborate ASCII infrastructure diagram
// using the topology graph for dependency-aware layout.
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

	// Detect provider
	provider := detectProvider(active)

	// Build layered diagram
	layers := g.buildLayers(active)

	// Build edge map from topology graph
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
	"Security":   {name: "Security & IAM", order: 6, icon: "🔒"},
	"Monitoring": {name: "Monitoring", order: 7, icon: "📊"},
	"Other":      {name: "Other", order: 8, icon: "📦"},
}

var layerMapping = map[string]string{
	// DNS & CDN
	"aws_route53_record":                    "DNS",
	"aws_route53_zone":                      "DNS",
	"aws_cloudfront_distribution":           "DNS",
	"aws_cloudfront_origin_access_control":  "DNS",
	"aws_cloudfront_origin_access_identity": "DNS",

	// Access / Load Balancing
	"aws_lb":                         "Access",
	"aws_alb":                        "Access",
	"aws_lb_listener":                "Access",
	"aws_lb_target_group":            "Access",
	"aws_lb_target_group_attachment": "Access",
	"aws_api_gateway_rest_api":       "Access",
	"aws_apigatewayv2_api":           "Access",
	"azurerm_lb":                     "Access",
	"google_compute_forwarding_rule": "Access",

	// Network Layer
	"aws_vpc":                     "Network",
	"aws_subnet":                  "Network",
	"aws_internet_gateway":        "Network",
	"aws_nat_gateway":             "Network",
	"aws_route_table":             "Network",
	"aws_route_table_association": "Network",
	"aws_route":                   "Network",
	"aws_eip":                     "Network",
	"aws_vpc_peering_connection":  "Network",
	"aws_network_interface":       "Network",
	"azurerm_virtual_network":     "Network",
	"azurerm_subnet":              "Network",
	"google_compute_network":      "Network",
	"google_compute_subnetwork":   "Network",

	// Compute Layer
	"aws_instance":                  "Compute",
	"aws_launch_template":           "Compute",
	"aws_autoscaling_group":         "Compute",
	"aws_appautoscaling_target":     "Compute",
	"aws_appautoscaling_policy":     "Compute",
	"aws_ecs_cluster":               "Compute",
	"aws_ecs_service":               "Compute",
	"aws_ecs_task_definition":       "Compute",
	"aws_eks_cluster":               "Compute",
	"aws_eks_node_group":            "Compute",
	"aws_lambda_function":           "Compute",
	"aws_lambda_permission":         "Compute",
	"azurerm_virtual_machine":       "Compute",
	"azurerm_linux_virtual_machine": "Compute",
	"google_compute_instance":       "Compute",

	// Data Layer
	"aws_db_instance":                                    "Data",
	"aws_db_subnet_group":                                "Data",
	"aws_rds_cluster":                                    "Data",
	"aws_rds_cluster_instance":                           "Data",
	"aws_dynamodb_table":                                 "Data",
	"aws_elasticache_cluster":                            "Data",
	"aws_elasticache_replication_group":                  "Data",
	"aws_elasticache_subnet_group":                       "Data",
	"aws_s3_bucket":                                      "Data",
	"aws_s3_bucket_versioning":                           "Data",
	"aws_s3_bucket_server_side_encryption_configuration": "Data",
	"aws_s3_bucket_public_access_block":                  "Data",
	"aws_s3_bucket_policy":                               "Data",
	"aws_s3_bucket_lifecycle_configuration":              "Data",
	"aws_s3_bucket_logging":                              "Data",
	"aws_s3_bucket_cors_configuration":                   "Data",
	"aws_sqs_queue":                                      "Data",
	"aws_sns_topic":                                      "Data",
	"aws_sns_topic_subscription":                         "Data",
	"aws_ebs_volume":                                     "Data",
	"azurerm_storage_account":                            "Data",
	"google_storage_bucket":                              "Data",
	"google_sql_database_instance":                       "Data",

	// Security Layer
	"aws_security_group":             "Security",
	"aws_security_group_rule":        "Security",
	"aws_iam_role":                   "Security",
	"aws_iam_policy":                 "Security",
	"aws_iam_role_policy":            "Security",
	"aws_iam_role_policy_attachment": "Security",
	"aws_iam_instance_profile":       "Security",
	"aws_iam_user":                   "Security",
	"aws_iam_group":                  "Security",
	"aws_kms_key":                    "Security",
	"aws_kms_alias":                  "Security",
	"aws_acm_certificate":            "Security",
	"aws_waf_web_acl":                "Security",
	"aws_wafv2_web_acl":              "Security",
	"azurerm_network_security_group": "Security",
	"google_compute_firewall":        "Security",

	// Monitoring Layer
	"aws_cloudwatch_log_group":          "Monitoring",
	"aws_cloudwatch_metric_alarm":       "Monitoring",
	"aws_cloudtrail":                    "Monitoring",
	"aws_flow_log":                      "Monitoring",
	"aws_config_configuration_recorder": "Monitoring",

	// Managed rules (Security Layer)
	"aws_wafv2_web_acl_association": "Security",
}

var serviceLabels = map[string]string{
	// AWS
	"aws_vpc":                               "Amazon VPC",
	"aws_subnet":                            "Subnet",
	"aws_internet_gateway":                  "Internet Gateway",
	"aws_nat_gateway":                       "NAT Gateway",
	"aws_route_table":                       "Route Table",
	"aws_eip":                               "Elastic IP",
	"aws_instance":                          "EC2 Instance",
	"aws_launch_template":                   "Launch Template",
	"aws_autoscaling_group":                 "Auto Scaling Group",
	"aws_ecs_cluster":                       "ECS Cluster",
	"aws_ecs_service":                       "ECS Service",
	"aws_ecs_task_definition":               "ECS Task Definition",
	"aws_eks_cluster":                       "EKS Cluster",
	"aws_eks_node_group":                    "EKS Node Group",
	"aws_lambda_function":                   "Lambda Function",
	"aws_db_instance":                       "Amazon RDS",
	"aws_rds_cluster":                       "RDS Cluster",
	"aws_dynamodb_table":                    "DynamoDB Table",
	"aws_elasticache_cluster":               "ElastiCache",
	"aws_s3_bucket":                         "Amazon S3",
	"aws_ebs_volume":                        "EBS Volume",
	"aws_sqs_queue":                         "Amazon SQS",
	"aws_sns_topic":                         "Amazon SNS",
	"aws_lb":                                "Application LB",
	"aws_alb":                               "Application LB",
	"aws_lb_listener":                       "LB Listener",
	"aws_lb_target_group":                   "LB Target Group",
	"aws_cloudfront_distribution":           "Amazon CloudFront",
	"aws_route53_zone":                      "Amazon Route 53",
	"aws_route53_record":                    "Route 53 Record",
	"aws_api_gateway_rest_api":              "API Gateway",
	"aws_apigatewayv2_api":                  "API Gateway v2",
	"aws_security_group":                    "Security Group",
	"aws_iam_role":                          "IAM Role",
	"aws_iam_policy":                        "IAM Policy",
	"aws_iam_role_policy":                   "IAM Role Policy",
	"aws_kms_key":                           "KMS Key",
	"aws_acm_certificate":                   "ACM Certificate",
	"aws_wafv2_web_acl":                     "WAF v2 ACL",
	"aws_cloudwatch_log_group":              "CloudWatch Logs",
	"aws_cloudwatch_metric_alarm":           "CloudWatch Alarm",
	"aws_cloudtrail":                        "CloudTrail",
	"aws_flow_log":                          "VPC Flow Log",
	"aws_rds_cluster_instance":              "RDS Instance",
	"aws_appautoscaling_target":             "Auto Scaling Target",
	"aws_appautoscaling_policy":             "Auto Scaling Policy",
	"aws_cloudfront_origin_access_control":  "CloudFront OAC",
	"aws_cloudfront_origin_access_identity": "CloudFront OAI",
	"aws_elasticache_replication_group":     "ElastiCache Redis",
	"aws_elasticache_subnet_group":          "ElastiCache Subnet",
	"aws_s3_bucket_lifecycle_configuration": "S3 Lifecycle",
	"aws_s3_bucket_versioning":              "S3 Versioning",
	"aws_s3_bucket_server_side_encryption_configuration": "S3 Encryption",
	"aws_s3_bucket_public_access_block":                  "S3 Access Block",
	"aws_s3_bucket_policy":                               "S3 Bucket Policy",
	"aws_s3_bucket_logging":                              "S3 Logging",
	"aws_s3_bucket_cors_configuration":                   "S3 CORS",
	"aws_iam_role_policy_attachment":                     "IAM Attachment",
	"aws_iam_instance_profile":                           "Instance Profile",
	"aws_iam_group":                                      "IAM Group",
	"aws_kms_alias":                                      "KMS Alias",
	"aws_route_table_association":                        "Route Assoc.",
	"aws_route":                                          "Route",
	"aws_db_subnet_group":                                "DB Subnet Group",
	"aws_vpc_peering_connection":                         "VPC Peering",
	"aws_network_interface":                              "Network Interface",
	"aws_security_group_rule":                            "SG Rule",
	"aws_lambda_permission":                              "Lambda Permission",
	"aws_waf_web_acl":                                    "WAF ACL",
	"aws_wafv2_web_acl_association":                      "WAF Association",
	"aws_config_configuration_recorder":                  "AWS Config",
	"aws_sns_topic_subscription":                         "SNS Subscription",
	"aws_lb_target_group_attachment":                     "TG Attachment",
	// Azure
	"azurerm_virtual_network":       "Virtual Network",
	"azurerm_subnet":                "Subnet",
	"azurerm_virtual_machine":       "Virtual Machine",
	"azurerm_linux_virtual_machine": "Linux VM",
	"azurerm_storage_account":       "Storage Account",
	"azurerm_lb":                    "Load Balancer",
	// GCP
	"google_compute_instance":   "Compute Instance",
	"google_compute_network":    "VPC Network",
	"google_compute_subnetwork": "Subnetwork",
	"google_storage_bucket":     "Cloud Storage",
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
			containsPart(parts, "sqs") || containsPart(parts, "sns"):
			return "Data"
		case containsPart(parts, "cloudfront") || containsPart(parts, "route53") || containsPart(parts, "dns"):
			return "DNS"
		case containsPart(parts, "lb") || containsPart(parts, "alb") || containsPart(parts, "gateway"):
			return "Access"
		case containsPart(parts, "security") || containsPart(parts, "iam") || containsPart(parts, "kms") ||
			containsPart(parts, "firewall") || containsPart(parts, "waf") || containsPart(parts, "acm"):
			return "Security"
		case containsPart(parts, "cloudwatch") || containsPart(parts, "log") || containsPart(parts, "alarm") ||
			containsPart(parts, "monitor") || containsPart(parts, "cloudtrail") || containsPart(parts, "config"):
			return "Monitoring"
		case containsPart(parts, "vpc") || containsPart(parts, "subnet") || containsPart(parts, "network") ||
			containsPart(parts, "route") || containsPart(parts, "eip") || containsPart(parts, "nat"):
			return "Network"
		case containsPart(parts, "instance") || containsPart(parts, "cluster") || containsPart(parts, "lambda") ||
			containsPart(parts, "ecs") || containsPart(parts, "eks") || containsPart(parts, "autoscaling"):
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
	boxMinWidth   = 35
	maxBoxWidth   = 55
	diagramWidth  = 80
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
		case "DNS", "Access":
			outsideLayers = append(outsideLayers, layer)
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

		// Row visual width = boxWidth (1 + 1 + colWidth + 1 + 1 + colWidth + 1 = colWidth*2 + 3 + 2... hmm)
		// Actually: │ + space + leftStr+pad=colWidth + │ + space + rightStr+pad=colWidth + │
		// = 1 + 1 + colWidth + 1 + 1 + colWidth + 1 = colWidth*2 + 5
		// But boxWidth = colWidth*2 + 3, so row is boxWidth + 2 wider
		// Fix: use boxWidth directly since the row content fills boxWidth visual chars
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
