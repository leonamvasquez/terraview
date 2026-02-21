package diagram

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
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
}

// Generator creates ASCII infrastructure diagrams from Terraform plan resources.
type Generator struct{}

// NewGenerator creates a new diagram Generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// Generate produces an ASCII infrastructure diagram from normalized resources.
func (g *Generator) Generate(resources []parser.NormalizedResource) string {
	if len(resources) == 0 {
		return "Infrastructure Diagram\n" +
			"======================\n\n" +
			"  (no resource changes)\n"
	}

	layers := g.groupByLayer(resources)
	return g.render(layers)
}

// layerMapping maps resource types to their logical layer.
var layerMapping = map[string]string{
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
	"aws_dynamodb_table":                                 "Data",
	"aws_elasticache_cluster":                            "Data",
	"aws_elasticache_replication_group":                  "Data",
	"aws_s3_bucket":                                      "Data",
	"aws_s3_bucket_versioning":                           "Data",
	"aws_s3_bucket_server_side_encryption_configuration": "Data",
	"aws_s3_bucket_public_access_block":                  "Data",
	"aws_s3_bucket_policy":                               "Data",
	"aws_sqs_queue":                                      "Data",
	"aws_sns_topic":                                      "Data",
	"azurerm_storage_account":                            "Data",
	"google_storage_bucket":                              "Data",
	"google_sql_database_instance":                       "Data",

	// Access Layer
	"aws_lb":                         "Access",
	"aws_alb":                        "Access",
	"aws_lb_listener":                "Access",
	"aws_lb_target_group":            "Access",
	"aws_lb_target_group_attachment": "Access",
	"aws_cloudfront_distribution":    "Access",
	"aws_api_gateway_rest_api":       "Access",
	"aws_apigatewayv2_api":           "Access",
	"aws_route53_record":             "Access",
	"aws_route53_zone":               "Access",
	"azurerm_lb":                     "Access",
	"google_compute_forwarding_rule": "Access",

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
}

// layerOrder defines the display order of layers.
var layerOrder = map[string]int{
	"Network":    1,
	"Access":     2,
	"Compute":    3,
	"Data":       4,
	"Security":   5,
	"Monitoring": 6,
	"Other":      7,
}

func (g *Generator) groupByLayer(resources []parser.NormalizedResource) []Layer {
	layerMap := make(map[string]*Layer)

	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			continue
		}

		layerName := getLayer(r.Type)
		layer, exists := layerMap[layerName]
		if !exists {
			order := layerOrder[layerName]
			if order == 0 {
				order = 99
			}
			layer = &Layer{
				Name:  layerName,
				Order: order,
			}
			layerMap[layerName] = layer
		}

		layer.Resources = append(layer.Resources, ResourceEntry{
			Address: r.Address,
			Type:    r.Type,
			Action:  r.Action,
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

func getLayer(resourceType string) string {
	if layer, ok := layerMapping[resourceType]; ok {
		return layer
	}

	parts := strings.Split(resourceType, "_")
	if len(parts) >= 2 {
		switch {
		case containsPart(parts, "vpc") || containsPart(parts, "subnet") || containsPart(parts, "network"):
			return "Network"
		case containsPart(parts, "instance") || containsPart(parts, "cluster") || containsPart(parts, "lambda"):
			return "Compute"
		case containsPart(parts, "db") || containsPart(parts, "database") || containsPart(parts, "storage") || containsPart(parts, "bucket") || containsPart(parts, "s3"):
			return "Data"
		case containsPart(parts, "lb") || containsPart(parts, "gateway") || containsPart(parts, "dns") || containsPart(parts, "route53"):
			return "Access"
		case containsPart(parts, "security") || containsPart(parts, "iam") || containsPart(parts, "kms") || containsPart(parts, "firewall"):
			return "Security"
		case containsPart(parts, "cloudwatch") || containsPart(parts, "log") || containsPart(parts, "alarm") || containsPart(parts, "monitor"):
			return "Monitoring"
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

func (g *Generator) render(layers []Layer) string {
	if len(layers) == 0 {
		return "Infrastructure Diagram\n" +
			"======================\n\n" +
			"  (no resource changes)\n"
	}

	var sb strings.Builder

	sb.WriteString("Infrastructure Diagram\n")
	sb.WriteString("======================\n\n")

	for i, layer := range layers {
		maxLen := len(layer.Name) + 6
		for _, r := range layer.Resources {
			entryLen := len(fmt.Sprintf("  %s %s", actionIcon(r.Action), r.Address)) + 2
			if entryLen > maxLen {
				maxLen = entryLen
			}
		}
		if maxLen < 40 {
			maxLen = 40
		}

		headerPad := maxLen - len(layer.Name) - 6
		if headerPad < 0 {
			headerPad = 0
		}

		sb.WriteString(fmt.Sprintf("  +--- %s %s+\n", layer.Name, strings.Repeat("-", headerPad)))
		for _, r := range layer.Resources {
			entry := fmt.Sprintf("%s %s", actionIcon(r.Action), r.Address)
			pad := maxLen - len(entry) - 4
			if pad < 0 {
				pad = 0
			}
			sb.WriteString(fmt.Sprintf("  |  %s%s|\n", entry, strings.Repeat(" ", pad)))
		}
		sb.WriteString(fmt.Sprintf("  +%s+\n", strings.Repeat("-", maxLen-2)))

		if i < len(layers)-1 {
			sb.WriteString("           |\n")
		}
	}

	sb.WriteString("\n  [+] create  [~] update  [-] delete  [!] replace  [ ] no change\n")

	return sb.String()
}
