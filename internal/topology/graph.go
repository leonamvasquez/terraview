package topology

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// Node represents a resource in the topology graph.
type Node struct {
	Address   string   `json:"address"`
	Type      string   `json:"type"`
	Name      string   `json:"name"`
	Action    string   `json:"action"`
	Provider  string   `json:"provider"`
	DependsOn []string `json:"depends_on,omitempty"`
}

// Edge represents a dependency between two resources.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Via  string `json:"via"` // the field that creates the dependency
}

// Graph is the complete resource dependency topology.
type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// referenceFields are terraform attribute names that typically reference other resources.
var referenceFields = []string{
	"vpc_id", "subnet_id", "subnet_ids", "security_groups", "security_group_ids",
	"target_group_arn", "db_subnet_group_name", "iam_role", "role_arn",
	"kms_key_id", "kms_key_arn", "instance_id", "cluster_id",
	"load_balancer_arn", "listener_arn", "certificate_arn",
	"network_interface_id", "route_table_id", "internet_gateway_id",
	"nat_gateway_id", "eip_id", "log_group_name", "bucket", "queue_url",
	"topic_arn", "function_name", "lambda_function_arn",
	"key_id", "policy_arn", "table_name", "stream_arn",
}

// BuildGraph constructs a dependency topology from normalized resources.
func BuildGraph(resources []parser.NormalizedResource) *Graph {
	g := &Graph{}

	// Index resources by address and type for reference resolution
	addrIndex := make(map[string]*Node)
	typeIndex := make(map[string][]string) // type -> []address

	for _, r := range resources {
		node := Node{
			Address:  r.Address,
			Type:     r.Type,
			Name:     r.Name,
			Action:   r.Action,
			Provider: r.Provider,
		}
		g.Nodes = append(g.Nodes, node)
		addrIndex[r.Address] = &g.Nodes[len(g.Nodes)-1]
		typeIndex[r.Type] = append(typeIndex[r.Type], r.Address)
	}

	// Build edges by scanning resource values for references
	for _, r := range resources {
		if r.Values == nil {
			continue
		}
		for _, field := range referenceFields {
			val, ok := r.Values[field]
			if !ok {
				continue
			}

			targets := resolveReference(val, field, typeIndex, addrIndex)
			for _, target := range targets {
				g.Edges = append(g.Edges, Edge{
					From: r.Address,
					To:   target,
					Via:  field,
				})
				if node, ok := addrIndex[r.Address]; ok {
					node.DependsOn = append(node.DependsOn, target)
				}
			}
		}
	}

	return g
}

// resolveReference tries to match a field value to a known resource address.
func resolveReference(val interface{}, field string, typeIndex map[string][]string, addrIndex map[string]*Node) []string {
	var results []string

	switch v := val.(type) {
	case string:
		if _, ok := addrIndex[v]; ok {
			results = append(results, v)
			return results
		}
		inferredType := inferTypeFromField(field)
		if addrs, ok := typeIndex[inferredType]; ok {
			for _, addr := range addrs {
				results = append(results, addr)
			}
		}
	case []interface{}:
		for _, item := range v {
			if s, ok := item.(string); ok {
				sub := resolveReference(s, field, typeIndex, addrIndex)
				results = append(results, sub...)
			}
		}
	}

	return results
}

// inferTypeFromField maps common field names to resource types.
func inferTypeFromField(field string) string {
	mapping := map[string]string{
		"vpc_id":               "aws_vpc",
		"subnet_id":            "aws_subnet",
		"subnet_ids":           "aws_subnet",
		"security_groups":      "aws_security_group",
		"security_group_ids":   "aws_security_group",
		"role_arn":             "aws_iam_role",
		"iam_role":             "aws_iam_role",
		"policy_arn":           "aws_iam_policy",
		"kms_key_id":           "aws_kms_key",
		"kms_key_arn":          "aws_kms_key",
		"target_group_arn":     "aws_lb_target_group",
		"load_balancer_arn":    "aws_lb",
		"listener_arn":         "aws_lb_listener",
		"certificate_arn":      "aws_acm_certificate",
		"route_table_id":       "aws_route_table",
		"internet_gateway_id":  "aws_internet_gateway",
		"nat_gateway_id":       "aws_nat_gateway",
		"instance_id":          "aws_instance",
		"cluster_id":           "aws_ecs_cluster",
		"log_group_name":       "aws_cloudwatch_log_group",
		"bucket":               "aws_s3_bucket",
		"queue_url":            "aws_sqs_queue",
		"topic_arn":            "aws_sns_topic",
		"function_name":        "aws_lambda_function",
		"lambda_function_arn":  "aws_lambda_function",
		"table_name":           "aws_dynamodb_table",
		"stream_arn":           "aws_kinesis_stream",
		"db_subnet_group_name": "aws_db_subnet_group",
		"key_id":               "aws_kms_key",
	}

	if t, ok := mapping[field]; ok {
		return t
	}
	return ""
}

// Layers groups resources into logical infrastructure layers.
func (g *Graph) Layers() map[string][]string {
	layers := map[string][]string{
		"network":  {},
		"security": {},
		"compute":  {},
		"storage":  {},
		"database": {},
		"other":    {},
	}

	for _, n := range g.Nodes {
		layer := classifyLayer(n.Type)
		layers[layer] = append(layers[layer], n.Address)
	}

	return layers
}

// classifyLayer determines the infrastructure layer of a resource type.
// Order matters: more specific patterns (database) must come before generic ones (compute).
func classifyLayer(resourceType string) string {
	if strings.Contains(resourceType, "vpc") || strings.Contains(resourceType, "subnet") ||
		strings.Contains(resourceType, "route") || strings.Contains(resourceType, "gateway") ||
		strings.Contains(resourceType, "network") || strings.Contains(resourceType, "eip") {
		return "network"
	}
	if strings.Contains(resourceType, "iam") || strings.Contains(resourceType, "security_group") ||
		strings.Contains(resourceType, "kms") || strings.Contains(resourceType, "acm") ||
		strings.Contains(resourceType, "waf") {
		return "security"
	}
	// Database before compute: aws_db_instance contains "instance" but is a database resource
	if strings.Contains(resourceType, "rds") || strings.HasPrefix(resourceType, "aws_db_") ||
		strings.Contains(resourceType, "dynamodb") || strings.Contains(resourceType, "elasticache") ||
		strings.Contains(resourceType, "redshift") {
		return "database"
	}
	if strings.Contains(resourceType, "instance") || strings.Contains(resourceType, "ecs") ||
		strings.Contains(resourceType, "eks") || strings.Contains(resourceType, "lambda") ||
		strings.Contains(resourceType, "autoscaling") {
		return "compute"
	}
	if strings.Contains(resourceType, "s3") || strings.Contains(resourceType, "efs") ||
		strings.Contains(resourceType, "ebs") {
		return "storage"
	}
	return "other"
}

// FormatContext generates a human-readable topology description for AI prompts.
func (g *Graph) FormatContext() string {
	var sb strings.Builder

	sb.WriteString("=== Infrastructure Topology ===\n\n")

	// Layers
	layers := g.Layers()
	layerOrder := []string{"network", "security", "compute", "storage", "database", "other"}

	for _, layer := range layerOrder {
		addrs := layers[layer]
		if len(addrs) == 0 {
			continue
		}
		sort.Strings(addrs)
		sb.WriteString(fmt.Sprintf("Layer: %s\n", strings.ToUpper(layer)))
		for _, addr := range addrs {
			action := ""
			for _, n := range g.Nodes {
				if n.Address == addr {
					action = n.Action
					break
				}
			}
			sb.WriteString(fmt.Sprintf("  - %s [%s]\n", addr, action))
		}
		sb.WriteString("\n")
	}

	// Dependencies
	if len(g.Edges) > 0 {
		sb.WriteString("Dependencies:\n")
		for _, e := range g.Edges {
			sb.WriteString(fmt.Sprintf("  %s --[%s]--> %s\n", e.From, e.Via, e.To))
		}
		sb.WriteString("\n")
	}

	// Impact chains
	changed := make(map[string]bool)
	for _, n := range g.Nodes {
		if n.Action != "no-op" && n.Action != "read" {
			changed[n.Address] = true
		}
	}

	impactChains := g.findImpactChains(changed)
	if len(impactChains) > 0 {
		sb.WriteString("Impact Chains (changed resources affecting others):\n")
		for root, affected := range impactChains {
			sb.WriteString(fmt.Sprintf("  %s impacts: %s\n", root, strings.Join(affected, ", ")))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// findImpactChains traces which changed resources have downstream dependents.
func (g *Graph) findImpactChains(changed map[string]bool) map[string][]string {
	reverseDeps := make(map[string][]string)
	for _, e := range g.Edges {
		reverseDeps[e.To] = append(reverseDeps[e.To], e.From)
	}

	impacts := make(map[string][]string)
	for addr := range changed {
		affected := g.bfsAffected(addr, reverseDeps)
		if len(affected) > 0 {
			impacts[addr] = affected
		}
	}

	return impacts
}

// bfsAffected finds all resources affected by a change to the given address.
func (g *Graph) bfsAffected(root string, reverseDeps map[string][]string) []string {
	visited := map[string]bool{root: true}
	queue := []string{root}
	var affected []string

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, dep := range reverseDeps[current] {
			if !visited[dep] {
				visited[dep] = true
				affected = append(affected, dep)
				queue = append(queue, dep)
			}
		}
	}

	sort.Strings(affected)
	return affected
}
