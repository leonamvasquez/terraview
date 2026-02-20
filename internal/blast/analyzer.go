package blast

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// Impact represents the blast radius of a single resource change.
type Impact struct {
	Resource      string   `json:"resource"`
	Action        string   `json:"action"`
	DirectDeps    []string `json:"direct_deps"`
	IndirectDeps  []string `json:"indirect_deps"`
	TotalAffected int      `json:"total_affected"`
	RiskLevel     string   `json:"risk_level"`
}

// BlastResult is the aggregate blast radius analysis.
type BlastResult struct {
	Impacts   []Impact `json:"impacts"`
	MaxRadius int      `json:"max_radius"`
	Summary   string   `json:"summary"`
}

// Analyzer performs blast radius analysis on Terraform plan resources.
type Analyzer struct{}

// NewAnalyzer creates a new blast radius Analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

var referenceFields = []string{
	"vpc_id", "subnet_id", "subnet_ids", "security_groups", "security_group_ids",
	"target_group_arn", "db_subnet_group_name", "iam_role", "role_arn",
	"kms_key_id", "kms_key_arn", "instance_id", "cluster_id",
	"load_balancer_arn", "listener_arn", "certificate_arn",
	"network_interface_id", "route_table_id", "internet_gateway_id",
	"nat_gateway_id", "eip_id", "log_group_name", "bucket", "queue_url",
	"topic_arn", "function_name", "lambda_function_arn",
}

// Analyze computes the blast radius for each changed resource.
func (a *Analyzer) Analyze(resources []parser.NormalizedResource) *BlastResult {
	depGraph := a.buildDependencyGraph(resources)

	var impacts []Impact
	maxRadius := 0

	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			continue
		}

		directDeps := depGraph[r.Address]
		indirectDeps := a.findIndirectDeps(r.Address, depGraph, directDeps)

		totalAffected := len(directDeps) + len(indirectDeps)
		riskLevel := a.computeRisk(r.Action, totalAffected)

		if totalAffected > maxRadius {
			maxRadius = totalAffected
		}

		impacts = append(impacts, Impact{
			Resource:      r.Address,
			Action:        r.Action,
			DirectDeps:    directDeps,
			IndirectDeps:  indirectDeps,
			TotalAffected: totalAffected,
			RiskLevel:     riskLevel,
		})
	}

	sort.Slice(impacts, func(i, j int) bool {
		return impacts[i].TotalAffected > impacts[j].TotalAffected
	})

	summary := fmt.Sprintf("%d changes, max blast radius: %d resources", len(impacts), maxRadius)

	return &BlastResult{
		Impacts:   impacts,
		MaxRadius: maxRadius,
		Summary:   summary,
	}
}

func (a *Analyzer) buildDependencyGraph(resources []parser.NormalizedResource) map[string][]string {
	graph := make(map[string][]string)

	addressSet := make(map[string]bool)
	for _, r := range resources {
		addressSet[r.Address] = true
	}

	for _, r := range resources {
		refs := a.extractReferences(r, addressSet)
		for _, ref := range refs {
			if !containsStr(graph[ref], r.Address) {
				graph[ref] = append(graph[ref], r.Address)
			}
		}
	}

	return graph
}

func (a *Analyzer) extractReferences(r parser.NormalizedResource, addressSet map[string]bool) []string {
	var refs []string
	seen := make(map[string]bool)

	values := r.Values
	if values == nil {
		return refs
	}

	for _, field := range referenceFields {
		if val, ok := values[field]; ok {
			foundRefs := a.resolveReference(val, addressSet)
			for _, ref := range foundRefs {
				if ref != r.Address && !seen[ref] {
					seen[ref] = true
					refs = append(refs, ref)
				}
			}
		}
	}

	return refs
}

func (a *Analyzer) resolveReference(val interface{}, addressSet map[string]bool) []string {
	var refs []string
	switch v := val.(type) {
	case string:
		for addr := range addressSet {
			if strings.Contains(v, addr) || v == addr {
				refs = append(refs, addr)
			}
		}
	case []interface{}:
		for _, item := range v {
			refs = append(refs, a.resolveReference(item, addressSet)...)
		}
	}
	return refs
}

func (a *Analyzer) findIndirectDeps(root string, graph map[string][]string, directDeps []string) []string {
	visited := make(map[string]bool)
	visited[root] = true
	for _, d := range directDeps {
		visited[d] = true
	}

	var indirect []string
	queue := make([]string, len(directDeps))
	copy(queue, directDeps)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, dep := range graph[current] {
			if !visited[dep] {
				visited[dep] = true
				indirect = append(indirect, dep)
				queue = append(queue, dep)
			}
		}
	}

	return indirect
}

func (a *Analyzer) computeRisk(action string, totalAffected int) string {
	weight := 1
	if action == "delete" || action == "replace" {
		weight = 2
	}

	score := totalAffected * weight

	switch {
	case score >= 10:
		return "critical"
	case score >= 6:
		return "high"
	case score >= 3:
		return "medium"
	default:
		return "low"
	}
}

// FormatPretty renders the blast radius analysis as a human-readable string.
func (br *BlastResult) FormatPretty() string {
	if len(br.Impacts) == 0 {
		return "Blast Radius Analysis\n=====================\n\n  No resource changes to analyze.\n"
	}

	var sb strings.Builder
	sb.WriteString("Blast Radius Analysis\n")
	sb.WriteString("=====================\n\n")

	for _, imp := range br.Impacts {
		icon := actionIcon(imp.Action)
		sb.WriteString(fmt.Sprintf("  %s %s\n", icon, imp.Resource))

		if len(imp.DirectDeps) > 0 {
			sb.WriteString(fmt.Sprintf("      Direct:   %s\n", strings.Join(imp.DirectDeps, ", ")))
		} else {
			sb.WriteString("      Direct:   (none)\n")
		}

		if len(imp.IndirectDeps) > 0 {
			sb.WriteString(fmt.Sprintf("      Indirect: %s\n", strings.Join(imp.IndirectDeps, ", ")))
		} else {
			sb.WriteString("      Indirect: (none)\n")
		}

		sb.WriteString(fmt.Sprintf("      Radius:   %d resources affected\n", imp.TotalAffected))
		sb.WriteString(fmt.Sprintf("      Risk:     %s\n\n", strings.ToUpper(imp.RiskLevel)))
	}

	sb.WriteString(fmt.Sprintf("  Summary: %s\n", br.Summary))
	return sb.String()
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

func containsStr(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
