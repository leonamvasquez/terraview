package blast

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/topology"
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

// AnalyzeWithGraph computes blast radius using a pre-built topology graph.
// This is the preferred method — avoids rebuilding dependencies.
func (a *Analyzer) AnalyzeWithGraph(resources []parser.NormalizedResource, g *topology.Graph) *BlastResult {
	// Build reverse dependency map: "if X changes, who depends on X?"
	reverseDeps := make(map[string][]string)
	for _, e := range g.Edges {
		// Edge: From --depends-on--> To
		// Reverse: if To changes, From is affected
		if !containsStr(reverseDeps[e.To], e.From) {
			reverseDeps[e.To] = append(reverseDeps[e.To], e.From)
		}
	}

	var impacts []Impact //nolint:prealloc
	maxRadius := 0

	for _, r := range resources {
		if r.Action == "no-op" || r.Action == "read" {
			continue
		}

		directDeps := reverseDeps[r.Address]
		indirectDeps := a.findIndirectDeps(r.Address, reverseDeps, directDeps)

		totalAffected := len(directDeps) + len(indirectDeps)
		riskLevel := computeRisk(r.Action, totalAffected)

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

// Analyze computes the blast radius by building the topology graph internally.
// Kept for backward compatibility — prefer AnalyzeWithGraph when a graph is already available.
func (a *Analyzer) Analyze(resources []parser.NormalizedResource) *BlastResult {
	g := topology.BuildGraph(resources)
	return a.AnalyzeWithGraph(resources, g)
}

func (a *Analyzer) findIndirectDeps(root string, reverseDeps map[string][]string, directDeps []string) []string {
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

		for _, dep := range reverseDeps[current] {
			if !visited[dep] {
				visited[dep] = true
				indirect = append(indirect, dep)
				queue = append(queue, dep)
			}
		}
	}

	return indirect
}

func computeRisk(action string, totalAffected int) string {
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
