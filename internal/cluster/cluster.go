package cluster

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// RiskCluster groups findings that target the same resource or related resources.
type RiskCluster struct {
	ID          string          `json:"id"`
	Resources   []string        `json:"resources"`
	Findings    []rules.Finding `json:"findings"`
	Sources     []string        `json:"sources"`
	RiskScore   float64         `json:"risk_score"`
	Severity    string          `json:"severity"`
	SourceCount int             `json:"source_count"`
}

// ClusterResult is the output of the risk cluster builder.
type ClusterResult struct {
	Clusters         []RiskCluster `json:"clusters"`
	TotalFindings    int           `json:"total_findings"`
	HighRiskClusters int           `json:"high_risk_clusters"`
	Summary          string        `json:"summary"`
}

// Builder constructs risk clusters from heterogeneous findings.
type Builder struct {
	severityWeights map[string]float64
}

// NewBuilder creates a Builder with default severity weights.
func NewBuilder() *Builder {
	return &Builder{
		severityWeights: map[string]float64{
			"CRITICAL": 40.0,
			"HIGH":     25.0,
			"MEDIUM":   10.0,
			"LOW":      3.0,
			"INFO":     1.0,
		},
	}
}

// Build groups findings into risk clusters by resource address.
func (b *Builder) Build(findings []rules.Finding) *ClusterResult {
	if len(findings) == 0 {
		return &ClusterResult{Summary: "No findings to cluster"}
	}

	byResource := make(map[string][]rules.Finding)
	for _, f := range findings {
		key := normalizeResourceKey(f.Resource)
		byResource[key] = append(byResource[key], f)
	}

	var clusters []RiskCluster //nolint:prealloc
	highRiskCount := 0

	for key, group := range byResource {
		c := b.buildCluster(key, group)
		clusters = append(clusters, c)
		if c.RiskScore >= 60.0 {
			highRiskCount++
		}
	}

	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i].RiskScore > clusters[j].RiskScore
	})

	summary := fmt.Sprintf("%d clusters from %d findings, %d high-risk",
		len(clusters), len(findings), highRiskCount)

	return &ClusterResult{
		Clusters:         clusters,
		TotalFindings:    len(findings),
		HighRiskClusters: highRiskCount,
		Summary:          summary,
	}
}

func (b *Builder) buildCluster(key string, findings []rules.Finding) RiskCluster {
	sourceSet := make(map[string]bool)
	resourceSet := make(map[string]bool)

	for _, f := range findings {
		sourceSet[f.Source] = true
		if f.Resource != "" {
			resourceSet[f.Resource] = true
		}
	}

	sources := setToSorted(sourceSet)
	resources := setToSorted(resourceSet)
	riskScore := b.calculateRisk(findings, len(sources))
	severity := highestSeverity(findings)

	return RiskCluster{
		ID:          key,
		Resources:   resources,
		Findings:    findings,
		Sources:     sources,
		RiskScore:   riskScore,
		Severity:    severity,
		SourceCount: len(sources),
	}
}

func (b *Builder) calculateRisk(findings []rules.Finding, sourceCount int) float64 {
	if len(findings) == 0 {
		return 0
	}

	baseScore := 0.0
	for _, f := range findings {
		w, ok := b.severityWeights[f.Severity]
		if !ok {
			w = 1.0
		}
		baseScore += w
	}

	sourceMultiplier := 1.0
	if sourceCount >= 3 {
		sourceMultiplier = 1.5
	} else if sourceCount >= 2 {
		sourceMultiplier = 1.25
	}

	score := baseScore * sourceMultiplier
	if score > 100.0 {
		score = 100.0
	}

	return score
}

func normalizeResourceKey(resource string) string {
	if resource == "" {
		return "(unknown)"
	}
	parts := strings.Split(resource, ".")
	if len(parts) >= 2 {
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] != "module" {
				return strings.Join(parts[i:], ".")
			}
			i++ // skip module name
		}
	}
	return resource
}

func highestSeverity(findings []rules.Finding) string {
	rank := map[string]int{
		"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
	}
	best := ""
	bestRank := 0
	for _, f := range findings {
		r := rank[f.Severity]
		if r > bestRank {
			bestRank = r
			best = f.Severity
		}
	}
	if best == "" {
		return "INFO"
	}
	return best
}

func setToSorted(m map[string]bool) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}

// FormatClusters returns a localized human-readable summary of clusters.
// It uses i18n.T() so the output language follows the active locale.
func FormatClusters(result *ClusterResult) string {
	m := i18n.T()
	if result == nil || len(result.Clusters) == 0 {
		return m.ClusterNoRisk
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(m.ClusterHeader+"\n\n", result.Summary))
	for i, c := range result.Clusters {
		icon := riskIcon(c.RiskScore)
		sb.WriteString(fmt.Sprintf(m.ClusterEntryFmt+"\n",
			icon, i+1, c.ID, c.RiskScore, c.Severity))
		sb.WriteString(fmt.Sprintf(m.ClusterSourcesLblFmt+"\n",
			m.ClusterSources, strings.Join(c.Sources, ", "), len(c.Findings)))
	}
	return sb.String()
}

func riskIcon(score float64) string {
	if score >= 60 {
		return "[!]"
	} else if score >= 30 {
		return "[~]"
	}
	return "[o]"
}
