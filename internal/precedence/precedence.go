package precedence

import (
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

var ToolRank = map[string]int{
	"checkov":        1,
	"tfsec":          2,
	"trivy":          2, // alias for tfsec
	"terrascan":      3,
	"kics":           4,
	"hard-rule":      5, // deterministic rules
	"deterministic":  5,
	"llm":            6, // AI analysis
	"ai":             6,
}

// Rank returns the precedence rank for a source name.
// Unknown sources get rank 99 (lowest precedence).
func Rank(source string) int {
	r, ok := ToolRank[strings.ToLower(source)]
	if ok {
		return r
	}
	return 99
}

// SortByPrecedence sorts findings in-place by source precedence (highest first),
// then by severity within same source.
func SortByPrecedence(findings []rules.Finding) {
	sevRank := map[string]int{
		"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1,
	}
	sort.SliceStable(findings, func(i, j int) bool {
		ri := Rank(findings[i].Source)
		rj := Rank(findings[j].Source)
		if ri != rj {
			return ri < rj // lower rank = higher precedence
		}
		return sevRank[findings[i].Severity] > sevRank[findings[j].Severity]
	})
}

// HighestPrecedenceSource returns the source with the lowest rank from a set of findings.
func HighestPrecedenceSource(findings []rules.Finding) string {
	best := ""
	bestRank := 100
	for _, f := range findings {
		r := Rank(f.Source)
		if r < bestRank {
			bestRank = r
			best = f.Source
		}
	}
	return best
}

// ClassifyTier returns a human-readable tier for a source rank.
func ClassifyTier(source string) string {
	r := Rank(source)
	switch {
	case r <= 2:
		return "Tier 1 (scanner)"
	case r <= 4:
		return "Tier 2 (scanner)"
	case r == 5:
		return "Tier 3 (deterministic)"
	case r == 6:
		return "Tier 4 (AI)"
	default:
		return "Tier 5 (unknown)"
	}
}

// ConfidenceWeight returns a weight multiplier based on source precedence.
// Higher-ranked tools get a higher confidence weight.
func ConfidenceWeight(source string) float64 {
	r := Rank(source)
	switch r {
	case 1:
		return 1.0
	case 2:
		return 0.95
	case 3:
		return 0.85
	case 4:
		return 0.80
	case 5:
		return 0.70
	case 6:
		return 0.50
	default:
		return 0.30
	}
}
