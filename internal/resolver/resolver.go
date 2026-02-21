package resolver

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/precedence"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Resolution describes how a finding conflict was resolved.
type Resolution struct {
	Action     string // "confirmed", "scanner-priority", "ai-only", "scanner-only"
	Confidence float64
	Note       string
}

// ResolvedFinding wraps a Finding with its resolution metadata.
type ResolvedFinding struct {
	rules.Finding
	Resolution Resolution `json:"resolution"`
}

// ConflictResult holds the complete output of the conflict resolver.
type ConflictResult struct {
	Resolved         []ResolvedFinding `json:"resolved"`
	Confirmed        int               `json:"confirmed"`
	ScannerPriority  int               `json:"scanner_priority"`
	AIOnly           int               `json:"ai_only"`
	ScannerOnly      int               `json:"scanner_only"`
	Summary          string            `json:"summary"`
}

// Resolver resolves conflicts between scanner and AI findings.
type Resolver struct{}

// New creates a new Resolver.
func New() *Resolver {
	return &Resolver{}
}

// Resolve takes scanner findings and AI findings and produces a merged,
// conflict-resolved list annotated with resolution metadata.
func (r *Resolver) Resolve(scannerFindings, aiFindings []rules.Finding) ConflictResult {
	result := ConflictResult{}

	// Index AI findings by normalised resource key
	aiByResource := make(map[string][]rules.Finding)
	for _, f := range aiFindings {
		key := normalizeKey(f.Resource)
		aiByResource[key] = append(aiByResource[key], f)
	}

	// Track which AI findings were matched
	matchedAI := make(map[string]bool)

	// Process scanner findings first (higher precedence)
	for _, sf := range scannerFindings {
		key := normalizeKey(sf.Resource)
		aiMatches := aiByResource[key]

		if len(aiMatches) == 0 {
			// Scanner-only: no AI finding for this resource
			result.Resolved = append(result.Resolved, ResolvedFinding{
				Finding: sf,
				Resolution: Resolution{
					Action:     "scanner-only",
					Confidence: precedence.ConfidenceWeight(sf.Source),
					Note:       "Detected by scanner only",
				},
			})
			result.ScannerOnly++
			continue
		}

		// Check for matching AI finding (same resource, overlapping category or similar message)
		matched := false
		for _, af := range aiMatches {
			if isRelated(sf, af) {
				matchedAI[aiKey(af)] = true
				matched = true

				if severitiesAgree(sf.Severity, af.Severity) {
					// Agreement: scanner and AI confirm the same issue
					resolved := sf
					if resolved.Remediation == "" && af.Remediation != "" {
						resolved.Remediation = af.Remediation
					}
					resolved.Source = sf.Source + "+ai"

					result.Resolved = append(result.Resolved, ResolvedFinding{
						Finding: resolved,
						Resolution: Resolution{
							Action:     "confirmed",
							Confidence: 1.0, // maximum confidence when both agree
							Note:       fmt.Sprintf("Confirmed by %s and AI", sf.Source),
						},
					})
					result.Confirmed++
				} else {
					// Severity conflict: scanner takes precedence
					resolved := sf
					if resolved.Remediation == "" && af.Remediation != "" {
						resolved.Remediation = af.Remediation
					}

					result.Resolved = append(result.Resolved, ResolvedFinding{
						Finding: resolved,
						Resolution: Resolution{
							Action:     "scanner-priority",
							Confidence: precedence.ConfidenceWeight(sf.Source),
							Note: fmt.Sprintf("Severity conflict: %s says %s, AI says %s — scanner precedence applied",
								sf.Source, sf.Severity, af.Severity),
						},
					})
					result.ScannerPriority++
				}
				break // one match per scanner finding
			}
		}

		if !matched {
			// Scanner finding with AI findings for same resource but different issues
			result.Resolved = append(result.Resolved, ResolvedFinding{
				Finding: sf,
				Resolution: Resolution{
					Action:     "scanner-only",
					Confidence: precedence.ConfidenceWeight(sf.Source),
					Note:       "Detected by scanner only",
				},
			})
			result.ScannerOnly++
		}
	}

	// Add unmatched AI findings (AI detected something scanners missed)
	for _, af := range aiFindings {
		if matchedAI[aiKey(af)] {
			continue
		}
		result.Resolved = append(result.Resolved, ResolvedFinding{
			Finding: af,
			Resolution: Resolution{
				Action:     "ai-only",
				Confidence: precedence.ConfidenceWeight(af.Source),
				Note:       "Detected by AI only — lower confidence",
			},
		})
		result.AIOnly++
	}

	result.Summary = r.buildSummary(result)
	return result
}

// ToFindings extracts the plain Finding list from resolved findings.
func ToFindings(resolved []ResolvedFinding) []rules.Finding {
	out := make([]rules.Finding, len(resolved))
	for i, rf := range resolved {
		out[i] = rf.Finding
	}
	return out
}

// buildSummary generates a human-readable summary.
func (r *Resolver) buildSummary(cr ConflictResult) string {
	total := len(cr.Resolved)
	if total == 0 {
		return "No findings to resolve."
	}
	parts := []string{fmt.Sprintf("%d findings resolved:", total)}
	if cr.Confirmed > 0 {
		parts = append(parts, fmt.Sprintf("  %d confirmed (scanner + AI agree)", cr.Confirmed))
	}
	if cr.ScannerPriority > 0 {
		parts = append(parts, fmt.Sprintf("  %d scanner-priority (severity conflict resolved)", cr.ScannerPriority))
	}
	if cr.ScannerOnly > 0 {
		parts = append(parts, fmt.Sprintf("  %d scanner-only", cr.ScannerOnly))
	}
	if cr.AIOnly > 0 {
		parts = append(parts, fmt.Sprintf("  %d ai-only (lower confidence)", cr.AIOnly))
	}
	return strings.Join(parts, "\n")
}

// FormatResolution formats the resolve result for display (EN).
func FormatResolution(cr ConflictResult) string {
	if len(cr.Resolved) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("=== Conflict Resolution ===\n")
	sb.WriteString(cr.Summary)
	sb.WriteString("\n")
	return sb.String()
}

// FormatResolutionBR formats the resolve result for display (pt-BR).
func FormatResolutionBR(cr ConflictResult) string {
	if len(cr.Resolved) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("=== Resolução de Conflitos ===\n")
	total := len(cr.Resolved)
	parts := []string{fmt.Sprintf("%d findings resolvidos:", total)}
	if cr.Confirmed > 0 {
		parts = append(parts, fmt.Sprintf("  %d confirmados (scanner + IA concordam)", cr.Confirmed))
	}
	if cr.ScannerPriority > 0 {
		parts = append(parts, fmt.Sprintf("  %d prioridade-scanner (conflito de severidade)", cr.ScannerPriority))
	}
	if cr.ScannerOnly > 0 {
		parts = append(parts, fmt.Sprintf("  %d apenas-scanner", cr.ScannerOnly))
	}
	if cr.AIOnly > 0 {
		parts = append(parts, fmt.Sprintf("  %d apenas-IA (menor confiança)", cr.AIOnly))
	}
	sb.WriteString(strings.Join(parts, "\n"))
	sb.WriteString("\n")
	return sb.String()
}

// --- helpers ---

// normalizeKey normalises a resource string for comparison.
func normalizeKey(resource string) string {
	return strings.ToLower(strings.TrimSpace(resource))
}

// aiKey produces a unique key for tracking matched AI findings.
func aiKey(f rules.Finding) string {
	return normalizeKey(f.Resource) + "|" + strings.ToLower(f.RuleID) + "|" + strings.ToLower(f.Category)
}

// isRelated checks if two findings about the same resource are related.
// They match if they share category or have overlapping rule IDs or similar messages.
func isRelated(a, b rules.Finding) bool {
	if a.Category != "" && b.Category != "" && strings.EqualFold(a.Category, b.Category) {
		return true
	}
	if a.RuleID != "" && b.RuleID != "" && strings.EqualFold(a.RuleID, b.RuleID) {
		return true
	}
	// Fuzzy: check if message keywords overlap significantly
	aWords := significantWords(a.Message)
	bWords := significantWords(b.Message)
	overlap := 0
	for w := range aWords {
		if bWords[w] {
			overlap++
		}
	}
	minLen := len(aWords)
	if len(bWords) < minLen {
		minLen = len(bWords)
	}
	if minLen > 0 && float64(overlap)/float64(minLen) >= 0.5 {
		return true
	}
	return false
}

// severitiesAgree returns true if severities are the same or within one level.
func severitiesAgree(a, b string) bool {
	order := map[string]int{
		"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
	}
	oa, okA := order[strings.ToUpper(a)]
	ob, okB := order[strings.ToUpper(b)]
	if !okA || !okB {
		return false
	}
	diff := oa - ob
	if diff < 0 {
		diff = -diff
	}
	return diff <= 1
}

// significantWords extracts meaningful words (4+ chars, lowercase) from a message.
func significantWords(msg string) map[string]bool {
	words := make(map[string]bool)
	for _, w := range strings.Fields(strings.ToLower(msg)) {
		w = strings.Trim(w, ".,;:!?()[]{}\"'")
		if len(w) >= 4 {
			words[w] = true
		}
	}
	return words
}
