// Package normalizer provides deterministic deduplication between scanner
// findings and AI findings. Only one scanner runs per execution; the normalizer
// merges the single-scanner output with the optional AI analysis, discarding
// AI duplicates and enriching scanner findings with AI context when applicable.
//
// Complexity: O(n) — single pass with map-based lookups, no nested loops.
package normalizer

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// DeduplicateResult holds the output of the deduplication pass.
type DeduplicateResult struct {
	Findings     []rules.Finding `json:"findings"`
	ScannerKept  int             `json:"scanner_kept"`
	AIDiscarded  int             `json:"ai_discarded"`
	AIEnriched   int             `json:"ai_enriched"`
	AIUniqueKept int             `json:"ai_unique_kept"`
	Summary      string          `json:"summary"`
}

// IsEquivalent returns true when an AI finding is considered a structural
// duplicate of a scanner finding. The comparison uses:
//
//   - Same resource identifier (case-insensitive)
//   - Same normalised risk category (case-insensitive)
//   - Similar severity level (same or within one rank)
//
// All three conditions must hold for equivalence.
func IsEquivalent(scanner, ai rules.Finding) bool {
	if !strings.EqualFold(
		strings.TrimSpace(scanner.Resource),
		strings.TrimSpace(ai.Resource),
	) {
		return false
	}

	if !strings.EqualFold(
		strings.TrimSpace(scanner.Category),
		strings.TrimSpace(ai.Category),
	) {
		return false
	}

	return severitiesClose(scanner.Severity, ai.Severity)
}

// Deduplicate merges scanner findings with AI findings, applying three rules:
//
//  1. If an AI finding is equivalent to a scanner finding → discard the AI
//     duplicate; if the AI provides remediation the scanner lacks, attach it.
//  2. If an AI finding shares the same resource as a scanner finding but is NOT
//     equivalent (different category or distant severity) → keep both.
//  3. If an AI finding targets a resource no scanner reported → keep it.
//
// Scanner findings are always preserved unchanged (except potential enrichment).
func Deduplicate(scannerFindings, aiFindings []rules.Finding) DeduplicateResult {
	result := DeduplicateResult{}

	// Fast path: nothing to merge
	if len(scannerFindings) == 0 && len(aiFindings) == 0 {
		result.Summary = "No findings to deduplicate."
		return result
	}
	if len(aiFindings) == 0 {
		result.Findings = make([]rules.Finding, len(scannerFindings))
		copy(result.Findings, scannerFindings)
		result.ScannerKept = len(scannerFindings)
		result.Summary = formatSummary(result)
		return result
	}
	if len(scannerFindings) == 0 {
		result.Findings = make([]rules.Finding, len(aiFindings))
		copy(result.Findings, aiFindings)
		result.AIUniqueKept = len(aiFindings)
		result.Summary = formatSummary(result)
		return result
	}

	// Index scanner findings by normalised resource for O(1) lookup.
	type indexEntry struct {
		idx int // position in the output slice
	}
	scannerByResource := make(map[string][]indexEntry, len(scannerFindings))

	// Copy scanner findings into output (always preserved).
	out := make([]rules.Finding, len(scannerFindings), len(scannerFindings)+len(aiFindings))
	copy(out, scannerFindings)
	result.ScannerKept = len(scannerFindings)

	for i := range scannerFindings {
		key := normalizeResource(scannerFindings[i].Resource)
		scannerByResource[key] = append(scannerByResource[key], indexEntry{idx: i})
	}

	// Process each AI finding against the scanner index.
	for _, af := range aiFindings {
		key := normalizeResource(af.Resource)
		entries, hasResource := scannerByResource[key]

		if !hasResource {
			// Rule 3: unique AI finding — no scanner coverage for this resource.
			out = append(out, af)
			result.AIUniqueKept++
			continue
		}

		// Check equivalence against scanner findings for the same resource.
		matched := false
		for _, entry := range entries {
			sf := &out[entry.idx]
			if IsEquivalent(*sf, af) {
				matched = true
				// Enrichment: attach AI remediation if scanner lacks one.
				if sf.Remediation == "" && af.Remediation != "" {
					sf.Remediation = af.Remediation
					result.AIEnriched++
				}
				result.AIDiscarded++
				break
			}
		}

		if !matched {
			// Rule 2: different issue on the same resource — keep AI finding.
			out = append(out, af)
			result.AIUniqueKept++
		}
	}

	result.Findings = out
	result.Summary = formatSummary(result)
	return result
}

// ── helpers ────────────────────────────────────────────────────────

// severitiesClose returns true if the two severity levels are the same or
// within one rank (e.g. HIGH↔MEDIUM is close, CRITICAL↔LOW is not).
func severitiesClose(a, b string) bool {
	ra := sevRank(a)
	rb := sevRank(b)
	diff := ra - rb
	if diff < 0 {
		diff = -diff
	}
	return diff <= 1
}

// sevRank maps severity strings to a numeric order (lower = more severe).
func sevRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case rules.SeverityCritical:
		return 0
	case rules.SeverityHigh:
		return 1
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 3
	case rules.SeverityInfo:
		return 4
	default:
		return 5
	}
}

// normalizeResource produces a canonical, comparable resource key.
func normalizeResource(r string) string {
	return strings.ToLower(strings.TrimSpace(r))
}

// formatSummary builds a human-readable summary line.
func formatSummary(r DeduplicateResult) string {
	total := len(r.Findings)
	parts := []string{}
	if r.ScannerKept > 0 {
		parts = append(parts, fmt.Sprintf("%d scanner", r.ScannerKept))
	}
	if r.AIDiscarded > 0 {
		parts = append(parts, fmt.Sprintf("%d AI discarded", r.AIDiscarded))
	}
	if r.AIEnriched > 0 {
		parts = append(parts, fmt.Sprintf("%d enriched", r.AIEnriched))
	}
	if r.AIUniqueKept > 0 {
		parts = append(parts, fmt.Sprintf("%d AI unique", r.AIUniqueKept))
	}
	if len(parts) == 0 {
		return "No findings to deduplicate."
	}
	return fmt.Sprintf("%d findings after dedup: %s", total, strings.Join(parts, ", "))
}
