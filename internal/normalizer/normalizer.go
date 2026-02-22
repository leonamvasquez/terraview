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
//   - Same resource identifier (case-insensitive, trimmed)
//   - Same canonical risk category
//
// Severity is intentionally excluded: a scanner HIGH and an AI MEDIUM about
// the same risk on the same resource are still equivalent. The scanner
// severity is always preserved.
func IsEquivalent(scanner, ai rules.Finding) bool {
	if !strings.EqualFold(
		strings.TrimSpace(scanner.Resource),
		strings.TrimSpace(ai.Resource),
	) {
		return false
	}

	return canonicalRiskCategory(scanner.Category) == canonicalRiskCategory(ai.Category)
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
				// Enrichment: merge AI remediation into scanner finding.
				if af.Remediation != "" {
					sf.Remediation = enrichRemediation(sf.Remediation, af.Remediation)
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

// canonicalRiskCategory normalises a category string to one of the five
// canonical categories defined in rules/types.go. AI providers sometimes
// return variations ("Security", "SECURITY", "sec", "iam-security"); this
// function maps them deterministically.
func canonicalRiskCategory(cat string) string {
	norm := strings.ToLower(strings.TrimSpace(cat))
	switch {
	case norm == "" || norm == "unknown":
		return "security" // safe default — most findings are security
	case strings.Contains(norm, "security") || strings.Contains(norm, "iam") || strings.Contains(norm, "encryption") || strings.Contains(norm, "network"):
		return rules.CategorySecurity
	case strings.Contains(norm, "compliance") || strings.Contains(norm, "regulatory"):
		return rules.CategoryCompliance
	case strings.Contains(norm, "best-practice") || strings.Contains(norm, "best_practice") || strings.Contains(norm, "convention") || strings.Contains(norm, "naming") || strings.Contains(norm, "tagging"):
		return rules.CategoryBestPractice
	case strings.Contains(norm, "maintain") || strings.Contains(norm, "readability") || strings.Contains(norm, "complexity"):
		return rules.CategoryMaintainability
	case strings.Contains(norm, "reliab") || strings.Contains(norm, "availability") || strings.Contains(norm, "disaster") || strings.Contains(norm, "backup"):
		return rules.CategoryReliability
	default:
		return norm // pass-through if already canonical
	}
}

// enrichRemediation merges AI remediation into a scanner finding's remediation.
// If the scanner has no remediation, the AI text replaces it directly.
// If the scanner already has remediation, AI suggestions are appended under a
// section header, avoiding duplicate text.
func enrichRemediation(scannerRem, aiRem string) string {
	scannerRem = strings.TrimSpace(scannerRem)
	aiRem = strings.TrimSpace(aiRem)

	if scannerRem == "" {
		return aiRem
	}
	if aiRem == "" {
		return scannerRem
	}

	// Avoid duplicating identical text.
	if strings.EqualFold(scannerRem, aiRem) {
		return scannerRem
	}

	// Check if the AI text is already embedded in the scanner remediation.
	if strings.Contains(
		strings.ToLower(scannerRem),
		strings.ToLower(aiRem),
	) {
		return scannerRem
	}

	return scannerRem + "\n\nAI Suggestions:\n" + aiRem
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
