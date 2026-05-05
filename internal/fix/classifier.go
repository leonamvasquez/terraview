package fix

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/leonamvasquez/terraview/internal/fix/failurelog"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// Advisory marks a fix as requiring human review instead of auto-application.
// Reason is the user-facing one-line justification. Group is the implicit
// category used to bucket advisories in the rendered output (no counts shown).
type Advisory struct {
	Reason string
	Group  AdvisoryGroup
}

// AdvisoryGroup is the bucket used to organize advisories on screen. Order
// matters: groups are rendered in the order declared here.
type AdvisoryGroup int

const (
	AdvisoryCrossResource AdvisoryGroup = iota
	AdvisoryArchitectural
	AdvisoryManualReview
)

func (g AdvisoryGroup) Title() string {
	switch g {
	case AdvisoryCrossResource:
		return "Cross-resource impact"
	case AdvisoryArchitectural:
		return "Architectural decision"
	default:
		return "Manual review recommended"
	}
}

// Classifier applies multiple independent signals to decide whether a fix is
// safe to auto-apply or should be surfaced as an advisory. Each signal is
// allowed to "promote" a fix to advisory; the most informative signal wins
// (rule catalog → graph → category) but in practice catalog hits short-circuit
// since they encode an explicit human decision.
type Classifier struct {
	graph      *topology.Graph
	projectDir string // used to scope failure-history lookups; "" disables signal 4
}

// NewClassifier constructs a Classifier with the given dependency graph.
// graph may be nil — the classifier degrades gracefully and skips the
// reverse-reference signal.
func NewClassifier(graph *topology.Graph) *Classifier {
	return &Classifier{graph: graph}
}

// NewClassifierWithProject is like NewClassifier but enables the
// failure-history signal scoped to the given project directory.
func NewClassifierWithProject(graph *topology.Graph, projectDir string) *Classifier {
	return &Classifier{graph: graph, projectDir: projectDir}
}

// PreClassifyFinding runs the static signals (catalog + architectural
// category) without needing an AI suggestion. Used by the generation pipeline
// to skip AI calls for findings that are already known to be advisory — saves
// real cost and time on `fix apply` runs with many findings.
//
// The graph signal (proposesDeletion / inboundRefs) is NOT applied here
// because it requires the suggestion HCL. Call Classify(pf) on the resulting
// PendingFix to incorporate that final signal.
func PreClassifyFinding(f rules.Finding) *Advisory {
	return PreClassifyFindingForProject(f, "")
}

// PreClassifyFindingForProject is PreClassifyFinding with the failure-history
// signal active. Pass the canonical project directory; "" disables it.
func PreClassifyFindingForProject(f rules.Finding, projectDir string) *Advisory {
	if reason, ok := rules.AdvisoryReasonForFinding(f); ok {
		return &Advisory{Reason: reason, Group: AdvisoryManualReview}
	}
	if rules.IsArchitecturalFinding(f.Source, f.Category) {
		return &Advisory{
			Reason: "design decision — review fits within team architecture",
			Group:  AdvisoryArchitectural,
		}
	}
	if projectDir != "" {
		key := failurelog.Key(projectDir, f.RuleID, f.Resource)
		if n := failurelog.Count(key); n >= failurelog.PromotionThreshold {
			reason := fmt.Sprintf("auto-fix has failed %d consecutive attempts — likely needs manual review", n)
			if last := failurelog.LastError(key); last != "" {
				reason += " (last error: " + truncateOneLine(last, 80) + ")"
			}
			return &Advisory{Reason: reason, Group: AdvisoryManualReview}
		}
	}
	return nil
}

// Classify returns nil when the fix is auto-applicable, or an Advisory when
// any signal flags it as requiring manual review.
func (c *Classifier) Classify(pf PendingFix) *Advisory {
	// Signal 1: static catalog. Rules whose remediation is a known human
	// decision (IAM identity changes, engine upgrades, policy audits).
	if reason, ok := rules.AdvisoryReasonForFinding(pf.Finding); ok {
		return &Advisory{Reason: reason, Group: AdvisoryManualReview}
	}

	// Signal 2: architectural category. Both AI and scanner architectural
	// findings encode design decisions, not textual patches.
	if rules.IsArchitecturalFinding(pf.Finding.Source, pf.Finding.Category) {
		return &Advisory{
			Reason: "design decision — review fits within team architecture",
			Group:  AdvisoryArchitectural,
		}
	}

	// Signal 3: graph reverse-reference for proposed deletions. If the AI's
	// HCL no longer contains the original resource header AND the project
	// graph shows inbound dependencies, the fix would orphan those references
	// and fail terraform validate on apply.
	if c.graph != nil && pf.Suggestion != nil && proposesDeletion(pf) {
		if refs := c.inboundRefs(pf.Finding.Resource, 3); len(refs) > 0 {
			return &Advisory{
				Reason: fmt.Sprintf("deletion would orphan references from %s",
					strings.Join(refs, ", ")),
				Group: AdvisoryCrossResource,
			}
		}
	}

	// Signal 4: failure history. If this (project, rule, resource) tuple has
	// already failed N consecutive auto-fix attempts, stop burning AI calls
	// on it and surface as advisory. Successful applies clear the counter,
	// so a transiently-flaky rule recovers automatically.
	if c.projectDir != "" {
		key := failurelog.Key(c.projectDir, pf.Finding.RuleID, pf.Finding.Resource)
		if n := failurelog.Count(key); n >= failurelog.PromotionThreshold {
			reason := fmt.Sprintf("auto-fix has failed %d consecutive attempts — likely needs manual review", n)
			if last := failurelog.LastError(key); last != "" {
				reason += " (last error: " + truncateOneLine(last, 80) + ")"
			}
			return &Advisory{Reason: reason, Group: AdvisoryManualReview}
		}
	}

	// Signal 5: AI self-assessment. The provider returns two optional fields
	// alongside the HCL: manual_review_reason (free-form explanation of why
	// the fix needs human eyes) and blast_radius ("none"/"low"/"medium"/"high").
	// Either signal independently promotes — the AI sees the actual HCL it
	// proposes, so it can flag context-specific risk that the static catalog
	// can't anticipate (e.g. removing a rule from a SG that turns out to be
	// the SSH bastion gateway).
	if pf.Suggestion != nil {
		if reason := strings.TrimSpace(pf.Suggestion.ManualReviewReason); reason != "" {
			return &Advisory{
				Reason: "AI flagged for review: " + truncateOneLine(reason, 160),
				Group:  AdvisoryManualReview,
			}
		}
		if pf.Suggestion.BlastRadius == "high" {
			return &Advisory{
				Reason: "AI estimates HIGH blast radius — review impact before applying",
				Group:  AdvisoryCrossResource,
			}
		}
	}

	return nil
}

func truncateOneLine(s string, max int) string {
	if i := strings.IndexAny(s, "\n\r"); i >= 0 {
		s = s[:i]
	}
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// proposesDeletion reports whether the suggested HCL no longer declares the
// original resource block. A missing `resource "TYPE" "NAME"` header in the
// new HCL means the AI is asking us to remove the resource — the most common
// trigger for cross-resource breakage.
func proposesDeletion(pf PendingFix) bool {
	if pf.Suggestion == nil || pf.Suggestion.HCL == "" {
		return false
	}
	parts := strings.SplitN(pf.Finding.Resource, ".", 2)
	if len(parts) != 2 {
		return false
	}
	rType, rName := parts[0], parts[1]
	pattern := fmt.Sprintf(`(?m)^\s*resource\s+%q\s+%q\s*\{`,
		regexp.QuoteMeta(rType), regexp.QuoteMeta(rName))
	matched, err := regexp.MatchString(pattern, pf.Suggestion.HCL)
	if err != nil {
		return false
	}
	return !matched
}

// inboundRefs returns up to limit resource addresses that reference addr in
// the dependency graph. Used to explain WHY a deletion is risky.
func (c *Classifier) inboundRefs(addr string, limit int) []string {
	refs := make([]string, 0, limit)
	seen := map[string]bool{}
	for _, e := range c.graph.Edges {
		if e.To != addr || seen[e.From] {
			continue
		}
		seen[e.From] = true
		refs = append(refs, e.From)
		if len(refs) >= limit {
			break
		}
	}
	return refs
}
