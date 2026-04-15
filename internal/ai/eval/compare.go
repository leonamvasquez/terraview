package eval

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// Compare checks a set of findings + summary against a Golden spec and
// returns a list of human-readable failure messages. An empty slice means
// the response met every assertion.
//
// Compare is pure: no I/O, no randomness. All text matching is
// case-insensitive so goldens stay resilient to small wording shifts
// between models.
func Compare(findings []rules.Finding, summary string, g Golden) []string {
	var failures []string

	failures = append(failures, checkRequiredTopics(findings, g.RequiredTopics)...)
	failures = append(failures, checkRequiredResources(findings, g.RequiredResources)...)
	failures = append(failures, checkMinSeverity(findings, g.MinSeverity)...)
	failures = append(failures, checkMaxFindings(findings, g.MaxFindings)...)
	failures = append(failures, checkSummaryContains(summary, g.SummaryContains)...)

	return failures
}

func checkRequiredTopics(findings []rules.Finding, topics []string) []string {
	if len(topics) == 0 {
		return nil
	}
	var failures []string
	haystacks := make([]string, 0, len(findings)*2)
	for _, f := range findings {
		haystacks = append(haystacks, strings.ToLower(f.Message), strings.ToLower(f.RuleID))
	}
	for _, topic := range topics {
		needle := strings.ToLower(topic)
		found := false
		for _, h := range haystacks {
			if strings.Contains(h, needle) {
				found = true
				break
			}
		}
		if !found {
			failures = append(failures, fmt.Sprintf("missing required topic: %q", topic))
		}
	}
	return failures
}

func checkRequiredResources(findings []rules.Finding, addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(findings))
	for _, f := range findings {
		seen[f.Resource] = true
	}
	var failures []string
	for _, addr := range addrs {
		if !seen[addr] {
			failures = append(failures, fmt.Sprintf("missing required resource: %q", addr))
		}
	}
	return failures
}

func checkMinSeverity(findings []rules.Finding, mins map[string]int) []string {
	if len(mins) == 0 {
		return nil
	}
	counts := make(map[string]int)
	for _, f := range findings {
		counts[strings.ToUpper(f.Severity)]++
	}
	var failures []string
	for sev, min := range mins {
		got := counts[strings.ToUpper(sev)]
		if got < min {
			failures = append(failures, fmt.Sprintf("severity %s: got %d finding(s), want >= %d", sev, got, min))
		}
	}
	return failures
}

func checkMaxFindings(findings []rules.Finding, max int) []string {
	if max <= 0 {
		return nil
	}
	if len(findings) > max {
		return []string{fmt.Sprintf("too many findings: got %d, want <= %d", len(findings), max)}
	}
	return nil
}

func checkSummaryContains(summary string, needles []string) []string {
	if len(needles) == 0 {
		return nil
	}
	lower := strings.ToLower(summary)
	var failures []string
	for _, n := range needles {
		if !strings.Contains(lower, strings.ToLower(n)) {
			failures = append(failures, fmt.Sprintf("summary missing %q", n))
		}
	}
	return failures
}
