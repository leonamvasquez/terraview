package fix

import "strings"

// diffKind tags each line in a unified diff output.
type diffKind int

const (
	diffContext diffKind = iota // unchanged context line
	diffRemove                  // line present only in old
	diffAdd                     // line present only in new
)

type diffLine struct {
	Kind    diffKind
	OldLine int // 1-based line number in old file (0 when Kind == diffAdd)
	Text    string
}

// unifiedDiff produces a context diff between old and new slices of lines.
// It uses a simple LCS-based algorithm adequate for small Terraform HCL blocks.
// ctx is the number of unchanged lines to show before and after each hunk.
func unifiedDiff(old, new []string, ctx int) []diffLine {
	lcs := computeLCS(old, new)
	script := buildEditScript(old, new, lcs)
	return addContext(script, old, ctx)
}

// --- LCS helpers ---

func computeLCS(a, b []string) [][]int {
	m, n := len(a), len(b)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if a[i-1] == b[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else if dp[i-1][j] >= dp[i][j-1] {
				dp[i][j] = dp[i-1][j]
			} else {
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	return dp
}

// buildEditScript walks the LCS table backwards to produce a raw edit list
// (no context lines yet). Each entry is a diffLine without OldLine set.
func buildEditScript(old, new []string, dp [][]int) []diffLine {
	var out []diffLine
	i, j := len(old), len(new)
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && old[i-1] == new[j-1]:
			out = append([]diffLine{{Kind: diffContext, OldLine: i, Text: old[i-1]}}, out...)
			i--
			j--
		case j > 0 && (i == 0 || dp[i][j-1] >= dp[i-1][j]):
			out = append([]diffLine{{Kind: diffAdd, Text: new[j-1]}}, out...)
			j--
		default:
			out = append([]diffLine{{Kind: diffRemove, OldLine: i, Text: old[i-1]}}, out...)
			i--
		}
	}
	return out
}

// addContext trims the raw edit script to only the changed regions plus ctx
// surrounding unchanged lines on each side.
func addContext(script []diffLine, old []string, ctx int) []diffLine {
	if len(script) == 0 {
		return nil
	}

	// Mark which indices of script are "interesting" (non-context).
	interesting := make([]bool, len(script))
	for i, l := range script {
		if l.Kind != diffContext {
			interesting[i] = true
		}
	}

	// Expand each interesting index by ctx in both directions.
	keep := make([]bool, len(script))
	for i, yes := range interesting {
		if !yes {
			continue
		}
		start := i - ctx
		if start < 0 {
			start = 0
		}
		end := i + ctx
		if end >= len(script) {
			end = len(script) - 1
		}
		for k := start; k <= end; k++ {
			keep[k] = true
		}
	}

	var out []diffLine
	for i, l := range script {
		if keep[i] {
			out = append(out, l)
		}
	}
	_ = old
	return out
}

// splitLines splits a multi-line string into individual lines, stripping
// a trailing newline if present.
func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
