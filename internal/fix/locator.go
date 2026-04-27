package fix

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Location identifies where a Terraform resource block is defined in a .tf file.
type Location struct {
	File      string // absolute path to the .tf file
	StartLine int    // 1-based: line containing 'resource "TYPE" "NAME" {'
	EndLine   int    // 1-based: line containing the closing '}'
}

// FindResource searches all .tf files under dir for the resource block that
// matches addr. Handles plain addresses ("aws_iam_role.eks_node") and module
// addresses ("module.vpc.aws_vpc.main") by using the last two dot-separated
// segments as (type, name).
//
// Returns nil, nil when no file contains the resource (non-fatal — the HCL
// suggestion will still be displayed for manual copy).
func FindResource(dir, addr string) (*Location, error) {
	rType, rName := splitAddr(addr)
	if rType == "" || rName == "" {
		return nil, fmt.Errorf("cannot parse resource address %q", addr)
	}

	var found *Location
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Skip hidden dirs and .terraform cache
			base := d.Name()
			if strings.HasPrefix(base, ".") || base == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tf") {
			return nil
		}
		loc, err := findInFile(path, rType, rName)
		if err != nil || loc == nil {
			return err
		}
		found = loc
		return filepath.SkipAll
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s: %w", dir, err)
	}
	return found, nil // nil = not found, caller handles gracefully
}

// ReadFileContext returns a compact summary of all resource declarations in the
// same file as loc, excluding the target resource itself. This gives the AI
// visibility into existing naming conventions, references, and sibling resources
// without sending the full file content (which may be very large).
//
// Format: one line per resource → `resource "TYPE" "NAME"  # line N`
func ReadFileContext(loc *Location, workDir string) string {
	data, err := os.ReadFile(loc.File)
	if err != nil {
		return ""
	}

	rel, _ := filepath.Rel(workDir, loc.File)
	targetType, targetName := splitAddr(filepath.Base(loc.File)) // placeholder — overridden below
	_ = targetType
	_ = targetName

	// Re-derive target type/name from Location for accurate exclusion.
	targetHeader := ""
	lines := strings.Split(string(data), "\n")
	if loc.StartLine > 0 && loc.StartLine <= len(lines) {
		targetHeader = strings.TrimSpace(lines[loc.StartLine-1])
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "# %s\n", rel)

	for i, line := range lines {
		trim := strings.TrimSpace(line)
		if !strings.HasPrefix(trim, `resource "`) {
			continue
		}
		lineNo := i + 1
		if lineNo == loc.StartLine || trim == targetHeader {
			continue // skip the resource being fixed
		}
		fmt.Fprintf(&sb, "%s  # line %d\n", trim, lineNo)
	}

	return strings.TrimRight(sb.String(), "\n")
}

// ReadLines returns the raw lines for the block defined by loc.
func ReadLines(loc *Location) ([]string, error) {
	data, err := os.ReadFile(loc.File)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", loc.File, err)
	}
	all := strings.Split(string(data), "\n")
	if loc.StartLine < 1 || loc.EndLine > len(all) {
		return nil, fmt.Errorf("line range %d-%d out of bounds (%d lines)",
			loc.StartLine, loc.EndLine, len(all))
	}
	out := make([]string, loc.EndLine-loc.StartLine+1)
	copy(out, all[loc.StartLine-1:loc.EndLine])
	return out, nil
}

// splitAddr extracts (resourceType, resourceName) from a Terraform address.
//
//	"aws_iam_role.eks_node"                → ("aws_iam_role", "eks_node")
//	"module.vpc.aws_vpc.main"              → ("aws_vpc", "main")
//	`aws_lambda_function.fn["handler"]`    → ("aws_lambda_function", "fn")
func splitAddr(addr string) (rType, rName string) {
	parts := strings.Split(addr, ".")
	if len(parts) < 2 {
		return "", ""
	}
	rType = parts[len(parts)-2]
	rName = parts[len(parts)-1]
	// Strip for_each instance key: `name["key"]` or `name[0]` → `name`
	if idx := strings.IndexByte(rName, '['); idx >= 0 {
		rName = rName[:idx]
	}
	return rType, rName
}

// findInFile scans a single .tf file for 'resource "rType" "rName"' and
// returns the Location of the complete block. Uses a string-and-heredoc-aware
// brace depth counter to find the matching closing '}'.
func findInFile(path, rType, rName string) (*Location, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	needle := fmt.Sprintf(`resource %q %q`, rType, rName)
	sc := bufio.NewScanner(f)
	lineNum := 0
	depth := 0
	var loc *Location
	heredocMarker := "" // non-empty while we are inside a <<MARKER block

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		// ── Heredoc tracking ──────────────────────────────────────────────────
		// A heredoc starts with <<MARKER or <<-MARKER and ends when MARKER
		// appears alone on a line (possibly with leading whitespace for <<-).
		// While inside a heredoc we must not count braces.
		if heredocMarker != "" {
			if strings.TrimSpace(line) == heredocMarker {
				heredocMarker = ""
			}
			// Heredoc content doesn't affect brace depth — skip line entirely.
			continue
		}
		if loc != nil || lineStartsResourceBlock(line, needle) {
			// Check for heredoc start on this line: <<MARKER or <<-MARKER
			if idx := strings.Index(line, "<<"); idx >= 0 {
				marker := strings.TrimSpace(line[idx+2:])
				marker = strings.TrimPrefix(marker, "-") // <<-MARKER
				// Strip any trailing comment
				if i := strings.IndexByte(marker, '#'); i >= 0 {
					marker = strings.TrimSpace(marker[:i])
				}
				if marker != "" && !strings.ContainsAny(marker, " \t{\"") {
					heredocMarker = marker
				}
			}
		}

		if loc == nil {
			// Match only at top level (depth == 0) and only when the line
			// actually starts with `resource "TYPE" "NAME"` — ignore comments
			// and substrings inside other blocks/strings.
			if depth == 0 && lineStartsResourceBlock(line, needle) {
				loc = &Location{File: path, StartLine: lineNum}
				depth = countBraces(line)
				if depth == 0 {
					loc.EndLine = lineNum
					return loc, nil
				}
				continue
			}
			// Track top-level depth so we don't match a needle that appears
			// inside an unrelated block (e.g. nested data source with the same
			// name in a description).
			depth += countBraces(line)
			continue
		}

		// We are inside the block — track brace depth.
		if heredocMarker == "" { // don't count braces inside heredocs
			depth += countBraces(line)
		}
		if depth <= 0 {
			loc.EndLine = lineNum
			return loc, nil
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, nil // not found in this file
}

// lineStartsResourceBlock reports whether line opens a resource block matching
// needle (`resource "TYPE" "NAME"`). Strict-match: the trimmed line must begin
// with needle followed by whitespace or `{`. Lines that begin with `#` or `//`
// (comments) never match. This prevents false positives where the needle
// appears inside a comment, string, or unrelated nested block — a class of
// bug observed in real fix runs where the applier replaced the wrong block.
func lineStartsResourceBlock(line, needle string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return false
	}
	if !strings.HasPrefix(trimmed, needle) {
		return false
	}
	rest := trimmed[len(needle):]
	if rest == "" {
		return true
	}
	switch rest[0] {
	case ' ', '\t', '{':
		return true
	}
	return false
}

// countBraces returns the net brace depth change for a single line.
// It is string-aware: braces inside double-quoted literals and after # or //
// comments are ignored, preventing jsonencode({...}) and JSON policies from
// confusing the block boundary finder.
func countBraces(line string) int {
	depth := 0
	inStr := false
	i := 0
	for i < len(line) {
		ch := line[i]
		if inStr {
			if ch == '\\' {
				i += 2 // skip escaped character (e.g. \", \\)
				continue
			}
			if ch == '"' {
				inStr = false
			}
			i++
			continue
		}
		// Outside a string
		if ch == '"' {
			inStr = true
			i++
			continue
		}
		// EOL comment: # ... or // ... — skip the rest of the line
		if ch == '#' {
			break
		}
		if ch == '/' && i+1 < len(line) && line[i+1] == '/' {
			break
		}
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
		}
		i++
	}
	return depth
}

// isBraceBalanced reports whether the HCL block string has balanced braces,
// using the same string-aware logic as countBraces.
// A block generated by AI that is not balanced will corrupt the target file.
//
// Deprecated: prefer isHCLBalanced which also tracks brackets and parentheses.
func isBraceBalanced(hcl string) bool {
	depth := 0
	for _, line := range strings.Split(hcl, "\n") {
		depth += countBraces(line)
	}
	return depth == 0
}

// isHCLBalanced reports whether the HCL string has balanced delimiters across
// all three pairs that matter for parsing: {} (blocks), [] (lists/jsonencode),
// and () (function calls). It is string-, comment- and heredoc-aware, and
// uses character-level early-exit so a closing delimiter that appears before
// its matching opener (e.g. `}}{{`) is rejected even if line totals zero out.
//
// AI-generated fixes commonly emit truncated jsonencode([...]) or function
// calls, leaving an orphaned ']' or ')' that passes a {}-only check but causes
// terraform validate to fail with "Argument or block definition required"
// after the bad block bleeds into the next resource.
func isHCLBalanced(hcl string) bool {
	curly, square, paren := 0, 0, 0
	inStr := false
	heredocMarker := ""
	lineStart := 0

	advanceLine := func(end int) (string, bool) {
		line := hcl[lineStart:end]
		lineStart = end + 1
		// Strip trailing \r for CRLF.
		line = strings.TrimRight(line, "\r")
		// Heredoc terminator detection.
		if heredocMarker != "" && strings.TrimSpace(line) == heredocMarker {
			heredocMarker = ""
			return line, true
		}
		return line, heredocMarker != ""
	}

	for i := 0; i < len(hcl); i++ {
		ch := hcl[i]

		// End of line: handle heredoc start/terminator and reset string state.
		if ch == '\n' {
			line, skipped := advanceLine(i)
			_ = skipped
			// Detect heredoc start: <<MARKER or <<-MARKER on the line we just
			// finished (only when not already inside one).
			if heredocMarker == "" {
				if idx := strings.Index(line, "<<"); idx >= 0 {
					marker := strings.TrimSpace(line[idx+2:])
					marker = strings.TrimPrefix(marker, "-")
					if h := strings.IndexByte(marker, '#'); h >= 0 {
						marker = strings.TrimSpace(marker[:h])
					}
					if marker != "" && !strings.ContainsAny(marker, " \t{\"") {
						heredocMarker = marker
					}
				}
			}
			inStr = false
			continue
		}

		// Skip everything inside a heredoc body.
		if heredocMarker != "" {
			continue
		}

		if inStr {
			if ch == '\\' {
				i++ // skip escaped char
				continue
			}
			if ch == '"' {
				inStr = false
			}
			continue
		}

		if ch == '"' {
			inStr = true
			continue
		}
		// EOL comment: skip to next newline.
		if ch == '#' {
			next := strings.IndexByte(hcl[i:], '\n')
			if next < 0 {
				break
			}
			i += next - 1
			continue
		}
		if ch == '/' && i+1 < len(hcl) && hcl[i+1] == '/' {
			next := strings.IndexByte(hcl[i:], '\n')
			if next < 0 {
				break
			}
			i += next - 1
			continue
		}

		switch ch {
		case '{':
			curly++
		case '}':
			curly--
		case '[':
			square++
		case ']':
			square--
		case '(':
			paren++
		case ')':
			paren--
		}
		// Character-level early exit: any negative depth means a close came
		// before its matching open, which no later content can repair.
		if curly < 0 || square < 0 || paren < 0 {
			return false
		}
	}
	return curly == 0 && square == 0 && paren == 0
}
