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
//	"aws_iam_role.eks_node"         → ("aws_iam_role", "eks_node")
//	"module.vpc.aws_vpc.main"       → ("aws_vpc", "main")
func splitAddr(addr string) (rType, rName string) {
	parts := strings.Split(addr, ".")
	if len(parts) < 2 {
		return "", ""
	}
	return parts[len(parts)-2], parts[len(parts)-1]
}

// findInFile scans a single .tf file for 'resource "rType" "rName"' and
// returns the Location of the complete block. Uses brace-depth counting to
// find the matching closing '}'.
func findInFile(path, rType, rName string) (*Location, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	needle := fmt.Sprintf(`resource "%s" "%s"`, rType, rName)
	sc := bufio.NewScanner(f)
	lineNum := 0
	depth := 0
	var loc *Location

	for sc.Scan() {
		lineNum++
		line := sc.Text()

		if loc == nil {
			if strings.Contains(line, needle) {
				loc = &Location{File: path, StartLine: lineNum}
				depth = countBraces(line)
				if depth == 0 {
					loc.EndLine = lineNum
					return loc, nil
				}
			}
			continue
		}

		// We are inside the block — track brace depth.
		depth += countBraces(line)
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

// countBraces returns net brace depth change for a single line.
// Does not handle braces inside strings (acceptable for Terraform HCL).
func countBraces(line string) int {
	depth := 0
	for _, ch := range line {
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}
