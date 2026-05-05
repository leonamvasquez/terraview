package fix

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ProjectContext is a project-wide snapshot of declarations the AI must NOT
// duplicate when generating a fix. Without this, fixes produced in isolation
// frequently re-add `data "aws_caller_identity" "current"` blocks, reference
// undeclared variables, or use providers (e.g. `random`) that aren't in
// `required_providers`, causing `terraform validate` to fail and forcing the
// outer loop to spend another iteration cleaning up the mess.
type ProjectContext struct {
	// Providers lists short provider names already present (from `provider "X"`
	// and `terraform { required_providers { X = { ... } } }`).
	Providers []string

	// Variables lists declared `variable "X"` names.
	Variables []string

	// DataSources lists `data "TYPE" "NAME"` declarations as full addresses
	// (e.g. "data.aws_caller_identity.current").
	DataSources []string

	// ResourcesByType maps resource type → list of declared addresses.
	// e.g. "aws_kms_key" → ["aws_kms_key.main", "aws_kms_key.logs"]
	ResourcesByType map[string][]string

	// Locals lists names declared inside `locals { ... }` blocks.
	Locals []string
}

// HasProvider reports whether a provider with this short name is already
// declared. Match is case-insensitive.
func (p *ProjectContext) HasProvider(name string) bool {
	for _, p := range p.Providers {
		if strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}

var (
	reProviderBlock = regexp.MustCompile(`(?m)^\s*provider\s+"([^"]+)"`)
	reReqProvOpen   = regexp.MustCompile(`required_providers\s*\{`)
	// Matches `name = {` or `name = "version"` at the top level of a
	// required_providers block. The leading anchor enforces "line starts at
	// outer indentation level"; brace-aware scanning (extractBalancedBlock)
	// guarantees we only feed top-level lines into this matcher.
	reReqProviderEntry = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=`)
	reVariableBlock    = regexp.MustCompile(`(?m)^\s*variable\s+"([^"]+)"`)
	reDataBlock        = regexp.MustCompile(`(?m)^\s*data\s+"([^"]+)"\s+"([^"]+)"`)
	reResourceBlock    = regexp.MustCompile(`(?m)^\s*resource\s+"([^"]+)"\s+"([^"]+)"`)
	reLocalsOpen       = regexp.MustCompile(`(?m)^\s*locals\s*\{`)
	reLocalsEntry      = regexp.MustCompile(`(?m)^\s*([a-zA-Z_][a-zA-Z0-9_-]*)\s*=`)
)

// extractBalancedBlock returns the body between the `{` at openOffset and the
// matching `}`. Naïve regex (`\{(.*?)\}`) fails on nested entries like
// `aws = { source = "..." }`. Returns "" when no balanced match is found.
func extractBalancedBlock(src string, openOffset int) string {
	if openOffset >= len(src) || src[openOffset] != '{' {
		return ""
	}
	depth := 1
	for i := openOffset + 1; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[openOffset+1 : i]
			}
		}
	}
	return ""
}

// findBlockBodies locates each match of openRe in src and returns the
// brace-balanced body of every block it opens. Used for required_providers
// and locals where regex alone cannot handle nested entries.
func findBlockBodies(src string, openRe *regexp.Regexp) []string {
	out := make([]string, 0)
	for _, loc := range openRe.FindAllStringIndex(src, -1) {
		// loc[1] points just past the matched suffix (e.g. just past `{`).
		// We need the position OF the `{`, which is loc[1]-1 because the
		// regex captures up to and including it.
		braceIdx := loc[1] - 1
		if braceIdx < 0 || braceIdx >= len(src) || src[braceIdx] != '{' {
			continue
		}
		body := extractBalancedBlock(src, braceIdx)
		if body != "" {
			out = append(out, body)
		}
	}
	return out
}

// BuildProjectContext walks dir, parses every .tf file at the top level
// (sub-directories are NOT recursed because Terraform modules have their own
// scope), and aggregates declarations into a ProjectContext.
//
// Failures to read individual files are silently skipped — the context is a
// best-effort hint to the AI; missing data is degraded gracefully into a
// less-informed fix, never a hard error.
func BuildProjectContext(dir string) *ProjectContext {
	pc := &ProjectContext{
		ResourcesByType: make(map[string][]string),
	}
	if dir == "" {
		return pc
	}

	providerSet := map[string]bool{}
	varSet := map[string]bool{}
	dataSet := map[string]bool{}
	resSet := map[string]bool{}
	localSet := map[string]bool{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return pc
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		src := string(data)

		for _, m := range reProviderBlock.FindAllStringSubmatch(src, -1) {
			providerSet[m[1]] = true
		}
		for _, body := range findBlockBodies(src, reReqProvOpen) {
			// Only top-level (zero indentation relative to body) entries are
			// provider names. Nested `source = ...`, `version = ...` inside
			// `aws = { ... }` would be matched too by reReqProviderEntry, so
			// we strip nested braces before scanning.
			top := stripNestedBraces(body)
			for _, e := range reReqProviderEntry.FindAllStringSubmatch(top, -1) {
				providerSet[e[1]] = true
			}
		}
		for _, m := range reVariableBlock.FindAllStringSubmatch(src, -1) {
			varSet[m[1]] = true
		}
		for _, m := range reDataBlock.FindAllStringSubmatch(src, -1) {
			addr := "data." + m[1] + "." + m[2]
			dataSet[addr] = true
		}
		for _, m := range reResourceBlock.FindAllStringSubmatch(src, -1) {
			rType := m[1]
			addr := rType + "." + m[2]
			if !resSet[addr] {
				resSet[addr] = true
				pc.ResourcesByType[rType] = append(pc.ResourcesByType[rType], addr)
			}
		}
		for _, body := range findBlockBodies(src, reLocalsOpen) {
			top := stripNestedBraces(body)
			for _, e := range reLocalsEntry.FindAllStringSubmatch(top, -1) {
				localSet[e[1]] = true
			}
		}
	}

	pc.Providers = sortedKeys(providerSet)
	pc.Variables = sortedKeys(varSet)
	pc.DataSources = sortedKeys(dataSet)
	pc.Locals = sortedKeys(localSet)
	for k := range pc.ResourcesByType {
		sort.Strings(pc.ResourcesByType[k])
	}
	return pc
}

// stripNestedBraces removes content inside `{ ... }` (recursively) so that a
// regex looking for top-level `name =` entries doesn't match nested keys like
// `source = "..."` that live inside `aws = { ... }`.
func stripNestedBraces(s string) string {
	var b strings.Builder
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
