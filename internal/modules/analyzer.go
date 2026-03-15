// Package modules provides static analysis of Terraform module usage
// including version pinning, source hygiene, and nesting depth.
package modules

import (
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Analyzer inspects Terraform plan module calls for best-practice violations.
type Analyzer struct {
	registry RegistryChecker
}

// RegistryChecker resolves the latest version of a Terraform registry module.
type RegistryChecker interface {
	LatestVersion(namespace, name, provider string) (string, error)
}

// NewAnalyzer creates a module analyzer. Pass nil for registry to skip
// outdated-version checks.
func NewAnalyzer(rc RegistryChecker) *Analyzer {
	return &Analyzer{registry: rc}
}

// Analyze inspects all module calls in the plan and returns findings.
func (a *Analyzer) Analyze(plan *parser.TerraformPlan) *AnalysisResult {
	var modules []ModuleInfo
	var findings []ModuleFinding

	// Walk the configuration tree collecting module calls.
	a.walkModules(&plan.Configuration.RootModule, "", 0, &modules, &findings)

	// Count resources per module from planned values.
	resCounts := countModuleResources(&plan.PlannedValues.RootModule)
	for i := range modules {
		key := "module." + modules[i].Name
		if modules[i].ParentPath != "" {
			key = modules[i].ParentPath + ".module." + modules[i].Name
		}
		modules[i].ResourceCount = resCounts[key]
	}

	summary := buildSummary(modules, findings)
	return &AnalysisResult{Modules: modules, Findings: findings, Summary: summary}
}

// ToFindings converts module findings into the standard rules.Finding slice.
func ToFindings(mf []ModuleFinding) []rules.Finding {
	out := make([]rules.Finding, len(mf))
	for i, f := range mf {
		out[i] = rules.Finding{
			RuleID:      f.RuleID,
			Severity:    f.Severity,
			Category:    rules.CategoryBestPractice,
			Resource:    f.Module,
			Message:     f.Message,
			Remediation: f.Remediation,
			Source:      "module-analyzer",
		}
	}
	return out
}

// walkModules recursively descends into module calls.
func (a *Analyzer) walkModules(
	cfg *parser.ConfigModule,
	parentPath string,
	depth int,
	modules *[]ModuleInfo,
	findings *[]ModuleFinding,
) {
	for name, mc := range cfg.ModuleCalls {
		srcType := classifySource(mc.Source)
		info := ModuleInfo{
			Name:              name,
			Source:            mc.Source,
			VersionConstraint: mc.VersionConstraint,
			SourceType:        srcType,
			Depth:             depth + 1,
			ParentPath:        parentPath,
		}
		*modules = append(*modules, info)

		a.checkModule(info, findings)

		// Recurse into nested modules.
		if mc.Module != nil {
			childPath := "module." + name
			if parentPath != "" {
				childPath = parentPath + ".module." + name
			}
			a.walkModules(mc.Module, childPath, depth+1, modules, findings)
		}
	}
}

// checkModule runs all analysis rules against a single module.
func (a *Analyzer) checkModule(m ModuleInfo, findings *[]ModuleFinding) {
	addr := moduleAddr(m)

	switch m.SourceType {
	case "registry":
		a.checkRegistry(m, addr, findings)
	case "git":
		a.checkGit(m, addr, findings)
	case "http":
		a.checkHTTP(m, addr, findings)
	}

	if m.Depth > maxNestingDepth {
		*findings = append(*findings, ModuleFinding{
			RuleID:      RuleDeepNesting,
			Severity:    rules.SeverityMedium,
			Module:      addr,
			Source:      m.Source,
			Message:     fmt.Sprintf("Module nesting depth %d exceeds recommended maximum of %d", m.Depth, maxNestingDepth),
			Remediation: "Flatten module hierarchy by extracting deeply nested modules into top-level modules.",
		})
	}
}

func (a *Analyzer) checkRegistry(m ModuleInfo, addr string, findings *[]ModuleFinding) {
	if m.VersionConstraint == "" {
		*findings = append(*findings, ModuleFinding{
			RuleID:      RuleUnpinnedRegistry,
			Severity:    rules.SeverityHigh,
			Module:      addr,
			Source:      m.Source,
			Message:     "Registry module has no version constraint — any version will be installed",
			Remediation: fmt.Sprintf("Add a version constraint: module %q { version = \"~> X.Y\" }", m.Name),
		})
	}

	if a.registry != nil && m.VersionConstraint != "" {
		ns, name, prov := parseRegistrySource(m.Source)
		if ns != "" {
			latest, err := a.registry.LatestVersion(ns, name, prov)
			if err == nil && latest != "" && !constraintAllows(m.VersionConstraint, latest) {
				*findings = append(*findings, ModuleFinding{
					RuleID:      RuleRegistryOutdated,
					Severity:    rules.SeverityMedium,
					Module:      addr,
					Source:      m.Source,
					Message:     fmt.Sprintf("Registry module pinned to %q but latest is %s", m.VersionConstraint, latest),
					Remediation: fmt.Sprintf("Consider updating version constraint to include %s", latest),
				})
			}
		}
	}
}

func (a *Analyzer) checkGit(m ModuleInfo, addr string, findings *[]ModuleFinding) {
	ref := extractGitRef(m.Source)
	if ref == "" {
		*findings = append(*findings, ModuleFinding{
			RuleID:      RuleGitNoRef,
			Severity:    rules.SeverityHigh,
			Module:      addr,
			Source:      m.Source,
			Message:     "Git module source has no ref — defaults to HEAD which can change unpredictably",
			Remediation: "Pin to a specific tag or commit: ?ref=v1.0.0",
		})
		return
	}

	if isBranchRef(ref) {
		*findings = append(*findings, ModuleFinding{
			RuleID:      RuleGitNoBranch,
			Severity:    rules.SeverityHigh,
			Module:      addr,
			Source:      m.Source,
			Message:     fmt.Sprintf("Git module pinned to branch %q — any push to this branch will change your infrastructure", ref),
			Remediation: "Pin to a semver tag (e.g., ?ref=v1.2.3) or a full commit SHA.",
		})
	}
}

func (a *Analyzer) checkHTTP(m ModuleInfo, addr string, findings *[]ModuleFinding) {
	if strings.HasPrefix(m.Source, "http://") {
		*findings = append(*findings, ModuleFinding{
			RuleID:      RuleHTTPSource,
			Severity:    rules.SeverityHigh,
			Module:      addr,
			Source:      m.Source,
			Message:     "Module downloaded over plain HTTP — vulnerable to man-in-the-middle attacks",
			Remediation: "Use HTTPS: " + strings.Replace(m.Source, "http://", "https://", 1),
		})
	}
}

// classifySource determines the module source type.
func classifySource(source string) string {
	switch {
	case source == "" || strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../"):
		return "local"
	case strings.HasPrefix(source, "git::") || strings.HasPrefix(source, "git@"):
		return "git"
	case strings.Contains(source, "github.com/") || strings.Contains(source, "bitbucket.org/"):
		return "git"
	case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
		return "http"
	case strings.HasPrefix(source, "s3::") || strings.HasPrefix(source, "gcs::"):
		return "http"
	default:
		// Registry format: namespace/name/provider or registry.terraform.io/namespace/name/provider
		parts := strings.Split(strings.TrimPrefix(source, "registry.terraform.io/"), "/")
		if len(parts) == 3 {
			return "registry"
		}
		return "unknown"
	}
}

// extractGitRef extracts the ref parameter from a git source URL.
func extractGitRef(source string) string {
	idx := strings.Index(source, "?ref=")
	if idx == -1 {
		idx = strings.Index(source, "&ref=")
	}
	if idx == -1 {
		return ""
	}
	ref := source[idx+5:]
	if end := strings.IndexByte(ref, '&'); end != -1 {
		ref = ref[:end]
	}
	return ref
}

// isBranchRef returns true if the ref looks like a branch name rather than
// a semver tag or commit SHA.
func isBranchRef(ref string) bool {
	branchNames := []string{"main", "master", "develop", "dev", "staging", "production", "release"}
	lower := strings.ToLower(ref)
	for _, b := range branchNames {
		if lower == b {
			return true
		}
	}
	// If it starts with "v" followed by a digit, it's likely a tag.
	if len(ref) > 1 && ref[0] == 'v' && ref[1] >= '0' && ref[1] <= '9' {
		return false
	}
	// Full SHA (40 hex chars) is OK.
	if len(ref) == 40 && isHex(ref) {
		return false
	}
	// Short SHA (7+ hex chars) — likely OK.
	if len(ref) >= 7 && isHex(ref) {
		return false
	}
	// Semver-like: contains digits and dots.
	if strings.ContainsAny(ref, ".") && strings.ContainsAny(ref, "0123456789") {
		return false
	}
	// Anything else looks like a branch name.
	return true
}

func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// parseRegistrySource splits "namespace/name/provider" into its parts.
func parseRegistrySource(source string) (namespace, name, provider string) {
	source = strings.TrimPrefix(source, "registry.terraform.io/")
	parts := strings.Split(source, "/")
	if len(parts) != 3 {
		return "", "", ""
	}
	return parts[0], parts[1], parts[2]
}

// constraintAllows does a simple check whether the constraint likely includes
// the latest version. This is a best-effort heuristic, not a full semver solver.
func constraintAllows(constraint, latest string) bool {
	// If the constraint literally contains the latest version, it's fine.
	if strings.Contains(constraint, latest) {
		return true
	}
	// Extract the major version from both.
	constraintMajor := extractMajor(strings.TrimLeft(constraint, "~>=<! "))
	latestMajor := extractMajor(latest)
	// If major versions differ, the constraint is likely outdated.
	return constraintMajor == latestMajor
}

func extractMajor(v string) string {
	v = strings.TrimPrefix(v, "v")
	if idx := strings.IndexByte(v, '.'); idx != -1 {
		return v[:idx]
	}
	return v
}

// moduleAddr builds a display address for the module.
func moduleAddr(m ModuleInfo) string {
	if m.ParentPath != "" {
		return m.ParentPath + ".module." + m.Name
	}
	return "module." + m.Name
}

// countModuleResources counts resources per module address from planned values.
func countModuleResources(root *parser.Module) map[string]int {
	counts := make(map[string]int)
	var walk func(m *parser.Module)
	walk = func(m *parser.Module) {
		if m.Address != "" {
			counts[m.Address] = len(m.Resources)
		}
		for i := range m.ChildModules {
			walk(&m.ChildModules[i])
		}
	}
	walk(root)
	return counts
}

func buildSummary(modules []ModuleInfo, findings []ModuleFinding) ResultSummary {
	byType := make(map[string]int)
	maxDepth := 0
	for _, m := range modules {
		byType[m.SourceType]++
		if m.Depth > maxDepth {
			maxDepth = m.Depth
		}
	}
	bySev := make(map[string]int)
	for _, f := range findings {
		bySev[f.Severity]++
	}
	return ResultSummary{
		TotalModules:    len(modules),
		BySourceType:    byType,
		FindingsBySev:   bySev,
		MaxNestingDepth: maxDepth,
	}
}
