package module

import (
	"fmt"
	"sort"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// Finding represents an issue found in module consistency analysis.
type Finding struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Module   string `json:"module,omitempty"`
	Message  string `json:"message"`
	Advice   string `json:"advice"`
}

// AnalysisResult holds the result of a module consistency analysis.
type AnalysisResult struct {
	Findings    []Finding `json:"findings"`
	ModuleCount int       `json:"module_count"`
	TotalIssues int       `json:"total_issues"`
	Summary     string    `json:"summary"`
	Score       float64   `json:"score"`
	ScoreLevel  string    `json:"score_level"`
}

// ModuleInfo tracks metadata about a module call in the plan.
type ModuleInfo struct {
	Name          string
	Source        string
	Version       string
	ResourceCount int
	ResourceTypes []string
	HasVariables  bool
	HasOutputs    bool
	Depth         int
}

// Analyzer checks module usage for consistency and best practices.
type Analyzer struct{}

// NewAnalyzer creates a new module consistency analyzer.
func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

// Analyze performs module consistency analysis on a Terraform plan.
func (a *Analyzer) Analyze(plan *parser.TerraformPlan, resources []parser.NormalizedResource) *AnalysisResult {
	result := &AnalysisResult{}

	// Extract module information from plan config
	modules := a.extractModules(plan)
	result.ModuleCount = len(modules)

	// Extract module usage from resource changes
	moduleResources := a.groupResourcesByModule(resources)

	// Run all checks
	result.Findings = append(result.Findings, a.checkModuleUsage(resources, modules)...)
	result.Findings = append(result.Findings, a.checkVersionPinning(modules)...)
	result.Findings = append(result.Findings, a.checkSourceConsistency(modules)...)
	result.Findings = append(result.Findings, a.checkModuleSize(moduleResources)...)
	result.Findings = append(result.Findings, a.checkNesting(modules)...)
	result.Findings = append(result.Findings, a.checkDuplicatePatterns(resources)...)

	// Sort by severity
	sevOrder := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
	sort.Slice(result.Findings, func(i, j int) bool {
		return sevOrder[result.Findings[i].Severity] < sevOrder[result.Findings[j].Severity]
	})

	result.TotalIssues = len(result.Findings)
	result.Score = computeScore(result.Findings)
	result.ScoreLevel = scoreLevel(result.Score)
	result.Summary = buildSummary(result, modules)

	return result
}

// extractModules walks the configuration tree and collects module metadata.
func (a *Analyzer) extractModules(plan *parser.TerraformPlan) []ModuleInfo {
	var modules []ModuleInfo
	a.walkModuleCalls(plan.Configuration.RootModule, 0, &modules)
	return modules
}

func (a *Analyzer) walkModuleCalls(cm parser.ConfigModule, depth int, modules *[]ModuleInfo) {
	for name, call := range cm.ModuleCalls {
		info := ModuleInfo{
			Name:    name,
			Source:  call.Source,
			Version: call.VersionConstraint,
			Depth:   depth + 1,
		}

		if call.Module != nil {
			info.ResourceCount = len(call.Module.Resources)
			info.HasVariables = len(call.Module.Variables) > 0

			typeSet := make(map[string]bool)
			for _, r := range call.Module.Resources {
				typeSet[r.Type] = true
			}
			for t := range typeSet {
				info.ResourceTypes = append(info.ResourceTypes, t)
			}

			// Recurse into nested modules
			a.walkModuleCalls(*call.Module, depth+1, modules)
		}

		*modules = append(*modules, info)
	}
}

// groupResourcesByModule groups resource changes by module address.
func (a *Analyzer) groupResourcesByModule(resources []parser.NormalizedResource) map[string][]parser.NormalizedResource {
	groups := make(map[string][]parser.NormalizedResource)
	for _, r := range resources {
		modAddr := extractModuleAddress(r.Address)
		groups[modAddr] = append(groups[modAddr], r)
	}
	return groups
}

// extractModuleAddress extracts the module path from a resource address.
// e.g., "module.vpc.aws_subnet.private[0]" -> "module.vpc"
func extractModuleAddress(address string) string {
	parts := strings.Split(address, ".")
	var modParts []string
	for i := 0; i < len(parts)-2; i += 2 {
		if parts[i] == "module" && i+1 < len(parts) {
			modParts = append(modParts, "module."+parts[i+1])
		}
	}
	if len(modParts) == 0 {
		return "root"
	}
	return strings.Join(modParts, ".")
}

// checkModuleUsage checks whether modules are being used appropriately.
func (a *Analyzer) checkModuleUsage(resources []parser.NormalizedResource, modules []ModuleInfo) []Finding {
	var findings []Finding

	// Check if there are too many resources without modules (flat structure)
	rootResources := 0
	for _, r := range resources {
		if !strings.Contains(r.Address, "module.") {
			rootResources++
		}
	}

	if rootResources > 20 && len(modules) == 0 {
		findings = append(findings, Finding{
			Type:     "no-modules",
			Severity: "MEDIUM",
			Message:  fmt.Sprintf("Plan has %d resources in the root module with no module usage. Large flat configurations are hard to maintain.", rootResources),
			Advice:   "Group related resources into modules for better organization, reuse, and testability.",
		})
	} else if rootResources > 10 && len(modules) > 0 {
		findings = append(findings, Finding{
			Type:     "low-modularization",
			Severity: "LOW",
			Message:  fmt.Sprintf("Root module still has %d resources. Consider moving more resources into modules.", rootResources),
			Advice:   "Keep the root module thin — it should primarily compose modules.",
		})
	}

	return findings
}

// checkVersionPinning checks if module versions are properly pinned.
func (a *Analyzer) checkVersionPinning(modules []ModuleInfo) []Finding {
	var findings []Finding

	for _, m := range modules {
		if !isRegistrySource(m.Source) {
			continue
		}

		if m.Version == "" {
			findings = append(findings, Finding{
				Type:     "no-version-pin",
				Severity: "HIGH",
				Module:   m.Name,
				Message:  fmt.Sprintf("Module %q (source: %s) has no version constraint. This may cause unexpected changes.", m.Name, m.Source),
				Advice:   "Pin module versions using version = \"~> X.Y\" to prevent breaking changes.",
			})
		} else if m.Version == "latest" || !strings.ContainsAny(m.Version, "~>=<!") {
			// Exact version without constraint operator is OK but could be loose
			if !strings.Contains(m.Version, ".") {
				findings = append(findings, Finding{
					Type:     "loose-version-pin",
					Severity: "MEDIUM",
					Module:   m.Name,
					Message:  fmt.Sprintf("Module %q has a loose version constraint: %q.", m.Name, m.Version),
					Advice:   "Use pessimistic constraint (e.g., ~> 3.0) to allow patches but prevent breaking changes.",
				})
			}
		}
	}

	return findings
}

// checkSourceConsistency checks for mixed source patterns.
func (a *Analyzer) checkSourceConsistency(modules []ModuleInfo) []Finding {
	var findings []Finding

	sourceTypes := make(map[string][]string) // "registry" / "git" / "local" -> module names
	for _, m := range modules {
		st := classifySource(m.Source)
		sourceTypes[st] = append(sourceTypes[st], m.Name)
	}

	if len(sourceTypes) > 2 {
		var parts []string
		for st, names := range sourceTypes {
			parts = append(parts, fmt.Sprintf("%s (%s)", st, strings.Join(names, ", ")))
		}
		findings = append(findings, Finding{
			Type:     "mixed-sources",
			Severity: "LOW",
			Message:  fmt.Sprintf("Modules use %d different source types: %s.", len(sourceTypes), strings.Join(parts, "; ")),
			Advice:   "Standardize module sources for consistency. Prefer a private registry or a monorepo for internal modules.",
		})
	}

	// Check for duplicate source targets with different references
	sourceToModules := make(map[string][]string)
	for _, m := range modules {
		normalized := normalizeSource(m.Source)
		sourceToModules[normalized] = append(sourceToModules[normalized], m.Name)
	}
	for src, names := range sourceToModules {
		if len(names) > 1 {
			findings = append(findings, Finding{
				Type:     "duplicate-module-source",
				Severity: "INFO",
				Message:  fmt.Sprintf("Modules %s all reference the same source (%s). Consider if they should be a single module with for_each.", strings.Join(names, ", "), src),
				Advice:   "Use for_each or count on a single module call instead of duplicating module blocks.",
			})
		}
	}

	return findings
}

// checkModuleSize checks if individual modules are too large or too small.
func (a *Analyzer) checkModuleSize(moduleResources map[string][]parser.NormalizedResource) []Finding {
	var findings []Finding

	for modAddr, resources := range moduleResources {
		if modAddr == "root" {
			continue
		}

		if len(resources) > 50 {
			findings = append(findings, Finding{
				Type:     "oversized-module",
				Severity: "MEDIUM",
				Module:   modAddr,
				Message:  fmt.Sprintf("Module %s manages %d resources. Large modules are harder to maintain and test.", modAddr, len(resources)),
				Advice:   "Split into smaller, focused sub-modules (e.g., networking, compute, data).",
			})
		}

		if len(resources) == 1 {
			findings = append(findings, Finding{
				Type:     "thin-module",
				Severity: "INFO",
				Module:   modAddr,
				Message:  fmt.Sprintf("Module %s manages only 1 resource. Single-resource modules add unnecessary complexity.", modAddr),
				Advice:   "Consider inlining single-resource modules or combining with related resources.",
			})
		}
	}

	return findings
}

// checkNesting checks for excessive nesting depth.
func (a *Analyzer) checkNesting(modules []ModuleInfo) []Finding {
	var findings []Finding

	for _, m := range modules {
		if m.Depth > 3 {
			findings = append(findings, Finding{
				Type:     "deep-nesting",
				Severity: "MEDIUM",
				Module:   m.Name,
				Message:  fmt.Sprintf("Module %q is nested %d levels deep. Deep nesting makes debugging and state management difficult.", m.Name, m.Depth),
				Advice:   "Keep module nesting to 2-3 levels maximum. Flatten deeply nested modules.",
			})
		}
	}

	return findings
}

// checkDuplicatePatterns detects repeated resource patterns that should be modules.
func (a *Analyzer) checkDuplicatePatterns(resources []parser.NormalizedResource) []Finding {
	var findings []Finding

	// Look for repeated patterns: same set of resource types appearing multiple times
	// in the root module (not in modules already)
	rootTypeSets := make(map[string]int)
	for _, r := range resources {
		if strings.Contains(r.Address, "module.") {
			continue
		}
		rootTypeSets[r.Type]++
	}

	// If a resource type appears 3+ times in root, suggest for_each or module
	for rType, count := range rootTypeSets {
		if count >= 3 {
			findings = append(findings, Finding{
				Type:     "repeated-resources",
				Severity: "LOW",
				Message:  fmt.Sprintf("Resource type %q appears %d times in the root module.", rType, count),
				Advice:   "Use for_each, count, or wrap in a module to reduce repetition and improve maintainability.",
			})
		}
	}

	return findings
}

// --- Helpers ---

func isRegistrySource(source string) bool {
	// Registry sources look like "hashicorp/consul/aws" or "registry.terraform.io/..."
	if strings.Contains(source, "registry.terraform.io") {
		return true
	}
	parts := strings.Split(source, "/")
	// Typical registry pattern: namespace/name/provider (3 parts)
	if len(parts) == 3 && !strings.Contains(source, ":") && !strings.Contains(source, ".") {
		return true
	}
	return false
}

func classifySource(source string) string {
	if source == "" {
		return "unknown"
	}
	if strings.HasPrefix(source, "./") || strings.HasPrefix(source, "../") {
		return "local"
	}
	if strings.HasPrefix(source, "git::") || strings.HasPrefix(source, "github.com") || strings.HasPrefix(source, "bitbucket.org") {
		return "git"
	}
	if strings.HasPrefix(source, "s3::") || strings.HasPrefix(source, "gcs::") {
		return "bucket"
	}
	if isRegistrySource(source) {
		return "registry"
	}
	return "other"
}

func normalizeSource(source string) string {
	// Remove git:: prefix, trailing .git, ref= parameters
	s := strings.TrimPrefix(source, "git::")
	s = strings.TrimSuffix(s, ".git")
	if idx := strings.Index(s, "?"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "//"); idx >= 0 {
		s = s[:idx]
	}
	return s
}

func computeScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 10.0
	}
	penalty := 0.0
	weights := map[string]float64{"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.3, "INFO": 0.0}
	for _, f := range findings {
		if w, ok := weights[f.Severity]; ok {
			penalty += w
		}
	}
	score := 10.0 - penalty
	if score < 0 {
		score = 0
	}
	return score
}

func scoreLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "EXCELLENT"
	case score >= 7.0:
		return "GOOD"
	case score >= 5.0:
		return "FAIR"
	case score >= 3.0:
		return "POOR"
	default:
		return "CRITICAL"
	}
}

func buildSummary(result *AnalysisResult, modules []ModuleInfo) string {
	if result.TotalIssues == 0 && result.ModuleCount == 0 {
		return "No modules detected. Consider using modules for better organization."
	}
	if result.TotalIssues == 0 {
		return fmt.Sprintf("Module analysis: %d modules, no issues detected. Consistency: %s (%.1f/10).",
			result.ModuleCount, result.ScoreLevel, result.Score)
	}
	return fmt.Sprintf("Module analysis: %d modules, %d issues detected. Consistency: %s (%.1f/10).",
		result.ModuleCount, result.TotalIssues, result.ScoreLevel, result.Score)
}

// FormatModuleAnalysis produces a human-readable module analysis report.
func FormatModuleAnalysis(result *AnalysisResult) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Module Consistency Report — Score: %s (%.1f/10)\n\n",
		result.ScoreLevel, result.Score))

	if result.TotalIssues == 0 {
		sb.WriteString("No module consistency issues detected.\n")
		return sb.String()
	}

	for _, f := range result.Findings {
		module := f.Module
		if module == "" {
			module = "(global)"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s — %s\n", f.Severity, f.Type, module))
		sb.WriteString(fmt.Sprintf("  %s\n", f.Message))
		sb.WriteString(fmt.Sprintf("  Advice: %s\n\n", f.Advice))
	}

	sb.WriteString(fmt.Sprintf("Summary: %s\n", result.Summary))
	return sb.String()
}
