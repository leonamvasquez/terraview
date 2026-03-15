package modules

// RuleID constants for module analysis findings.
const (
	RuleUnpinnedRegistry = "MOD_001" // registry module without version constraint
	RuleGitNoBranch      = "MOD_002" // git source using branch ref instead of tag
	RuleGitNoRef         = "MOD_003" // git source without any ref
	RuleDeepNesting      = "MOD_004" // module nesting exceeds threshold
	RuleHTTPSource       = "MOD_005" // module source uses HTTP instead of HTTPS
	RuleRegistryOutdated = "MOD_006" // registry module has newer version available
)

// maxNestingDepth is the threshold above which deep nesting is flagged.
const maxNestingDepth = 3

// ModuleInfo represents a parsed module call with analysis metadata.
type ModuleInfo struct {
	Name              string `json:"name"`
	Source            string `json:"source"`
	VersionConstraint string `json:"version_constraint,omitempty"`
	SourceType        string `json:"source_type"` // registry, git, local, http
	Depth             int    `json:"depth"`
	ParentPath        string `json:"parent_path,omitempty"`
	ResourceCount     int    `json:"resource_count"`
}

// AnalysisResult holds the complete module analysis output.
type AnalysisResult struct {
	Modules  []ModuleInfo    `json:"modules"`
	Findings []ModuleFinding `json:"findings"`
	Summary  ResultSummary   `json:"summary"`
}

// ModuleFinding is a module-specific finding before conversion to rules.Finding.
type ModuleFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Module      string `json:"module"`
	Source      string `json:"source"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

// ResultSummary provides aggregate statistics.
type ResultSummary struct {
	TotalModules    int            `json:"total_modules"`
	BySourceType    map[string]int `json:"by_source_type"`
	FindingsBySev   map[string]int `json:"findings_by_severity"`
	MaxNestingDepth int            `json:"max_nesting_depth"`
}
