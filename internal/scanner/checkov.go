package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func init() {
	Register(&CheckovScanner{})
}

// CheckovScanner implements the Scanner interface for Bridgecrew Checkov.
type CheckovScanner struct{}

func (s *CheckovScanner) Name() string { return "checkov" }

func (s *CheckovScanner) Available() bool { return commandExists("checkov") }

func (s *CheckovScanner) Priority() int { return 1 }

func (s *CheckovScanner) EnsureInstalled() (bool, InstallHint) {
	if s.Available() {
		return true, InstallHint{}
	}
	// Try auto-install via package manager (pip3, brew, etc.)
	result := AutoInstallScanner("checkov")
	if result.Installed {
		return true, InstallHint{}
	}
	return false, InstallHint{
		Pip:     "pip3 install checkov",
		Brew:    "brew install checkov",
		URL:     "https://www.checkov.io/",
		Default: "pip3 install checkov",
	}
}

func (s *CheckovScanner) Version() string {
	return getCommandVersion("checkov")
}

func (s *CheckovScanner) SupportedModes() []ScanMode {
	return []ScanMode{ScanModePlan, ScanModeSource}
}

func (s *CheckovScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	// Prefer scanning plan.json if available (richer context)
	if ctx.PlanPath != "" {
		return s.scanPlan(ctx.PlanPath)
	}
	if ctx.SourceDir != "" {
		return s.scanSource(ctx.SourceDir)
	}
	return nil, fmt.Errorf("checkov: no plan or source directory provided")
}

func (s *CheckovScanner) scanPlan(planPath string) ([]rules.Finding, error) {
	absPath, err := filepath.Abs(planPath)
	if err != nil {
		return nil, fmt.Errorf("checkov: invalid plan path: %w", err)
	}

	// Use stdout only: --output-file-path names the file unpredictably across
	// checkov versions (results_json.json vs results_json_results.json), making
	// the file-read path unreliable. Stdout JSON output is stable in all versions.
	cmd := exec.Command("checkov",
		"--file", absPath,
		"--framework", "terraform_plan",
		"--output", "json",
		"--compact",
		"--quiet",
	)
	cmd.Env = append(os.Environ(), "LOG_LEVEL=WARNING")

	// Checkov exits non-zero when findings exist — that's expected
	output, _ := cmd.CombinedOutput()

	return parseCheckovOutput(output)
}

func (s *CheckovScanner) scanSource(sourceDir string) ([]rules.Finding, error) {
	cmd := exec.Command("checkov",
		"--directory", sourceDir,
		"--framework", "terraform",
		"--output", "json",
		"--compact",
		"--quiet",
	)
	cmd.Env = append(os.Environ(), "LOG_LEVEL=WARNING")

	output, _ := cmd.CombinedOutput()
	return parseCheckovOutput(output)
}

// checkovReport represents the Checkov JSON output structure.
type checkovReport struct {
	Results checkovResults `json:"results"`
}

type checkovResults struct {
	FailedChecks []checkovCheck `json:"failed_checks"`
}

type checkovCheck struct {
	CheckID     string `json:"check_id"`
	BCCheckID   string `json:"bc_check_id"`
	CheckName   string `json:"check_name"`
	CheckResult struct {
		Result string `json:"result"`
	} `json:"check_result"`
	CheckType     string `json:"check_type"`
	ResourceAddr  string `json:"resource_address"`
	Guideline     string `json:"guideline"`
	Severity      string `json:"severity"`
	Description   string `json:"description"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
}

func parseCheckovOutput(data []byte) ([]rules.Finding, error) {
	if len(data) == 0 {
		return nil, nil
	}

	// Checkov sometimes mixes ERROR/WARNING log lines into stdout BEFORE the
	// JSON payload (e.g. when --quiet doesn't suppress per-check tracebacks).
	// CombinedOutput() then yields "[ERROR] ...\n{...}", which fails to parse
	// as JSON and would silently report zero findings. Strip the log preamble
	// by skipping to the first '{' or '[' character.
	payload := extractJSON(data)
	if len(payload) == 0 {
		return nil, nil
	}

	// Checkov can return a single object or an array (multi-framework)
	var single checkovReport
	if err := json.Unmarshal(payload, &single); err == nil && len(single.Results.FailedChecks) > 0 {
		return convertCheckovFindings(single.Results.FailedChecks), nil
	}

	// Try array format
	var multi []checkovReport
	if err := json.Unmarshal(payload, &multi); err == nil {
		var allChecks []checkovCheck
		for _, r := range multi {
			allChecks = append(allChecks, r.Results.FailedChecks...)
		}
		if len(allChecks) > 0 {
			return convertCheckovFindings(allChecks), nil
		}
	}

	return nil, nil
}

// extractJSON returns the JSON payload from a stream that may include log-line
// preambles. Two checkov output styles must work:
//
//  1. Compact single line: {"results":{...}}
//  2. Pretty-printed multi-line preceded by [ERROR]/[MainThread] log lines.
//
// We scan candidate start offsets — every line that, after trimming, begins
// with '{' or '[' — and accept the first one whose tail parses as valid JSON.
// json.Valid is the only reliable filter: line-shape heuristics break on
// Python tracebacks that contain `{` inside source snippets.
func extractJSON(data []byte) []byte {
	offset := 0
	for offset < len(data) {
		nl := bytes.IndexByte(data[offset:], '\n')
		var line []byte
		if nl < 0 {
			line = data[offset:]
		} else {
			line = data[offset : offset+nl]
		}
		trimmed := bytes.TrimLeft(line, " \t")
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			start := offset + (len(line) - len(trimmed))
			if json.Valid(data[start:]) {
				return data[start:]
			}
		}
		if nl < 0 {
			break
		}
		offset += nl + 1
	}
	return nil
}

func convertCheckovFindings(checks []checkovCheck) []rules.Finding {
	findings := make([]rules.Finding, 0, len(checks))
	for _, check := range checks {
		severity := mapCheckovSeverity(check.Severity, check.CheckID)
		category := inferCheckovCategory(check.CheckID)

		// Use check_name (most descriptive), fall back to description, then guideline
		desc := check.CheckName
		if desc == "" {
			desc = check.Description
		}
		if desc == "" {
			desc = check.Guideline
		}

		resource := check.ResourceAddr
		if resource == "" && check.FilePath != "" {
			resource = check.FilePath
		}

		findings = append(findings, rules.Finding{
			RuleID:      check.CheckID,
			Severity:    severity,
			Category:    category,
			Resource:    resource,
			Message:     fmt.Sprintf("[checkov] %s: %s", check.CheckID, desc),
			Remediation: check.Guideline,
			Source:      "scanner:checkov",
		})
	}
	return findings
}

func mapCheckovSeverity(severity, checkID string) string {
	if severity != "" {
		switch strings.ToUpper(severity) {
		case "CRITICAL":
			return rules.SeverityCritical
		case "HIGH":
			return rules.SeverityHigh
		case "MEDIUM":
			return rules.SeverityMedium
		case "LOW":
			return rules.SeverityLow
		case "INFO":
			return rules.SeverityInfo
		}
	}

	// Fallback: infer from check ID prefixes
	switch {
	case strings.Contains(checkID, "SECRET") || strings.Contains(checkID, "CRED"):
		return rules.SeverityCritical
	default:
		return rules.SeverityHigh
	}
}

func inferCheckovCategory(checkID string) string {
	id := strings.ToUpper(checkID)
	switch {
	case strings.Contains(id, "ENCRYPT") || strings.Contains(id, "SSL") || strings.Contains(id, "TLS"):
		return rules.CategorySecurity
	case strings.Contains(id, "LOG") || strings.Contains(id, "MONITOR"):
		return rules.CategoryCompliance
	case strings.Contains(id, "BACKUP") || strings.Contains(id, "HA") || strings.Contains(id, "MULTI"):
		return rules.CategoryReliability
	default:
		return rules.CategorySecurity
	}
}
