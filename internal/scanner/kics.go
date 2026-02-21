package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func init() {
	Register(&KICSScanner{})
}

// KICSScanner implements the Scanner interface for Checkmarx KICS.
type KICSScanner struct{}

func (s *KICSScanner) Name() string { return "kics" }

func (s *KICSScanner) Available() bool { return commandExists("kics") }

func (s *KICSScanner) Priority() int { return 4 }

func (s *KICSScanner) EnsureInstalled() (bool, InstallHint) {
	if s.Available() {
		return true, InstallHint{}
	}
	// Try auto-install via bininstaller
	result := AutoInstallScanner("kics")
	if result.Installed {
		return true, InstallHint{}
	}
	return false, InstallHint{
		Brew:    "brew install kics",
		URL:     "https://kics.io/",
		Default: "Install with: brew install kics",
	}
}

func (s *KICSScanner) Version() string { return getCommandVersion("kics") }

func (s *KICSScanner) SupportedModes() []ScanMode {
	return []ScanMode{ScanModeSource}
}

func (s *KICSScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	scanDir := ctx.SourceDir
	if scanDir == "" {
		scanDir = ctx.WorkDir
	}
	if scanDir == "" {
		return nil, fmt.Errorf("kics: no source directory provided")
	}

	// Create temp dir for output
	tmpDir, err := os.MkdirTemp("", "kics-*")
	if err != nil {
		return nil, fmt.Errorf("kics: failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	cmd := exec.Command("kics", "scan",
		"-p", scanDir,
		"--output-path", tmpDir,
		"--report-formats", "json",
		"--output-name", "results",
		"--no-color",
		"--ci",
	)

	// KICS exits non-zero when findings exist
	cmd.Run()

	resultFile := filepath.Join(tmpDir, "results.json")
	data, err := os.ReadFile(resultFile)
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	return parseKICSOutput(data)
}

// KICS JSON output structures
type kicsReport struct {
	TotalCounter int         `json:"total_counter"`
	Queries      []kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName string     `json:"query_name"`
	QueryID   string     `json:"query_id"`
	QueryURL  string     `json:"query_url"`
	Severity  string     `json:"severity"`
	Category  string     `json:"category"`
	Platform  string     `json:"platform"`
	Desc      string     `json:"description"`
	Files     []kicsFile `json:"files"`
}

type kicsFile struct {
	FileName       string `json:"file_name"`
	SimilarityID   string `json:"similarity_id"`
	Line           int    `json:"line"`
	ResourceType   string `json:"resource_type"`
	ResourceName   string `json:"resource_name"`
	IssueType      string `json:"issue_type"`
	SearchKey      string `json:"search_key"`
	ExpectedValue  string `json:"expected_value"`
	ActualValue    string `json:"actual_value"`
	KeyActualValue string `json:"key_actual_value"`
}

func parseKICSOutput(data []byte) ([]rules.Finding, error) {
	var report kicsReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("kics: failed to parse output: %w", err)
	}

	var findings []rules.Finding
	for _, q := range report.Queries {
		for _, f := range q.Files {
			resource := f.ResourceName
			if resource == "" {
				resource = f.FileName
				if f.Line > 0 {
					resource = fmt.Sprintf("%s:%d", f.FileName, f.Line)
				}
			}

			desc := q.Desc
			if f.ExpectedValue != "" && f.ActualValue != "" {
				desc = fmt.Sprintf("%s (expected: %s, actual: %s)", desc, f.ExpectedValue, f.ActualValue)
			}

			findings = append(findings, rules.Finding{
				RuleID:      q.QueryID,
				Severity:    mapKICSSeverity(q.Severity),
				Category:    mapKICSCategory(q.Category),
				Resource:    resource,
				Message:     fmt.Sprintf("[kics] %s: %s", q.QueryName, desc),
				Remediation: f.ExpectedValue,
				Source:      "scanner:kics",
			})
		}
	}

	return findings, nil
}

func mapKICSSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return rules.SeverityCritical
	case "HIGH":
		return rules.SeverityHigh
	case "MEDIUM":
		return rules.SeverityMedium
	case "LOW":
		return rules.SeverityLow
	case "INFO", "TRACE":
		return rules.SeverityInfo
	default:
		return rules.SeverityMedium
	}
}

func mapKICSCategory(category string) string {
	cat := strings.ToLower(category)
	switch {
	case strings.Contains(cat, "access control") || strings.Contains(cat, "encrypt") || strings.Contains(cat, "secret"):
		return rules.CategorySecurity
	case strings.Contains(cat, "observ") || strings.Contains(cat, "log") || strings.Contains(cat, "monitor"):
		return rules.CategoryCompliance
	case strings.Contains(cat, "availab") || strings.Contains(cat, "backup") || strings.Contains(cat, "resilien"):
		return rules.CategoryReliability
	case strings.Contains(cat, "best practice") || strings.Contains(cat, "resource management"):
		return rules.CategoryBestPractice
	case strings.Contains(cat, "insecure") || strings.Contains(cat, "network"):
		return rules.CategorySecurity
	default:
		return rules.CategorySecurity
	}
}
