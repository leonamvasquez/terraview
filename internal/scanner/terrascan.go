package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

func init() {
	Register(&TerrascanScanner{})
}

// TerrascanScanner implements the Scanner interface for Tenable Terrascan.
type TerrascanScanner struct{}

func (s *TerrascanScanner) Name() string { return "terrascan" }

func (s *TerrascanScanner) Available() bool { return commandExists("terrascan") }

func (s *TerrascanScanner) Priority() int { return 3 }

func (s *TerrascanScanner) EnsureInstalled() (bool, InstallHint) {
	if s.Available() {
		return true, InstallHint{}
	}
	// Try auto-install via bininstaller
	result := AutoInstallScanner("terrascan")
	if result.Installed {
		return true, InstallHint{}
	}
	return false, InstallHint{
		Brew:    "brew install terrascan",
		URL:     "https://runterrascan.io/",
		Default: "Install with: brew install terrascan",
	}
}

// Terrascan uses a subcommand 'version' rather than a --version flag.
func (s *TerrascanScanner) Version() string { return getCommandVersionArgs("terrascan", "version") }

func (s *TerrascanScanner) SupportedModes() []ScanMode {
	return []ScanMode{ScanModeSource}
}

func (s *TerrascanScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	scanDir := ctx.SourceDir
	if scanDir == "" {
		scanDir = ctx.WorkDir
	}
	if scanDir == "" {
		return nil, fmt.Errorf("terrascan: no source directory provided")
	}

	tmpFile, err := os.CreateTemp("", "terrascan-*.json")
	if err != nil {
		return nil, fmt.Errorf("terrascan: failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cmd := exec.Command("terrascan", "scan",
		"-i", "terraform",
		"-t", "aws",
		"-d", scanDir,
		"-o", "json",
	)

	// Terrascan exits non-zero when findings exist
	output, _ := cmd.CombinedOutput()

	// Try to parse stdout directly (terrascan writes to stdout, not file by default)
	if len(output) > 0 {
		return parseTerrascanOutput(output)
	}

	return nil, nil
}

// Terrascan JSON output structures
type terrascanReport struct {
	Results struct {
		Violations []terrascanViolation `json:"violations"`
		Count      struct {
			Low    int `json:"low"`
			Medium int `json:"medium"`
			High   int `json:"high"`
			Total  int `json:"total"`
		} `json:"count"`
	} `json:"results"`
}

type terrascanViolation struct {
	RuleName     string `json:"rule_name"`
	Description  string `json:"description"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	ResourceName string `json:"resource_name"`
	ResourceType string `json:"resource_type"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	PlanRoot     string `json:"plan_root"`
}

func parseTerrascanOutput(data []byte) ([]rules.Finding, error) {
	var report terrascanReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("terrascan: failed to parse output: %w", err)
	}

	var findings []rules.Finding
	for _, v := range report.Results.Violations {
		resource := v.ResourceName
		if resource == "" && v.File != "" {
			resource = fmt.Sprintf("%s:%d", v.File, v.Line)
		}

		ruleID := v.RuleID
		if ruleID == "" {
			ruleID = v.RuleName
		}

		findings = append(findings, rules.Finding{
			RuleID:      ruleID,
			Severity:    mapTerrascanSeverity(v.Severity),
			Category:    mapTerrascanCategory(v.Category),
			Resource:    resource,
			Message:     fmt.Sprintf("[terrascan] %s: %s", ruleID, v.Description),
			Remediation: "",
			Source:      "scanner:terrascan",
		})
	}

	return findings, nil
}

func mapTerrascanSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return rules.SeverityHigh
	case "MEDIUM":
		return rules.SeverityMedium
	case "LOW":
		return rules.SeverityLow
	default:
		return rules.SeverityMedium
	}
}

func mapTerrascanCategory(category string) string {
	cat := strings.ToLower(category)
	switch {
	case strings.Contains(cat, "security") || strings.Contains(cat, "iam") || strings.Contains(cat, "encrypt"):
		return rules.CategorySecurity
	case strings.Contains(cat, "compliance") || strings.Contains(cat, "logging") || strings.Contains(cat, "monitor"):
		return rules.CategoryCompliance
	case strings.Contains(cat, "resilience") || strings.Contains(cat, "availability") || strings.Contains(cat, "backup"):
		return rules.CategoryReliability
	case strings.Contains(cat, "best") || strings.Contains(cat, "practice"):
		return rules.CategoryBestPractice
	default:
		return rules.CategorySecurity
	}
}
