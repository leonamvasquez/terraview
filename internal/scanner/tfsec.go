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
	Register(&TfsecScanner{})
}

// TfsecScanner implements the Scanner interface for Aqua tfsec (now trivy).
type TfsecScanner struct{}

func (s *TfsecScanner) Name() string { return "tfsec" }

func (s *TfsecScanner) Available() bool {
	// Check for both tfsec and trivy (tfsec is now part of trivy)
	return commandExists("tfsec") || commandExists("trivy")
}

func (s *TfsecScanner) Priority() int { return 2 }

func (s *TfsecScanner) EnsureInstalled() (bool, InstallHint) {
	if s.Available() {
		return true, InstallHint{}
	}
	// Try auto-install via bininstaller
	result := AutoInstallScanner("tfsec")
	if result.Installed {
		return true, InstallHint{}
	}
	return false, InstallHint{
		Brew:    "brew install tfsec",
		URL:     "https://aquasecurity.github.io/tfsec/",
		Default: "terraview scanners install tfsec",
	}
}

func (s *TfsecScanner) Version() string {
	if commandExists("tfsec") {
		return getCommandVersion("tfsec")
	}
	if commandExists("trivy") {
		return getCommandVersion("trivy")
	}
	return ""
}

func (s *TfsecScanner) SupportedModes() []ScanMode {
	return []ScanMode{ScanModeSource}
}

func (s *TfsecScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	scanDir := ctx.SourceDir
	if scanDir == "" {
		scanDir = ctx.WorkDir
	}
	if scanDir == "" {
		return nil, fmt.Errorf("tfsec: no source directory provided")
	}

	// Try tfsec first, then trivy
	if commandExists("tfsec") {
		return s.runTfsec(scanDir)
	}
	return s.runTrivy(scanDir)
}

func (s *TfsecScanner) runTfsec(dir string) ([]rules.Finding, error) {
	tmpFile, err := os.CreateTemp("", "tfsec-*.json")
	if err != nil {
		return nil, fmt.Errorf("tfsec: failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cmd := exec.Command("tfsec",
		dir,
		"--format", "json",
		"--out", tmpFile.Name(),
		"--no-color",
		"--exclude-downloaded-modules",
	)

	// tfsec exits non-zero when findings exist
	_ = cmd.Run()

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	return parseTfsecOutput(data)
}

func (s *TfsecScanner) runTrivy(dir string) ([]rules.Finding, error) {
	tmpFile, err := os.CreateTemp("", "trivy-*.json")
	if err != nil {
		return nil, fmt.Errorf("trivy: failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	cmd := exec.Command("trivy",
		"config",
		"--format", "json",
		"--output", tmpFile.Name(),
		dir,
	)

	_ = cmd.Run()

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	return parseTrivyOutput(data)
}

// tfsec JSON output structures
type tfsecReport struct {
	Results []tfsecResult `json:"results"`
}

type tfsecResult struct {
	RuleID      string `json:"rule_id"`
	LongID      string `json:"long_id"`
	RuleDesc    string `json:"rule_description"`
	Description string `json:"description"`
	Impact      string `json:"impact"`
	Resolution  string `json:"resolution"`
	Severity    string `json:"severity"`
	Resource    string `json:"resource"`
	Location    struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	} `json:"location"`
	Links []string `json:"links"`
}

func parseTfsecOutput(data []byte) ([]rules.Finding, error) {
	var report tfsecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("tfsec: failed to parse output: %w", err)
	}

	findings := make([]rules.Finding, 0, len(report.Results))
	for _, r := range report.Results {
		resource := r.Resource
		if resource == "" {
			resource = r.Location.Filename
		}

		desc := r.Description
		if desc == "" {
			desc = r.RuleDesc
		}

		ruleID := r.RuleID
		if ruleID == "" {
			ruleID = r.LongID
		}

		findings = append(findings, rules.Finding{
			RuleID:      ruleID,
			Severity:    mapTfsecSeverity(r.Severity),
			Category:    inferTfsecCategory(ruleID),
			Resource:    resource,
			Message:     fmt.Sprintf("[tfsec] %s: %s", ruleID, desc),
			Remediation: r.Resolution,
			Source:      "scanner:tfsec",
		})
	}

	return findings, nil
}

// trivy config JSON output structures
type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target            string           `json:"Target"`
	Misconfigurations []trivyMisconfig `json:"Misconfigurations"`
}

type trivyMisconfig struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Desc          string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	Status        string   `json:"Status"`
	References    []string `json:"References"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		Provider  string `json:"Provider"`
		Service   string `json:"Service"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

func parseTrivyOutput(data []byte) ([]rules.Finding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: failed to parse output: %w", err)
	}

	var findings []rules.Finding
	for _, r := range report.Results {
		for _, m := range r.Misconfigurations {
			if m.Status == "PASS" {
				continue
			}

			resource := m.CauseMetadata.Resource
			if resource == "" {
				resource = r.Target
			}

			ruleID := m.AVDID
			if ruleID == "" {
				ruleID = m.ID
			}

			desc := m.Message
			if desc == "" {
				desc = m.Desc
			}

			findings = append(findings, rules.Finding{
				RuleID:      ruleID,
				Severity:    mapTfsecSeverity(m.Severity),
				Category:    inferTfsecCategory(ruleID),
				Resource:    resource,
				Message:     fmt.Sprintf("[trivy] %s: %s", ruleID, desc),
				Remediation: m.Resolution,
				Source:      "scanner:trivy",
			})
		}
	}

	return findings, nil
}

func mapTfsecSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return rules.SeverityCritical
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

func inferTfsecCategory(ruleID string) string {
	id := strings.ToLower(ruleID)
	switch {
	case strings.Contains(id, "iam") || strings.Contains(id, "auth") || strings.Contains(id, "encrypt"):
		return rules.CategorySecurity
	case strings.Contains(id, "log") || strings.Contains(id, "monitor") || strings.Contains(id, "audit"):
		return rules.CategoryCompliance
	case strings.Contains(id, "backup") || strings.Contains(id, "replica"):
		return rules.CategoryReliability
	default:
		return rules.CategorySecurity
	}
}
