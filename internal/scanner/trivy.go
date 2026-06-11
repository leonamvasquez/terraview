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
	Register(&TrivyScanner{})
}

// TrivyScanner implements the Scanner interface for Aqua Trivy
// (misconfiguration scanning via "trivy config" — successor of tfsec).
type TrivyScanner struct{}

func (s *TrivyScanner) Name() string { return "trivy" }

func (s *TrivyScanner) Available() bool {
	return commandExists("trivy")
}

func (s *TrivyScanner) Priority() int { return 2 }

func (s *TrivyScanner) EnsureInstalled() (bool, InstallHint) {
	if s.Available() {
		return true, InstallHint{}
	}
	// Try auto-install via bininstaller
	result := AutoInstallScanner("trivy")
	if result.Installed {
		return true, InstallHint{}
	}
	return false, InstallHint{
		Brew:    "brew install trivy",
		URL:     "https://trivy.dev/latest/getting-started/installation/",
		Default: "terraview scanners install trivy",
	}
}

func (s *TrivyScanner) Version() string {
	if commandExists("trivy") {
		return getCommandVersion("trivy")
	}
	return ""
}

func (s *TrivyScanner) SupportedModes() []ScanMode {
	return []ScanMode{ScanModeSource}
}

func (s *TrivyScanner) Scan(ctx ScanContext) ([]rules.Finding, error) {
	scanDir := ctx.SourceDir
	if scanDir == "" {
		scanDir = ctx.WorkDir
	}
	if scanDir == "" {
		return nil, fmt.Errorf("trivy: no source directory provided")
	}

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
		scanDir,
	)

	// trivy exits non-zero when findings exist (with --exit-code) or on partial
	// errors; parse whatever was written regardless.
	_ = cmd.Run()

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil || len(data) == 0 {
		return nil, nil
	}

	return parseTrivyOutput(data)
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
				Severity:    mapTrivySeverity(m.Severity),
				Category:    inferTrivyCategory(ruleID),
				Resource:    resource,
				Message:     fmt.Sprintf("[trivy] %s: %s", ruleID, desc),
				Remediation: m.Resolution,
				Source:      "scanner:trivy",
			})
		}
	}

	return findings, nil
}

func mapTrivySeverity(severity string) string {
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

func inferTrivyCategory(ruleID string) string {
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
