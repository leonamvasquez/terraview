package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// FormatSARIF is the SARIF output format constant.
const FormatSARIF = "sarif"

// SARIFReport is the top-level SARIF 2.1.0 structure.
type SARIFReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun represents a single analysis run.
type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

// SARIFTool describes the analysis tool.
type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

// SARIFDriver is the tool driver with rules.
type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []SARIFRule `json:"rules"`
}

// SARIFRule is a rule definition in SARIF.
type SARIFRule struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	ShortDescription SARIFMessage             `json:"shortDescription"`
	DefaultConfig    SARIFDefaultConfig       `json:"defaultConfiguration"`
	Help             *SARIFMultiformatMessage `json:"help,omitempty"`
	Properties       SARIFRuleProps           `json:"properties,omitempty"`
}

// SARIFDefaultConfig is the default severity config.
type SARIFDefaultConfig struct {
	Level string `json:"level"`
}

// SARIFRuleProps holds extra rule properties.
type SARIFRuleProps struct {
	Category string `json:"category,omitempty"`
}

// SARIFMultiformatMessage supports text (and optionally markdown) content.
type SARIFMultiformatMessage struct {
	Text string `json:"text"`
}

// SARIFResult is a single finding result.
type SARIFResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   SARIFMessage    `json:"message"`
	Locations []SARIFLocation `json:"locations,omitempty"`
}

// SARIFMessage is a text message.
type SARIFMessage struct {
	Text string `json:"text"`
}

// SARIFLocation is a finding location.
type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	Message          *SARIFMessage         `json:"message,omitempty"`
}

// SARIFPhysicalLocation points to a specific file.
type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

// SARIFArtifactLocation is the file URI.
type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

// WriteSARIF writes the review result as a SARIF 2.1.0 report to the given file path.
// The parent directory is created automatically if it does not exist.
func (w *Writer) WriteSARIF(result aggregator.ReviewResult, path string) error {
	report := buildSARIF(result, w.config.Version)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("failed to create directory for %s: %w", path, err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write SARIF to %s: %w", path, err)
	}

	return nil
}

// WriteSARIFWriter serializes the review result as SARIF to an arbitrary io.Writer.
// Used when --format sarif is requested without an explicit -o directory (stdout).
func (w *Writer) WriteSARIFWriter(result aggregator.ReviewResult, dst io.Writer) error {
	report := buildSARIF(result, w.config.Version)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SARIF: %w", err)
	}

	if _, err := dst.Write(data); err != nil {
		return fmt.Errorf("failed to write SARIF: %w", err)
	}

	return nil
}

func buildSARIF(result aggregator.ReviewResult, version string) SARIFReport {
	if version == "" {
		version = "dev"
	}
	rulesMap := make(map[string]int)
	var sarifRules []SARIFRule

	for _, f := range result.Findings {
		if _, exists := rulesMap[f.RuleID]; !exists {
			rulesMap[f.RuleID] = len(sarifRules)
			rule := SARIFRule{
				ID:   f.RuleID,
				Name: f.RuleID,
				ShortDescription: SARIFMessage{
					Text: f.Message,
				},
				DefaultConfig: SARIFDefaultConfig{
					Level: mapSeverityToSARIFLevel(f.Severity),
				},
				Properties: SARIFRuleProps{
					Category: f.Category,
				},
			}
			if f.Remediation != "" {
				rule.Help = &SARIFMultiformatMessage{Text: f.Remediation}
			}
			sarifRules = append(sarifRules, rule)
		}
	}

	var results []SARIFResult //nolint:prealloc
	for _, f := range result.Findings {
		ruleIndex := rulesMap[f.RuleID]

		r := SARIFResult{
			RuleID:    f.RuleID,
			RuleIndex: ruleIndex,
			Level:     mapSeverityToSARIFLevel(f.Severity),
			Message: SARIFMessage{
				Text: fmt.Sprintf("[%s] %s: %s", f.Source, f.Resource, f.Message),
			},
		}

		if f.Resource != "" {
			r.Locations = []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: f.Resource,
						},
					},
				},
			}
		}

		results = append(results, r)
	}

	return SARIFReport{
		Schema:  "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "terraview",
						Version:        version,
						InformationURI: "https://github.com/leonamvasquez/terraview",
						Rules:          sarifRules,
					},
				},
				Results: results,
			},
		},
	}
}

func mapSeverityToSARIFLevel(severity string) string {
	switch strings.ToUpper(severity) {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	case rules.SeverityLow, rules.SeverityInfo:
		return "note"
	default:
		return "warning"
	}
}
