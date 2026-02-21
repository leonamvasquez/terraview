package importer

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// DetectFormat identifies the format of the findings file.
func DetectFormat(data []byte) string {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return "unknown"
	}

	if _, ok := raw["$schema"]; ok {
		if schema, ok := raw["$schema"].(string); ok && strings.Contains(schema, "sarif") {
			return "sarif"
		}
	}

	if _, ok := raw["runs"]; ok {
		return "sarif"
	}

	if _, ok := raw["results"]; ok {
		if results, ok := raw["results"].(map[string]interface{}); ok {
			if _, ok := results["failed_checks"]; ok {
				return "checkov"
			}
		}
	}

	if results, ok := raw["results"]; ok {
		if arr, ok := results.([]interface{}); ok && len(arr) > 0 {
			if item, ok := arr[0].(map[string]interface{}); ok {
				if _, ok := item["rule_id"]; ok {
					return "tfsec"
				}
			}
		}
	}

	return "unknown"
}

// Import reads a findings file and converts it to rules.Finding slice.
func Import(filePath string) ([]rules.Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read findings file %q: %w", filePath, err)
	}

	format := DetectFormat(data)

	switch format {
	case "checkov":
		return importCheckov(data)
	case "tfsec":
		return importTfsec(data)
	case "sarif":
		return importSARIF(data)
	default:
		return nil, fmt.Errorf("unknown findings format in %q. Supported: checkov, tfsec, sarif", filePath)
	}
}

func importCheckov(data []byte) ([]rules.Finding, error) {
	var report struct {
		Results struct {
			FailedChecks []struct {
				CheckID     string `json:"check_id"`
				CheckResult struct {
					Result string `json:"result"`
				} `json:"check_result"`
				CheckType    string `json:"check_type"`
				ResourceAddr string `json:"resource_address"`
				Guideline    string `json:"guideline"`
			} `json:"failed_checks"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse checkov output: %w", err)
	}

	var findings []rules.Finding
	for _, check := range report.Results.FailedChecks {
		findings = append(findings, rules.Finding{
			RuleID:   check.CheckID,
			Severity: mapCheckovSeverity(check.CheckID),
			Resource: check.ResourceAddr,
			Message:  fmt.Sprintf("[checkov] %s: %s", check.CheckID, check.Guideline),
			Source:   "external:checkov",
		})
	}

	return findings, nil
}

func importTfsec(data []byte) ([]rules.Finding, error) {
	var report struct {
		Results []struct {
			RuleID      string `json:"rule_id"`
			Description string `json:"description"`
			Severity    string `json:"severity"`
			Location    struct {
				Filename string `json:"filename"`
			} `json:"location"`
			Resource string `json:"resource"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse tfsec output: %w", err)
	}

	var findings []rules.Finding
	for _, result := range report.Results {
		findings = append(findings, rules.Finding{
			RuleID:   result.RuleID,
			Severity: mapTfsecSeverity(result.Severity),
			Resource: result.Resource,
			Message:  fmt.Sprintf("[tfsec] %s: %s", result.RuleID, result.Description),
			Source:   "external:tfsec",
		})
	}

	return findings, nil
}

func importSARIF(data []byte) ([]rules.Finding, error) {
	var report struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						DefaultConfiguration struct {
							Level string `json:"level"`
						} `json:"defaultConfiguration"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID  string `json:"ruleId"`
				Level   string `json:"level"`
				Message struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}

	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF output: %w", err)
	}

	var findings []rules.Finding
	for _, run := range report.Runs {
		toolName := run.Tool.Driver.Name
		if toolName == "" {
			toolName = "sarif"
		}

		for _, result := range run.Results {
			resource := ""
			if len(result.Locations) > 0 {
				resource = result.Locations[0].PhysicalLocation.ArtifactLocation.URI
			}

			findings = append(findings, rules.Finding{
				RuleID:   result.RuleID,
				Severity: mapSARIFLevel(result.Level),
				Resource: resource,
				Message:  fmt.Sprintf("[%s] %s: %s", toolName, result.RuleID, result.Message.Text),
				Source:   fmt.Sprintf("external:%s", toolName),
			})
		}
	}

	return findings, nil
}

func mapCheckovSeverity(checkID string) string {
	if strings.HasPrefix(checkID, "CKV_AWS_") {
		return "HIGH"
	}
	return "MEDIUM"
}

func mapTfsecSeverity(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "MEDIUM"
	}
}

func mapSARIFLevel(level string) string {
	switch strings.ToLower(level) {
	case "error":
		return "HIGH"
	case "warning":
		return "MEDIUM"
	case "note":
		return "LOW"
	default:
		return "MEDIUM"
	}
}
