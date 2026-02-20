package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// Format constants for output mode.
const (
	FormatPretty  = "pretty"
	FormatCompact = "compact"
	FormatJSON    = "json"
)

// WriterConfig configures output behavior.
type WriterConfig struct {
	Format string // "pretty", "compact", "json"
}

// IsJSON returns true if format is json-only.
func (c WriterConfig) IsJSON() bool { return c.Format == FormatJSON }

// IsCompact returns true if format is compact.
func (c WriterConfig) IsCompact() bool { return c.Format == FormatCompact }

// Writer generates output files from review results.
type Writer struct {
	config WriterConfig
}

// NewWriter creates a new Writer with default config.
func NewWriter() *Writer {
	return &Writer{config: WriterConfig{}}
}

// NewWriterWithConfig creates a Writer with the given config.
func NewWriterWithConfig(config WriterConfig) *Writer {
	return &Writer{config: config}
}

// WriteJSON writes the review result as structured JSON.
func (w *Writer) WriteJSON(result aggregator.ReviewResult, path string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal review result: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}

// WriteMarkdown writes the review result as a formatted Markdown report.
func (w *Writer) WriteMarkdown(result aggregator.ReviewResult, path string) error {
	md := w.renderMarkdown(result)

	if err := os.WriteFile(path, []byte(md), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", path, err)
	}

	return nil
}

// PrintSummary prints the review summary to stdout.
func (w *Writer) PrintSummary(result aggregator.ReviewResult) {
	if w.config.IsJSON() {
		return
	}

	if w.config.IsCompact() {
		w.printCompact(result)
		return
	}

	w.printFull(result)
}

func (w *Writer) printCompact(result aggregator.ReviewResult) {
	ratio := fmt.Sprintf("%d findings / %d resources", len(result.Findings), result.TotalResources)

	fmt.Printf("terraview: %s | score=%.1f | exit=%d",
		ratio, result.Score.OverallScore, result.ExitCode)

	if len(result.SeverityCounts) > 0 {
		parts := []string{}
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				parts = append(parts, fmt.Sprintf("%s:%d", sev, count))
			}
		}
		if len(parts) > 0 {
			fmt.Printf(" [%s]", strings.Join(parts, " "))
		}
	}
	fmt.Println()
}

func (w *Writer) printFull(result aggregator.ReviewResult) {
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Terraform Semantic Review Complete")
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Printf("  Resources analyzed: %d\n", result.TotalResources)
	fmt.Printf("  Total findings:     %d (%d per resource avg)\n",
		len(result.Findings), findingsPerResource(len(result.Findings), result.TotalResources))
	fmt.Println()

	if len(result.SeverityCounts) > 0 {
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				fmt.Printf("  %-10s %d\n", sev+":", count)
			}
		}
		fmt.Println()
	}

	// Top 3 critical risks
	topRisks := getTopRisks(result.Findings, 3)
	if len(topRisks) > 0 {
		fmt.Println("  Top risks:")
		for _, f := range topRisks {
			fmt.Printf("    [%s] %s: %s\n", f.Severity, f.Resource, truncate(f.Message, 70))
		}
		fmt.Println()
	}

	fmt.Printf("  Security Score:        %.1f/10\n", result.Score.SecurityScore)
	fmt.Printf("  Compliance Score:      %.1f/10\n", result.Score.ComplianceScore)
	fmt.Printf("  Maintainability Score: %.1f/10\n", result.Score.MaintainabilityScore)
	fmt.Printf("  Overall Score:         %.1f/10\n", result.Score.OverallScore)
	fmt.Println()
	fmt.Printf("  Exit code: %d\n", result.ExitCode)
	fmt.Println("═══════════════════════════════════════════════")
}

func (w *Writer) renderMarkdown(result aggregator.ReviewResult) string {
	var sb strings.Builder

	sb.WriteString("# Terraform Plan Review\n\n")
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
	sb.WriteString(fmt.Sprintf("**Plan:** `%s`  \n", result.PlanFile))
	sb.WriteString(fmt.Sprintf("**Resources Analyzed:** %d  \n\n", result.TotalResources))

	// Score section
	sb.WriteString("## Quality Score\n\n")
	sb.WriteString("| Metric | Score |\n")
	sb.WriteString("|--------|-------|\n")
	sb.WriteString(fmt.Sprintf("| Security | %s %.1f/10 |\n", scoreEmoji(result.Score.SecurityScore), result.Score.SecurityScore))
	sb.WriteString(fmt.Sprintf("| Compliance | %s %.1f/10 |\n", scoreEmoji(result.Score.ComplianceScore), result.Score.ComplianceScore))
	sb.WriteString(fmt.Sprintf("| Maintainability | %s %.1f/10 |\n", scoreEmoji(result.Score.MaintainabilityScore), result.Score.MaintainabilityScore))
	sb.WriteString(fmt.Sprintf("| **Overall** | **%s %.1f/10** |\n\n", scoreEmoji(result.Score.OverallScore), result.Score.OverallScore))

	// Summary
	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("%s\n\n", result.Summary))

	// Severity counts
	if len(result.Findings) > 0 {
		sb.WriteString("## Findings Overview\n\n")
		sb.WriteString(fmt.Sprintf("**%d findings across %d resources**\n\n", len(result.Findings), result.TotalResources))
		sb.WriteString("| Severity | Count |\n")
		sb.WriteString("|----------|-------|\n")
		for _, sev := range []string{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow, rules.SeverityInfo} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				sb.WriteString(fmt.Sprintf("| %s %s | %d |\n", severityIcon(sev), sev, count))
			}
		}
		sb.WriteString("\n")
	}

	// Detailed findings grouped by severity
	if len(result.Findings) > 0 {
		sb.WriteString("## Detailed Findings\n\n")

		grouped := groupBySeverity(result.Findings)
		counter := 1
		for _, sev := range []string{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow, rules.SeverityInfo} {
			group := grouped[sev]
			if len(group) == 0 {
				continue
			}

			sb.WriteString(fmt.Sprintf("### %s %s (%d)\n\n", severityIcon(sev), sev, len(group)))

			for _, f := range group {
				sb.WriteString(fmt.Sprintf("%d. **`%s`** — %s\n", counter, f.Resource, f.Message))
				if f.Remediation != "" {
					sb.WriteString(fmt.Sprintf("   - *Remediation:* %s\n", f.Remediation))
				}
				sb.WriteString(fmt.Sprintf("   - Rule: `%s` | Category: %s | Source: %s\n\n", f.RuleID, f.Category, f.Source))
				counter++
			}
		}
	} else {
		sb.WriteString("## No Issues Found\n\n")
		sb.WriteString("The Terraform plan passed all checks successfully.\n\n")
	}

	// Footer
	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Generated by [terraview](https://github.com/leonamvasquez/terraview) | Exit code: %d*\n", result.ExitCode))

	return sb.String()
}

func groupBySeverity(findings []rules.Finding) map[string][]rules.Finding {
	grouped := make(map[string][]rules.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

func getTopRisks(findings []rules.Finding, max int) []rules.Finding {
	// Findings are already sorted by severity (CRITICAL first)
	if len(findings) <= max {
		return findings
	}
	return findings[:max]
}

func findingsPerResource(findings, resources int) int {
	if resources == 0 {
		return 0
	}
	return findings / resources
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func scoreEmoji(score float64) string {
	switch {
	case score >= 9.0:
		return "🟢"
	case score >= 7.0:
		return "🟡"
	case score >= 5.0:
		return "🟠"
	default:
		return "🔴"
	}
}

func severityIcon(severity string) string {
	switch severity {
	case rules.SeverityCritical:
		return "🔴"
	case rules.SeverityHigh:
		return "🟠"
	case rules.SeverityMedium:
		return "🟡"
	case rules.SeverityLow:
		return "🔵"
	case rules.SeverityInfo:
		return "⚪"
	default:
		return "⚪"
	}
}
