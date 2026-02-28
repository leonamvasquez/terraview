package output

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/util"
)

// Format constants for output mode.
const (
	FormatPretty  = "pretty"
	FormatCompact = "compact"
	FormatJSON    = "json"
)

// WriterConfig configures output behavior.
type WriterConfig struct {
	Format  string // "pretty", "compact", "json"
	Lang    string // "pt-BR" for Brazilian Portuguese
	Version string // application version for SARIF reports
}

// IsBR returns true if output should be in Brazilian Portuguese.
func (c WriterConfig) IsBR() bool { return c.Lang == "pt-BR" }

// IsJSON returns true if format is json-only.
func (c WriterConfig) IsJSON() bool { return c.Format == FormatJSON }

// IsCompact returns true if format is compact.
func (c WriterConfig) IsCompact() bool { return c.Format == FormatCompact }

// Writer generates output files from review results.
type Writer struct {
	config WriterConfig
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
	if w.config.IsBR() {
		ratio = fmt.Sprintf("%d achados / %d recursos", len(result.Findings), result.TotalResources)
	}

	label := result.Verdict.Label
	if w.config.IsBR() {
		if result.Verdict.Safe {
			label = "SEGURO"
		} else {
			label = "NÃO SEGURO"
		}
	}

	if result.Verdict.Safe {
		label = VerdictSafe(label)
	} else {
		label = VerdictUnsafe(label)
	}

	fmt.Printf("terraview: %s | %s | score=%s | exit=%d",
		label, ratio, ScoreColor(result.Score.OverallScore), result.ExitCode)

	if len(result.SeverityCounts) > 0 {
		parts := []string{}
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				sevLabel := sev
				if w.config.IsBR() {
					sevLabel = sevBR(sev)
				}
				parts = append(parts, fmt.Sprintf("%s:%d", SevColor(sevLabel), count))
			}
		}
		if len(parts) > 0 {
			fmt.Printf(" [%s]", strings.Join(parts, " "))
		}
	}
	fmt.Println()
}

func (w *Writer) printFull(result aggregator.ReviewResult) {
	br := w.config.IsBR()
	fmt.Println()

	// Diagram (before verdict)
	if result.Diagram != "" {
		fmt.Println(result.Diagram)
		fmt.Println()
	}

	fmt.Println(Bar())
	if result.Verdict.Safe {
		if br {
			fmt.Printf("  %s\n", VerdictSafe("VEREDITO: SEGURO PARA APLICAR"))
		} else {
			fmt.Printf("  %s\n", VerdictSafe("VERDICT: SAFE TO APPLY"))
		}
	} else {
		if br {
			fmt.Printf("  %s\n", VerdictUnsafe("VEREDITO: NÃO SEGURO — revisão necessária"))
		} else {
			fmt.Printf("  %s\n", VerdictUnsafe("VERDICT: NOT SAFE — review required"))
		}
	}
	for _, reason := range result.Verdict.Reasons {
		if br {
			reason = translateReason(reason)
		}
		fmt.Printf("    %s\n", Dimmed(reason))
	}
	fmt.Println(Bar())
	fmt.Println()

	// AI Explanation (after verdict, before findings)
	if result.Explanation != nil {
		if br {
			fmt.Println("  Explicação IA:")
		} else {
			fmt.Println("  AI Explanation:")
		}
		if result.Explanation.Summary != "" {
			fmt.Printf("  %s\n", result.Explanation.Summary)
		}
		fmt.Println()
		if len(result.Explanation.Risks) > 0 {
			if br {
				fmt.Println("  Riscos:")
			} else {
				fmt.Println("  Risks:")
			}
			for _, r := range result.Explanation.Risks {
				fmt.Printf("    • %s\n", r)
			}
			fmt.Println()
		}
		if len(result.Explanation.Suggestions) > 0 {
			if br {
				fmt.Println("  Sugestões:")
			} else {
				fmt.Println("  Suggestions:")
			}
			for _, s := range result.Explanation.Suggestions {
				fmt.Printf("    • %s\n", s)
			}
			fmt.Println()
		}
	}

	// Blast Radius
	if result.BlastRadius != nil {
		fmt.Print(result.BlastRadius.FormatPretty())
		fmt.Println()
	}

	if br {
		fmt.Printf("  Recursos analisados: %d\n", result.TotalResources)
		fmt.Printf("  Total de achados:    %d (%d por recurso)\n",
			len(result.Findings), findingsPerResource(len(result.Findings), result.TotalResources))
	} else {
		fmt.Printf("  Resources analyzed: %d\n", result.TotalResources)
		fmt.Printf("  Total findings:     %d (%d per resource avg)\n",
			len(result.Findings), findingsPerResource(len(result.Findings), result.TotalResources))
	}
	fmt.Println()

	if len(result.SeverityCounts) > 0 {
		for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				label := sev
				if br {
					label = sevBR(sev)
				}
				fmt.Println(SevCountLine(sev, label, count))
			}
		}
		fmt.Println()
	}

	// Full findings list grouped by source
	if len(result.Findings) > 0 {
		sourceGroups := groupBySource(result.Findings)
		sourceOrder := []string{}
		// Stable ordering: scanner sources first, then AI, then others
		seen := map[string]bool{}
		for _, f := range result.Findings {
			src := sourceLabel(f.Source)
			if !seen[src] {
				seen[src] = true
				sourceOrder = append(sourceOrder, src)
			}
		}

		for _, src := range sourceOrder {
			findings := sourceGroups[src]
			if br {
				fmt.Printf("  %s\n", SourceHeader(fmt.Sprintf("── %s (%d achados) ──", src, len(findings))))
			} else {
				fmt.Printf("  %s\n", SourceHeader(fmt.Sprintf("── %s (%d findings) ──", src, len(findings))))
			}
			for _, f := range findings {
				sevLabel := f.Severity
				if br {
					sevLabel = sevBR(f.Severity)
				}
				fmt.Printf("    [%s] %s\n", SevColor(sevLabel), util.Truncate(f.Message, 80))
				fmt.Printf("           %s\n", Resource(f.Resource))
			}
			fmt.Println()
		}
	}

	if br {
		fmt.Printf("  Score Segurança:       %s\n", ScoreColor(result.Score.SecurityScore))
		fmt.Printf("  Score Conformidade:    %s\n", ScoreColor(result.Score.ComplianceScore))
		fmt.Printf("  Score Manutenibilidade:%s\n", ScoreColor(result.Score.MaintainabilityScore))
		fmt.Printf("  %s           %s\n", Header("Score Geral:"), ScoreColor(result.Score.OverallScore))
	} else {
		fmt.Printf("  Security Score:        %s\n", ScoreColor(result.Score.SecurityScore))
		fmt.Printf("  Compliance Score:      %s\n", ScoreColor(result.Score.ComplianceScore))
		fmt.Printf("  Maintainability Score: %s\n", ScoreColor(result.Score.MaintainabilityScore))
		fmt.Printf("  %s         %s\n", Header("Overall Score:"), ScoreColor(result.Score.OverallScore))
	}
	fmt.Println()
	if br {
		fmt.Printf("  Código de saída: %d\n", result.ExitCode)
	} else {
		fmt.Printf("  Exit code: %d\n", result.ExitCode)
	}
	fmt.Println(Bar())
}

func (w *Writer) renderMarkdown(result aggregator.ReviewResult) string {
	var sb strings.Builder
	br := w.config.IsBR()

	if br {
		sb.WriteString("# Revisão do Plano Terraform\n\n")
	} else {
		sb.WriteString("# Terraform Plan Review\n\n")
	}
	if br {
		sb.WriteString(fmt.Sprintf("**Data:** %s  \n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
		sb.WriteString(fmt.Sprintf("**Plano:** `%s`  \n", result.PlanFile))
		sb.WriteString(fmt.Sprintf("**Recursos Analisados:** %d  \n\n", result.TotalResources))
	} else {
		sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC")))
		sb.WriteString(fmt.Sprintf("**Plan:** `%s`  \n", result.PlanFile))
		sb.WriteString(fmt.Sprintf("**Resources Analyzed:** %d  \n\n", result.TotalResources))
	}

	// Verdict section
	if br {
		sb.WriteString("## Veredito\n\n")
		if result.Verdict.Safe {
			sb.WriteString("**SEGURO** — Este plano é seguro para aplicar.\n\n")
		} else {
			sb.WriteString("**NÃO SEGURO** — Este plano requer revisão antes de aplicar.\n\n")
		}
	} else {
		sb.WriteString("## Verdict\n\n")
		if result.Verdict.Safe {
			sb.WriteString("**SAFE** — This plan is safe to apply.\n\n")
		} else {
			sb.WriteString("**NOT SAFE** — This plan requires review before applying.\n\n")
		}
	}
	for _, reason := range result.Verdict.Reasons {
		if br {
			reason = translateReason(reason)
		}
		sb.WriteString(fmt.Sprintf("- %s\n", reason))
	}
	if br {
		sb.WriteString(fmt.Sprintf("\n*Confiança: %s*\n\n", result.Verdict.Confidence))
	} else {
		sb.WriteString(fmt.Sprintf("\n*Confidence: %s*\n\n", result.Verdict.Confidence))
	}

	// Diagram
	if result.Diagram != "" {
		if br {
			sb.WriteString("## Diagrama de Infraestrutura\n\n")
		} else {
			sb.WriteString("## Infrastructure Diagram\n\n")
		}
		sb.WriteString("```\n")
		sb.WriteString(result.Diagram)
		sb.WriteString("\n```\n\n")
	}

	// AI Explanation
	if result.Explanation != nil {
		if br {
			sb.WriteString("## Explicação IA\n\n")
		} else {
			sb.WriteString("## AI Explanation\n\n")
		}
		if result.Explanation.Summary != "" {
			sb.WriteString(fmt.Sprintf("%s\n\n", result.Explanation.Summary))
		}
		if len(result.Explanation.Changes) > 0 {
			if br {
				sb.WriteString("### Mudanças\n\n")
			} else {
				sb.WriteString("### Changes\n\n")
			}
			for _, c := range result.Explanation.Changes {
				sb.WriteString(fmt.Sprintf("- %s\n", c))
			}
			sb.WriteString("\n")
		}
		if len(result.Explanation.Risks) > 0 {
			if br {
				sb.WriteString("### Riscos\n\n")
			} else {
				sb.WriteString("### Risks\n\n")
			}
			for _, r := range result.Explanation.Risks {
				sb.WriteString(fmt.Sprintf("- %s\n", r))
			}
			sb.WriteString("\n")
		}
		if len(result.Explanation.Suggestions) > 0 {
			if br {
				sb.WriteString("### Sugestões\n\n")
			} else {
				sb.WriteString("### Suggestions\n\n")
			}
			for _, s := range result.Explanation.Suggestions {
				sb.WriteString(fmt.Sprintf("- %s\n", s))
			}
			sb.WriteString("\n")
		}
		if br {
			sb.WriteString(fmt.Sprintf("**Nível de Risco:** %s\n\n", result.Explanation.RiskLevel))
		} else {
			sb.WriteString(fmt.Sprintf("**Risk Level:** %s\n\n", result.Explanation.RiskLevel))
		}
	}

	// Score section
	if br {
		sb.WriteString("## Score de Qualidade\n\n")
		sb.WriteString("| Métrica | Score |\n")
		sb.WriteString("|---------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Segurança | %s %.1f/10 |\n", scoreEmoji(result.Score.SecurityScore), result.Score.SecurityScore))
		sb.WriteString(fmt.Sprintf("| Conformidade | %s %.1f/10 |\n", scoreEmoji(result.Score.ComplianceScore), result.Score.ComplianceScore))
		sb.WriteString(fmt.Sprintf("| Manutenibilidade | %s %.1f/10 |\n", scoreEmoji(result.Score.MaintainabilityScore), result.Score.MaintainabilityScore))
		sb.WriteString(fmt.Sprintf("| **Geral** | **%s %.1f/10** |\n\n", scoreEmoji(result.Score.OverallScore), result.Score.OverallScore))
	} else {
		sb.WriteString("## Quality Score\n\n")
		sb.WriteString("| Metric | Score |\n")
		sb.WriteString("|--------|-------|\n")
		sb.WriteString(fmt.Sprintf("| Security | %s %.1f/10 |\n", scoreEmoji(result.Score.SecurityScore), result.Score.SecurityScore))
		sb.WriteString(fmt.Sprintf("| Compliance | %s %.1f/10 |\n", scoreEmoji(result.Score.ComplianceScore), result.Score.ComplianceScore))
		sb.WriteString(fmt.Sprintf("| Maintainability | %s %.1f/10 |\n", scoreEmoji(result.Score.MaintainabilityScore), result.Score.MaintainabilityScore))
		sb.WriteString(fmt.Sprintf("| **Overall** | **%s %.1f/10** |\n\n", scoreEmoji(result.Score.OverallScore), result.Score.OverallScore))
	}

	// Summary
	if br {
		sb.WriteString("## Resumo\n\n")
	} else {
		sb.WriteString("## Summary\n\n")
	}
	sb.WriteString(fmt.Sprintf("%s\n\n", result.Summary))

	// Severity counts
	if len(result.Findings) > 0 {
		if br {
			sb.WriteString("## Visão Geral dos Achados\n\n")
			sb.WriteString(fmt.Sprintf("**%d achados em %d recursos**\n\n", len(result.Findings), result.TotalResources))
			sb.WriteString("| Severidade | Qtd |\n")
			sb.WriteString("|------------|-----|\n")
		} else {
			sb.WriteString("## Findings Overview\n\n")
			sb.WriteString(fmt.Sprintf("**%d findings across %d resources**\n\n", len(result.Findings), result.TotalResources))
			sb.WriteString("| Severity | Count |\n")
			sb.WriteString("|----------|-------|\n")
		}
		for _, sev := range []string{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow, rules.SeverityInfo} {
			if count, ok := result.SeverityCounts[sev]; ok && count > 0 {
				label := sev
				if br {
					label = sevBR(sev)
				}
				sb.WriteString(fmt.Sprintf("| %s %s | %d |\n", severityIcon(sev), label, count))
			}
		}
		sb.WriteString("\n")
	}

	// Detailed findings grouped by severity
	if len(result.Findings) > 0 {
		if br {
			sb.WriteString("## Achados Detalhados\n\n")
		} else {
			sb.WriteString("## Detailed Findings\n\n")
		}

		grouped := groupBySeverity(result.Findings)
		counter := 1
		for _, sev := range []string{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow, rules.SeverityInfo} {
			group := grouped[sev]
			if len(group) == 0 {
				continue
			}

			label := sev
			if br {
				label = sevBR(sev)
			}
			sb.WriteString(fmt.Sprintf("### %s %s (%d)\n\n", severityIcon(sev), label, len(group)))

			for _, f := range group {
				sb.WriteString(fmt.Sprintf("%d. **`%s`** — %s\n", counter, f.Resource, f.Message))
				if f.Remediation != "" {
					if br {
						sb.WriteString(fmt.Sprintf("   - *Remediação:* %s\n", f.Remediation))
					} else {
						sb.WriteString(fmt.Sprintf("   - *Remediation:* %s\n", f.Remediation))
					}
				}
				if br {
					sb.WriteString(fmt.Sprintf("   - Regra: `%s` | Categoria: %s | Origem: %s\n\n", f.RuleID, f.Category, f.Source))
				} else {
					sb.WriteString(fmt.Sprintf("   - Rule: `%s` | Category: %s | Source: %s\n\n", f.RuleID, f.Category, f.Source))
				}
				counter++
			}
		}
	} else {
		if br {
			sb.WriteString("## Nenhum Problema Encontrado\n\n")
			sb.WriteString("O plano Terraform passou em todas as verificações.\n\n")
		} else {
			sb.WriteString("## No Issues Found\n\n")
			sb.WriteString("The Terraform plan passed all checks successfully.\n\n")
		}
	}

	// Footer
	sb.WriteString("---\n\n")
	if br {
		sb.WriteString(fmt.Sprintf("*Gerado por [terraview](https://github.com/leonamvasquez/terraview) | Código de saída: %d*\n", result.ExitCode))
	} else {
		sb.WriteString(fmt.Sprintf("*Generated by [terraview](https://github.com/leonamvasquez/terraview) | Exit code: %d*\n", result.ExitCode))
	}

	return sb.String()
}

// sevBR translates severity labels to Portuguese.
func sevBR(sev string) string {
	switch sev {
	case "CRITICAL":
		return "CRÍTICO"
	case "HIGH":
		return "ALTO"
	case "MEDIUM":
		return "MÉDIO"
	case "LOW":
		return "BAIXO"
	default:
		return sev
	}
}

// translateReason translates known verdict reason patterns to Portuguese.
func translateReason(reason string) string {
	// Pattern: "N CRITICAL finding(s) detected"
	if strings.Contains(reason, "CRITICAL finding") {
		return strings.NewReplacer(
			"CRITICAL finding(s) detected", "achado(s) CRÍTICO(S) detectado(s)",
			"CRITICAL findings detected", "achados CRÍTICOS detectados",
		).Replace(reason)
	}
	// Pattern: "N HIGH finding(s) detected (strict mode)"
	if strings.Contains(reason, "HIGH finding") {
		return strings.NewReplacer(
			"HIGH finding(s) detected (strict mode)", "achado(s) ALTO(S) detectado(s) (modo estrito)",
			"HIGH findings detected (strict mode)", "achados ALTOS detectados (modo estrito)",
		).Replace(reason)
	}
	switch reason {
	case "No issues found":
		return "Nenhum problema encontrado"
	case "No CRITICAL or HIGH severity issues":
		return "Nenhum achado CRÍTICO ou ALTO"
	}
	// Pattern: "No CRITICAL issues found (N HIGH — use --strict to block)"
	if strings.Contains(reason, "No CRITICAL issues found") && strings.Contains(reason, "--strict") {
		// Replace English parts, keeping the count number
		r := strings.NewReplacer(
			"No CRITICAL issues found", "Nenhum achado CRÍTICO encontrado",
			"HIGH — use --strict to block", "ALTO(S) — use --strict para bloquear",
		)
		return r.Replace(reason)
	}
	return reason
}

func groupBySeverity(findings []rules.Finding) map[string][]rules.Finding {
	grouped := make(map[string][]rules.Finding)
	for _, f := range findings {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}

func groupBySource(findings []rules.Finding) map[string][]rules.Finding {
	grouped := make(map[string][]rules.Finding)
	for _, f := range findings {
		key := sourceLabel(f.Source)
		grouped[key] = append(grouped[key], f)
	}
	return grouped
}

func sourceLabel(source string) string {
	switch {
	case strings.HasPrefix(source, "scanner:"):
		name := strings.TrimPrefix(source, "scanner:")
		// Handle merged sources like "scanner:checkov+tfsec"
		return strings.ToUpper(name)
	case source == "llm" || source == "ai":
		return "AI"
	case strings.HasPrefix(source, "external:"):
		name := strings.TrimPrefix(source, "external:")
		return strings.ToUpper(name) + " (import)"
	default:
		if source == "" {
			return "AI"
		}
		return source
	}
}

func findingsPerResource(findings, resources int) int {
	if resources == 0 {
		return 0
	}
	return findings / resources
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
