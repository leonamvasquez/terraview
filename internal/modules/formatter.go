package modules

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
)

// FormatPretty renders the analysis result as colored terminal output.
func FormatPretty(r *AnalysisResult) string {
	var b strings.Builder

	// Header
	b.WriteString(output.Header(pick("Module Analysis", "Análise de Módulos")))
	b.WriteString("\n")

	if r.Summary.TotalModules == 0 {
		b.WriteString(pick("  No module calls found in this plan.\n", "  Nenhuma chamada de módulo encontrada neste plano.\n"))
		return b.String()
	}

	// Module inventory
	b.WriteString(fmt.Sprintf("  %s: %d\n", pick("Modules found", "Módulos encontrados"), r.Summary.TotalModules))
	for typ, count := range r.Summary.BySourceType {
		b.WriteString(fmt.Sprintf("    %s: %d\n", typ, count))
	}
	if r.Summary.MaxNestingDepth > 0 {
		b.WriteString(fmt.Sprintf("  %s: %d\n", pick("Max nesting depth", "Profundidade máx. de aninhamento"), r.Summary.MaxNestingDepth))
	}
	b.WriteString("\n")

	// Module list
	b.WriteString(output.Header(pick("Modules", "Módulos")))
	b.WriteString("\n")
	for _, m := range r.Modules {
		addr := moduleAddr(m)
		var version string
		switch {
		case m.VersionConstraint != "":
			version = output.Dimmed(m.VersionConstraint)
		case m.SourceType == "local":
			version = ""
		case m.SourceType == "git":
			if ref := extractGitRef(m.Source); ref != "" {
				version = output.SevColor("MEDIUM") + " ref=" + ref
			} else {
				version = output.SevColor("HIGH") + " " + pick("(no ref)", "(sem ref)")
			}
		default:
			version = output.SevColor("HIGH") + " " + pick("(no version)", "(sem versão)")
		}
		indent := strings.Repeat("  ", m.Depth)
		b.WriteString(fmt.Sprintf("  %s%s  %s  %s", indent, output.Resource(addr), output.Dimmed(m.SourceType), version))
		if m.ResourceCount > 0 {
			b.WriteString(fmt.Sprintf("  %s", output.Dimmed(fmt.Sprintf("(%d resources)", m.ResourceCount))))
		}
		b.WriteString("\n")
	}

	// Findings
	if len(r.Findings) > 0 {
		b.WriteString("\n")
		b.WriteString(output.Header(fmt.Sprintf("%s (%d)", pick("Findings", "Achados"), len(r.Findings))))
		b.WriteString("\n")
		for _, f := range r.Findings {
			sev := output.SevColor(f.Severity)
			b.WriteString(fmt.Sprintf("  %s  %s\n", sev, output.Resource(f.Module)))
			b.WriteString(fmt.Sprintf("         %s [%s]\n", f.Message, output.Dimmed(f.RuleID)))
			if f.Remediation != "" {
				b.WriteString(fmt.Sprintf("         %s %s\n", output.Dimmed("→"), f.Remediation))
			}
			b.WriteString("\n")
		}
	} else {
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s %s\n", output.VerdictSafe("✓"), pick("No module issues found.", "Nenhum problema de módulo encontrado.")))
	}

	return b.String()
}

// FormatJSON renders the analysis result as JSON.
func FormatJSON(r *AnalysisResult) (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal modules result: %w", err)
	}
	return string(data), nil
}

func pick(en, br string) string {
	if i18n.IsBR() {
		return br
	}
	return en
}
