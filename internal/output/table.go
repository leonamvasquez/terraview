package output

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/util"
)

// ansiRe strips ANSI escape codes to compute visible character length.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func visibleLen(s string) int {
	return len([]rune(ansiRe.ReplaceAllString(s, "")))
}

// padRight pads s to visibleWidth based on visible (non-ANSI) character count.
func padRight(s string, width int) string {
	v := visibleLen(s)
	if v >= width {
		return s
	}
	return s + strings.Repeat(" ", width-v)
}

// Table column widths (visible characters).
const (
	colRuleID   = 22
	colSeverity = 10
	colResource = 30
	colMessage  = 44
	colCategory = 15
)

func tableHRule() string {
	return fmt.Sprintf("|-%s-|-%s-|-%s-|-%s-|-%s-|",
		strings.Repeat("-", colRuleID),
		strings.Repeat("-", colSeverity),
		strings.Repeat("-", colResource),
		strings.Repeat("-", colMessage),
		strings.Repeat("-", colCategory),
	)
}

func tableHeader(br bool) string {
	ruleHdr, sevHdr, resHdr, msgHdr, catHdr := "RULE ID", "SEVERITY", "RESOURCE", "MESSAGE", "CATEGORY"
	if br {
		ruleHdr, sevHdr, resHdr, msgHdr, catHdr = "REGRA", "SEVERIDADE", "RECURSO", "MENSAGEM", "CATEGORIA"
	}
	return colorize(bold, fmt.Sprintf("| %-*s | %-*s | %-*s | %-*s | %-*s |",
		colRuleID, ruleHdr,
		colSeverity, sevHdr,
		colResource, resHdr,
		colMessage, msgHdr,
		colCategory, catHdr,
	))
}

// PrintFindingsTable renders findings as an Orca-style bordered table.
func PrintFindingsTable(findings []rules.Finding, br bool) {
	if len(findings) == 0 {
		return
	}

	fmt.Println(tableHeader(br))
	fmt.Println(tableHRule())

	for _, f := range findings {
		ruleID := padRight(util.Truncate(f.RuleID, colRuleID), colRuleID)
		sevLabel := i18n.SevLabel(f.Severity)
		sevCell := padRight(SevColor(sevLabel), colSeverity)
		resource := padRight(util.Truncate(f.Resource, colResource), colResource)
		message := padRight(util.Truncate(f.Message, colMessage), colMessage)
		category := padRight(util.Truncate(f.Category, colCategory), colCategory)

		fmt.Printf("| %s | %s | %s | %s | %s |\n",
			ruleID, sevCell, resource, message, category)
	}
	fmt.Println()
}

// FindingsSummaryLine returns "[TOTAL: N | CRITICAL: N | HIGH: N | ...]".
func FindingsSummaryLine(counts map[string]int, total int) string {
	sevs := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	parts := make([]string, 0, len(sevs)+1)
	parts = append(parts, fmt.Sprintf("TOTAL: %d", total))
	for _, sev := range sevs {
		parts = append(parts, fmt.Sprintf("%s: %d", sev, counts[sev]))
	}
	return Dimmed("[" + strings.Join(parts, " | ") + "]")
}

// ScanStatusLine returns the "SCAN STATUS: FAILED/WARNING/PASSED — detail" line.
func ScanStatusLine(exitCode int, br bool) string {
	var statusText, detail string
	switch exitCode {
	case 2:
		statusText = colorize(bold+brightRed, "FAILED")
		if br {
			detail = "achados CRÍTICOS detectados"
		} else {
			detail = "CRITICAL findings detected"
		}
	case 1:
		statusText = colorize(yellow, "WARNING")
		if br {
			detail = "achados HIGH detectados"
		} else {
			detail = "HIGH findings detected"
		}
	default:
		statusText = colorize(bold+brightGreen, "PASSED")
		if br {
			detail = "nenhum problema encontrado"
		} else {
			detail = "no issues found"
		}
	}

	prefix := "SCAN STATUS:"
	if br {
		prefix = "STATUS DO SCAN:"
	}
	return fmt.Sprintf("  %s %s — %s", colorize(bold+brightWhite, prefix), statusText, Dimmed(detail))
}
