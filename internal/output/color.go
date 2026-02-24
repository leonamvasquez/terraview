package output

import (
	"fmt"
	"os"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ANSI color codes
const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"

	// Foreground colors
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	white  = "\033[37m"

	// Bright foreground
	brightRed   = "\033[91m"
	brightGreen = "\033[92m"
	brightBlue  = "\033[94m"
	brightCyan  = "\033[96m"
	brightWhite = "\033[97m"
)

// ColorEnabled controls whether ANSI colors are emitted.
// Respects NO_COLOR env var (https://no-color.org/) and --no-color flag.
var ColorEnabled = true

func init() {
	// Respect NO_COLOR standard (https://no-color.org/)
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		ColorEnabled = false
	}
}

// DisableColor turns off color output globally.
func DisableColor() {
	ColorEnabled = false
}

// colorize wraps text with ANSI codes if colors are enabled.
func colorize(code, text string) string {
	if !ColorEnabled {
		return text
	}
	return code + text + reset
}

// --- Semantic color functions ---

// SevColor returns the colored severity label.
func SevColor(severity string) string {
	if !ColorEnabled {
		return severity
	}
	// Map Portuguese labels back to English for color matching
	sevKey := severity
	switch severity {
	case "CRÍTICO":
		sevKey = rules.SeverityCritical
	case "ALTO":
		sevKey = rules.SeverityHigh
	case "MÉDIO":
		sevKey = rules.SeverityMedium
	case "BAIXO":
		sevKey = rules.SeverityLow
	}
	switch sevKey {
	case rules.SeverityCritical:
		return bold + red + severity + reset
	case rules.SeverityHigh:
		return brightRed + severity + reset
	case rules.SeverityMedium:
		return yellow + severity + reset
	case rules.SeverityLow:
		return brightBlue + severity + reset
	case rules.SeverityInfo:
		return cyan + severity + reset
	default:
		return severity
	}
}

// VerdictSafe returns the styled SAFE verdict.
func VerdictSafe(text string) string {
	return colorize(bold+brightGreen, text)
}

// VerdictUnsafe returns the styled NOT SAFE verdict.
func VerdictUnsafe(text string) string {
	return colorize(bold+brightRed, text)
}

// ScoreColor returns the score colored by value.
func ScoreColor(score float64) string {
	text := fmt.Sprintf("%.1f/10", score)
	if !ColorEnabled {
		return text
	}
	switch {
	case score >= 9.0:
		return brightGreen + text + reset
	case score >= 7.0:
		return green + text + reset
	case score >= 5.0:
		return yellow + text + reset
	case score >= 3.0:
		return brightRed + text + reset
	default:
		return bold + red + text + reset
	}
}

// Header returns bold text for section headers.
func Header(text string) string {
	return colorize(bold+brightWhite, text)
}

// Dimmed returns dimmed text for secondary info.
func Dimmed(text string) string {
	return colorize(dim, text)
}

// SourceHeader returns the styled source group header.
func SourceHeader(text string) string {
	return colorize(bold+brightCyan, text)
}

// Resource returns the styled resource name.
func Resource(text string) string {
	return colorize(dim+white, text)
}

// SevCountLine returns a colored severity label with count for the summary.
func SevCountLine(severity string, label string, count int) string {
	return fmt.Sprintf("  %s %d", SevColor(fmt.Sprintf("%-10s", label+":")), count)
}

// Bar returns the styled separator bar.
func Bar() string {
	return colorize(dim, "═══════════════════════════════════════════════")
}

// Terraform purple (close to Terraform's brand purple #7B42BC)
const terraformPurple = "\033[38;5;129m"

// Prefix returns the styled [terraview] prefix in Terraform's signature purple.
func Prefix() string {
	return colorize(bold+terraformPurple, "[terraview]")
}
