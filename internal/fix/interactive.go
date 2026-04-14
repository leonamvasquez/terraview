package fix

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ANSI color helpers — reset automatically on each call.
const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

// PendingFix pairs a finding, its generated suggestion, its source location (may
// be nil when the file could not be found), and any validation warnings.
type PendingFix struct {
	Finding    rules.Finding
	Suggestion *FixSuggestion
	Location   *Location // nil → file not found, display only
	Warnings   []ValidationWarning
}

// ApplySession holds configuration for an interactive fix review session.
type ApplySession struct {
	WorkDir string // directory to search for .tf files
	NoColor bool   // suppress ANSI codes when true
}

// Preview prints the diff for every pending fix without applying anything.
// Used by `terraview fix plan` as a dry-run.
func (s *ApplySession) Preview(pending []PendingFix) {
	total := len(pending)
	if total == 0 {
		return
	}
	fmt.Printf("\n  Preview of %d fix(es) — nothing will be written.\n", total)

	for i, pf := range pending {
		s.printFindingHeader(i+1, total, pf)
		s.printDiff(pf)
		s.printWarnings(pf.Warnings)
	}

	fmt.Printf("\n%s%s%s\n", s.col(ansiDim), strings.Repeat("━", 50), s.col(ansiReset))
	fmt.Printf("  %sRun %sterraview fix apply%s to apply these changes interactively.%s\n\n",
		s.col(ansiDim), s.col(ansiBold), s.col(ansiReset+ansiDim), s.col(ansiReset))
}

// ApplyAll applies every pending fix without prompting.
// Fixes with no file location are skipped and reported.
// Returns the count of applied and failed fixes.
func (s *ApplySession) ApplyAll(pending []PendingFix) (applied, failed int) {
	total := len(pending)
	fmt.Printf("\n  Applying %d fix(es) automatically...\n\n", total)

	for _, pf := range pending {
		sevColor := ansiYellow
		if pf.Finding.Severity == "CRITICAL" {
			sevColor = ansiRed
		}
		label := fmt.Sprintf("%s%s%s  %s  %s",
			s.col(sevColor), pf.Finding.Severity, s.col(ansiReset),
			pf.Finding.RuleID, pf.Finding.Resource,
		)

		if pf.Location == nil {
			fmt.Printf("  %s✗%s %s\n    %s⚠ .tf file not found — skipped%s\n\n",
				s.col(ansiRed), s.col(ansiReset), label,
				s.col(ansiYellow), s.col(ansiReset))
			failed++
			continue
		}

		if HasCriticalWarning(pf.Warnings) {
			fmt.Printf("  %s✗%s %s\n    %s⚠ fix bloqueado por aviso crítico — revise com %sterraview fix%s%s\n\n",
				s.col(ansiRed), s.col(ansiReset), label,
				s.col(ansiYellow), s.col(ansiBold), s.col(ansiReset+ansiYellow), s.col(ansiReset))
			failed++
			continue
		}

		if err := s.applyFix(pf); err != nil {
			fmt.Printf("  %s✗%s %s\n    %s%v%s\n\n",
				s.col(ansiRed), s.col(ansiReset), label,
				s.col(ansiRed), err, s.col(ansiReset))
			failed++
		} else {
			rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
			fmt.Printf("  %s✓%s %s\n    %s→ %s%s\n\n",
				s.col(ansiGreen), s.col(ansiReset), label,
				s.col(ansiDim), rel, s.col(ansiReset))
			applied++
		}
	}

	s.printSummary(applied, failed, total)
	return applied, failed
}

// Review presents each pending fix for user approval and applies accepted ones.
// It returns the count of applied and rejected fixes.
func (s *ApplySession) Review(pending []PendingFix) (applied, rejected int) {
	total := len(pending)
	if total == 0 {
		return
	}

	fmt.Println()

	for i, pf := range pending {
		s.printFindingHeader(i+1, total, pf)
		s.printDiff(pf)
		s.printWarnings(pf.Warnings)

		action := s.promptAction(pf.Location != nil)

		switch action {
		case "a":
			if pf.Location == nil {
				fmt.Printf("  %s✗ Não foi possível localizar o arquivo .tf — copie o HCL manualmente.%s\n",
					s.col(ansiRed), s.col(ansiReset))
				rejected++
				continue
			}
			if err := s.applyFix(pf); err != nil {
				fmt.Printf("  %s✗ Erro ao aplicar: %v%s\n", s.col(ansiRed), err, s.col(ansiReset))
				rejected++
			} else {
				rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
				fmt.Printf("  %s✓ Aplicado em %s%s\n", s.col(ansiGreen), rel, s.col(ansiReset))
				applied++
			}
		case "r":
			fmt.Printf("  %s— Rejeitado%s\n", s.col(ansiDim), s.col(ansiReset))
			rejected++
		default: // s = skip / q = quit handled below
			if action == "q" {
				fmt.Printf("\n  %sSessão encerrada.%s\n", s.col(ansiDim), s.col(ansiReset))
				return
			}
			fmt.Printf("  %s— Ignorado%s\n", s.col(ansiDim), s.col(ansiReset))
		}
		fmt.Println()
	}

	s.printSummary(applied, rejected, total)
	return applied, rejected
}

// ── internal helpers ──────────────────────────────────────────────────────────

func (s *ApplySession) printFindingHeader(idx, total int, pf PendingFix) {
	bar := strings.Repeat("━", 48)
	sev := pf.Finding.Severity
	sevColor := ansiYellow
	if sev == "CRITICAL" {
		sevColor = ansiRed
	}

	fmt.Printf("\n%s%s [%d/%d]%s\n", s.col(ansiDim), bar, idx, total, s.col(ansiReset))
	fmt.Printf("%s%s%s  %s%s%s  %s\n",
		s.col(ansiBold+sevColor), sev, s.col(ansiReset),
		s.col(ansiBold), pf.Finding.RuleID, s.col(ansiReset),
		pf.Finding.Resource,
	)

	if pf.Location != nil {
		rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
		fmt.Printf("%s%s:%d%s\n", s.col(ansiDim), rel, pf.Location.StartLine, s.col(ansiReset))
	} else {
		fmt.Printf("%s⚠ arquivo .tf não localizado em %s%s\n",
			s.col(ansiYellow), s.WorkDir, s.col(ansiReset))
	}

	if pf.Finding.Message != "" {
		fmt.Println()
		for _, line := range strings.Split(pf.Finding.Message, "\n") {
			fmt.Printf("  %s\n", line)
		}
	}

	if pf.Suggestion.Explanation != "" {
		fmt.Printf("\n  %s%s%s\n", s.col(ansiDim), pf.Suggestion.Explanation, s.col(ansiReset))
	}
}

func (s *ApplySession) printDiff(pf PendingFix) {
	fmt.Println()

	// BEFORE — existing block from the .tf file
	if pf.Location != nil {
		existing, err := ReadLines(pf.Location)
		if err == nil && len(existing) > 0 {
			rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
			s.printDiffHeader(fmt.Sprintf("─ %s", rel))
			for i, line := range existing {
				lineNo := pf.Location.StartLine + i
				fmt.Printf("  %s%4d %s- %s%s\n",
					s.col(ansiRed), lineNo, s.col(ansiReset+ansiRed), line, s.col(ansiReset))
			}
		}
	}

	// AFTER — AI-proposed fix
	if pf.Suggestion.HCL != "" {
		newLines := strings.Split(strings.TrimRight(pf.Suggestion.HCL, "\n"), "\n")
		for _, line := range newLines {
			fmt.Printf("  %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
		}
	}

	// Prerequisites (new resources to append)
	if len(pf.Suggestion.Prerequisites) > 0 {
		fmt.Printf("\n  %sRecursos a adicionar:%s\n", s.col(ansiBold), s.col(ansiReset))
		for _, prereq := range pf.Suggestion.Prerequisites {
			for _, line := range strings.Split(strings.TrimRight(prereq, "\n"), "\n") {
				fmt.Printf("  %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
			}
		}
	}

	s.printDiffHeader(strings.Repeat("─", 50))
	fmt.Printf("  %sEsforço: %s%s\n", s.col(ansiDim), pf.Suggestion.Effort, s.col(ansiReset))
}

func (s *ApplySession) printWarnings(warnings []ValidationWarning) {
	for _, w := range warnings {
		fmt.Printf("\n  %s⚠  %s%s\n", s.col(ansiYellow), w.Message, s.col(ansiReset))
	}
}

func (s *ApplySession) printDiffHeader(line string) {
	fmt.Printf("  %s%s%s\n", s.col(ansiDim), line, s.col(ansiReset))
}

// promptAction reads a single keypress from the user (raw terminal mode).
// Falls back to line-based input when stdin is not a TTY (e.g. piped).
// canApply controls whether [a]plicar is offered.
func (s *ApplySession) promptAction(canApply bool) string {
	if canApply {
		fmt.Printf("\n  %s[a]%s Aplicar   %s[r]%s Rejeitar   %s[s]%s Pular   %s[q]%s Sair  ",
			s.col(ansiBold+ansiGreen), s.col(ansiReset),
			s.col(ansiBold+ansiRed), s.col(ansiReset),
			s.col(ansiBold), s.col(ansiReset),
			s.col(ansiBold), s.col(ansiReset),
		)
	} else {
		fmt.Printf("\n  %s[r]%s Rejeitar   %s[s]%s Pular   %s[q]%s Sair  ",
			s.col(ansiBold+ansiRed), s.col(ansiReset),
			s.col(ansiBold), s.col(ansiReset),
			s.col(ansiBold), s.col(ansiReset),
		)
	}

	key := readKey()
	fmt.Println() // move past the prompt line

	switch strings.ToLower(key) {
	case "a":
		if canApply {
			return "a"
		}
		return "s"
	case "r":
		return "r"
	case "q":
		return "q"
	default:
		return "s"
	}
}

// readKey reads a single character from stdin. Uses raw terminal mode when
// stdin is a TTY so the user does not need to press Enter (Claude Code style).
// Falls back to buffered line reading in non-interactive contexts.
func readKey() string {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err == nil {
			defer term.Restore(fd, oldState) //nolint:errcheck
			buf := make([]byte, 1)
			if _, err := os.Stdin.Read(buf); err == nil {
				return string(buf)
			}
		}
	}
	// Non-TTY fallback: read a line, use first character.
	var line string
	_, _ = fmt.Scanln(&line)
	if len(line) > 0 {
		return string(line[0])
	}
	return "s"
}

func (s *ApplySession) applyFix(pf PendingFix) error {
	// Pre-flight: verify the generated HCL has balanced braces before touching
	// any file. An unbalanced block would corrupt the target file.
	if pf.Suggestion.HCL != "" && !isBraceBalanced(pf.Suggestion.HCL) {
		return fmt.Errorf("HCL gerado tem chaves desbalanceadas — fix rejeitado para evitar corrupção do arquivo")
	}

	// Backup the file before any modification so we can roll back if validate fails.
	bakPath, err := BackupFile(pf.Location.File)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	// Replace the existing resource block with the AI fix.
	if pf.Suggestion.HCL != "" {
		if err := ApplyToFile(pf.Location, pf.Suggestion.HCL); err != nil {
			_ = RestoreBackup(bakPath)
			return err
		}
	}

	// Append prerequisite resources — only those not already present in the project.
	prereqs := deduplicatePrereqs(pf.Suggestion.Prerequisites, s.WorkDir)
	if len(prereqs) > 0 {
		if err := AppendToFile(pf.Location.File, prereqs); err != nil {
			_ = RestoreBackup(bakPath)
			return fmt.Errorf("append prerequisites: %w", err)
		}
	}

	// Run terraform validate to catch any HCL errors introduced by the fix.
	if validateErr := terraformValidate(s.WorkDir); validateErr != nil {
		_ = RestoreBackup(bakPath)
		return fmt.Errorf("terraform validate falhou — fix revertido automaticamente:\n%w", validateErr)
	}

	// Validation passed — remove the backup.
	_ = os.Remove(bakPath)
	return nil
}

// deduplicatePrereqs filters out prerequisite HCL blocks whose resource already
// exists somewhere in dir. Prevents duplicate resource declarations.
func deduplicatePrereqs(blocks []string, dir string) []string {
	out := make([]string, 0, len(blocks))
	for _, block := range blocks {
		rType, rName := parsePrereqHeader(block)
		if rType == "" {
			out = append(out, block) // can't parse — include it and let validate catch
			continue
		}
		loc, _ := FindResource(dir, rType+"."+rName)
		if loc != nil {
			continue // already exists — skip
		}
		out = append(out, block)
	}
	return out
}

// parsePrereqHeader extracts (resourceType, resourceName) from the first
// `resource "TYPE" "NAME"` line of a prerequisite HCL block.
func parsePrereqHeader(block string) (rType, rName string) {
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `resource "`) {
			continue
		}
		// resource "aws_kms_key" "my_key" {
		parts := strings.Fields(line)
		if len(parts) < 3 {
			return "", ""
		}
		return strings.Trim(parts[1], `"`), strings.Trim(parts[2], `"`)
	}
	return "", ""
}

// terraformValidate runs `terraform validate -no-color` in dir.
// Returns nil if terraform is not installed (non-fatal) or validation passes.
func terraformValidate(dir string) error {
	bin, err := exec.LookPath("terraform")
	if err != nil {
		return nil // terraform not installed; skip validation
	}
	var out bytes.Buffer
	cmd := exec.Command(bin, "validate", "-no-color")
	cmd.Dir = dir
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(out.String()))
	}
	return nil
}

func (s *ApplySession) printSummary(applied, rejected, total int) {
	skipped := total - applied - rejected
	fmt.Printf("\n%s%s%s\n", s.col(ansiDim), strings.Repeat("━", 50), s.col(ansiReset))
	fmt.Printf("  %s%d aplicado(s)%s  •  %s%d rejeitado(s)%s  •  %s%d ignorado(s)%s\n\n",
		s.col(ansiGreen), applied, s.col(ansiReset),
		s.col(ansiRed), rejected, s.col(ansiReset),
		s.col(ansiDim), skipped, s.col(ansiReset),
	)
	if applied > 0 {
		fmt.Printf("  %sDica:%s execute %sterraform validate%s para verificar os arquivos modificados.\n\n",
			s.col(ansiDim), s.col(ansiReset),
			s.col(ansiBold), s.col(ansiReset),
		)
	}
}

// col returns the ANSI code or empty string when color is disabled.
func (s *ApplySession) col(code string) string {
	if s.NoColor {
		return ""
	}
	return code
}
