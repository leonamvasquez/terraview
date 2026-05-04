package fix

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/leonamvasquez/terraview/internal/fix/failurelog"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
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
//
// Advisory is non-nil when the Classifier determined this fix should be
// surfaced as a point of attention rather than auto-applied. Advisories are
// skipped by ApplyAll and rendered in a separate section by Preview/ApplyAll
// so the user sees them without the loop attempting (and failing) to apply.
type PendingFix struct {
	Finding    rules.Finding
	Suggestion *FixSuggestion
	Location   *Location // nil → file not found, display only
	Warnings   []ValidationWarning
	Advisory   *Advisory
}

// ApplySession holds configuration for an interactive fix review session.
type ApplySession struct {
	WorkDir    string    // directory to search for .tf files
	ProjectDir string    // canonical project root used to key failure-history; "" disables persistence
	NoColor    bool      // suppress ANSI codes when true
	Out        io.Writer // destination for all printed output; defaults to os.Stdout when nil
}

func (s *ApplySession) recordFailureForFinding(pf PendingFix, reason string) {
	if s.ProjectDir == "" {
		return
	}
	failurelog.RecordFailure(
		failurelog.Key(s.ProjectDir, pf.Finding.RuleID, pf.Finding.Resource),
		reason,
	)
}

func (s *ApplySession) recordSuccessForFinding(pf PendingFix) {
	if s.ProjectDir == "" {
		return
	}
	failurelog.RecordSuccess(
		failurelog.Key(s.ProjectDir, pf.Finding.RuleID, pf.Finding.Resource),
	)
}

// out returns the configured writer or os.Stdout when nil.
func (s *ApplySession) out() io.Writer {
	if s.Out != nil {
		return s.Out
	}
	return os.Stdout
}

// Preview prints the diff for every pending fix without applying anything.
// Used by `terraview fix plan` as a dry-run. Advisories are rendered as a
// separate section at the end (no diffs, just the reason line) so the user
// sees what would NOT be auto-applied even in plan mode.
func (s *ApplySession) Preview(pending []PendingFix) {
	total := len(pending)
	if total == 0 {
		return
	}

	applicable := make([]PendingFix, 0, total)
	advisories := make([]PendingFix, 0)
	for _, pf := range pending {
		if pf.Advisory != nil {
			advisories = append(advisories, pf)
			continue
		}
		applicable = append(applicable, pf)
	}

	if len(applicable) > 0 {
		fmt.Fprintf(s.out(), "\nPlan: %d fix(es) to apply. Nothing will be written.\n\n",
			len(applicable))

		width := compactLabelWidth(applicable)
		dups := markBatchDuplicates(applicable)

		for i, pf := range applicable {
			marker, color, note := "+", ansiGreen, ""
			if dups[i] {
				note = "covered by previous batch"
			}
			if pf.Location == nil {
				note = ".tf file not found"
			}
			s.printCompactLine(marker, color, pf, width, note)

			if !dups[i] {
				s.printPreviewDiff(pf)
				s.printWarnings(pf.Warnings)
			}
		}
	}

	if len(advisories) > 0 {
		s.printAdvisorySection(advisories)
	}

	if len(applicable) > 0 {
		fmt.Fprintf(s.out(), "Run %sterraview fix apply%s to apply these changes.\n\n",
			s.col(ansiBold), s.col(ansiReset))
	}
}

// printPreviewDiff renders only the +/- diff body (no header bar, no
// effort/explanation footer) indented under the compact line.
func (s *ApplySession) printPreviewDiff(pf PendingFix) {
	if pf.Suggestion == nil {
		return
	}
	if pf.Location != nil {
		existing, err := ReadLines(pf.Location)
		if err == nil && len(existing) > 0 {
			s.printUnifiedDiff(existing, splitLines(pf.Suggestion.HCL), pf.Location.StartLine)
		}
	} else if pf.Suggestion.HCL != "" {
		for _, line := range splitLines(pf.Suggestion.HCL) {
			fmt.Fprintf(s.out(), "      %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
		}
	}
	if len(pf.Suggestion.Prerequisites) > 0 {
		for _, prereq := range pf.Suggestion.Prerequisites {
			for _, line := range splitLines(prereq) {
				fmt.Fprintf(s.out(), "      %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
			}
		}
	}
	fmt.Fprintln(s.out())
}

// markBatchDuplicates identifies PendingFix entries produced by the same batch
// — i.e. multiple findings on the same resource sharing one merged HCL. The
// first occurrence of a (resource, hcl) pair is the "primary" that should be
// applied; subsequent entries are duplicates whose effect is already included.
// Returns a slice of bools of len(pending) where true means "duplicate, skip
// re-apply but report as covered".
func markBatchDuplicates(pending []PendingFix) []bool {
	seen := make(map[string]bool, len(pending))
	dup := make([]bool, len(pending))
	for i, pf := range pending {
		if pf.Suggestion == nil || pf.Suggestion.HCL == "" {
			continue
		}
		key := pf.Finding.Resource + "\x00" + strings.TrimSpace(pf.Suggestion.HCL)
		if seen[key] {
			dup[i] = true
			continue
		}
		seen[key] = true
	}
	return dup
}

// failedFix carries data needed to print a single failure line at the end of ApplyAll.
type failedFix struct {
	pf     PendingFix
	reason string
}

// ApplyAll applies every pending fix without prompting.
//
// Output is a single in-place updating line:
//
//	[terraview] ⠋ Applying fixes [12/145]
//
// On completion the spinner clears and only a summary plus failure lines
// (when any) remain on screen — successful fixes are not echoed individually.
//
// When Out is overridden (tests, pipes), the spinner is bypassed and a plain
// header + summary is written so output stays deterministic.
func (s *ApplySession) ApplyAll(pending []PendingFix) (applied, failed int) {
	total := len(pending)
	dups := markBatchDuplicates(pending)
	width := compactLabelWidth(pending)

	useSpinner := s.Out == nil && total > 0

	if !useSpinner {
		fmt.Fprintf(s.out(), "\nApplying %d fix(es)...\n\n", total)
	}

	var spinner *output.Spinner
	if useSpinner {
		spinner = output.NewSpinner(fmt.Sprintf("Applying fixes [0/%d]", total))
		spinner.Start()
	}

	failures := make([]failedFix, 0)

	advisories := make([]PendingFix, 0)

	for i, pf := range pending {
		switch {
		case dups[i]:
			applied++
		case pf.Advisory != nil:
			// Advisories are not failures — they are points of attention.
			// They count toward neither applied nor failed and are rendered
			// in a separate section after the apply summary.
			advisories = append(advisories, pf)
		case pf.Location == nil:
			failed++
			failures = append(failures, failedFix{pf, ".tf file not found"})
		case HasCriticalWarning(pf.Warnings):
			failed++
			failures = append(failures, failedFix{pf, "blocked by critical warning — review with `terraview fix`"})
		default:
			if err := s.applyFix(pf); err != nil {
				failed++
				failures = append(failures, failedFix{pf, fmt.Sprintf("%v", err)})
				s.recordFailureForFinding(pf, err.Error())
			} else {
				applied++
				s.recordSuccessForFinding(pf)
			}
		}

		if useSpinner {
			spinner.SetMessage(fmt.Sprintf("Applying fixes [%d/%d]", i+1, total))
		}
	}

	if useSpinner {
		spinner.Stop(failed == 0)
	}

	if len(failures) > 0 {
		fmt.Fprintln(s.out())
		for _, f := range failures {
			s.printCompactLine("✗", ansiRed, f.pf, width, f.reason)
		}
	}

	s.printApplySummary(applied, failed, total-len(advisories))
	if len(advisories) > 0 {
		s.printAdvisorySection(advisories)
	}
	return applied, failed
}

// printCompactLine renders a single terraform-apply-style line:
//
//	<marker> <RULE_ID padded> <resource padded> <file:line>  <note?>
func (s *ApplySession) printCompactLine(marker, markerColor string, pf PendingFix, width compactWidth, note string) {
	loc := "—"
	if pf.Location != nil {
		rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
		loc = fmt.Sprintf("%s:%d", rel, pf.Location.StartLine)
	}

	rule := padRight(pf.Finding.RuleID, width.rule)
	res := padRight(pf.Finding.Resource, width.resource)

	fmt.Fprintf(s.out(), "  %s%s%s %s  %s  %s",
		s.col(markerColor), marker, s.col(ansiReset),
		rule, res, loc,
	)
	if note != "" {
		fmt.Fprintf(s.out(), "  %s%s%s", s.col(ansiDim), note, s.col(ansiReset))
	}
	fmt.Fprintln(s.out())
}

type compactWidth struct{ rule, resource int }

func compactLabelWidth(pending []PendingFix) compactWidth {
	w := compactWidth{rule: 8, resource: 16}
	for _, pf := range pending {
		if l := len(pf.Finding.RuleID); l > w.rule {
			w.rule = l
		}
		if l := len(pf.Finding.Resource); l > w.resource {
			w.resource = l
		}
	}
	if w.rule > 24 {
		w.rule = 24
	}
	if w.resource > 40 {
		w.resource = 40
	}
	return w
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}

// printAdvisorySection groups advisories by AdvisoryGroup and renders each
// bucket with a title (no counts) followed by compact lines explaining why
// each finding was promoted to manual review.
func (s *ApplySession) printAdvisorySection(advisories []PendingFix) {
	if len(advisories) == 0 {
		return
	}

	groups := map[AdvisoryGroup][]PendingFix{}
	order := make([]AdvisoryGroup, 0)
	for _, pf := range advisories {
		g := pf.Advisory.Group
		if _, ok := groups[g]; !ok {
			order = append(order, g)
		}
		groups[g] = append(groups[g], pf)
	}

	width := compactLabelWidth(advisories)
	fmt.Fprintln(s.out())
	fmt.Fprintf(s.out(), "%sⓘ %s%s\n",
		s.col(ansiBold+ansiCyan), i18n.T().FixAdvisoryHeader, s.col(ansiReset))

	for _, g := range order {
		fmt.Fprintln(s.out())
		fmt.Fprintf(s.out(), "  %s▸ %s%s\n",
			s.col(ansiBold), g.Title(), s.col(ansiReset))
		for _, pf := range groups[g] {
			s.printCompactLine("ⓘ", ansiCyan, pf, width, pf.Advisory.Reason)
		}
	}
	fmt.Fprintln(s.out())
}

func (s *ApplySession) printApplySummary(applied, failed, total int) {
	skipped := total - applied - failed
	fmt.Fprintln(s.out())
	parts := []string{fmt.Sprintf("%s%d applied%s", s.col(ansiGreen), applied, s.col(ansiReset))}
	if failed > 0 {
		parts = append(parts, fmt.Sprintf("%s%d failed%s", s.col(ansiRed), failed, s.col(ansiReset)))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%s%d skipped%s", s.col(ansiDim), skipped, s.col(ansiReset)))
	}
	fmt.Fprintf(s.out(), "Apply complete: %s.\n\n", strings.Join(parts, ", "))
}

// Review presents each pending fix for user approval and applies accepted ones.
// It returns the count of applied and rejected fixes.
func (s *ApplySession) Review(pending []PendingFix) (applied, rejected int) {
	if len(pending) == 0 {
		return
	}

	applicable := make([]PendingFix, 0, len(pending))
	advisories := make([]PendingFix, 0)
	for _, pf := range pending {
		if pf.Advisory != nil || pf.Suggestion == nil {
			advisories = append(advisories, pf)
			continue
		}
		applicable = append(applicable, pf)
	}

	total := len(applicable)
	if total == 0 {
		s.printAdvisorySection(advisories)
		return
	}

	fmt.Fprintln(s.out())

	dups := markBatchDuplicates(applicable)
	for i, pf := range applicable {
		s.printFindingHeader(i+1, total, pf)
		if dups[i] {
			fmt.Fprintf(s.out(), "  %s✓ %s%s\n\n",
				s.col(ansiGreen), i18n.T().FixCoveredByBatch, s.col(ansiReset))
			applied++
			continue
		}
		s.printDiff(pf)
		s.printWarnings(pf.Warnings)

		action := s.promptAction(pf.Location != nil)

		switch action {
		case "a":
			if pf.Location == nil {
				fmt.Fprintf(s.out(), "  %s✗ %s%s\n",
					s.col(ansiRed), i18n.T().FixCannotLocateFile, s.col(ansiReset))
				rejected++
				continue
			}
			if err := s.applyFix(pf); err != nil {
				fmt.Fprintf(s.out(), "  %s✗ %s: %v%s\n", s.col(ansiRed), i18n.T().FixApplyError, err, s.col(ansiReset))
				rejected++
				s.recordFailureForFinding(pf, err.Error())
			} else {
				rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
				fmt.Fprintf(s.out(), "  %s✓ %s %s%s\n", s.col(ansiGreen), i18n.T().FixAppliedTo, rel, s.col(ansiReset))
				applied++
				s.recordSuccessForFinding(pf)
			}
		case "r":
			fmt.Fprintf(s.out(), "  %s— %s%s\n", s.col(ansiDim), i18n.T().FixRejected, s.col(ansiReset))
			rejected++
		default: // s = skip / q = quit handled below
			if action == "q" {
				fmt.Fprintf(s.out(), "\n  %s%s%s\n", s.col(ansiDim), i18n.T().FixSessionEnded, s.col(ansiReset))
				s.printAdvisorySection(advisories)
				return
			}
			fmt.Fprintf(s.out(), "  %s— %s%s\n", s.col(ansiDim), i18n.T().FixSkipped, s.col(ansiReset))
		}
		fmt.Fprintln(s.out())
	}

	s.printSummary(applied, rejected, total)
	s.printAdvisorySection(advisories)
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

	fmt.Fprintf(s.out(), "\n%s%s [%d/%d]%s\n", s.col(ansiDim), bar, idx, total, s.col(ansiReset))
	fmt.Fprintf(s.out(), "%s%s%s  %s%s%s  %s\n",
		s.col(ansiBold+sevColor), sev, s.col(ansiReset),
		s.col(ansiBold), pf.Finding.RuleID, s.col(ansiReset),
		pf.Finding.Resource,
	)

	if pf.Location != nil {
		rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
		fmt.Fprintf(s.out(), "%s%s:%d%s\n", s.col(ansiDim), rel, pf.Location.StartLine, s.col(ansiReset))
	} else {
		fmt.Fprintf(s.out(), "%s%s%s\n",
			s.col(ansiYellow), fmt.Sprintf(i18n.T().FixFileNotFound, s.WorkDir), s.col(ansiReset))
	}

	if pf.Finding.Message != "" {
		fmt.Fprintln(s.out())
		for _, line := range strings.Split(pf.Finding.Message, "\n") {
			fmt.Fprintf(s.out(), "  %s\n", line)
		}
	}

	if pf.Suggestion.Explanation != "" {
		fmt.Fprintf(s.out(), "\n  %s%s%s\n", s.col(ansiDim), pf.Suggestion.Explanation, s.col(ansiReset))
	}
}

func (s *ApplySession) printDiff(pf PendingFix) {
	fmt.Fprintln(s.out())

	if pf.Location != nil {
		existing, err := ReadLines(pf.Location)
		if err == nil && len(existing) > 0 {
			rel, _ := filepath.Rel(s.WorkDir, pf.Location.File)
			s.printDiffHeader(fmt.Sprintf("─ %s", rel))
			s.printUnifiedDiff(existing, splitLines(pf.Suggestion.HCL), pf.Location.StartLine)
		}
	} else if pf.Suggestion.HCL != "" {
		// No source file — show the proposed HCL as pure additions.
		for _, line := range splitLines(pf.Suggestion.HCL) {
			fmt.Fprintf(s.out(), "  %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
		}
	}

	// Prerequisites (new resources to append)
	if len(pf.Suggestion.Prerequisites) > 0 {
		fmt.Fprintf(s.out(), "\n  %sRecursos a adicionar:%s\n", s.col(ansiBold), s.col(ansiReset))
		for _, prereq := range pf.Suggestion.Prerequisites {
			for _, line := range splitLines(prereq) {
				fmt.Fprintf(s.out(), "  %s+ %s%s\n", s.col(ansiGreen), line, s.col(ansiReset))
			}
		}
	}

	s.printDiffHeader(strings.Repeat("─", 50))
	fmt.Fprintf(s.out(), "  %s%s: %s%s\n", s.col(ansiDim), i18n.T().FixEffort, pf.Suggestion.Effort, s.col(ansiReset))
}

// printUnifiedDiff renders a context diff between old and nLines, offset by
// startLine so line numbers reflect the actual file position.
func (s *ApplySession) printUnifiedDiff(old, nLines []string, startLine int) {
	lines := unifiedDiff(old, nLines)
	if len(lines) == 0 {
		// No diff — show a note.
		fmt.Fprintf(s.out(), "  %s%s%s\n", s.col(ansiDim), i18n.T().FixNoChanges, s.col(ansiReset))
		return
	}
	for _, l := range lines {
		lineNo := 0
		if l.OldLine > 0 {
			lineNo = startLine + l.OldLine - 1
		}
		switch l.Kind {
		case diffRemove:
			fmt.Fprintf(s.out(), "  %s%4d - %s%s\n",
				s.col(ansiRed), lineNo, l.Text, s.col(ansiReset))
		case diffAdd:
			fmt.Fprintf(s.out(), "  %s     + %s%s\n",
				s.col(ansiGreen), l.Text, s.col(ansiReset))
		default: // diffContext
			fmt.Fprintf(s.out(), "  %s%4d   %s%s\n",
				s.col(ansiDim), lineNo, l.Text, s.col(ansiReset))
		}
	}
}

func (s *ApplySession) printWarnings(warnings []ValidationWarning) {
	for _, w := range warnings {
		fmt.Fprintf(s.out(), "\n  %s⚠  %s%s\n", s.col(ansiYellow), w.Message, s.col(ansiReset))
	}
}

func (s *ApplySession) printDiffHeader(line string) {
	fmt.Fprintf(s.out(), "  %s%s%s\n", s.col(ansiDim), line, s.col(ansiReset))
}

// promptAction reads a single keypress from the user (raw terminal mode).
// Falls back to line-based input when stdin is not a TTY (e.g. piped).
// canApply controls whether [a]plicar is offered.
func (s *ApplySession) promptAction(canApply bool) string {
	t := i18n.T()
	if canApply {
		fmt.Fprintf(s.out(), "\n  %s[a]%s %s   %s[r]%s %s   %s[s]%s %s   %s[q]%s %s  ",
			s.col(ansiBold+ansiGreen), s.col(ansiReset), t.FixActionApply,
			s.col(ansiBold+ansiRed), s.col(ansiReset), t.FixActionReject,
			s.col(ansiBold), s.col(ansiReset), t.FixActionSkip,
			s.col(ansiBold), s.col(ansiReset), t.FixActionQuit,
		)
	} else {
		fmt.Fprintf(s.out(), "\n  %s[r]%s %s   %s[s]%s %s   %s[q]%s %s  ",
			s.col(ansiBold+ansiRed), s.col(ansiReset), t.FixActionReject,
			s.col(ansiBold), s.col(ansiReset), t.FixActionSkip,
			s.col(ansiBold), s.col(ansiReset), t.FixActionQuit,
		)
	}

	key := readKey()
	fmt.Fprintln(s.out()) // move past the prompt line

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
	// Pre-flight: verify the generated HCL has balanced delimiters before
	// touching any file. Unbalanced {}, [] or () corrupt the target file when
	// the broken block bleeds into the next resource.
	if pf.Suggestion.HCL != "" && !isHCLBalanced(pf.Suggestion.HCL) {
		return fmt.Errorf("%s", i18n.T().FixHCLUnbalanced)
	}

	// Pre-flight: reject AI-hallucinated attributes (e.g. web_acl_arn on aws_lb)
	// when the resource type is in our curated schema map.
	if pf.Suggestion.HCL != "" {
		resourceType := extractResourceTypeFromHCL(pf.Suggestion.HCL)
		if resourceType != "" {
			if err := ValidateAttributes(pf.Suggestion.HCL, resourceType); err != nil {
				return err
			}
		}
	}

	// Refresh Location against the current file state. Earlier fixes may have
	// shifted line offsets; using the stale StartLine/EndLine would corrupt
	// neighbouring blocks. We re-locate by resource address right before the
	// substitution so offsets always match the on-disk content.
	if pf.Location != nil && s.WorkDir != "" && pf.Finding.Resource != "" {
		if fresh, _ := FindResource(s.WorkDir, pf.Finding.Resource); fresh != nil {
			pf.Location = fresh
		}
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

// deduplicatePrereqs filters out prerequisite HCL blocks whose resource (or
// terraform/required_providers entries) already exists somewhere in dir.
// Prevents duplicate declarations that fail terraform validate.
func deduplicatePrereqs(blocks []string, dir string) []string {
	var pc *ProjectContext
	out := make([]string, 0, len(blocks))
	for _, block := range blocks {
		// Drop terraform { ... } blocks whose required_providers entries are
		// all already declared in the project. A second `terraform {}` block
		// triggers "Duplicate required providers configuration".
		if isTerraformBlock(block) {
			if pc == nil {
				pc = BuildProjectContext(dir)
			}
			providers := extractRequiredProviderNames(block)
			allKnown := len(providers) > 0
			for _, p := range providers {
				if !pc.HasProvider(p) {
					allKnown = false
					break
				}
			}
			if allKnown {
				continue
			}
			// At least one new provider — let the block through and rely on
			// terraform validate to catch the duplicate-terraform-block case
			// (rare; most projects have a single versions.tf).
			out = append(out, block)
			continue
		}

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

// isTerraformBlock reports whether block opens with `terraform {` (settings
// block, including required_providers / backend).
func isTerraformBlock(block string) bool {
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		return strings.HasPrefix(trimmed, "terraform ") || strings.HasPrefix(trimmed, "terraform{")
	}
	return false
}

// extractRequiredProviderNames returns the short provider names declared inside
// the required_providers { ... } sub-block of a terraform block. Returns nil
// when the block has no required_providers section.
func extractRequiredProviderNames(block string) []string {
	for _, body := range findBlockBodies(block, reReqProvOpen) {
		top := stripNestedBraces(body)
		var names []string
		for _, e := range reReqProviderEntry.FindAllStringSubmatch(top, -1) {
			names = append(names, e[1])
		}
		return names
	}
	return nil
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
	fmt.Fprintf(s.out(), "\n%s%s%s\n", s.col(ansiDim), strings.Repeat("━", 50), s.col(ansiReset))
	t := i18n.T()
	fmt.Fprintf(s.out(), "  %s%d %s%s  •  %s%d %s%s  •  %s%d %s%s\n\n",
		s.col(ansiGreen), applied, t.FixSummaryApplied, s.col(ansiReset),
		s.col(ansiRed), rejected, t.FixSummaryRejected, s.col(ansiReset),
		s.col(ansiDim), skipped, t.FixSummarySkipped, s.col(ansiReset),
	)
	if applied > 0 {
		fmt.Fprintf(s.out(), "  %s%s%s\n\n",
			s.col(ansiDim),
			fmt.Sprintf(t.FixSummaryHint, s.col(ansiBold)+"terraform validate"+s.col(ansiReset)+s.col(ansiDim)),
			s.col(ansiReset),
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
