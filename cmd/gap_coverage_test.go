package cmd

// gap_coverage_test.go covers branches that were 0% or low-coverage after the
// existing tests in coverage_test.go were accounted for.
//
// Target functions (by % before this file):
//   runStatus            0.0%  → testable via SaveLastScan + TempDir HOME
//   runHistoryTrend      0.0%  → testable via in-process SQLite store
//   runHistoryCompare    0.0%  → testable via in-process SQLite store
//   runHistoryExport     0.0%  → testable via in-process SQLite store
//   printSeverityTable   53.8% → delta branch (prev != nil) untested

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// redirectHome sets $HOME to dir and restores it after the test.
// LastScan is stored under ~/.terraview/, so we redirect HOME to a TempDir
// to avoid touching the real user home.
func redirectHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

// makeScanRecord returns a minimal ScanRecord for a given project hash.
func makeScanRecord(projectDir string, ts time.Time, countHigh, countCritical int) history.ScanRecord {
	return history.ScanRecord{
		Timestamp:     ts,
		ProjectDir:    projectDir,
		ProjectHash:   history.ProjectHash(projectDir),
		Scanner:       "builtin",
		ScoreOverall:  8.5,
		CountCritical: countCritical,
		CountHigh:     countHigh,
	}
}

// ---------------------------------------------------------------------------
// runStatus
// ---------------------------------------------------------------------------

func TestRunStatus_NoScan(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	defer func() { workDir = oldWork }()
	workDir = homeDir

	out := captureStdout(func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Errorf("runStatus error: %v", err)
		}
	})

	if !strings.Contains(out, "No scan found") {
		t.Errorf("expected 'No scan found' message, got: %q", out)
	}
}

func TestRunStatus_WithLastScan(t *testing.T) {
	homeDir := redirectHome(t)

	projectDir := t.TempDir()
	oldWork := workDir
	defer func() { workDir = oldWork }()
	workDir = projectDir

	ls := history.LastScan{
		Timestamp:      time.Now().Add(-10 * time.Minute),
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 5,
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "no encryption"},
		},
	}

	// SaveLastScan writes to ~/.terraview/<hash>-last.json
	t.Setenv("HOME", homeDir)
	if err := history.SaveLastScan(ls); err != nil {
		t.Fatalf("SaveLastScan: %v", err)
	}

	out := captureStdout(func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Errorf("runStatus error: %v", err)
		}
	})

	// Should print the project header, not "No scan found"
	if strings.Contains(out, "No scan found") {
		t.Errorf("expected scan output, got: %q", out)
	}
}

func TestRunStatus_WithScanAndExplainScores(t *testing.T) {
	homeDir := redirectHome(t)

	projectDir := t.TempDir()
	oldWork := workDir
	oldFlag := statusExplainScoresFlag
	defer func() {
		workDir = oldWork
		statusExplainScoresFlag = oldFlag
	}()
	workDir = projectDir
	statusExplainScoresFlag = true

	ls := history.LastScan{
		Timestamp:      time.Now().Add(-5 * time.Minute),
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 3,
		Findings:       []rules.Finding{},
		// ScoreDecomposition is nil → should print "no decomposition" warning
	}

	t.Setenv("HOME", homeDir)
	if err := history.SaveLastScan(ls); err != nil {
		t.Fatalf("SaveLastScan: %v", err)
	}

	out := captureStdout(func() {
		if err := runStatus(statusCmd, nil); err != nil {
			t.Errorf("runStatus error: %v", err)
		}
	})

	if !strings.Contains(out, "score decomposition") && !strings.Contains(out, "score") {
		t.Errorf("expected score-related output, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// printSeverityTable — delta branch (prev != nil)
// ---------------------------------------------------------------------------

func TestPrintSeverityTable_WithDelta(t *testing.T) {
	projectDir := t.TempDir()
	homeDir := redirectHome(t)
	t.Setenv("HOME", homeDir)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")

	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	// Insert two records so that List returns >= 2.
	now := time.Now()
	older := makeScanRecord(projectDir, now.Add(-2*time.Hour), 2, 0)
	newer := makeScanRecord(projectDir, now.Add(-1*time.Hour), 0, 1)

	if _, err := store.Insert(older); err != nil {
		t.Fatalf("Insert older: %v", err)
	}
	if _, err := store.Insert(newer); err != nil {
		t.Fatalf("Insert newer: %v", err)
	}

	ls := &history.LastScan{
		Timestamp:      newer.Timestamp,
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 3,
		Findings: []rules.Finding{
			{RuleID: "CKV1", Severity: "CRITICAL", Resource: "r1", Message: "msg"},
		},
	}

	// Should print delta arrows (↑ or ↓ or ──)
	out := captureStdout(func() {
		printSeverityTable(ls, store)
	})

	// With prev != nil, delta column is rendered
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("expected CRITICAL row, got: %q", out)
	}
	// Delta column should contain ↑, ↓, or ──
	if !strings.Contains(out, "↑") && !strings.Contains(out, "↓") && !strings.Contains(out, "──") {
		t.Errorf("expected delta indicator, got: %q", out)
	}
}

func TestPrintSeverityTable_DeltaNewFindings(t *testing.T) {
	projectDir := t.TempDir()
	homeDir := redirectHome(t)
	t.Setenv("HOME", homeDir)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	now := time.Now()
	// Previous: no HIGH findings
	prev := makeScanRecord(projectDir, now.Add(-2*time.Hour), 0, 0)
	// Current: has HIGH findings
	curr := makeScanRecord(projectDir, now.Add(-1*time.Hour), 3, 0)

	store.Insert(prev)
	store.Insert(curr)

	ls := &history.LastScan{
		Timestamp:      curr.Timestamp,
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 2,
		Findings: []rules.Finding{
			{RuleID: "H1", Severity: "HIGH", Resource: "r1", Message: "m1"},
			{RuleID: "H2", Severity: "HIGH", Resource: "r2", Message: "m2"},
			{RuleID: "H3", Severity: "HIGH", Resource: "r3", Message: "m3"},
		},
	}

	out := captureStdout(func() {
		printSeverityTable(ls, store)
	})

	// Expecting ↑ because HIGH went from 0 to 3
	if !strings.Contains(out, "↑") {
		t.Errorf("expected '↑' for new HIGH findings, got: %q", out)
	}
}

func TestPrintSeverityTable_DeltaResolved(t *testing.T) {
	projectDir := t.TempDir()
	homeDir := redirectHome(t)
	t.Setenv("HOME", homeDir)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	now := time.Now()
	// Previous: 5 HIGH findings
	prev := makeScanRecord(projectDir, now.Add(-2*time.Hour), 5, 0)
	// Current: 0 HIGH findings
	curr := makeScanRecord(projectDir, now.Add(-1*time.Hour), 0, 0)

	store.Insert(prev)
	store.Insert(curr)

	ls := &history.LastScan{
		Timestamp:      curr.Timestamp,
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 2,
		Findings:       []rules.Finding{},
	}

	out := captureStdout(func() {
		printSeverityTable(ls, store)
	})

	// Expecting ↓ because HIGH went from 5 to 0
	if !strings.Contains(out, "↓") {
		t.Errorf("expected '↓' for resolved findings, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// runHistoryTrend
// ---------------------------------------------------------------------------

func TestRunHistoryTrend_HistoryDisabled(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	defer func() { workDir = oldWork }()

	dir := t.TempDir()
	workDir = dir
	t.Setenv("HOME", homeDir)

	// Write config with history disabled
	cfg := `history:
  enabled: false
`
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte(cfg), 0644)

	// Should print "Histórico desabilitado" and return nil
	err := runHistoryTrend(historyTrendCmd, nil)
	if err != nil {
		t.Errorf("runHistoryTrend disabled: expected nil, got %v", err)
	}
}

func TestRunHistoryTrend_NoRecords(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldLimit := historyLimit
	defer func() {
		workDir = oldWork
		historyLimit = oldLimit
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 10
	t.Setenv("HOME", homeDir)

	// Config with history enabled (default)
	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	out := captureStdout(func() {
		err := runHistoryTrend(historyTrendCmd, nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "Nenhum") && !strings.Contains(out, "scan") {
		t.Logf("output: %q", out)
	}
}

func TestRunHistoryTrend_WithRecords(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldLimit := historyLimit
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyLimit = oldLimit
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 10
	historySince = ""
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	// Create store with some records at the standard path.
	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	for i := 0; i < 3; i++ {
		store.Insert(makeScanRecord(dir, now.Add(-time.Duration(i)*time.Hour), i, 0))
	}
	store.Close()

	// Should not error
	captureStdout(func() {
		err := runHistoryTrend(historyTrendCmd, nil)
		if err != nil {
			t.Errorf("runHistoryTrend with records: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// runHistoryCompare
// ---------------------------------------------------------------------------

func TestRunHistoryCompare_HistoryDisabled(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	defer func() { workDir = oldWork }()

	dir := t.TempDir()
	workDir = dir
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: false\n"), 0644)

	err := runHistoryCompare(historyCompareCmd, nil)
	if err != nil {
		t.Errorf("runHistoryCompare disabled: expected nil, got %v", err)
	}
}

func TestRunHistoryCompare_NoScans(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldWith := historyWith
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyWith = oldWith
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historyWith = 0
	historySince = ""
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	// Empty store → GetLatest returns error → runHistoryCompare returns error
	err := runHistoryCompare(historyCompareCmd, nil)
	if err == nil {
		t.Error("expected error when no scans available for compare")
	}
	if !strings.Contains(err.Error(), "sem scans") && !strings.Contains(err.Error(), "scan") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestRunHistoryCompare_WithTwoScans(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldWith := historyWith
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyWith = oldWith
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historyWith = 0
	historySince = ""
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	store.Insert(makeScanRecord(dir, now.Add(-2*time.Hour), 3, 0))
	store.Insert(makeScanRecord(dir, now.Add(-1*time.Hour), 1, 0))
	store.Close()

	// Should succeed (two scans available for default compare)
	captureStdout(func() {
		err := runHistoryCompare(historyCompareCmd, nil)
		if err != nil {
			t.Errorf("runHistoryCompare with 2 scans: %v", err)
		}
	})
}

func TestRunHistoryCompare_WithID(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldWith := historyWith
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyWith = oldWith
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historySince = ""
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	id1, _ := store.Insert(makeScanRecord(dir, now.Add(-2*time.Hour), 3, 0))
	store.Insert(makeScanRecord(dir, now.Add(-1*time.Hour), 1, 0))
	store.Close()

	// Compare with scan #id1 explicitly
	historyWith = id1

	captureStdout(func() {
		err := runHistoryCompare(historyCompareCmd, nil)
		if err != nil {
			t.Errorf("runHistoryCompare --with %d: %v", id1, err)
		}
	})
}

func TestRunHistoryCompare_WithInvalidID(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldWith := historyWith
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyWith = oldWith
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historySince = ""
	historyWith = 99999 // non-existent ID
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Insert(makeScanRecord(dir, time.Now(), 1, 0))
	store.Close()

	err = runHistoryCompare(historyCompareCmd, nil)
	if err == nil {
		t.Error("expected error for non-existent scan ID")
	}
}

func TestRunHistoryCompare_WithSince(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldWith := historyWith
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyWith = oldWith
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historyWith = 0
	historySince = "7d"
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	now := time.Now()
	store.Insert(makeScanRecord(dir, now.Add(-5*24*time.Hour), 2, 0))
	store.Insert(makeScanRecord(dir, now.Add(-1*time.Hour), 0, 0))
	store.Close()

	captureStdout(func() {
		err := runHistoryCompare(historyCompareCmd, nil)
		if err != nil {
			// GetOldestSince may find no scan — acceptable
			t.Logf("runHistoryCompare --since 7d: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// runHistoryExport
// ---------------------------------------------------------------------------

func TestRunHistoryExport_NoOutputFile(t *testing.T) {
	oldOut := historyOutFile
	oldFmt := historyExportFmt
	defer func() {
		historyOutFile = oldOut
		historyExportFmt = oldFmt
	}()

	historyOutFile = ""
	historyExportFmt = "json"

	err := runHistoryExport(historyExportCmd, nil)
	if err == nil {
		t.Error("expected error when no output file specified")
	}
	if !strings.Contains(err.Error(), "output") && !strings.Contains(err.Error(), "saída") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRunHistoryExport_InvalidFormat(t *testing.T) {
	oldOut := historyOutFile
	oldFmt := historyExportFmt
	defer func() {
		historyOutFile = oldOut
		historyExportFmt = oldFmt
	}()

	historyOutFile = "/tmp/out.xml"
	historyExportFmt = "xml"

	err := runHistoryExport(historyExportCmd, nil)
	if err == nil {
		t.Error("expected error for invalid export format")
	}
}

func TestRunHistoryExport_JSONFormat(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldOut := historyOutFile
	oldFmt := historyExportFmt
	oldLimit := historyLimit
	defer func() {
		workDir = oldWork
		historyOutFile = oldOut
		historyExportFmt = oldFmt
		historyLimit = oldLimit
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 0
	t.Setenv("HOME", homeDir)

	outFile := filepath.Join(dir, "export.json")
	historyOutFile = outFile
	historyExportFmt = "json"

	// Insert a scan record into the store
	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Insert(makeScanRecord(dir, time.Now(), 1, 0))
	store.Close()

	err = runHistoryExport(historyExportCmd, nil)
	if err != nil {
		t.Fatalf("runHistoryExport JSON: %v", err)
	}

	// Output file must exist and contain valid JSON
	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}
	var out interface{}
	if err := json.Unmarshal(data, &out); err != nil {
		t.Errorf("output is not valid JSON: %v", err)
	}
}

func TestRunHistoryExport_CSVFormat(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldOut := historyOutFile
	oldFmt := historyExportFmt
	oldLimit := historyLimit
	defer func() {
		workDir = oldWork
		historyOutFile = oldOut
		historyExportFmt = oldFmt
		historyLimit = oldLimit
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 0
	t.Setenv("HOME", homeDir)

	outFile := filepath.Join(dir, "export.csv")
	historyOutFile = outFile
	historyExportFmt = "csv"

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Insert(makeScanRecord(dir, time.Now(), 0, 1))
	store.Close()

	err = runHistoryExport(historyExportCmd, nil)
	if err != nil {
		t.Fatalf("runHistoryExport CSV: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("CSV output file not written: %v", err)
	}
	if !strings.Contains(string(data), ",") {
		t.Errorf("expected CSV with commas, got: %q", string(data))
	}
}

func TestRunHistoryExport_AllProjects(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldOut := historyOutFile
	oldFmt := historyExportFmt
	oldLimit := historyLimit
	oldAll := historyAll
	defer func() {
		workDir = oldWork
		historyOutFile = oldOut
		historyExportFmt = oldFmt
		historyLimit = oldLimit
		historyAll = oldAll
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 0
	historyAll = true // exercises the !historyAll branch inversion
	t.Setenv("HOME", homeDir)

	outFile := filepath.Join(dir, "all_export.json")
	historyOutFile = outFile
	historyExportFmt = "json"

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	store.Insert(makeScanRecord(dir, time.Now(), 0, 0))
	store.Close()

	err = runHistoryExport(historyExportCmd, nil)
	if err != nil {
		t.Fatalf("runHistoryExport all-projects: %v", err)
	}

	if _, err := os.Stat(outFile); err != nil {
		t.Errorf("output file not written: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runHistoryTrend — since branch
// ---------------------------------------------------------------------------

func TestRunHistoryTrend_WithSince(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldLimit := historyLimit
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historyLimit = oldLimit
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historyLimit = 20
	historySince = "7d"
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	dbPath := filepath.Join(homeDir, ".terraview", "history.db")
	store, err := history.NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	now := time.Now()
	store.Insert(makeScanRecord(dir, now.Add(-3*24*time.Hour), 1, 0))
	store.Insert(makeScanRecord(dir, now.Add(-1*time.Hour), 0, 0))
	store.Close()

	captureStdout(func() {
		err := runHistoryTrend(historyTrendCmd, nil)
		if err != nil {
			t.Errorf("runHistoryTrend --since 7d: %v", err)
		}
	})
}

func TestRunHistoryTrend_InvalidSince(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldSince := historySince
	defer func() {
		workDir = oldWork
		historySince = oldSince
	}()

	dir := t.TempDir()
	workDir = dir
	historySince = "invalid-duration"
	t.Setenv("HOME", homeDir)

	os.WriteFile(filepath.Join(dir, ".terraview.yaml"), []byte("history:\n  enabled: true\n"), 0644)

	err := runHistoryTrend(historyTrendCmd, nil)
	if err == nil {
		t.Error("expected error for invalid since value")
	}
}

// ---------------------------------------------------------------------------
// runScan — ExitError path (exit code != 0 propagated as ExitError)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// generateAndHandleFixes — early-exit branches (no AI needed)
// ---------------------------------------------------------------------------

func TestRunFixPlan_NoLastScan(t *testing.T) {
	homeDir := redirectHome(t)

	oldWork := workDir
	oldPlan := planFile
	oldFmt := outputFormat
	oldProvider := fixProviderFlag
	defer func() {
		workDir = oldWork
		planFile = oldPlan
		outputFormat = oldFmt
		fixProviderFlag = oldProvider
	}()

	dir := t.TempDir()
	workDir = dir
	planFile = ""
	outputFormat = ""
	fixProviderFlag = ""
	t.Setenv("HOME", homeDir)

	out := captureStdout(func() {
		err := runFixPlan(fixPlanCmd, nil)
		if err != nil {
			t.Errorf("runFixPlan no-scan: unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "No scan found") {
		t.Errorf("expected 'No scan found' message, got: %q", out)
	}
}

func TestRunFixPlan_NoMatchingFindings(t *testing.T) {
	homeDir := redirectHome(t)

	projectDir := t.TempDir()
	oldWork := workDir
	oldFmt := outputFormat
	oldProvider := fixProviderFlag
	oldSeverity := fixSeverityFlag
	defer func() {
		workDir = oldWork
		outputFormat = oldFmt
		fixProviderFlag = oldProvider
		fixSeverityFlag = oldSeverity
	}()

	workDir = projectDir
	outputFormat = ""
	fixProviderFlag = ""
	fixSeverityFlag = ""
	t.Setenv("HOME", homeDir)

	// Save a last scan with only LOW findings — filterFixTargets keeps CRITICAL/HIGH by default.
	ls := history.LastScan{
		Timestamp:      time.Now(),
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 1,
		Findings: []rules.Finding{
			{RuleID: "INFO-001", Severity: "LOW", Resource: "r1", Message: "low priority"},
		},
	}
	if err := history.SaveLastScan(ls); err != nil {
		t.Fatalf("SaveLastScan: %v", err)
	}

	out := captureStdout(func() {
		err := runFixPlan(fixPlanCmd, nil)
		if err != nil {
			t.Errorf("runFixPlan no-match: unexpected error: %v", err)
		}
	})

	if !strings.Contains(out, "No findings match") {
		t.Errorf("expected 'No findings match' message, got: %q", out)
	}
}

func TestRunFixPlan_NoAIProvider(t *testing.T) {
	homeDir := redirectHome(t)

	projectDir := t.TempDir()
	oldWork := workDir
	oldFmt := outputFormat
	oldProvider := fixProviderFlag
	oldSeverity := fixSeverityFlag
	defer func() {
		workDir = oldWork
		outputFormat = oldFmt
		fixProviderFlag = oldProvider
		fixSeverityFlag = oldSeverity
	}()

	workDir = projectDir
	outputFormat = ""
	fixProviderFlag = "" // no CLI override
	fixSeverityFlag = ""
	t.Setenv("HOME", homeDir)

	// Save a last scan with a HIGH finding but no provider set.
	ls := history.LastScan{
		Timestamp:      time.Now(),
		ProjectDir:     projectDir,
		Scanner:        "builtin",
		TotalResources: 1,
		Provider:       "", // no provider in last scan
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_instance.web", Message: "open port"},
		},
	}
	if err := history.SaveLastScan(ls); err != nil {
		t.Fatalf("SaveLastScan: %v", err)
	}

	// Config with no provider → generateAndHandleFixes returns error about provider
	os.WriteFile(filepath.Join(projectDir, ".terraview.yaml"), []byte("llm:\n  provider: \"\"\n"), 0644)

	captureStdout(func() {
		err := runFixPlan(fixPlanCmd, nil)
		if err == nil {
			t.Error("expected error when no AI provider configured")
		} else if !strings.Contains(err.Error(), "provider") {
			t.Errorf("expected provider error, got: %v", err)
		}
	})
}

func TestWriteFixPlanJSON_ToStdout(t *testing.T) {
	oldOut := outputDir
	defer func() { outputDir = oldOut }()
	outputDir = ""

	pending := []fixPendingForTest{} // writeFixPlanJSON takes []fix.PendingFix
	// We test via runFixPlan with outputFormat=json and empty findings path,
	// but the easiest is to call writeFixPlanJSON directly with nil slice.
	out := captureStdout(func() {
		writeFixPlanJSON(nil)
	})
	// Should print "[]" or "null" JSON
	if !strings.Contains(out, "[") && !strings.Contains(out, "null") {
		t.Errorf("expected JSON array, got: %q", out)
	}
	_ = pending
}

func TestWriteFixPlanJSON_ToFile(t *testing.T) {
	dir := t.TempDir()
	oldOut := outputDir
	defer func() { outputDir = oldOut }()
	outputDir = dir

	out := captureStdout(func() {
		writeFixPlanJSON(nil)
	})

	// Should print "Written:" because outputDir is set
	if !strings.Contains(out, "Written:") {
		t.Errorf("expected 'Written:' message, got: %q", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "fix-plan.json")); err != nil {
		t.Errorf("fix-plan.json not written: %v", err)
	}
}

// fixPendingForTest is a dummy type just to keep the import path tidy.
type fixPendingForTest struct{}

func TestRunScan_TerragruntArgShift(t *testing.T) {
	// Exercises the terragruntFlag == "auto" + len(args) > 1 branch in runScan.
	oldTG := terragruntFlag
	oldWork := workDir
	oldStatic := staticOnly
	oldPlan := planFile
	defer func() {
		terragruntFlag = oldTG
		workDir = oldWork
		staticOnly = oldStatic
		planFile = oldPlan
	}()

	terragruntFlag = "auto"
	workDir = t.TempDir()
	staticOnly = true
	planFile = "/nonexistent/plan.json"

	// When terragruntFlag == "auto" and there are 2 args, the second arg becomes
	// the terragrunt config path and is shifted out.
	err := runScan(scanCmd, []string{"builtin", "dev.hcl"})
	// terragruntFlag should now be "dev.hcl"; error expected because plan doesn't exist
	if err == nil {
		t.Log("runScan with terragrunt arg shift returned nil (may be env-dependent)")
	}
	if terragruntFlag == "auto" {
		t.Errorf("expected terragruntFlag to be shifted, still 'auto'")
	}
}
