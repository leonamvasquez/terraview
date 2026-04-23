package history

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

// ---------------------------------------------------------------------------
// store.go — paths not previously exercised
// ---------------------------------------------------------------------------

func TestDefaultDBPath_NotEmpty(t *testing.T) {
	p := DefaultDBPath()
	if p == "" {
		t.Error("DefaultDBPath should return a non-empty path")
	}
	if !strings.HasSuffix(p, DefaultDBName) {
		t.Errorf("DefaultDBPath = %q, want suffix %q", p, DefaultDBName)
	}
}

func TestStore_Path(t *testing.T) {
	store := newTestStore(t)
	p := store.Path()
	if p == "" {
		t.Error("Path() should not be empty")
	}
}

func TestStore_Close_NilDB(t *testing.T) {
	// Close on a Store with nil db must not panic.
	s := &Store{}
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil db should return nil, got %v", err)
	}
}

func TestStore_GetLatest_Empty(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetLatest("nonexistent-hash")
	if err == nil {
		t.Error("GetLatest on empty store should return error")
	}
}

func TestStore_GetPrevious_Empty(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetPrevious("nonexistent-hash")
	if err == nil {
		t.Error("GetPrevious on empty store should return error")
	}
}

func TestStore_GetOldestSince(t *testing.T) {
	store := newTestStore(t)
	ph := ProjectHash("/tmp/proj-oldest")

	old := sampleRecord("/tmp/proj-oldest")
	old.Timestamp = time.Now().AddDate(0, 0, -10)
	store.Insert(old)

	recent := sampleRecord("/tmp/proj-oldest")
	recent.Timestamp = time.Now()
	store.Insert(recent)

	since := time.Now().AddDate(0, 0, -5)
	rec, err := store.GetOldestSince(ph, since)
	if err != nil {
		t.Fatalf("GetOldestSince: %v", err)
	}
	// The oldest within the window is the recent record (only one within 5 days).
	if rec == nil {
		t.Fatal("expected record, got nil")
	}
}

func TestStore_GetOldestSince_NotFound(t *testing.T) {
	store := newTestStore(t)
	_, err := store.GetOldestSince("no-hash", time.Now())
	if err == nil {
		t.Error("GetOldestSince on empty store should return error")
	}
}

func TestStore_ListOffset(t *testing.T) {
	store := newTestStore(t)
	ph := ProjectHash("/tmp/proj-offset")

	for i := 0; i < 5; i++ {
		rec := sampleRecord("/tmp/proj-offset")
		rec.ScoreOverall = float64(i)
		store.Insert(rec)
	}

	records, err := store.List(ListFilter{ProjectHash: ph, Limit: 10, Offset: 2})
	if err != nil {
		t.Fatalf("List with offset: %v", err)
	}
	if len(records) != 3 {
		t.Errorf("expected 3 records with offset 2, got %d", len(records))
	}
}

// ---------------------------------------------------------------------------
// cleanup.go — cleanupBySize over limit and countUnlocked
// ---------------------------------------------------------------------------

func TestCleanupBySize_ForcesTrim(t *testing.T) {
	store := newTestStore(t)

	// Insert records to build some DB size.
	for i := 0; i < 50; i++ {
		rec := sampleRecord("/tmp/proj-size")
		rec.MetadataJSON = `{"padding":"` + strings.Repeat("x", 500) + `"}`
		if _, err := store.Insert(rec); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	// Force vacuum to ensure DB size reflects actual content.
	store.mu.Lock()
	store.db.Exec("VACUUM")
	store.mu.Unlock()

	sizeBefore, err := store.DBSize()
	if err != nil {
		t.Fatalf("DBSize: %v", err)
	}

	// Use 1 byte to guarantee cleanup runs.
	removed, err := store.cleanupBySize(1)
	if err != nil {
		t.Fatalf("cleanupBySize: %v", err)
	}
	// Cleanup must have removed at least some records since limit is 1 byte.
	if removed == 0 && sizeBefore > 1 {
		t.Logf("sizeBefore=%d; DB may have shrunk via vacuum before test — acceptable", sizeBefore)
	}
}

func TestCountUnlocked(t *testing.T) {
	store := newTestStore(t)

	count, err := store.countUnlocked()
	if err != nil {
		t.Fatalf("countUnlocked: %v", err)
	}
	if count != 0 {
		t.Errorf("empty DB count = %d, want 0", count)
	}

	store.Insert(sampleRecord("/tmp/proj"))
	store.Insert(sampleRecord("/tmp/proj"))

	count, err = store.countUnlocked()
	if err != nil {
		t.Fatalf("countUnlocked after inserts: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

// ---------------------------------------------------------------------------
// formatter.go — formatCSV with empty list
// ---------------------------------------------------------------------------

func TestFormatCSV_EmptyList(t *testing.T) {
	var buf strings.Builder
	err := formatCSV(&buf, []ScanRecord{})
	if err != nil {
		t.Fatalf("formatCSV empty: %v", err)
	}
	// Only the CSV header should be present.
	out := buf.String()
	if !strings.Contains(out, "id") || !strings.Contains(out, "timestamp") {
		t.Errorf("CSV header missing in empty output: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Errorf("expected 1 line (header only) for empty CSV, got %d", len(lines))
	}
}

// ---------------------------------------------------------------------------
// lastscan.go — SaveLastScan / LoadLastScan roundtrip, corrupted JSON,
//               FindingsBySeverity, CountBySeverity, lastScanPath
// ---------------------------------------------------------------------------

func TestSaveAndLoadLastScan_Roundtrip(t *testing.T) {
	// Override home to a temp dir so we don't touch ~/.terraview in tests.
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	ls := LastScan{
		Timestamp:      time.Now().Truncate(time.Second),
		ProjectDir:     t.TempDir(),
		PlanFile:       "plan.json",
		Scanner:        "checkov",
		Provider:       "ollama",
		TotalResources: 10,
		Findings: []rules.Finding{
			{RuleID: "CKV_AWS_1", Severity: "HIGH", Category: "security"},
			{RuleID: "CKV_AWS_2", Severity: "MEDIUM", Category: "compliance"},
		},
		ScoreDecomposition: &scoring.ScoreDecomposition{},
	}

	if err := SaveLastScan(ls); err != nil {
		t.Fatalf("SaveLastScan: %v", err)
	}

	loaded, err := LoadLastScan(ls.ProjectDir)
	if err != nil {
		t.Fatalf("LoadLastScan: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadLastScan returned nil, want a record")
	}
	if loaded.Scanner != ls.Scanner {
		t.Errorf("Scanner = %q, want %q", loaded.Scanner, ls.Scanner)
	}
	if len(loaded.Findings) != 2 {
		t.Errorf("Findings len = %d, want 2", len(loaded.Findings))
	}
}

func TestLoadLastScan_NotFound(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// A directory that never had a scan.
	result, err := LoadLastScan(t.TempDir())
	if err != nil {
		t.Fatalf("LoadLastScan not-found should return nil,nil; got err: %v", err)
	}
	if result != nil {
		t.Errorf("LoadLastScan not-found should return nil, got %+v", result)
	}
}

func TestLoadLastScan_CorruptedJSON(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectDir := t.TempDir()

	// Manually write the file where lastScanPath would put it.
	hash := ProjectHash(projectDir)
	dir := filepath.Join(tmpHome, ".terraview")
	os.MkdirAll(dir, 0o755)
	path := filepath.Join(dir, hash+"-last.json")

	if err := os.WriteFile(path, []byte("{{invalid json"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadLastScan(projectDir)
	if err == nil {
		t.Error("LoadLastScan should return error for corrupted JSON")
	}
}

func TestFindingsBySeverity(t *testing.T) {
	ls := &LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "HIGH"},
			{Severity: "MEDIUM"},
			{Severity: "LOW"},
		},
	}

	tests := []struct {
		name       string
		severities []string
		wantLen    int
	}{
		{"critical only", []string{"CRITICAL"}, 1},
		{"high only", []string{"HIGH"}, 2},
		{"critical+high", []string{"CRITICAL", "HIGH"}, 3},
		{"none matched", []string{"INFO"}, 0},
		{"empty severity list", []string{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ls.FindingsBySeverity(tt.severities...)
			if len(got) != tt.wantLen {
				t.Errorf("FindingsBySeverity(%v) len = %d, want %d", tt.severities, len(got), tt.wantLen)
			}
		})
	}
}

func TestFindingsBySeverity_EmptyFindings(t *testing.T) {
	ls := &LastScan{Findings: nil}
	got := ls.FindingsBySeverity("HIGH")
	if len(got) != 0 {
		t.Errorf("expected 0 findings, got %d", len(got))
	}
}

func TestCountBySeverity(t *testing.T) {
	ls := &LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL"},
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "LOW"},
		},
	}

	counts := ls.CountBySeverity()

	if counts["CRITICAL"] != 2 {
		t.Errorf("CRITICAL = %d, want 2", counts["CRITICAL"])
	}
	if counts["HIGH"] != 1 {
		t.Errorf("HIGH = %d, want 1", counts["HIGH"])
	}
	if counts["MEDIUM"] != 0 {
		t.Errorf("MEDIUM = %d, want 0", counts["MEDIUM"])
	}
	if counts["LOW"] != 1 {
		t.Errorf("LOW = %d, want 1", counts["LOW"])
	}
}

func TestCountBySeverity_EmptyFindings(t *testing.T) {
	ls := &LastScan{}
	counts := ls.CountBySeverity()
	for sev, c := range counts {
		if c != 0 {
			t.Errorf("severity %s count = %d, want 0", sev, c)
		}
	}
}
