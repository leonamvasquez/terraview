package history

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func sampleRecord(projectDir string) ScanRecord {
	return ScanRecord{
		Timestamp:       time.Now(),
		ProjectDir:      projectDir,
		ProjectHash:     ProjectHash(projectDir),
		Scanner:         "checkov",
		Provider:        "ollama",
		Model:           "llama3.1",
		ScoreSecurity:   7.5,
		ScoreCompliance: 8.0,
		ScoreMaintain:   9.0,
		ScoreOverall:    8.2,
		CountCritical:   0,
		CountHigh:       2,
		CountMedium:     5,
		CountLow:        4,
		CountInfo:       1,
		DurationMs:      1500,
		StaticOnly:      false,
		MetadataJSON:    `{"total_resources":5}`,
	}
}

func TestStore_CreateAndClose(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("DB file should exist after creation")
	}

	if err := store.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestStore_InsertAndRetrieve(t *testing.T) {
	store := newTestStore(t)
	rec := sampleRecord("/tmp/proj")

	id, err := store.Insert(rec)
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if id < 1 {
		t.Errorf("expected positive ID, got %d", id)
	}

	records, err := store.List(ListFilter{ProjectHash: rec.ProjectHash})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}

	r := records[0]
	if r.ID != id {
		t.Errorf("ID = %d, want %d", r.ID, id)
	}
	if r.ScoreOverall != 8.2 {
		t.Errorf("ScoreOverall = %.1f, want 8.2", r.ScoreOverall)
	}
	if r.Scanner != "checkov" {
		t.Errorf("Scanner = %q, want %q", r.Scanner, "checkov")
	}
	if r.CountHigh != 2 {
		t.Errorf("CountHigh = %d, want 2", r.CountHigh)
	}
}

func TestStore_ListWithLimit(t *testing.T) {
	store := newTestStore(t)

	for i := 0; i < 10; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.ScoreOverall = float64(i)
		if _, err := store.Insert(rec); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	records, err := store.List(ListFilter{ProjectHash: ProjectHash("/tmp/proj"), Limit: 5})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 5 {
		t.Errorf("expected 5 records, got %d", len(records))
	}
}

func TestStore_ListFilterBySince(t *testing.T) {
	store := newTestStore(t)

	// Insert old record
	old := sampleRecord("/tmp/proj")
	old.Timestamp = time.Now().AddDate(0, 0, -30)
	if _, err := store.Insert(old); err != nil {
		t.Fatalf("Insert old: %v", err)
	}

	// Insert recent record
	recent := sampleRecord("/tmp/proj")
	recent.Timestamp = time.Now()
	if _, err := store.Insert(recent); err != nil {
		t.Fatalf("Insert recent: %v", err)
	}

	// Filter since 7 days ago
	since := time.Now().AddDate(0, 0, -7)
	records, err := store.List(ListFilter{
		ProjectHash: ProjectHash("/tmp/proj"),
		Since:       since,
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 1 {
		t.Errorf("expected 1 recent record, got %d", len(records))
	}
}

func TestStore_ListFilterByProject(t *testing.T) {
	store := newTestStore(t)

	// Insert records for different projects
	for _, dir := range []string{"/tmp/proj-a", "/tmp/proj-b", "/tmp/proj-a"} {
		if _, err := store.Insert(sampleRecord(dir)); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	records, err := store.List(ListFilter{ProjectHash: ProjectHash("/tmp/proj-a")})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(records) != 2 {
		t.Errorf("expected 2 records for proj-a, got %d", len(records))
	}
}

func TestStore_GetByID(t *testing.T) {
	store := newTestStore(t)

	id, err := store.Insert(sampleRecord("/tmp/proj"))
	if err != nil {
		t.Fatalf("Insert: %v", err)
	}

	rec, err := store.GetByID(id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if rec.ID != id {
		t.Errorf("ID = %d, want %d", rec.ID, id)
	}
}

func TestStore_GetByID_NotFound(t *testing.T) {
	store := newTestStore(t)

	_, err := store.GetByID(999)
	if err == nil {
		t.Error("expected error for non-existent ID")
	}
}

func TestStore_GetLatestAndPrevious(t *testing.T) {
	store := newTestStore(t)
	ph := ProjectHash("/tmp/proj")

	rec1 := sampleRecord("/tmp/proj")
	rec1.Timestamp = time.Now().Add(-2 * time.Hour)
	rec1.ScoreOverall = 6.0
	store.Insert(rec1)

	rec2 := sampleRecord("/tmp/proj")
	rec2.Timestamp = time.Now().Add(-1 * time.Hour)
	rec2.ScoreOverall = 7.0
	store.Insert(rec2)

	rec3 := sampleRecord("/tmp/proj")
	rec3.Timestamp = time.Now()
	rec3.ScoreOverall = 8.0
	store.Insert(rec3)

	latest, err := store.GetLatest(ph)
	if err != nil {
		t.Fatalf("GetLatest: %v", err)
	}
	if latest.ScoreOverall != 8.0 {
		t.Errorf("latest.ScoreOverall = %.1f, want 8.0", latest.ScoreOverall)
	}

	prev, err := store.GetPrevious(ph)
	if err != nil {
		t.Fatalf("GetPrevious: %v", err)
	}
	if prev.ScoreOverall != 7.0 {
		t.Errorf("previous.ScoreOverall = %.1f, want 7.0", prev.ScoreOverall)
	}
}

func TestStore_DeleteByProject(t *testing.T) {
	store := newTestStore(t)

	store.Insert(sampleRecord("/tmp/proj-a"))
	store.Insert(sampleRecord("/tmp/proj-a"))
	store.Insert(sampleRecord("/tmp/proj-b"))

	removed, err := store.DeleteByProject(ProjectHash("/tmp/proj-a"))
	if err != nil {
		t.Fatalf("DeleteByProject: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	// proj-b should still exist
	count, _ := store.Count()
	if count != 1 {
		t.Errorf("remaining = %d, want 1", count)
	}
}

func TestStore_DeleteAll(t *testing.T) {
	store := newTestStore(t)

	store.Insert(sampleRecord("/tmp/proj-a"))
	store.Insert(sampleRecord("/tmp/proj-b"))

	removed, err := store.DeleteAll()
	if err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}

	count, _ := store.Count()
	if count != 0 {
		t.Errorf("remaining = %d, want 0", count)
	}
}

func TestStore_DeleteBefore(t *testing.T) {
	store := newTestStore(t)

	old := sampleRecord("/tmp/proj")
	old.Timestamp = time.Now().AddDate(0, 0, -60)
	store.Insert(old)

	recent := sampleRecord("/tmp/proj")
	recent.Timestamp = time.Now()
	store.Insert(recent)

	cutoff := time.Now().AddDate(0, 0, -30)
	removed, err := store.DeleteBefore(cutoff)
	if err != nil {
		t.Fatalf("DeleteBefore: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}

	count, _ := store.Count()
	if count != 1 {
		t.Errorf("remaining = %d, want 1", count)
	}
}

func TestStore_ConcurrentWrites(t *testing.T) {
	store := newTestStore(t)

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			rec := sampleRecord("/tmp/proj")
			rec.ScoreOverall = float64(n)
			if _, err := store.Insert(rec); err != nil {
				errs <- err
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent insert error: %v", err)
	}

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 20 {
		t.Errorf("count = %d, want 20", count)
	}
}

func TestStore_FirstRun_NewDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "subdir", "deep", "history.db")

	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore on new path: %v", err)
	}
	defer store.Close()

	// Should be able to insert immediately
	_, err = store.Insert(sampleRecord("/tmp/proj"))
	if err != nil {
		t.Fatalf("Insert on new DB: %v", err)
	}
}

func TestStore_ExistingDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.db")

	// First open
	store1, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore 1: %v", err)
	}
	store1.Insert(sampleRecord("/tmp/proj"))
	store1.Close()

	// Second open
	store2, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore 2: %v", err)
	}
	defer store2.Close()

	count, _ := store2.Count()
	if count != 1 {
		t.Errorf("count after reopen = %d, want 1", count)
	}
}

func TestStore_CorruptedDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "corrupt.db")

	// Write garbage
	os.WriteFile(dbPath, []byte("this is not sqlite"), 0644)

	_, err := NewStore(dbPath)
	if err == nil {
		t.Error("expected error for corrupted DB")
	}
}

func TestStore_Count(t *testing.T) {
	store := newTestStore(t)

	count, err := store.Count()
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if count != 0 {
		t.Errorf("empty DB count = %d, want 0", count)
	}

	store.Insert(sampleRecord("/tmp/proj"))
	count, _ = store.Count()
	if count != 1 {
		t.Errorf("after insert count = %d, want 1", count)
	}
}

func TestStore_CountByProject(t *testing.T) {
	store := newTestStore(t)

	store.Insert(sampleRecord("/tmp/proj-a"))
	store.Insert(sampleRecord("/tmp/proj-a"))
	store.Insert(sampleRecord("/tmp/proj-b"))

	count, err := store.CountByProject(ProjectHash("/tmp/proj-a"))
	if err != nil {
		t.Fatalf("CountByProject: %v", err)
	}
	if count != 2 {
		t.Errorf("count for proj-a = %d, want 2", count)
	}
}

func TestStore_DBSize(t *testing.T) {
	store := newTestStore(t)

	store.Insert(sampleRecord("/tmp/proj"))

	size, err := store.DBSize()
	if err != nil {
		t.Fatalf("DBSize: %v", err)
	}
	if size == 0 {
		t.Error("expected non-zero DB size")
	}
}
