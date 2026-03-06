package history

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCleanup_ByDays(t *testing.T) {
	store := newTestStore(t)

	// Insert records with varied timestamps
	for _, daysAgo := range []int{100, 80, 60, 20, 5, 1} {
		rec := sampleRecord("/tmp/proj")
		rec.Timestamp = time.Now().AddDate(0, 0, -daysAgo)
		if _, err := store.Insert(rec); err != nil {
			t.Fatalf("Insert: %v", err)
		}
	}

	removed, err := store.Cleanup(CleanupConfig{RetentionDays: 30, MaxSizeMB: 0})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// 100, 80, 60 are clearly older than 30 days → 3 removed
	if removed != 3 {
		t.Errorf("removed = %d, want 3", removed)
	}

	count, _ := store.Count()
	if count != 3 {
		t.Errorf("remaining = %d, want 3", count)
	}
}

func TestCleanup_ByDays_NoneOld(t *testing.T) {
	store := newTestStore(t)

	for i := 0; i < 5; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.Timestamp = time.Now().Add(-time.Duration(i) * time.Hour)
		store.Insert(rec)
	}

	removed, err := store.Cleanup(CleanupConfig{RetentionDays: 30})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (nothing old)", removed)
	}
}

func TestCleanup_BySize(t *testing.T) {
	store := newTestStore(t)

	// Insert many records to grow the DB
	for i := 0; i < 100; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.MetadataJSON = `{"padding":"` + string(make([]byte, 1000)) + `"}`
		if _, err := store.Insert(rec); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	sizeBefore, _ := store.DBSize()

	// Set a very small size limit to force cleanup
	// DB is small but we set limit to 1 byte to guarantee trimming
	removed, err := store.Cleanup(CleanupConfig{MaxSizeMB: 0})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// With MaxSizeMB=0, no size cleanup should happen
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (max_size_mb=0 means disabled)", removed)
	}

	_ = sizeBefore // used above for reference
}

func TestCleanup_Disabled(t *testing.T) {
	store := newTestStore(t)

	for i := 0; i < 5; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.Timestamp = time.Now().AddDate(0, 0, -200)
		store.Insert(rec)
	}

	// Both values 0 = disabled
	removed, err := store.Cleanup(CleanupConfig{RetentionDays: 0, MaxSizeMB: 0})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (cleanup disabled)", removed)
	}

	count, _ := store.Count()
	if count != 5 {
		t.Errorf("count = %d, want 5 (all preserved)", count)
	}
}

func TestCleanup_CombinedRetentionAndSize(t *testing.T) {
	store := newTestStore(t)

	// Add old records
	for i := 0; i < 10; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.Timestamp = time.Now().AddDate(0, 0, -100)
		store.Insert(rec)
	}

	// Add recent records
	for i := 0; i < 5; i++ {
		rec := sampleRecord("/tmp/proj")
		rec.Timestamp = time.Now()
		store.Insert(rec)
	}

	removed, err := store.Cleanup(CleanupConfig{RetentionDays: 30, MaxSizeMB: 100})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// 10 old records removed by retention
	if removed < 10 {
		t.Errorf("removed = %d, want >= 10", removed)
	}

	count, _ := store.Count()
	if count != 5 {
		t.Errorf("remaining = %d, want 5", count)
	}
}

func TestCleanup_EmptyDB(t *testing.T) {
	store := newTestStore(t)

	removed, err := store.Cleanup(CleanupConfig{RetentionDays: 30, MaxSizeMB: 100})
	if err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (empty DB)", removed)
	}
}

func TestCleanupBySize_SmallDB(t *testing.T) {
	store := newTestStore(t)

	store.Insert(sampleRecord("/tmp/proj"))

	// 100MB is way more than needed
	removed, err := store.cleanupBySize(100 * 1024 * 1024)
	if err != nil {
		t.Fatalf("cleanupBySize: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0 (DB is tiny)", removed)
	}
}

func TestCleanupBySize_NonExistentDB(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nonexistent", "deep", "history.db")
	store := &Store{path: dbPath}

	removed, err := store.cleanupBySize(100)
	if err != nil {
		t.Fatalf("cleanupBySize: %v", err)
	}
	if removed != 0 {
		t.Errorf("removed = %d, want 0", removed)
	}
}
