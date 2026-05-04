package failurelog

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var osWriteFile = func(p string, data []byte) error {
	return os.WriteFile(p, data, 0o644)
}

func TestRecordFailure_IncrementsAndPersists(t *testing.T) {
	dir := t.TempDir()
	SetPathForTest(filepath.Join(dir, "failure.json"))

	key := Key("/proj", "CKV_AWS_19", "aws_s3_bucket.foo")
	RecordFailure(key, "patch did not apply")
	RecordFailure(key, "still no luck")

	if got := Count(key); got != 2 {
		t.Errorf("Count=%d, want 2", got)
	}
	if got := LastError(key); got != "still no luck" {
		t.Errorf("LastError=%q, want last reason", got)
	}
}

func TestRecordSuccess_Clears(t *testing.T) {
	dir := t.TempDir()
	SetPathForTest(filepath.Join(dir, "failure.json"))

	key := Key("/proj", "CKV_AWS_19", "aws_s3_bucket.foo")
	RecordFailure(key, "x")
	RecordFailure(key, "y")
	RecordSuccess(key)

	if got := Count(key); got != 0 {
		t.Errorf("Count after success=%d, want 0", got)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	dir := t.TempDir()
	SetPathForTest(filepath.Join(dir, "does-not-exist.json"))

	l, err := Load()
	if err != nil {
		t.Fatalf("Load missing file: %v", err)
	}
	if len(l.Entries) != 0 {
		t.Errorf("expected empty log, got %d entries", len(l.Entries))
	}
}

func TestPromotionThreshold(t *testing.T) {
	if PromotionThreshold < 2 {
		t.Errorf("PromotionThreshold=%d should be >= 2 (one transient failure must not promote)", PromotionThreshold)
	}
}

func TestLoad_CorruptedFile_StartsFresh(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "failure.json")
	SetPathForTest(p)

	// Write garbage
	if err := writeFile(p, []byte("not json")); err != nil {
		t.Fatal(err)
	}
	l, err := Load()
	if err != nil {
		t.Fatalf("Load corrupted: %v", err)
	}
	if len(l.Entries) != 0 {
		t.Error("expected empty log on corruption")
	}
}

func writeFile(p string, data []byte) error {
	return osWriteFile(p, data)
}

func TestLoad_DropsExpiredEntries(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "failure.json")
	SetPathForTest(p)

	stale := time.Now().UTC().Add(-2 * EntryTTL)
	fresh := time.Now().UTC().Add(-1 * time.Hour)
	seed := `{"entries":{"old":{"count":3,"last_seen":"` + stale.Format(time.RFC3339Nano) + `"},"new":{"count":1,"last_seen":"` + fresh.Format(time.RFC3339Nano) + `"}}}`
	if err := writeFile(p, []byte(seed)); err != nil {
		t.Fatal(err)
	}

	l, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := l.Entries["old"]; ok {
		t.Error("expected stale entry to be dropped on Load")
	}
	if _, ok := l.Entries["new"]; !ok {
		t.Error("expected fresh entry to be retained")
	}
}

func TestSave_AtomicWrite_NoTempLeak(t *testing.T) {
	dir := t.TempDir()
	SetPathForTest(filepath.Join(dir, "failure.json"))

	RecordFailure(Key("/p", "R", "r1"), "boom")

	matches, err := filepath.Glob(filepath.Join(dir, ".failure_history-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no temp files left behind, got %d: %v", len(matches), matches)
	}
}
