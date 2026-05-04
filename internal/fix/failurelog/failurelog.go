// Package failurelog tracks how often a given (project, rule, resource) tuple
// has failed to auto-fix across iterations. The Classifier consults this log
// to promote chronically-failing findings to advisories so the loop stops
// burning AI calls on remediations that consistently break.
//
// The log is stored as JSON at ~/.terraview/failure_history.json. Reads and
// writes are guarded by a process-level mutex; cross-process concurrency is
// not supported (and not needed — terraview fix is a single-user CLI).
package failurelog

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PromotionThreshold is the consecutive-failure count at which a finding is
// promoted to advisory by the Classifier.
const PromotionThreshold = 2

// Entry tracks failure state for a single (project, rule, resource) tuple.
type Entry struct {
	Count     int       `json:"count"`
	LastSeen  time.Time `json:"last_seen"`
	LastError string    `json:"last_error,omitempty"`
}

// Log is the persisted state. Map key is the composite key returned by Key().
type Log struct {
	Entries map[string]Entry `json:"entries"`
}

var (
	mu         sync.Mutex
	pathOnce   sync.Once
	cachedPath string
)

// Key produces the composite key used to index entries.
func Key(projectDir, ruleID, resource string) string {
	return projectDir + "::" + ruleID + "::" + resource
}

// Path returns the resolved path to the failure history file. It is created
// lazily — callers do not need to ensure the parent directory exists.
func Path() string {
	pathOnce.Do(func() {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			cachedPath = ".terraview-failure-history.json"
			return
		}
		cachedPath = filepath.Join(home, ".terraview", "failure_history.json")
	})
	return cachedPath
}

// Load reads the log from disk. A missing file returns an empty log without
// error so callers can treat first-run as "no failures yet".
func Load() (*Log, error) {
	mu.Lock()
	defer mu.Unlock()
	return loadLocked()
}

func loadLocked() (*Log, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &Log{Entries: map[string]Entry{}}, nil
		}
		return nil, fmt.Errorf("read failure log: %w", err)
	}
	l := &Log{}
	if err := json.Unmarshal(data, l); err != nil {
		// Corrupted log — start fresh rather than blocking the user.
		return &Log{Entries: map[string]Entry{}}, nil
	}
	if l.Entries == nil {
		l.Entries = map[string]Entry{}
	}
	return l, nil
}

func saveLocked(l *Log) error {
	if err := os.MkdirAll(filepath.Dir(Path()), 0o755); err != nil {
		return fmt.Errorf("create failure log dir: %w", err)
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal failure log: %w", err)
	}
	if err := os.WriteFile(Path(), data, 0o644); err != nil {
		return fmt.Errorf("write failure log: %w", err)
	}
	return nil
}

// RecordFailure increments the counter for the given key. The reason is
// stored as LastError so the user can inspect it later.
func RecordFailure(key, reason string) {
	mu.Lock()
	defer mu.Unlock()
	l, err := loadLocked()
	if err != nil {
		return
	}
	e := l.Entries[key]
	e.Count++
	e.LastSeen = time.Now().UTC()
	if reason != "" {
		e.LastError = reason
	}
	l.Entries[key] = e
	_ = saveLocked(l)
}

// RecordSuccess clears the counter for the given key — a successful apply
// resets the failure budget so a stable rule does not stay marked forever.
func RecordSuccess(key string) {
	mu.Lock()
	defer mu.Unlock()
	l, err := loadLocked()
	if err != nil {
		return
	}
	if _, ok := l.Entries[key]; !ok {
		return
	}
	delete(l.Entries, key)
	_ = saveLocked(l)
}

// Count returns the current failure count for the key, 0 when unknown.
func Count(key string) int {
	l, err := Load()
	if err != nil || l == nil {
		return 0
	}
	return l.Entries[key].Count
}

// LastError returns the last recorded reason for the key, "" when unknown.
func LastError(key string) string {
	l, err := Load()
	if err != nil || l == nil {
		return ""
	}
	return l.Entries[key].LastError
}

// SetPathForTest overrides the resolved path. Test-only — not safe in
// production because pathOnce is bypassed.
func SetPathForTest(p string) {
	mu.Lock()
	defer mu.Unlock()
	cachedPath = p
	pathOnce.Do(func() {}) // mark consumed so Path() returns cachedPath
}
