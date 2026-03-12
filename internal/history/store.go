package history

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	// DefaultDBName is the database filename inside ~/.terraview/.
	DefaultDBName = "history.db"

	createTableSQL = `
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    project_dir     TEXT NOT NULL,
    project_hash    TEXT NOT NULL,
    plan_hash       TEXT,
    scanner         TEXT NOT NULL,
    provider        TEXT,
    model           TEXT,
    score_security  REAL NOT NULL,
    score_compliance REAL NOT NULL,
    score_maintain  REAL NOT NULL,
    score_overall   REAL NOT NULL,
    count_critical  INTEGER NOT NULL DEFAULT 0,
    count_high      INTEGER NOT NULL DEFAULT 0,
    count_medium    INTEGER NOT NULL DEFAULT 0,
    count_low       INTEGER NOT NULL DEFAULT 0,
    count_info      INTEGER NOT NULL DEFAULT 0,
    duration_ms     INTEGER,
    static_only     BOOLEAN NOT NULL DEFAULT FALSE,
    metadata_json   TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_hash, timestamp);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
`

	insertSQL = `
INSERT INTO scans (
    timestamp, project_dir, project_hash, plan_hash, scanner, provider, model,
    score_security, score_compliance, score_maintain, score_overall,
    count_critical, count_high, count_medium, count_low, count_info,
    duration_ms, static_only, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

	listSQL = `
SELECT id, timestamp, project_dir, project_hash, plan_hash, scanner, provider, model,
       score_security, score_compliance, score_maintain, score_overall,
       count_critical, count_high, count_medium, count_low, count_info,
       duration_ms, static_only, metadata_json
FROM scans
`
)

// Store provides thread-safe access to the scan history SQLite database.
type Store struct {
	db   *sql.DB
	mu   sync.Mutex
	path string
}

// DefaultDBPath returns ~/.terraview/history.db.
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".terraview", DefaultDBName)
}

// NewStore opens or creates the history database at the given path.
func NewStore(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create history dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("open history db: %w", err)
	}

	// Set connection pool for single-writer
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(createTableSQL); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	return &Store{db: db, path: dbPath}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Path returns the database file path.
func (s *Store) Path() string {
	return s.path
}

// Insert adds a scan record to the database.
func (s *Store) Insert(rec ScanRecord) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := rec.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	result, err := s.db.Exec(insertSQL,
		ts.UTC().Format(time.RFC3339),
		rec.ProjectDir, rec.ProjectHash, rec.PlanHash,
		rec.Scanner, rec.Provider, rec.Model,
		rec.ScoreSecurity, rec.ScoreCompliance, rec.ScoreMaintain, rec.ScoreOverall,
		rec.CountCritical, rec.CountHigh, rec.CountMedium, rec.CountLow, rec.CountInfo,
		rec.DurationMs, rec.StaticOnly, rec.MetadataJSON,
	)
	if err != nil {
		return 0, fmt.Errorf("insert scan: %w", err)
	}
	return result.LastInsertId()
}

// ListFilter describes how to query stored scans.
type ListFilter struct {
	ProjectHash string
	Since       time.Time
	Limit       int
	Offset      int
}

// List returns scans matching the filter, ordered by timestamp descending.
func (s *Store) List(f ListFilter) ([]ScanRecord, error) {
	query := listSQL
	var args []interface{}
	var conditions []string

	if f.ProjectHash != "" {
		conditions = append(conditions, "project_hash = ?")
		args = append(args, f.ProjectHash)
	}
	if !f.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, f.Since.UTC().Format(time.RFC3339))
	}

	if len(conditions) > 0 {
		query += " WHERE "
		for i, c := range conditions {
			if i > 0 {
				query += " AND "
			}
			query += c
		}
	}

	query += " ORDER BY timestamp DESC"

	if f.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	if f.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", f.Offset)
	}

	return s.queryScans(query, args...)
}

// GetByID retrieves a single scan record by ID.
func (s *Store) GetByID(id int64) (*ScanRecord, error) {
	records, err := s.queryScans(listSQL+" WHERE id = ?", id)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("scan #%d not found", id)
	}
	return &records[0], nil
}

// GetLatest returns the most recent scan for a project.
func (s *Store) GetLatest(projectHash string) (*ScanRecord, error) {
	query := listSQL + " WHERE project_hash = ? ORDER BY timestamp DESC LIMIT 1"
	records, err := s.queryScans(query, projectHash)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no scans found for project")
	}
	return &records[0], nil
}

// GetPrevious returns the scan before the latest for a project.
func (s *Store) GetPrevious(projectHash string) (*ScanRecord, error) {
	query := listSQL + " WHERE project_hash = ? ORDER BY timestamp DESC LIMIT 1 OFFSET 1"
	records, err := s.queryScans(query, projectHash)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no previous scan found")
	}
	return &records[0], nil
}

// GetOldestSince returns the oldest scan for a project since the given time.
func (s *Store) GetOldestSince(projectHash string, since time.Time) (*ScanRecord, error) {
	query := listSQL + " WHERE project_hash = ? AND timestamp >= ? ORDER BY timestamp ASC LIMIT 1"
	records, err := s.queryScans(query, projectHash, since.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no scans found since %s", since.Format("2006-01-02"))
	}
	return &records[0], nil
}

// Count returns the total number of scan records.
func (s *Store) Count() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	return count, err
}

// CountByProject returns the number of scans for a specific project.
func (s *Store) CountByProject(projectHash string) (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans WHERE project_hash = ?", projectHash).Scan(&count)
	return count, err
}

// DeleteByProject removes all scans for a project.
func (s *Store) DeleteByProject(projectHash string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM scans WHERE project_hash = ?", projectHash)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DeleteAll removes all scan records.
func (s *Store) DeleteAll() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM scans")
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DeleteBefore removes scans older than the given time.
func (s *Store) DeleteBefore(before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM scans WHERE timestamp < ?", before.UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// DBSize returns the database file size in bytes.
func (s *Store) DBSize() (int64, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *Store) queryScans(query string, args ...interface{}) ([]ScanRecord, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query scans: %w", err)
	}
	defer rows.Close()

	var records []ScanRecord
	for rows.Next() {
		var r ScanRecord
		var ts string
		var planHash, provider, model, metaJSON sql.NullString
		var durationMs sql.NullInt64

		err := rows.Scan(
			&r.ID, &ts, &r.ProjectDir, &r.ProjectHash,
			&planHash, &r.Scanner, &provider, &model,
			&r.ScoreSecurity, &r.ScoreCompliance, &r.ScoreMaintain, &r.ScoreOverall,
			&r.CountCritical, &r.CountHigh, &r.CountMedium, &r.CountLow, &r.CountInfo,
			&durationMs, &r.StaticOnly, &metaJSON,
		)
		if err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		var parseErr error
		r.Timestamp, parseErr = time.Parse(time.RFC3339, ts)
		if parseErr != nil {
			return nil, fmt.Errorf("scan row: invalid timestamp %q: %w", ts, parseErr)
		}
		if planHash.Valid {
			r.PlanHash = planHash.String
		}
		if provider.Valid {
			r.Provider = provider.String
		}
		if model.Valid {
			r.Model = model.String
		}
		if durationMs.Valid {
			r.DurationMs = durationMs.Int64
		}
		if metaJSON.Valid {
			r.MetadataJSON = metaJSON.String
		}

		records = append(records, r)
	}

	return records, rows.Err()
}
