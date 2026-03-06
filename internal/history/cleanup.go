package history

import (
	"fmt"
	"os"
	"time"
)

// CleanupConfig holds cleanup parameters.
type CleanupConfig struct {
	RetentionDays int
	MaxSizeMB     int
}

// Cleanup removes old records and enforces size limits.
func (s *Store) Cleanup(cfg CleanupConfig) (int64, error) {
	var totalRemoved int64

	// 1. Remove records older than retention period
	if cfg.RetentionDays > 0 {
		cutoff := time.Now().AddDate(0, 0, -cfg.RetentionDays)
		removed, err := s.DeleteBefore(cutoff)
		if err != nil {
			return totalRemoved, fmt.Errorf("retention cleanup: %w", err)
		}
		totalRemoved += removed
	}

	// 2. Enforce max size by removing oldest records
	if cfg.MaxSizeMB > 0 {
		removed, err := s.cleanupBySize(int64(cfg.MaxSizeMB) * 1024 * 1024)
		if err != nil {
			return totalRemoved, fmt.Errorf("size cleanup: %w", err)
		}
		totalRemoved += removed
	}

	// 3. Vacuum if records were removed
	if totalRemoved > 0 {
		s.mu.Lock()
		_, _ = s.db.Exec("VACUUM")
		s.mu.Unlock()
	}

	return totalRemoved, nil
}

// cleanupBySize removes the oldest records until the DB is under maxBytes.
func (s *Store) cleanupBySize(maxBytes int64) (int64, error) {
	size, err := s.DBSize()
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}

	if size <= maxBytes {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete oldest 10% at a time until under limit
	var totalRemoved int64
	for size > maxBytes {
		count, err := s.countUnlocked()
		if err != nil || count == 0 {
			break
		}
		batch := count / 10
		if batch < 1 {
			batch = 1
		}
		result, err := s.db.Exec(
			"DELETE FROM scans WHERE id IN (SELECT id FROM scans ORDER BY timestamp ASC LIMIT ?)",
			batch,
		)
		if err != nil {
			return totalRemoved, err
		}
		affected, _ := result.RowsAffected()
		totalRemoved += affected

		if affected == 0 {
			break
		}

		// Re-check size
		size, err = s.DBSize()
		if err != nil {
			break
		}
	}

	return totalRemoved, nil
}

func (s *Store) countUnlocked() (int64, error) {
	var count int64
	err := s.db.QueryRow("SELECT COUNT(*) FROM scans").Scan(&count)
	return count, err
}
