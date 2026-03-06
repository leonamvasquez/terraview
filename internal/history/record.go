package history

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ScanRecord represents a single scan stored in the history database.
type ScanRecord struct {
	ID              int64     `json:"id"`
	Timestamp       time.Time `json:"timestamp"`
	ProjectDir      string    `json:"project_dir"`
	ProjectHash     string    `json:"project_hash"`
	PlanHash        string    `json:"plan_hash,omitempty"`
	Scanner         string    `json:"scanner"`
	Provider        string    `json:"provider,omitempty"`
	Model           string    `json:"model,omitempty"`
	ScoreSecurity   float64   `json:"score_security"`
	ScoreCompliance float64   `json:"score_compliance"`
	ScoreMaintain   float64   `json:"score_maintain"`
	ScoreOverall    float64   `json:"score_overall"`
	CountCritical   int       `json:"count_critical"`
	CountHigh       int       `json:"count_high"`
	CountMedium     int       `json:"count_medium"`
	CountLow        int       `json:"count_low"`
	CountInfo       int       `json:"count_info"`
	DurationMs      int64     `json:"duration_ms,omitempty"`
	StaticOnly      bool      `json:"static_only"`
	MetadataJSON    string    `json:"metadata_json,omitempty"`
}

// ScanMetadata holds extra metadata serialized as JSON.
type ScanMetadata struct {
	TotalResources int    `json:"total_resources,omitempty"`
	Verdict        string `json:"verdict,omitempty"`
	MaxSeverity    string `json:"max_severity,omitempty"`
	ExitCode       int    `json:"exit_code,omitempty"`
}

// ProjectHash computes a stable hash from the absolute project directory.
func ProjectHash(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	h := sha256.Sum256([]byte(abs))
	return fmt.Sprintf("%x", h[:8])
}

// PlanHash computes a hash of the plan content.
func PlanHash(content []byte) string {
	if len(content) == 0 {
		return ""
	}
	h := sha256.Sum256(content)
	return fmt.Sprintf("%x", h[:8])
}

// NewRecordFromResult creates a ScanRecord from a ReviewResult and scan context.
func NewRecordFromResult(
	result aggregator.ReviewResult,
	projectDir, scannerName, provider, model string,
	durationMs int64, staticOnly bool,
) ScanRecord {
	severityCounts := countSeverities(result.Findings)

	meta := ScanMetadata{
		TotalResources: result.TotalResources,
		Verdict:        result.Verdict.Label,
		MaxSeverity:    result.MaxSeverity,
		ExitCode:       result.ExitCode,
	}
	metaJSON, _ := json.Marshal(meta)

	return ScanRecord{
		Timestamp:       time.Now(),
		ProjectDir:      projectDir,
		ProjectHash:     ProjectHash(projectDir),
		Scanner:         scannerName,
		Provider:        provider,
		Model:           model,
		ScoreSecurity:   result.Score.SecurityScore,
		ScoreCompliance: result.Score.ComplianceScore,
		ScoreMaintain:   result.Score.MaintainabilityScore,
		ScoreOverall:    result.Score.OverallScore,
		CountCritical:   severityCounts["CRITICAL"],
		CountHigh:       severityCounts["HIGH"],
		CountMedium:     severityCounts["MEDIUM"],
		CountLow:        severityCounts["LOW"],
		CountInfo:       severityCounts["INFO"],
		DurationMs:      durationMs,
		StaticOnly:      staticOnly,
		MetadataJSON:    string(metaJSON),
	}
}

// countSeverities counts findings by severity.
func countSeverities(findings []rules.Finding) map[string]int {
	counts := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// TotalFindings returns the total finding count.
func (r ScanRecord) TotalFindings() int {
	return r.CountCritical + r.CountHigh + r.CountMedium + r.CountLow + r.CountInfo
}

// FindingsSummary returns a short string like "0C 2H 5M 4L".
func (r ScanRecord) FindingsSummary() string {
	return fmt.Sprintf("%dC %dH %dM %dL", r.CountCritical, r.CountHigh, r.CountMedium, r.CountLow)
}
