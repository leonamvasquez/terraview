package history

import (
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
)

func TestProjectHash_SameDir(t *testing.T) {
	h1 := ProjectHash("/tmp/my-project")
	h2 := ProjectHash("/tmp/my-project")

	if h1 != h2 {
		t.Errorf("same dir should produce same hash: %q != %q", h1, h2)
	}
}

func TestProjectHash_DifferentDir(t *testing.T) {
	h1 := ProjectHash("/tmp/project-a")
	h2 := ProjectHash("/tmp/project-b")

	if h1 == h2 {
		t.Error("different dirs should produce different hashes")
	}
}

func TestProjectHash_RelativeVsAbsolute(t *testing.T) {
	// Abs of "." should equal the actual working dir
	abs, _ := filepath.Abs(".")
	h1 := ProjectHash(".")
	h2 := ProjectHash(abs)

	if h1 != h2 {
		t.Errorf("relative and absolute paths should produce same hash: %q != %q", h1, h2)
	}
}

func TestProjectHash_Length(t *testing.T) {
	h := ProjectHash("/some/dir")
	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16 hex chars", len(h))
	}
}

func TestPlanHash_Empty(t *testing.T) {
	h := PlanHash(nil)
	if h != "" {
		t.Errorf("empty content should produce empty hash, got %q", h)
	}
}

func TestPlanHash_Content(t *testing.T) {
	h := PlanHash([]byte(`{"resource_changes":[]}`))
	if h == "" {
		t.Error("non-empty content should produce non-empty hash")
	}
	if len(h) != 16 {
		t.Errorf("hash length = %d, want 16", len(h))
	}
}

func TestPlanHash_DifferentContent(t *testing.T) {
	h1 := PlanHash([]byte(`{"a":1}`))
	h2 := PlanHash([]byte(`{"a":2}`))
	if h1 == h2 {
		t.Error("different content should produce different hashes")
	}
}

func TestNewRecordFromResult(t *testing.T) {
	result := aggregator.ReviewResult{
		TotalResources: 5,
		Score: scoring.Score{
			SecurityScore:        7.5,
			ComplianceScore:      8.0,
			MaintainabilityScore: 9.0,
			OverallScore:         8.2,
		},
		Verdict: aggregator.Verdict{
			Label: "SAFE",
		},
		Findings: []rules.Finding{
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "HIGH"},
			{Severity: "MEDIUM"},
		},
		MaxSeverity: "CRITICAL",
		ExitCode:    2,
	}

	rec := NewRecordFromResult(result, "/tmp/proj", "checkov", "ollama", "llama3.1", 1500, false)

	if rec.ScoreOverall != 8.2 {
		t.Errorf("ScoreOverall = %.1f, want 8.2", rec.ScoreOverall)
	}
	if rec.ScoreSecurity != 7.5 {
		t.Errorf("ScoreSecurity = %.1f, want 7.5", rec.ScoreSecurity)
	}
	if rec.CountCritical != 1 {
		t.Errorf("CountCritical = %d, want 1", rec.CountCritical)
	}
	if rec.CountHigh != 2 {
		t.Errorf("CountHigh = %d, want 2", rec.CountHigh)
	}
	if rec.CountMedium != 1 {
		t.Errorf("CountMedium = %d, want 1", rec.CountMedium)
	}
	if rec.Scanner != "checkov" {
		t.Errorf("Scanner = %q, want %q", rec.Scanner, "checkov")
	}
	if rec.Provider != "ollama" {
		t.Errorf("Provider = %q, want %q", rec.Provider, "ollama")
	}
	if rec.StaticOnly {
		t.Error("StaticOnly should be false")
	}
	if rec.MetadataJSON == "" {
		t.Error("MetadataJSON should not be empty")
	}
}

func TestNewRecordFromResult_Static(t *testing.T) {
	result := aggregator.ReviewResult{
		Score: scoring.Score{OverallScore: 6.0},
	}

	rec := NewRecordFromResult(result, "/tmp/proj", "tfsec", "", "", 0, true)
	if !rec.StaticOnly {
		t.Error("StaticOnly should be true")
	}
	if rec.Provider != "" {
		t.Errorf("Provider should be empty for static, got %q", rec.Provider)
	}
}

func TestTotalFindings(t *testing.T) {
	rec := ScanRecord{
		CountCritical: 1,
		CountHigh:     2,
		CountMedium:   3,
		CountLow:      4,
		CountInfo:     5,
	}
	if rec.TotalFindings() != 15 {
		t.Errorf("TotalFindings = %d, want 15", rec.TotalFindings())
	}
}

func TestFindingsSummary(t *testing.T) {
	rec := ScanRecord{
		CountCritical: 0,
		CountHigh:     2,
		CountMedium:   5,
		CountLow:      4,
	}
	want := "0C 2H 5M 4L"
	if rec.FindingsSummary() != want {
		t.Errorf("FindingsSummary = %q, want %q", rec.FindingsSummary(), want)
	}
}

func TestMetadataJSON_Serialization(t *testing.T) {
	result := aggregator.ReviewResult{
		TotalResources: 10,
		Verdict:        aggregator.Verdict{Label: "NOT SAFE"},
		MaxSeverity:    "CRITICAL",
		ExitCode:       2,
		Score:          scoring.Score{OverallScore: 3.5},
	}

	rec := NewRecordFromResult(result, "/tmp", "checkov", "", "", 0, true)

	if rec.MetadataJSON == "" {
		t.Fatal("MetadataJSON should not be empty")
	}

	// Verify it contains expected fields
	if !contains(rec.MetadataJSON, "total_resources") {
		t.Error("MetadataJSON should contain total_resources")
	}
	if !contains(rec.MetadataJSON, "NOT SAFE") {
		t.Error("MetadataJSON should contain verdict")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
