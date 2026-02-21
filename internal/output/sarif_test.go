package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestWriteSARIF_CreatesValidJSON(t *testing.T) {
	w := NewWriter()
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 3,
		Findings: []rules.Finding{
			{
				RuleID:   "SEC001",
				Severity: "CRITICAL",
				Category: "security",
				Resource: "aws_instance.web",
				Message:  "Public SSH access",
				Source:   "hard-rule",
			},
			{
				RuleID:   "TAG001",
				Severity: "MEDIUM",
				Category: "compliance",
				Resource: "aws_s3_bucket.data",
				Message:  "Missing required tags",
				Source:   "hard-rule",
			},
		},
	}
	tmpDir := t.TempDir()
	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	err := w.WriteSARIF(result, sarifPath)
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed to read SARIF file: %v", err)
	}
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed to parse SARIF JSON: %v", err)
	}
	if sarif.Version != "2.1.0" {
		t.Errorf("expected SARIF version 2.1.0, got %s", sarif.Version)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Results) != 2 {
		t.Errorf("expected 2 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestWriteSARIF_EmptyFindings(t *testing.T) {
	w := NewWriter()
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 0,
	}
	tmpDir := t.TempDir()
	sarifPath := filepath.Join(tmpDir, "review.sarif.json")
	err := w.WriteSARIF(result, sarifPath)
	if err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	data, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatalf("failed to read SARIF file: %v", err)
	}
	var sarif SARIFReport
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("failed to parse SARIF JSON: %v", err)
	}
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(sarif.Runs[0].Results))
	}
}

func TestSeverityToSARIFLevel(t *testing.T) {
	if got := mapSeverityToSARIFLevel("CRITICAL"); got != "error" {
		t.Errorf("expected error, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("HIGH"); got != "error" {
		t.Errorf("expected error, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("MEDIUM"); got != "warning" {
		t.Errorf("expected warning, got %s", got)
	}
	if got := mapSeverityToSARIFLevel("LOW"); got != "note" {
		t.Errorf("expected note, got %s", got)
	}
}
