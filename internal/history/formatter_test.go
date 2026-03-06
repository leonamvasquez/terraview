package history

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatList_Pretty_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	FormatList(&buf, nil, FormatPretty, "test-project")
	out := buf.String()

	if !strings.Contains(out, "Nenhum scan encontrado") {
		t.Errorf("expected empty message, got: %s", out)
	}
}

func TestFormatList_Pretty_WithRecords(t *testing.T) {
	records := []ScanRecord{
		{
			ID:           1,
			Timestamp:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			ProjectDir:   "/tmp/proj",
			Scanner:      "checkov",
			Provider:     "ollama",
			ScoreOverall: 8.5,
			ScoreSecurity: 7.0,
			CountCritical: 0,
			CountHigh:     2,
			CountMedium:   3,
			CountLow:      1,
			CountInfo:     0,
		},
	}

	var buf bytes.Buffer
	FormatList(&buf, records, FormatPretty, "my-project")
	out := buf.String()

	if !strings.Contains(out, "my-project") {
		t.Errorf("missing project name: %s", out)
	}
	if !strings.Contains(out, "checkov") {
		t.Errorf("missing scanner: %s", out)
	}
	if !strings.Contains(out, "ollama") {
		t.Errorf("missing provider: %s", out)
	}
	if !strings.Contains(out, "8.5") {
		t.Errorf("missing score: %s", out)
	}
}

func TestFormatList_Pretty_StaticOnly(t *testing.T) {
	records := []ScanRecord{
		{
			ID:           1,
			Timestamp:    time.Now(),
			ProjectDir:   "/tmp/proj",
			Scanner:      "checkov",
			StaticOnly:   true,
			ScoreOverall: 7.0,
			ScoreSecurity: 6.0,
		},
	}

	var buf bytes.Buffer
	FormatList(&buf, records, FormatPretty, "")
	out := buf.String()

	if !strings.Contains(out, "(static)") {
		t.Errorf("expected (static) for empty provider with static_only: %s", out)
	}
}

func TestFormatList_JSON_Valid(t *testing.T) {
	records := []ScanRecord{
		{
			ID:           1,
			Timestamp:    time.Now(),
			ProjectDir:   "/tmp/proj",
			Scanner:      "checkov",
			ScoreOverall: 8.0,
		},
	}

	var buf bytes.Buffer
	err := FormatList(&buf, records, FormatJSON, "")
	if err != nil {
		t.Fatalf("FormatList JSON: %v", err)
	}

	var parsed []interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Errorf("invalid JSON output: %v\nOutput: %s", err, buf.String())
	}
	if len(parsed) != 1 {
		t.Errorf("expected 1 JSON item, got %d", len(parsed))
	}
}

func TestFormatList_JSON_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	FormatList(&buf, nil, FormatJSON, "")

	var parsed []interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON for empty list: %v", err)
	}
	if len(parsed) != 0 {
		t.Errorf("expected empty JSON array, got %d items", len(parsed))
	}
}

func TestFormatList_CSV_Headers(t *testing.T) {
	records := []ScanRecord{
		{
			ID:              1,
			Timestamp:       time.Now(),
			ProjectDir:      "/tmp/proj",
			Scanner:         "checkov",
			Provider:        "ollama",
			Model:           "llama3.1",
			ScoreOverall:    8.0,
			ScoreSecurity:   7.0,
			ScoreCompliance: 9.0,
			ScoreMaintain:   8.5,
			CountCritical:   0,
			CountHigh:       1,
			CountMedium:     2,
			CountLow:        3,
			CountInfo:       0,
			DurationMs:      1500,
		},
	}

	var buf bytes.Buffer
	err := FormatList(&buf, records, FormatCSV, "")
	if err != nil {
		t.Fatalf("FormatList CSV: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least header + 1 row, got %d lines", len(lines))
	}

	header := lines[0]
	expectedHeaders := []string{"id", "timestamp", "project_dir", "scanner", "provider",
		"model", "score_overall", "score_security", "score_compliance", "score_maintain",
		"critical", "high", "medium", "low", "info", "duration_ms", "static_only"}

	for _, h := range expectedHeaders {
		if !strings.Contains(header, h) {
			t.Errorf("CSV header missing %q: %s", h, header)
		}
	}
}

func TestFormatList_CSV_Values(t *testing.T) {
	records := []ScanRecord{
		{
			ID:           1,
			Timestamp:    time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC),
			ProjectDir:   "/tmp/proj",
			Scanner:      "checkov",
			Provider:     "ollama",
			ScoreOverall: 8.0,
			CountCritical: 2,
		},
	}

	var buf bytes.Buffer
	FormatList(&buf, records, FormatCSV, "")

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatal("expected data row")
	}

	dataRow := lines[1]
	if !strings.Contains(dataRow, "checkov") {
		t.Errorf("CSV data missing scanner: %s", dataRow)
	}
	if !strings.Contains(dataRow, "2025-01-15") {
		t.Errorf("CSV data missing timestamp: %s", dataRow)
	}
}

func TestFormatTrendOutput_Empty(t *testing.T) {
	var buf bytes.Buffer
	FormatTrendOutput(&buf, nil, "my-project", 0)
	out := buf.String()

	if !strings.Contains(out, "Nenhum dado para tendência") {
		t.Errorf("expected no-data message: %s", out)
	}
}

func TestFormatTrendOutput_WithTrends(t *testing.T) {
	trends := []TrendData{
		ComputeTrend("Overall", []float64{5.0, 7.0, 9.0}),
		ComputeTrend("Security", []float64{4.0, 6.0, 8.0}),
	}

	var buf bytes.Buffer
	FormatTrendOutput(&buf, trends, "my-project", 3)
	out := buf.String()

	if !strings.Contains(out, "my-project") {
		t.Errorf("missing project name: %s", out)
	}
	if !strings.Contains(out, "Tendência") {
		t.Errorf("missing title: %s", out)
	}
}

func TestFormatCompareOutput(t *testing.T) {
	oldScan := ScanRecord{ScoreOverall: 5.0, ScoreSecurity: 4.0}
	newScan := ScanRecord{ScoreOverall: 8.0, ScoreSecurity: 7.0}

	cr := CompareTwoScans("Antes", oldScan, newScan)

	var buf bytes.Buffer
	FormatCompareOutput(&buf, cr, "my-project")
	out := buf.String()

	if !strings.Contains(out, "Comparação") {
		t.Errorf("missing title: %s", out)
	}
	if !strings.Contains(out, "my-project") {
		t.Errorf("missing project name: %s", out)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		max   int
		want  string
	}{
		{"short", 10, "short"},
		{"exactly10c", 10, "exactly10c"},
		{"this is a very long string", 10, "this is a…"},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.max)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.max, got, tt.want)
		}
	}
}
