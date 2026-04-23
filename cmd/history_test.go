package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseSince
// ---------------------------------------------------------------------------

func TestParseSince_DateFormat(t *testing.T) {
	got, err := parseSince("2025-01-01")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want, _ := time.Parse("2006-01-02", "2025-01-01")
	if !got.Equal(want) {
		t.Errorf("parseSince(\"2025-01-01\") = %v, want %v", got, want)
	}
}

func TestParseSince_DateFormat_Midyear(t *testing.T) {
	got, err := parseSince("2024-06-15")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Year() != 2024 || got.Month() != 6 || got.Day() != 15 {
		t.Errorf("unexpected date: %v", got)
	}
}

func TestParseSince_Days(t *testing.T) {
	before := time.Now()
	got, err := parseSince("7d")
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	low := before.AddDate(0, 0, -7).Add(-time.Second)
	high := after.AddDate(0, 0, -7).Add(time.Second)
	if got.Before(low) || got.After(high) {
		t.Errorf("parseSince(\"7d\") = %v, want between %v and %v", got, low, high)
	}
}

func TestParseSince_Days_30(t *testing.T) {
	before := time.Now()
	got, err := parseSince("30d")
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	low := before.AddDate(0, 0, -30).Add(-time.Second)
	high := after.AddDate(0, 0, -30).Add(time.Second)
	if got.Before(low) || got.After(high) {
		t.Errorf("parseSince(\"30d\") = %v out of expected range", got)
	}
}

func TestParseSince_Days_Zero(t *testing.T) {
	before := time.Now()
	got, err := parseSince("0d")
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Before(before.Add(-time.Second)) || got.After(after.Add(time.Second)) {
		t.Errorf("parseSince(\"0d\") = %v, want close to now", got)
	}
}

func TestParseSince_Hours(t *testing.T) {
	before := time.Now()
	got, err := parseSince("24h")
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	low := before.Add(-24 * time.Hour).Add(-time.Second)
	high := after.Add(-24 * time.Hour).Add(time.Second)
	if got.Before(low) || got.After(high) {
		t.Errorf("parseSince(\"24h\") = %v out of expected range", got)
	}
}

func TestParseSince_Hours_1(t *testing.T) {
	before := time.Now()
	got, err := parseSince("1h")
	after := time.Now()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	low := before.Add(-time.Hour).Add(-time.Second)
	high := after.Add(-time.Hour).Add(time.Second)
	if got.Before(low) || got.After(high) {
		t.Errorf("parseSince(\"1h\") = %v out of expected range", got)
	}
}

func TestParseSince_InvalidUnit(t *testing.T) {
	_, err := parseSince("7w")
	if err == nil {
		t.Fatal("expected error for unknown unit 'w', got nil")
	}
	if !strings.Contains(err.Error(), "unidade inválida") {
		t.Errorf("error %q should mention 'unidade inválida'", err.Error())
	}
}

func TestParseSince_InvalidUnit_Months(t *testing.T) {
	_, err := parseSince("7m")
	if err == nil {
		t.Fatal("expected error for unknown unit 'm'")
	}
}

func TestParseSince_TooShort_Empty(t *testing.T) {
	_, err := parseSince("")
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestParseSince_TooShort_SingleChar(t *testing.T) {
	_, err := parseSince("d")
	if err == nil {
		t.Fatal("expected error for single char 'd', got nil")
	}
	if !strings.Contains(err.Error(), "formato inválido") {
		t.Errorf("error %q should mention 'formato inválido'", err.Error())
	}
}

func TestParseSince_NonNumeric(t *testing.T) {
	_, err := parseSince("Xd")
	if err == nil {
		t.Fatal("expected error for non-numeric 'Xd'")
	}
	if !strings.Contains(err.Error(), "formato inválido") {
		t.Errorf("error %q should mention 'formato inválido'", err.Error())
	}
}

func TestParseSince_NonNumericLong(t *testing.T) {
	_, err := parseSince("abcd")
	if err == nil {
		t.Fatal("expected error for 'abcd'")
	}
}

func TestParseSince_TableDriven(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
		errMsg  string
	}{
		{"2025-01-01", false, ""},
		{"7d", false, ""},
		{"30d", false, ""},
		{"24h", false, ""},
		{"1h", false, ""},
		{"0d", false, ""},
		{"7w", true, "unidade inválida"},
		{"7m", true, "unidade inválida"},
		{"", true, "formato inválido"},
		{"d", true, "formato inválido"},
		{"Xd", true, "formato inválido"},
		{"nope", true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			_, err := parseSince(tt.input)
			if tt.wantErr && err == nil {
				t.Errorf("parseSince(%q) expected error, got nil", tt.input)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("parseSince(%q) unexpected error: %v", tt.input, err)
			}
			if tt.errMsg != "" && err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("parseSince(%q) error = %q, want to contain %q", tt.input, err.Error(), tt.errMsg)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// resolveProjectName
// ---------------------------------------------------------------------------

func TestResolveProjectName_NonEmpty(t *testing.T) {
	// resolveProjectName returns filepath.Base of the working directory.
	// It should always return a non-empty string.
	name := resolveProjectName()
	if name == "" {
		t.Error("resolveProjectName() returned empty string")
	}
}

func TestResolveProjectName_WithWorkDir(t *testing.T) {
	old := workDir
	defer func() { workDir = old }()
	workDir = "/some/path/to/myproject"

	name := resolveProjectName()
	if name != "myproject" {
		t.Errorf("resolveProjectName() = %q, want %q", name, "myproject")
	}
}

func TestResolveProjectDir_WithWorkDir(t *testing.T) {
	old := workDir
	defer func() { workDir = old }()
	workDir = "/some/explicit/dir"

	dir := resolveProjectDir()
	if dir != "/some/explicit/dir" {
		t.Errorf("resolveProjectDir() = %q, want %q", dir, "/some/explicit/dir")
	}
}

func TestResolveProjectDir_Default(t *testing.T) {
	old := workDir
	defer func() { workDir = old }()
	workDir = ""

	dir := resolveProjectDir()
	// Should return a non-empty path (cwd or ".")
	if dir == "" {
		t.Error("resolveProjectDir() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// runHistoryClear — exercises branches via real SQLite store in tempdir
// ---------------------------------------------------------------------------

func TestRunHistoryClear_All(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = true
	historyBefore = ""
	defer func() { historyAll = false }()

	if err := runHistoryClear(nil, nil); err != nil {
		t.Errorf("runHistoryClear (all) failed: %v", err)
	}
}

func TestRunHistoryClear_BeforeDate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = false
	historyBefore = "30d"
	defer func() { historyBefore = "" }()

	if err := runHistoryClear(nil, nil); err != nil {
		t.Errorf("runHistoryClear (before=30d) failed: %v", err)
	}
}

func TestRunHistoryClear_InvalidBefore(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = false
	historyBefore = "invalid-date-format"
	defer func() { historyBefore = "" }()

	if err := runHistoryClear(nil, nil); err == nil {
		t.Error("expected error for invalid --before value")
	}
}

func TestRunHistoryClear_ByProject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = false
	historyBefore = ""
	origWorkDir := workDir
	workDir = dir
	defer func() { workDir = origWorkDir }()

	if err := runHistoryClear(nil, nil); err != nil {
		t.Errorf("runHistoryClear (by project) failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// runHistoryList — exercises enabled + store path via tempdir HOME
// ---------------------------------------------------------------------------

func TestRunHistoryList_HappyPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = true
	historyProject = ""
	historySince = ""
	historyLimit = 20
	historyFormat = "table"
	origWorkDir := workDir
	workDir = dir
	defer func() {
		historyAll = false
		historyLimit = 20
		workDir = origWorkDir
	}()

	// History is enabled by default config; store is created fresh in tempdir.
	if err := runHistoryList(nil, nil); err != nil {
		t.Errorf("runHistoryList happy path failed: %v", err)
	}
}

func TestRunHistoryList_FilterByProject(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	os.MkdirAll(filepath.Join(dir, ".terraview"), 0755)

	historyAll = false
	historyProject = ""
	historySince = ""
	historyLimit = 10
	historyFormat = "table"
	origWorkDir := workDir
	workDir = dir
	defer func() {
		historyLimit = 20
		workDir = origWorkDir
	}()

	if err := runHistoryList(nil, nil); err != nil {
		t.Errorf("runHistoryList (by project) failed: %v", err)
	}
}
