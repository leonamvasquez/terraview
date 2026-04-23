package cmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// captureStatus redirects os.Stdout for the duration of fn and returns the output.
func captureStatus(fn func()) string {
	r, w, _ := os.Pipe()
	old := os.Stdout
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

// ---------------------------------------------------------------------------
// status.go — printStatusHeader
// ---------------------------------------------------------------------------

func TestPrintStatusHeader_NoProviderNoModel(t *testing.T) {
	ls := &history.LastScan{
		Timestamp:      time.Now().Add(-10 * time.Minute),
		Scanner:        "checkov",
		TotalResources: 5,
	}
	out := captureStatus(func() {
		printStatusHeader(ls, "/project/infra")
	})
	if !strings.Contains(out, "checkov") {
		t.Errorf("output should contain scanner name, got: %q", out)
	}
	if !strings.Contains(out, "/project/infra") {
		t.Errorf("output should contain project dir, got: %q", out)
	}
}

func TestPrintStatusHeader_WithProviderAndModel(t *testing.T) {
	ls := &history.LastScan{
		Timestamp: time.Now().Add(-2 * time.Hour),
		Scanner:   "checkov",
		Provider:  "claude",
		Model:     "claude-3-5-sonnet",
	}
	out := captureStatus(func() {
		printStatusHeader(ls, "/project")
	})
	if !strings.Contains(out, "claude") {
		t.Errorf("output should contain provider, got: %q", out)
	}
	if !strings.Contains(out, "claude-3-5-sonnet") {
		t.Errorf("output should contain model, got: %q", out)
	}
}

func TestPrintStatusHeader_ProviderNoModel(t *testing.T) {
	ls := &history.LastScan{
		Timestamp: time.Now(),
		Scanner:   "tfsec",
		Provider:  "gemini",
	}
	out := captureStatus(func() {
		printStatusHeader(ls, "/dir")
	})
	if !strings.Contains(out, "gemini") {
		t.Errorf("output should contain provider, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// status.go — printSeverityTable
// ---------------------------------------------------------------------------

func TestPrintSeverityTable_NoPrev(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL"},
			{Severity: "HIGH"},
			{Severity: "MEDIUM"},
		},
	}
	out := captureStatus(func() {
		printSeverityTable(ls, nil)
	})
	if !strings.Contains(out, "CRITICAL") {
		t.Errorf("output should contain CRITICAL, got: %q", out)
	}
	if !strings.Contains(out, "HIGH") {
		t.Errorf("output should contain HIGH, got: %q", out)
	}
}

func TestPrintSeverityTable_ZeroCounts(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{},
	}
	out := captureStatus(func() {
		printSeverityTable(ls, nil)
	})
	// Should still print all severity rows
	if !strings.Contains(out, "LOW") {
		t.Errorf("output should contain LOW row, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// status.go — printOpenFindings
// ---------------------------------------------------------------------------

func TestPrintOpenFindings_NoFindings(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "MEDIUM", RuleID: "R1", Resource: "res.a"},
		},
	}
	statusAllFlag = false
	out := captureStatus(func() {
		printOpenFindings(ls)
	})
	// Only CRITICAL/HIGH are shown by default; no CRITICAL/HIGH means "no findings"
	if !strings.Contains(out, "No open findings") {
		t.Errorf("expected 'No open findings', got: %q", out)
	}
}

func TestPrintOpenFindings_WithCritical(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL", RuleID: "CKV_AWS_1", Resource: "aws_s3_bucket.x", Message: "Bucket is public"},
			{Severity: "HIGH", RuleID: "CKV_AWS_2", Resource: "aws_iam_role.y"},
		},
	}
	statusAllFlag = false
	out := captureStatus(func() {
		printOpenFindings(ls)
	})
	if !strings.Contains(out, "CKV_AWS_1") {
		t.Errorf("output should contain rule ID, got: %q", out)
	}
	if !strings.Contains(out, "Bucket is public") {
		t.Errorf("output should contain message, got: %q", out)
	}
}

func TestPrintOpenFindings_AllFlag(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "MEDIUM", RuleID: "R1", Resource: "res.a"},
			{Severity: "LOW", RuleID: "R2", Resource: "res.b"},
		},
	}
	statusAllFlag = true
	defer func() { statusAllFlag = false }()
	out := captureStatus(func() {
		printOpenFindings(ls)
	})
	if !strings.Contains(out, "R1") {
		t.Errorf("with --all flag, MEDIUM should appear, got: %q", out)
	}
}

func TestPrintOpenFindings_LongMessage(t *testing.T) {
	longMsg := strings.Repeat("x", 100)
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL", RuleID: "R1", Resource: "res.a", Message: longMsg},
		},
	}
	statusAllFlag = false
	out := captureStatus(func() {
		printOpenFindings(ls)
	})
	// Message should be truncated to ~90 chars
	if strings.Contains(out, longMsg) {
		t.Error("long message should be truncated")
	}
}

func TestPrintOpenFindings_MoreThanMaxShown(t *testing.T) {
	findings := make([]rules.Finding, 15)
	for i := range findings {
		findings[i] = rules.Finding{Severity: "CRITICAL", RuleID: "R1", Resource: "res.x"}
	}
	ls := &history.LastScan{Findings: findings}
	statusAllFlag = false
	out := captureStatus(func() {
		printOpenFindings(ls)
	})
	if !strings.Contains(out, "more") {
		t.Errorf("expected '+ N more' message for >10 findings, got: %q", out)
	}
}

// ---------------------------------------------------------------------------
// status.go — printStatusFooter
// ---------------------------------------------------------------------------

func TestPrintStatusFooter_WithActionable(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "CRITICAL"},
		},
	}
	out := captureStatus(func() {
		printStatusFooter(ls)
	})
	if !strings.Contains(out, "fix apply") {
		t.Errorf("expected 'fix apply' suggestion, got: %q", out)
	}
}

func TestPrintStatusFooter_NoActionable(t *testing.T) {
	ls := &history.LastScan{
		Findings: []rules.Finding{
			{Severity: "MEDIUM"},
		},
	}
	out := captureStatus(func() {
		printStatusFooter(ls)
	})
	if !strings.Contains(out, "No CRITICAL/HIGH") {
		t.Errorf("expected 'No CRITICAL/HIGH' message, got: %q", out)
	}
}
