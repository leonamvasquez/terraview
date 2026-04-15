package fix

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// fakeProvider is a minimal ai.Provider that returns a canned Complete
// response. Enough to drive Suggester through both success and retry paths.
type fakeProvider struct {
	name    string
	reply   string
	err     error
	calls   int
	onRetry string // when set, second call returns this instead of err
}

func (f *fakeProvider) Name() string                       { return f.name }
func (f *fakeProvider) Validate(ctx context.Context) error { return nil }
func (f *fakeProvider) Analyze(ctx context.Context, req ai.Request) (ai.Completion, error) {
	return ai.Completion{}, nil
}
func (f *fakeProvider) Complete(ctx context.Context, system, user string) (string, error) {
	f.calls++
	if f.err != nil {
		if f.onRetry != "" && f.calls > 1 {
			return f.onRetry, nil
		}
		return "", f.err
	}
	return f.reply, nil
}

func TestSuggester_Suggest_Success(t *testing.T) {
	reply := `{"hcl":"resource \"aws_s3_bucket\" \"x\" {}","effort":"low"}`
	p := &fakeProvider{name: "fake", reply: reply}
	s := NewSuggester(p)

	got, err := s.Suggest(context.Background(), FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_1"},
		ResourceAddr: "aws_s3_bucket.x",
		ResourceType: "aws_s3_bucket",
	})
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if got.HCL == "" {
		t.Error("expected non-empty HCL in suggestion")
	}
	if p.calls != 1 {
		t.Errorf("expected 1 provider call, got %d", p.calls)
	}
}

func TestSuggester_Suggest_RetryOnTimeout(t *testing.T) {
	reply := `{"hcl":"resource \"x\" \"y\" {}","effort":"low"}`
	p := &fakeProvider{
		name:    "fake",
		err:     errors.New("context timed out"),
		onRetry: reply,
	}
	s := NewSuggester(p)

	_, err := s.Suggest(context.Background(), FixRequest{
		Finding:        FixFinding{RuleID: "CKV_AWS_1"},
		ResourceAddr:   "aws_s3_bucket.x",
		ResourceType:   "aws_s3_bucket",
		ResourceConfig: map[string]interface{}{"a": 1},
	})
	if err != nil {
		t.Fatalf("Suggest: %v", err)
	}
	if p.calls != 2 {
		t.Errorf("expected 2 calls (initial + retry), got %d", p.calls)
	}
}

func TestSuggester_Suggest_NonRetryableError(t *testing.T) {
	p := &fakeProvider{name: "fake", err: errors.New("invalid api key")}
	s := NewSuggester(p)

	_, err := s.Suggest(context.Background(), FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_1"},
		ResourceAddr: "aws_s3_bucket.x",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if p.calls != 1 {
		t.Errorf("expected 1 call (no retry), got %d", p.calls)
	}
}

func TestParsePrereqHeader(t *testing.T) {
	tests := []struct {
		name     string
		block    string
		wantType string
		wantName string
	}{
		{
			name:     "valid header",
			block:    `resource "aws_kms_key" "main" { enable_key_rotation = true }`,
			wantType: "aws_kms_key",
			wantName: "main",
		},
		{
			name:     "header with leading blank line",
			block:    "\n  resource \"aws_sns_topic\" \"alerts\" {\n  name = \"x\"\n}",
			wantType: "aws_sns_topic",
			wantName: "alerts",
		},
		{
			name:     "no resource line",
			block:    "variable \"x\" { default = 1 }",
			wantType: "",
			wantName: "",
		},
		{
			name:     "empty",
			block:    "",
			wantType: "",
			wantName: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotName := parsePrereqHeader(tc.block)
			if gotType != tc.wantType || gotName != tc.wantName {
				t.Errorf("got (%q,%q), want (%q,%q)", gotType, gotName, tc.wantType, tc.wantName)
			}
		})
	}
}

// silenceStdout redirects os.Stdout for the duration of fn; used for the
// print-heavy display helpers that we only want to exercise for coverage.
func silenceStdout(t *testing.T, fn func()) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = old
	_, _ = io.Copy(io.Discard, r)
}

func TestPreview_PrintsPendingFixes(t *testing.T) {
	file := copyFixture(t)
	dir := filepath.Dir(file)
	loc, err := FindResource(dir, "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}

	pending := []PendingFix{
		{
			Finding:    rules.Finding{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_s3_bucket.logs", Message: "test"},
			Suggestion: &FixSuggestion{HCL: "resource \"aws_s3_bucket\" \"logs\" {}", Explanation: "fix", Effort: "low"},
			Location:   loc,
			Warnings:   []ValidationWarning{{Message: "heads up"}},
		},
		{
			Finding:    rules.Finding{RuleID: "CKV_AWS_2", Severity: "CRITICAL", Resource: "aws_s3_bucket.gone"},
			Suggestion: &FixSuggestion{HCL: "resource \"aws_s3_bucket\" \"gone\" {}", Effort: "high"},
			Location:   nil,
		},
	}

	s := &ApplySession{WorkDir: dir, NoColor: true}
	silenceStdout(t, func() {
		s.Preview(pending)
		s.Preview(nil) // empty path
	})
}

func TestApplyAll_MixedOutcomes(t *testing.T) {
	t.Setenv("PATH", "")
	file := copyFixture(t)
	dir := filepath.Dir(file)
	loc, err := FindResource(dir, "aws_s3_bucket.logs")
	if err != nil || loc == nil {
		t.Fatalf("FindResource: loc=%v err=%v", loc, err)
	}

	pending := []PendingFix{
		// Happy path: balanced HCL + location set.
		{
			Finding:    rules.Finding{RuleID: "CKV_AWS_1", Severity: "HIGH", Resource: "aws_s3_bucket.logs"},
			Suggestion: &FixSuggestion{HCL: "resource \"aws_s3_bucket\" \"logs\" {\n  bucket = \"x\"\n}", Effort: "low"},
			Location:   loc,
		},
		// No location → counted as failed/skipped.
		{
			Finding:    rules.Finding{RuleID: "CKV_AWS_2", Severity: "HIGH", Resource: "aws_s3_bucket.ghost"},
			Suggestion: &FixSuggestion{HCL: "x"},
			Location:   nil,
		},
		// Critical warning → blocked.
		{
			Finding:    rules.Finding{RuleID: "CKV_AWS_3", Severity: "CRITICAL", Resource: "aws_s3_bucket.data"},
			Suggestion: &FixSuggestion{HCL: "resource \"aws_s3_bucket\" \"data\" {}"},
			Location:   loc,
			Warnings:   []ValidationWarning{{Code: "PLACEHOLDER", Message: "crítico"}},
		},
	}

	s := &ApplySession{WorkDir: dir, NoColor: true}
	var applied, failed int
	silenceStdout(t, func() {
		applied, failed = s.ApplyAll(pending)
	})
	if applied < 1 {
		t.Errorf("expected at least 1 applied fix, got %d", applied)
	}
	if failed < 2 {
		t.Errorf("expected 2 failures (missing location + critical warning), got %d", failed)
	}
	// Verify the happy-path fix actually landed.
	got, _ := os.ReadFile(loc.File)
	if !strings.Contains(string(got), "bucket = \"x\"") {
		t.Errorf("expected patched content, got:\n%s", got)
	}
}
