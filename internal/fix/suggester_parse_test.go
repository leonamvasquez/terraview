package fix

import (
	"errors"
	"strings"
	"testing"
)

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"shorter than n", "hello", 10, "hello"},
		{"equal to n", "hello", 5, "hello"},
		{"longer than n", "hello world", 5, "hello..."},
		{"empty", "", 5, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := truncate(tc.in, tc.n); got != tc.want {
				t.Errorf("truncate(%q,%d) = %q, want %q", tc.in, tc.n, got, tc.want)
			}
		})
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"timeout", errors.New("request timeout"), true},
		{"timed out", errors.New("context timed out"), true},
		{"context length", errors.New("model context length exceeded"), true},
		{"too long", errors.New("prompt is too long"), true},
		{"max_tokens", errors.New("max_tokens too small"), true},
		{"unrelated", errors.New("invalid api key"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableError(tc.err); got != tc.want {
				t.Errorf("isRetryableError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "raw JSON",
			in:   `{"hcl":"x","effort":"low"}`,
			want: `{"hcl":"x","effort":"low"}`,
		},
		{
			name: "fenced with json tag",
			in:   "```json\n{\"hcl\":\"x\"}\n```",
			want: `{"hcl":"x"}`,
		},
		{
			name: "fenced without tag",
			in:   "```\n{\"hcl\":\"x\"}\n```",
			want: `{"hcl":"x"}`,
		},
		{
			name: "prose before JSON",
			in:   "Here is the fix:\n{\"hcl\":\"x\"}\nThat is all.",
			want: `{"hcl":"x"}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := extractJSON(tc.in)
			if !strings.Contains(got, `"hcl"`) {
				t.Errorf("extractJSON returned %q, expected JSON with hcl", got)
			}
		})
	}
}

func TestParseFixResponse_Valid(t *testing.T) {
	text := "```json\n" + `{
		"hcl": "resource \"aws_s3_bucket\" \"x\" {}",
		"explanation": "adds encryption",
		"prerequisites": ["kms key"],
		"effort": "medium"
	}` + "\n```"

	req := FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_19"},
		ResourceAddr: "aws_s3_bucket.x",
	}
	got, err := parseFixResponse(text, req)
	if err != nil {
		t.Fatalf("parseFixResponse: %v", err)
	}
	if got.RuleID != "CKV_AWS_19" {
		t.Errorf("RuleID = %q", got.RuleID)
	}
	if got.Effort != "medium" {
		t.Errorf("Effort = %q, want medium", got.Effort)
	}
	if len(got.Prerequisites) != 1 {
		t.Errorf("Prerequisites = %v", got.Prerequisites)
	}
}

func TestParseFixResponse_DefaultEffort(t *testing.T) {
	text := `{"hcl": "resource \"x\" \"y\" {}", "effort": "nonsense"}`
	got, err := parseFixResponse(text, FixRequest{})
	if err != nil {
		t.Fatalf("parseFixResponse: %v", err)
	}
	if got.Effort != "medium" {
		t.Errorf("Effort = %q, want medium (default)", got.Effort)
	}
}

func TestParseFixResponse_InvalidJSON(t *testing.T) {
	if _, err := parseFixResponse("not json at all", FixRequest{}); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseFixResponse_MissingHCL(t *testing.T) {
	text := `{"explanation": "no hcl field"}`
	if _, err := parseFixResponse(text, FixRequest{}); err == nil {
		t.Fatal("expected error for missing hcl field")
	}
}

func TestParseFixResponse_AISelfAssessment_Captured(t *testing.T) {
	text := `{
		"hcl": "resource \"aws_s3_bucket\" \"x\" {}",
		"explanation": "removes lifecycle rule",
		"effort": "medium",
		"manual_review_reason": "lifecycle rule may be required for compliance retention",
		"blast_radius": "high"
	}`
	got, err := parseFixResponse(text, FixRequest{Finding: FixFinding{RuleID: "CKV_AWS_X"}})
	if err != nil {
		t.Fatalf("parseFixResponse: %v", err)
	}
	if got.ManualReviewReason == "" {
		t.Error("expected manual_review_reason captured, got empty")
	}
	if got.BlastRadius != "high" {
		t.Errorf("BlastRadius=%q, want high", got.BlastRadius)
	}
}

func TestParseFixResponse_AISelfAssessment_DefaultsWhenAbsent(t *testing.T) {
	text := `{"hcl":"resource \"x\" \"y\" {}","effort":"low"}`
	got, err := parseFixResponse(text, FixRequest{})
	if err != nil {
		t.Fatalf("parseFixResponse: %v", err)
	}
	if got.ManualReviewReason != "" {
		t.Errorf("ManualReviewReason should default to empty, got %q", got.ManualReviewReason)
	}
	if got.BlastRadius != "low" {
		t.Errorf("BlastRadius should default to 'low' when absent, got %q", got.BlastRadius)
	}
}

func TestParseBatchFixResponse_AISelfAssessment_PerFinding(t *testing.T) {
	text := `{
		"hcl": "resource \"aws_s3_bucket\" \"x\" {}",
		"fixes": [
			{"rule_id":"CKV_AWS_1","explanation":"a","effort":"low","manual_review_reason":"","blast_radius":"low"},
			{"rule_id":"CKV_AWS_2","explanation":"b","effort":"high","manual_review_reason":"alters retention","blast_radius":"high"}
		]
	}`
	reqs := []FixRequest{
		{Finding: FixFinding{RuleID: "CKV_AWS_1"}, ResourceAddr: "aws_s3_bucket.x"},
		{Finding: FixFinding{RuleID: "CKV_AWS_2"}, ResourceAddr: "aws_s3_bucket.x"},
	}
	got, err := parseBatchFixResponse(text, reqs)
	if err != nil {
		t.Fatalf("parseBatchFixResponse: %v", err)
	}
	if got[0].ManualReviewReason != "" || got[0].BlastRadius != "low" {
		t.Errorf("fix[0] mrr=%q blast=%q, want empty/low", got[0].ManualReviewReason, got[0].BlastRadius)
	}
	if got[1].ManualReviewReason == "" || got[1].BlastRadius != "high" {
		t.Errorf("fix[1] mrr=%q blast=%q, want non-empty/high", got[1].ManualReviewReason, got[1].BlastRadius)
	}
}
