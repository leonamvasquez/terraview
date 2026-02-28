package providers

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/parser"
)

// ---------------------------------------------------------------------------
// backoffWithJitter
// ---------------------------------------------------------------------------

func TestBackoffWithJitter_Attempt1(t *testing.T) {
	d := backoffWithJitter(1)
	// base = 1s, jitter ±25% → range [750ms, 1250ms]
	if d < 750*time.Millisecond || d > 1250*time.Millisecond {
		t.Errorf("attempt 1: got %v, want [750ms, 1250ms]", d)
	}
}

func TestBackoffWithJitter_Cap30s(t *testing.T) {
	d := backoffWithJitter(100) // 100² = 10000s → capped at 30s
	// base = 30s, jitter ±25% → range [22.5s, 37.5s]
	if d < 22500*time.Millisecond || d > 37500*time.Millisecond {
		t.Errorf("attempt 100: got %v, want [22.5s, 37.5s]", d)
	}
}

func TestBackoffWithJitter_MinFloor(t *testing.T) {
	// For small attempts, result should be at least 100ms (floor)
	for i := 0; i < 20; i++ {
		d := backoffWithJitter(1)
		if d < 100*time.Millisecond {
			t.Errorf("attempt 1 iteration %d: got %v, want >= 100ms", i, d)
		}
	}
}

// ---------------------------------------------------------------------------
// extractSummary
// ---------------------------------------------------------------------------

func TestExtractSummary_PlainString(t *testing.T) {
	r := llmResponse{Summary: json.RawMessage(`"all good"`)}
	if got := r.extractSummary(); got != "all good" {
		t.Errorf("got %q, want %q", got, "all good")
	}
}

func TestExtractSummary_Object(t *testing.T) {
	r := llmResponse{Summary: json.RawMessage(`{"key":"val"}`)}
	got := r.extractSummary()
	if got != `{"key":"val"}` {
		t.Errorf("got %q, want raw JSON object", got)
	}
}

func TestExtractSummary_Empty(t *testing.T) {
	r := llmResponse{}
	if got := r.extractSummary(); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestExtractSummary_Array(t *testing.T) {
	r := llmResponse{Summary: json.RawMessage(`[1,2,3]`)}
	got := r.extractSummary()
	if got != `[1,2,3]` {
		t.Errorf("got %q, want raw JSON array", got)
	}
}

// ---------------------------------------------------------------------------
// buildSystemPrompt
// ---------------------------------------------------------------------------

func TestBuildSystemPrompt_AllSections(t *testing.T) {
	prompts := ai.Prompts{
		System:       "base system",
		Security:     "sec rules",
		Architecture: "arch rules",
		Standards:    "std rules",
	}
	got := buildSystemPrompt(prompts)

	for _, want := range []string{
		"base system",
		"## Security Review Guidelines",
		"sec rules",
		"## Architecture Review Guidelines",
		"arch rules",
		"## Standards Review Guidelines",
		"std rules",
		"MUST respond ONLY with valid JSON",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in prompt", want)
		}
	}
}

func TestBuildSystemPrompt_NoOptionalSections(t *testing.T) {
	prompts := ai.Prompts{System: "base only"}
	got := buildSystemPrompt(prompts)

	if !strings.Contains(got, "base only") {
		t.Error("missing base system prompt")
	}
	if strings.Contains(got, "Security Review Guidelines") {
		t.Error("unexpected security section")
	}
	if strings.Contains(got, "Architecture Review Guidelines") {
		t.Error("unexpected architecture section")
	}
	if strings.Contains(got, "Standards Review Guidelines") {
		t.Error("unexpected standards section")
	}
}

// ---------------------------------------------------------------------------
// buildUserPrompt
// ---------------------------------------------------------------------------

func TestBuildUserPrompt_Normal(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_instance.web", Action: "create", Type: "aws_instance", Provider: "aws"},
	}
	summary := map[string]interface{}{"total": 1}

	got, err := buildUserPrompt(resources, summary, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "aws_instance.web") {
		t.Error("missing resource address")
	}
	if !strings.Contains(got, "Plan Summary") {
		t.Error("missing plan summary section")
	}
}

func TestBuildUserPrompt_Truncation(t *testing.T) {
	resources := make([]parser.NormalizedResource, 35)
	for i := range resources {
		resources[i] = parser.NormalizedResource{
			Address:  "aws_instance.r" + string(rune('A'+i)),
			Action:   "create",
			Type:     "aws_instance",
			Provider: "aws",
		}
	}
	summary := map[string]interface{}{"total": 35}

	got, err := buildUserPrompt(resources, summary, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "5 more resources (truncated") {
		t.Error("expected truncation message for >30 resources")
	}
}

func TestBuildUserPrompt_Empty(t *testing.T) {
	got, err := buildUserPrompt(nil, map[string]interface{}{}, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "Resource Changes") {
		t.Error("missing resource changes section")
	}
}

// ---------------------------------------------------------------------------
// parseResponse
// ---------------------------------------------------------------------------

func TestParseResponse_ValidJSON(t *testing.T) {
	resp := `{
		"findings": [
			{
				"severity": "HIGH",
				"category": "security",
				"resource": "aws_instance.web",
				"message": "no encryption",
				"remediation": "enable encryption"
			}
		],
		"summary": "one issue found"
	}`
	findings, summary, err := parseResponse(resp, "claude")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", findings[0].Severity)
	}
	if findings[0].Source != "ai/claude" {
		t.Errorf("source = %q, want ai/claude", findings[0].Source)
	}
	if findings[0].RuleID != "AI-CLA-SEC" {
		t.Errorf("ruleID = %q, want AI-CLA-SEC", findings[0].RuleID)
	}
	if summary != "one issue found" {
		t.Errorf("summary = %q", summary)
	}
}

func TestParseResponse_MarkdownWrapped(t *testing.T) {
	resp := "```json\n{\"findings\":[], \"summary\":\"clean\"}\n```"
	findings, summary, err := parseResponse(resp, "gemini")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
	if summary != "clean" {
		t.Errorf("summary = %q", summary)
	}
}

func TestParseResponse_GenericCodeBlock(t *testing.T) {
	resp := "```\n{\"findings\":[], \"summary\":\"ok\"}\n```"
	findings, _, err := parseResponse(resp, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseResponse_InvalidJSON(t *testing.T) {
	_, _, err := parseResponse("not json at all", "test")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error = %q, want 'not valid JSON'", err)
	}
}

func TestParseResponse_SkipsEmptyResourceOrMessage(t *testing.T) {
	resp := `{
		"findings": [
			{"severity":"HIGH","category":"security","resource":"","message":"no resource","remediation":""},
			{"severity":"HIGH","category":"security","resource":"r","message":"","remediation":""},
			{"severity":"LOW","category":"security","resource":"r","message":"valid","remediation":"fix"}
		],
		"summary":"mixed"
	}`
	findings, _, err := parseResponse(resp, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 valid finding, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// normalizeSeverity
// ---------------------------------------------------------------------------

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct{ input, want string }{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"INFO", "INFO"},
		{"critical", "CRITICAL"},
		{"  high  ", "HIGH"},
		{"unknown", "INFO"},
		{"", "INFO"},
	}
	for _, c := range cases {
		if got := normalizeSeverity(c.input); got != c.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// normalizeCategory
// ---------------------------------------------------------------------------

func TestNormalizeCategory(t *testing.T) {
	cases := []struct{ input, want string }{
		{"security", "security"},
		{"compliance", "compliance"},
		{"best-practice", "best-practice"},
		{"maintainability", "maintainability"},
		{"reliability", "reliability"},
		{"SECURITY", "security"},
		{"  Compliance  ", "compliance"},
		{"unknown", "best-practice"},
		{"", "best-practice"},
	}
	for _, c := range cases {
		if got := normalizeCategory(c.input); got != c.want {
			t.Errorf("normalizeCategory(%q) = %q, want %q", c.input, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// truncateJSON
// ---------------------------------------------------------------------------

func TestTruncateJSON_Short(t *testing.T) {
	s := `{"a":1}`
	got := truncateJSON(s, 100)
	if got != s {
		t.Errorf("expected no truncation, got %q", got)
	}
}

func TestTruncateJSON_Long(t *testing.T) {
	s := strings.Repeat("x", 200)
	got := truncateJSON(s, 50)
	if len(got) < 50 {
		t.Errorf("truncated too short: %d", len(got))
	}
	if !strings.Contains(got, "(truncated)") {
		t.Error("missing truncation marker")
	}
}

func TestTruncateJSON_ExactLength(t *testing.T) {
	s := strings.Repeat("y", 100)
	got := truncateJSON(s, 100)
	if got != s {
		t.Error("should not truncate when exactly at limit")
	}
}
