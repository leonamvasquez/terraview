package compress

import (
	"encoding/json"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aicache"
)

func TestNewProviderAdapter(t *testing.T) {
	pa := NewProviderAdapter(nil)
	if pa == nil {
		t.Fatal("expected non-nil ProviderAdapter")
	}
	if pa.provider != nil {
		t.Error("expected nil provider when constructed with nil")
	}
}

func TestParseCompressedResponse_ValidJSON(t *testing.T) {
	resp := aicache.Response{
		RiskCategories:    []string{"security", "compliance"},
		Severity:          "HIGH",
		ArchitecturalRisk: "Open security group",
		Remediation:       "Restrict CIDR blocks",
		Confidence:        0.9,
	}
	raw, _ := json.Marshal(resp)

	got, err := parseCompressedResponse(string(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", got.Severity)
	}
	if got.Confidence != 0.9 {
		t.Errorf("confidence = %f, want 0.9", got.Confidence)
	}
	if got.ArchitecturalRisk != "Open security group" {
		t.Errorf("architectural_risk = %q, want 'Open security group'", got.ArchitecturalRisk)
	}
	if len(got.RiskCategories) != 2 {
		t.Errorf("risk_categories length = %d, want 2", len(got.RiskCategories))
	}
}

func TestParseCompressedResponse_MarkdownFencedJSON(t *testing.T) {
	resp := aicache.Response{
		Severity:          "CRITICAL",
		ArchitecturalRisk: "No encryption",
		Remediation:       "Enable encryption",
		Confidence:        0.85,
	}
	raw, _ := json.Marshal(resp)
	fenced := "```json\n" + string(raw) + "\n```"

	got, err := parseCompressedResponse(fenced)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", got.Severity)
	}
	if got.Confidence != 0.85 {
		t.Errorf("confidence = %f, want 0.85", got.Confidence)
	}
}

func TestParseCompressedResponse_PlainFencedJSON(t *testing.T) {
	resp := aicache.Response{
		Severity:          "MEDIUM",
		ArchitecturalRisk: "Missing tags",
		Remediation:       "Add tags",
		Confidence:        0.7,
	}
	raw, _ := json.Marshal(resp)
	fenced := "```\n" + string(raw) + "\n```"

	got, err := parseCompressedResponse(fenced)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "MEDIUM" {
		t.Errorf("severity = %q, want MEDIUM", got.Severity)
	}
}

func TestParseCompressedResponse_WithWhitespace(t *testing.T) {
	resp := aicache.Response{
		Severity:          "LOW",
		ArchitecturalRisk: "Minor issue",
		Remediation:       "Consider fixing",
		Confidence:        0.5,
	}
	raw, _ := json.Marshal(resp)
	padded := "  \n" + string(raw) + "\n  "

	got, err := parseCompressedResponse(padded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "LOW" {
		t.Errorf("severity = %q, want LOW", got.Severity)
	}
}

func TestParseCompressedResponse_InvalidJSON_FallsBackToINFO(t *testing.T) {
	got, err := parseCompressedResponse("not valid json at all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO", got.Severity)
	}
	if got.Confidence != 0.3 {
		t.Errorf("confidence = %f, want 0.3", got.Confidence)
	}
	if got.ArchitecturalRisk != "not valid json at all" {
		t.Errorf("architectural_risk = %q, want raw text", got.ArchitecturalRisk)
	}
}

func TestParseCompressedResponse_EmptyString(t *testing.T) {
	got, err := parseCompressedResponse("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO", got.Severity)
	}
	if got.Confidence != 0.3 {
		t.Errorf("confidence = %f, want 0.3", got.Confidence)
	}
}

func TestParseCompressedResponse_ValidJSON_NoSeverity_FallsBack(t *testing.T) {
	// Valid JSON but no severity → fallback
	raw := `{"confidence": 0.8, "architectural_risk": "something"}`
	got, err := parseCompressedResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO (fallback when no severity)", got.Severity)
	}
}

func TestParseCompressedResponse_MarkdownFence_NoClosure(t *testing.T) {
	// ```json without closing ``` → fence extraction won't match, falls back
	raw := "```json\n{\"severity\":\"HIGH\"}\n"
	got, err := parseCompressedResponse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The string after trim won't be valid JSON (starts with ```json)
	if got.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO (unclosed fence)", got.Severity)
	}
}

func TestParseCompressedResponse_ExtraTextAroundJSON(t *testing.T) {
	// Text before and after valid JSON → not parseable
	input := "Here is the result: {\"severity\":\"HIGH\"} hope this helps!"
	got, err := parseCompressedResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Severity != "INFO" {
		t.Errorf("severity = %q, want INFO (extra text around JSON)", got.Severity)
	}
}
