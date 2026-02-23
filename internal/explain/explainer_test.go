package explain

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
)

func TestParseExplanation_DirectJSON(t *testing.T) {
	raw := `{"summary":"All good","changes":["create vpc"],"risks":["none"],"suggestions":["add tags"],"risk_level":"low"}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != "All good" {
		t.Errorf("expected 'All good', got %q", expl.Summary)
	}
	if expl.RiskLevel != "low" {
		t.Errorf("expected 'low', got %q", expl.RiskLevel)
	}
	if len(expl.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(expl.Changes))
	}
}

func TestParseExplanation_SummaryAsObject(t *testing.T) {
	raw := `{"summary":{"summary":"Nested summary","details":"extra"},"changes":["a"],"risks":[],"risk_level":"high"}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != "Nested summary" {
		t.Errorf("expected 'Nested summary', got %q", expl.Summary)
	}
	if expl.RiskLevel != "high" {
		t.Errorf("expected 'high', got %q", expl.RiskLevel)
	}
}

func TestParseExplanation_SummaryAsObjectWithOverview(t *testing.T) {
	raw := `{"summary":{"overview":"The overview text","risk":"low"},"changes":["b"],"risks":["r1"],"risk_level":"medium"}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != "The overview text" {
		t.Errorf("expected 'The overview text', got %q", expl.Summary)
	}
}

func TestParseExplanation_SummaryAsObjectFallbackSerialize(t *testing.T) {
	raw := `{"summary":{"foo":"bar","baz":42},"changes":[],"risks":[],"risk_level":"low"}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should serialize the object as JSON string
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(expl.Summary), &m); err != nil {
		t.Errorf("expected valid JSON in summary, got %q", expl.Summary)
	}
}

func TestParseExplanation_CodeFence(t *testing.T) {
	raw := "Here is the analysis:\n```json\n{\"summary\":\"fenced\",\"changes\":[],\"risks\":[],\"risk_level\":\"low\"}\n```\n"
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != "fenced" {
		t.Errorf("expected 'fenced', got %q", expl.Summary)
	}
}

func TestParseExplanation_RawTextFallback(t *testing.T) {
	raw := "This is just plain text, not JSON at all."
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != raw {
		t.Errorf("expected raw text as summary, got %q", expl.Summary)
	}
	if expl.RiskLevel != "medium" {
		t.Errorf("expected default 'medium', got %q", expl.RiskLevel)
	}
}

func TestParseExplanation_InvalidRiskLevel(t *testing.T) {
	raw := `{"summary":"ok","changes":[],"risks":[],"risk_level":"EXTREME"}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.RiskLevel != "medium" {
		t.Errorf("expected normalized 'medium', got %q", expl.RiskLevel)
	}
}

func TestParseExplanation_BRSummaryAsObject(t *testing.T) {
	// Real-world scenario: AI returns pt-BR with nested summary
	raw := `{
		"summary": {
			"summary": "Esta infraestrutura cria uma instância EC2 na AWS.",
			"detalhes": "Configuração básica com VPC padrão"
		},
		"changes": ["Criação de instância EC2"],
		"risks": ["Sem grupo de segurança explícito"],
		"suggestions": ["Adicionar tags de custo"],
		"risk_level": "medium"
	}`
	expl, err := ParseExplanation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if expl.Summary != "Esta infraestrutura cria uma instância EC2 na AWS." {
		t.Errorf("expected BR summary, got %q", expl.Summary)
	}
}

// ---------------------------------------------------------------------------
// normalizeRiskLevel
// ---------------------------------------------------------------------------

func TestNormalizeRiskLevel(t *testing.T) {
	tests := []struct {
		level string
		want  string
	}{
		{"low", "low"},
		{"medium", "medium"},
		{"high", "high"},
		{"critical", "critical"},
		{"LOW", "low"},
		{"HIGH", "high"},
		{"  medium  ", "medium"},
		{"extreme", "medium"},
		{"", "medium"},
		{"VERY HIGH", "medium"},
	}
	for _, tt := range tests {
		if got := normalizeRiskLevel(tt.level); got != tt.want {
			t.Errorf("normalizeRiskLevel(%q) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// extractFromCodeFence
// ---------------------------------------------------------------------------

func TestExtractFromCodeFence_JsonFence(t *testing.T) {
	raw := "Some text\n```json\n{\"key\":\"value\"}\n```\nMore text"
	got := extractFromCodeFence(raw)
	if got != `{"key":"value"}` {
		t.Errorf("expected JSON content, got %q", got)
	}
}

func TestExtractFromCodeFence_PlainFence(t *testing.T) {
	raw := "Text\n```\n{\"key\":\"val\"}\n```\nEnd"
	got := extractFromCodeFence(raw)
	if got != `{"key":"val"}` {
		t.Errorf("expected fenced content, got %q", got)
	}
}

func TestExtractFromCodeFence_NoFence(t *testing.T) {
	raw := "No code fences here"
	got := extractFromCodeFence(raw)
	if got != raw {
		t.Errorf("expected original string, got %q", got)
	}
}

func TestExtractFromCodeFence_UnterminatedFence(t *testing.T) {
	raw := "```json\n{\"key\":\"val\"}"
	got := extractFromCodeFence(raw)
	if got != raw {
		t.Errorf("unterminated fence should return original, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// toStringSlice
// ---------------------------------------------------------------------------

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		input interface{}
		want  int
	}{
		{[]interface{}{"a", "b", "c"}, 3},
		{[]interface{}{}, 0},
		{nil, 0},
		{"not a slice", 0},
		{[]interface{}{"a", 42, "b"}, 2}, // non-strings filtered
	}
	for _, tt := range tests {
		got := toStringSlice(tt.input)
		if len(got) != tt.want {
			t.Errorf("toStringSlice(%v) length = %d, want %d", tt.input, len(got), tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// buildSummaryMap
// ---------------------------------------------------------------------------

func TestBuildSummaryMap(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_vpc.main", Action: "create", Type: "aws_vpc"},
		{Address: "aws_subnet.a", Action: "create", Type: "aws_subnet"},
		{Address: "aws_instance.web", Action: "update", Type: "aws_instance"},
	}

	summary := buildSummaryMap(resources)

	if summary["total_resources"] != 3 {
		t.Errorf("expected 3 total, got %v", summary["total_resources"])
	}

	actions, ok := summary["actions"].(map[string]int)
	if !ok {
		t.Fatal("expected actions map")
	}
	if actions["create"] != 2 {
		t.Errorf("expected 2 creates, got %d", actions["create"])
	}
	if actions["update"] != 1 {
		t.Errorf("expected 1 update, got %d", actions["update"])
	}

	types, ok := summary["resource_types"].(map[string]int)
	if !ok {
		t.Fatal("expected resource_types map")
	}
	if types["aws_vpc"] != 1 {
		t.Errorf("expected 1 aws_vpc, got %d", types["aws_vpc"])
	}
}

func TestBuildSummaryMap_Empty(t *testing.T) {
	summary := buildSummaryMap(nil)
	if summary["total_resources"] != 0 {
		t.Errorf("expected 0 total, got %v", summary["total_resources"])
	}
}

// ---------------------------------------------------------------------------
// buildExplainPrompt
// ---------------------------------------------------------------------------

func TestBuildExplainPrompt_ContainsFindings(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "HIGH", Resource: "aws_instance.web", Message: "Public SSH"},
	}
	prompt := buildExplainPrompt(nil, findings)

	if !strings.Contains(prompt, "HIGH") {
		t.Error("expected severity in prompt")
	}
	if !strings.Contains(prompt, "Public SSH") {
		t.Error("expected finding message in prompt")
	}
}

func TestBuildExplainPrompt_NoFindings(t *testing.T) {
	prompt := buildExplainPrompt(nil, nil)

	if !strings.Contains(prompt, "senior infrastructure engineer") {
		t.Error("expected role description in prompt")
	}
	if strings.Contains(prompt, "scanner findings") {
		t.Error("should not mention scanner findings when empty")
	}
}

// ---------------------------------------------------------------------------
// explFromMap
// ---------------------------------------------------------------------------

func TestExplFromMap_StringSummary(t *testing.T) {
	m := map[string]interface{}{
		"summary":    "Simple summary",
		"changes":    []interface{}{"c1"},
		"risks":      []interface{}{"r1", "r2"},
		"risk_level": "high",
	}
	expl := explFromMap(m)
	if expl.Summary != "Simple summary" {
		t.Errorf("got summary %q", expl.Summary)
	}
	if len(expl.Changes) != 1 {
		t.Errorf("expected 1 change, got %d", len(expl.Changes))
	}
	if len(expl.Risks) != 2 {
		t.Errorf("expected 2 risks, got %d", len(expl.Risks))
	}
	if expl.RiskLevel != "high" {
		t.Errorf("expected high, got %s", expl.RiskLevel)
	}
}

func TestExplFromMap_NestedSummary(t *testing.T) {
	m := map[string]interface{}{
		"summary": map[string]interface{}{
			"summary": "Nested",
		},
	}
	expl := explFromMap(m)
	if expl.Summary != "Nested" {
		t.Errorf("expected 'Nested', got %q", expl.Summary)
	}
}

func TestExplFromMap_EmptyMap(t *testing.T) {
	m := map[string]interface{}{}
	expl := explFromMap(m)
	if expl.RiskLevel != "medium" {
		t.Errorf("expected default medium, got %s", expl.RiskLevel)
	}
}

// ---------------------------------------------------------------------------
// NewExplainer/NewExplainerWithLang
// ---------------------------------------------------------------------------

func TestNewExplainer(t *testing.T) {
	e := NewExplainer(nil)
	if e == nil {
		t.Fatal("expected non-nil explainer")
	}
	if e.lang != "" {
		t.Errorf("expected empty lang, got %q", e.lang)
	}
}

func TestNewExplainerWithLang(t *testing.T) {
	e := NewExplainerWithLang(nil, "pt-BR")
	if e.lang != "pt-BR" {
		t.Errorf("expected pt-BR, got %q", e.lang)
	}
}
