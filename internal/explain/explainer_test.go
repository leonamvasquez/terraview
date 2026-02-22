package explain

import (
	"encoding/json"
	"testing"
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
