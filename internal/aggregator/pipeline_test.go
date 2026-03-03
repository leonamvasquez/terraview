package aggregator

import (
	"encoding/json"
	"testing"
)

func TestPipelineStatus_Completeness(t *testing.T) {
	tests := []struct {
		name               string
		scanner            *ComponentStatus
		ai                 *ComponentStatus
		resultCompleteness string
	}{
		{
			name:               "both success",
			scanner:            &ComponentStatus{Status: "success", DurationMs: 1200, Tool: "checkov"},
			ai:                 &ComponentStatus{Status: "success", DurationMs: 3400, Provider: "openai", Model: "gpt-4o"},
			resultCompleteness: "complete",
		},
		{
			name:               "scanner only",
			scanner:            &ComponentStatus{Status: "success", DurationMs: 1200, Tool: "checkov"},
			ai:                 &ComponentStatus{Status: "failed", Error: "timeout", DurationMs: 30000, Provider: "openai"},
			resultCompleteness: "partial_scanner_only",
		},
		{
			name:               "ai only",
			scanner:            &ComponentStatus{Status: "failed", Error: "checkov not found", DurationMs: 50, Tool: "checkov"},
			ai:                 &ComponentStatus{Status: "success", DurationMs: 3400, Provider: "openai", Model: "gpt-4o"},
			resultCompleteness: "partial_ai_only",
		},
		{
			name:               "both failed",
			scanner:            &ComponentStatus{Status: "failed", Error: "checkov not found"},
			ai:                 &ComponentStatus{Status: "failed", Error: "invalid api key"},
			resultCompleteness: "failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := &PipelineStatus{
				Scanner:            tt.scanner,
				AI:                 tt.ai,
				ResultCompleteness: tt.resultCompleteness,
			}
			if ps.ResultCompleteness != tt.resultCompleteness {
				t.Errorf("expected completeness %q, got %q", tt.resultCompleteness, ps.ResultCompleteness)
			}
		})
	}
}

func TestPipelineStatus_JSONSerialization(t *testing.T) {
	ps := &PipelineStatus{
		Scanner: &ComponentStatus{
			Status:     "success",
			DurationMs: 1500,
			Tool:       "checkov",
			Version:    "3.2.1",
		},
		AI: &ComponentStatus{
			Status:     "success",
			DurationMs: 4200,
			Provider:   "openai",
			Model:      "gpt-4o",
			Retries:    1,
		},
		ResultCompleteness: "complete",
	}

	data, err := json.Marshal(ps)
	if err != nil {
		t.Fatalf("failed to marshal PipelineStatus: %v", err)
	}

	var decoded PipelineStatus
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal PipelineStatus: %v", err)
	}

	if decoded.ResultCompleteness != "complete" {
		t.Errorf("expected completeness 'complete', got %q", decoded.ResultCompleteness)
	}
	if decoded.Scanner.Tool != "checkov" {
		t.Errorf("expected scanner tool 'checkov', got %q", decoded.Scanner.Tool)
	}
	if decoded.AI.Provider != "openai" {
		t.Errorf("expected AI provider 'openai', got %q", decoded.AI.Provider)
	}
	if decoded.AI.Retries != 1 {
		t.Errorf("expected AI retries 1, got %d", decoded.AI.Retries)
	}
}

func TestPipelineStatus_OmitEmpty(t *testing.T) {
	// When PipelineStatus is nil, it should not appear in ReviewResult JSON
	result := ReviewResult{
		PlanFile:       "test.json",
		PipelineStatus: nil,
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if _, found := m["pipeline_status"]; found {
		t.Error("pipeline_status should be omitted when nil")
	}
}

func TestPipelineStatus_ComponentStatusOmitEmpty(t *testing.T) {
	// When ComponentStatus has zero-value fields, they should be omitted
	cs := &ComponentStatus{
		Status: "success",
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	for _, field := range []string{"error", "duration_ms", "tool", "version", "provider", "model", "retries"} {
		if _, found := m[field]; found {
			t.Errorf("field %q should be omitted when zero-value", field)
		}
	}

	// status should always be present
	if _, found := m["status"]; !found {
		t.Error("field 'status' should always be present")
	}
}

func TestReviewResult_WithPipelineStatus(t *testing.T) {
	// Verify PipelineStatus appears in the full ReviewResult JSON
	result := ReviewResult{
		PlanFile:    "test.json",
		MaxSeverity: "HIGH",
		ExitCode:    1,
		PipelineStatus: &PipelineStatus{
			Scanner:            &ComponentStatus{Status: "success", Tool: "checkov"},
			AI:                 &ComponentStatus{Status: "failed", Error: "timeout", Provider: "openai"},
			ResultCompleteness: "partial_scanner_only",
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	ps, ok := m["pipeline_status"].(map[string]interface{})
	if !ok {
		t.Fatal("pipeline_status should be present in JSON")
	}

	if ps["result_completeness"] != "partial_scanner_only" {
		t.Errorf("expected result_completeness 'partial_scanner_only', got %v", ps["result_completeness"])
	}

	aiStatus, ok := ps["ai"].(map[string]interface{})
	if !ok {
		t.Fatal("ai component status should be present")
	}
	if aiStatus["status"] != "failed" {
		t.Errorf("expected AI status 'failed', got %v", aiStatus["status"])
	}
	if aiStatus["error"] != "timeout" {
		t.Errorf("expected AI error 'timeout', got %v", aiStatus["error"])
	}
}
