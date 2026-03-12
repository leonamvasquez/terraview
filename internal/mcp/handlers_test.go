package mcp

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/config"
)

func testLogger() *log.Logger {
	return log.New(os.Stderr, "[test] ", 0)
}

// --- Diagram handler tests ---

func TestHandleDiagram_NonexistentDir(t *testing.T) {
	args := json.RawMessage(`{"dir":"/nonexistent-dir-xyz"}`)
	_, err := handleDiagram(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestHandleDiagram_WithPlanFile(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]string{
		"dir":  planDir,
		"plan": planPath,
	})

	result, err := handleDiagram(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
	if result.Content[0].Type != "text" {
		t.Errorf("content type = %q, want %q", result.Content[0].Type, "text")
	}
	if result.Content[0].Text == "" {
		t.Error("expected non-empty diagram text")
	}
}

func TestHandleDiagram_NilArgs(t *testing.T) {
	_, err := handleDiagram(nil, testLogger())
	if err == nil {
		t.Error("expected error for nil args (no plan)")
	}
}

// --- Drift handler tests ---

func TestHandleDrift_NonexistentDir(t *testing.T) {
	args := json.RawMessage(`{"dir":"/nonexistent-dir-xyz"}`)
	_, err := handleDrift(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestHandleDrift_WithPlanFile(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":  planDir,
		"plan": planPath,
	})

	result, err := handleDrift(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content")
	}
	if result.IsError {
		t.Error("expected no error")
	}

	// Verify it's valid JSON
	var driftResp driftResponse
	if err := json.Unmarshal([]byte(result.Content[0].Text), &driftResp); err != nil {
		t.Fatalf("result should be valid JSON: %v", err)
	}
}

func TestHandleDrift_WithIntelligence(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":          planDir,
		"plan":         planPath,
		"intelligence": true,
	})

	result, err := handleDrift(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var driftResp driftResponse
	if err := json.Unmarshal([]byte(result.Content[0].Text), &driftResp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if driftResp.Intelligence == nil {
		t.Error("expected intelligence result when flag is set")
	}
}

// --- Scan handler tests ---

func TestHandleScan_NonexistentDir(t *testing.T) {
	args := json.RawMessage(`{"dir":"/nonexistent-dir-xyz"}`)
	_, err := handleScan(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestHandleScan_WithPlanNoScanner(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"plan":   planPath,
		"static": true,
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content")
	}

	// Should be valid JSON (ReviewResult)
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("result should be valid JSON: %v", err)
	}
}

func TestHandleScan_InvalidScannerName(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":     planDir,
		"plan":    planPath,
		"scanner": "invalid_scanner_xyz",
	})

	_, err := handleScan(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid scanner")
	}
}

// --- Scan handler: static/plan/AI argument tests ---

func TestHandleScan_StaticTrueSkipsAI(t *testing.T) {
	// Override HOME so no real AI provider is found
	t.Setenv("HOME", t.TempDir())

	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"plan":   planPath,
		"static": true,
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse result and verify no AI findings
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// With static=true and no scanner, should have no findings
	findings, ok := parsed["findings"].([]interface{})
	if ok {
		for _, f := range findings {
			fm, _ := f.(map[string]interface{})
			if source, _ := fm["source"].(string); source == "ai/context" {
				t.Error("found ai/context finding with static=true — AI should have been skipped")
			}
		}
	}
}

func TestHandleScan_StaticOmittedDefaultsFalse(t *testing.T) {
	// Override HOME so no real AI provider is found (graceful degradation)
	t.Setenv("HOME", t.TempDir())

	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	// Omit "static" field — should default to false
	args, _ := json.Marshal(map[string]interface{}{
		"dir":  planDir,
		"plan": planPath,
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
}

func TestHandleScan_PlanParameterUsed(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"plan":   planPath,
		"static": true,
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse result and verify plan_file is set
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	pf, _ := parsed["plan_file"].(string)
	if pf == "" {
		t.Error("plan_file should not be empty when plan parameter is provided")
	}
	if pf != planPath {
		t.Errorf("plan_file = %q, want %q", pf, planPath)
	}
}

func TestHandleScan_PlanNonexistentFile(t *testing.T) {
	args, _ := json.Marshal(map[string]interface{}{
		"dir":    t.TempDir(),
		"plan":   "/nonexistent/path/plan.json",
		"static": true,
	})

	_, err := handleScan(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent plan file")
	}
}

func TestHandleScan_PlanAutoDetected(t *testing.T) {
	// Create a plan.json in the directory — it should be auto-detected
	planDir := createTestPlan(t)

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"static": true,
		// "plan" is omitted — should auto-detect plan.json in dir
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	pf, _ := parsed["plan_file"].(string)
	if pf == "" {
		t.Error("plan_file should not be empty — plan.json should be auto-detected")
	}
}

func TestHandleScan_StaticFalseNoProviderGracefulDegradation(t *testing.T) {
	// Override HOME so no provider is configured
	t.Setenv("HOME", t.TempDir())

	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"plan":   planPath,
		"static": false,
	})

	// Should NOT error — graceful degradation when no AI provider configured
	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
}

func TestHandleScan_CanResolveAIProviderFromConfig(t *testing.T) {
	// Test with empty provider
	cfg := config.DefaultConfig()
	cfg.LLM.Provider = ""
	if canResolveAIProviderFromConfig(cfg) {
		t.Error("should return false for empty provider")
	}

	// Test with a non-registered provider
	cfg.LLM.Provider = "nonexistent_provider_xyz"
	if canResolveAIProviderFromConfig(cfg) {
		t.Error("should return false for non-registered provider")
	}
}

func TestHandleScan_PipelineStatusIncluded(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]interface{}{
		"dir":    planDir,
		"plan":   planPath,
		"static": true,
	})

	result, err := handleScan(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	ps, ok := parsed["pipeline_status"].(map[string]interface{})
	if !ok {
		t.Fatal("expected pipeline_status in result")
	}

	completeness, _ := ps["result_completeness"].(string)
	if completeness == "" {
		t.Error("expected result_completeness in pipeline_status")
	}
}

// --- Explain handler tests ---

func TestHandleExplain_NonexistentDir(t *testing.T) {
	args := json.RawMessage(`{"dir":"/nonexistent-dir-xyz"}`)
	_, err := handleExplain(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestHandleExplain_NoProvider(t *testing.T) {
	// Override HOME so config.Load won't find the user's global .terraview.yaml
	t.Setenv("HOME", t.TempDir())

	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]string{
		"dir":  planDir,
		"plan": planPath,
	})

	_, err := handleExplain(args, testLogger())
	if err == nil {
		t.Error("expected error when no AI provider is configured")
	}
}

// --- Impact handler tests ---

func TestHandleImpact_NonexistentDir(t *testing.T) {
	args := json.RawMessage(`{"dir":"/nonexistent-dir-xyz"}`)
	_, err := handleImpact(args, testLogger())
	if err == nil {
		t.Error("expected error for nonexistent dir")
	}
}

func TestHandleImpact_WithPlanFile(t *testing.T) {
	planDir := createTestPlan(t)
	planPath := filepath.Join(planDir, "plan.json")

	args, _ := json.Marshal(map[string]string{
		"dir":  planDir,
		"plan": planPath,
	})

	result, err := handleImpact(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}

	// Verify it's valid JSON with expected fields
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := parsed["impacts"]; !ok {
		t.Error("expected impacts field in result")
	}
	if _, ok := parsed["max_radius"]; !ok {
		t.Error("expected max_radius field in result")
	}
}

// --- Cache handler tests ---

func TestHandleCache_Status(t *testing.T) {
	args := json.RawMessage(`{"action":"status"}`)
	result, err := handleCache(args, testLogger())
	if err != nil {
		// DiskStats may error on missing cache dir — skip gracefully
		t.Skipf("cache status not available: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if _, ok := parsed["cache_dir"]; !ok {
		t.Error("expected cache_dir in result")
	}
}

func TestHandleCache_DefaultAction(t *testing.T) {
	// Empty args should default to "status"
	result, err := handleCache(json.RawMessage(`{}`), testLogger())
	if err != nil {
		t.Skipf("cache status not available: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
}

func TestHandleCache_InvalidAction(t *testing.T) {
	args := json.RawMessage(`{"action":"invalid_xyz"}`)
	_, err := handleCache(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid action")
	}
}

// --- Scanners handler tests ---

func TestHandleScanners(t *testing.T) {
	result, err := handleScanners(nil, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}

	var parsed []interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(parsed) == 0 {
		t.Error("expected at least one scanner in result")
	}

	// Verify each entry has expected fields
	for _, entry := range parsed {
		m, ok := entry.(map[string]interface{})
		if !ok {
			t.Fatal("expected map entry")
		}
		if _, ok := m["name"]; !ok {
			t.Error("expected name field")
		}
		if _, ok := m["installed"]; !ok {
			t.Error("expected installed field")
		}
	}
}

// --- Version handler tests ---

func TestHandleVersion(t *testing.T) {
	result, err := handleVersion(nil, testLogger(), "1.2.3-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(result.Content[0].Text), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if v, _ := parsed["version"].(string); v != "1.2.3-test" {
		t.Errorf("version = %q, want %q", v, "1.2.3-test")
	}
	if _, ok := parsed["protocol_version"]; !ok {
		t.Error("expected protocol_version in result")
	}
	if _, ok := parsed["go_version"]; !ok {
		t.Error("expected go_version in result")
	}
}

// --- History handler tests ---

func TestHandleHistory_EmptyDB(t *testing.T) {
	// Use temp dir so DB is fresh/empty
	t.Setenv("HOME", t.TempDir())

	args := json.RawMessage(`{"dir":"/tmp/nonexistent-project"}`)
	result, err := handleHistory(args, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Content) == 0 {
		t.Error("expected content in result")
	}
}

func TestHandleHistory_InvalidSinceDate(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	args := json.RawMessage(`{"dir":".","since":"not-a-date"}`)
	_, err := handleHistory(args, testLogger())
	if err == nil {
		t.Error("expected error for invalid since date")
	}
}

func TestHandleHistoryTrend_NotEnoughRecords(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	args := json.RawMessage(`{"dir":"/tmp/nonexistent-project"}`)
	_, err := handleHistoryTrend(args, testLogger())
	if err == nil {
		t.Error("expected error when not enough records for trend")
	}
}

func TestHandleHistoryCompare_NotEnoughRecords(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	args := json.RawMessage(`{"dir":"/tmp/nonexistent-project"}`)
	_, err := handleHistoryCompare(args, testLogger())
	if err == nil {
		t.Error("expected error when not enough records to compare")
	}
}

// --- Tools list test ---

func TestAllTools_Count(t *testing.T) {
	tools := AllTools()
	expected := 11 // 4 original + 7 new
	if len(tools) != expected {
		t.Errorf("AllTools() returned %d tools, want %d", len(tools), expected)
	}
}

func TestLookupTool_NewTools(t *testing.T) {
	newTools := []string{
		"terraview_history",
		"terraview_history_trend",
		"terraview_history_compare",
		"terraview_impact",
		"terraview_cache",
		"terraview_scanners",
		"terraview_version",
	}
	for _, name := range newTools {
		if LookupTool(name) == nil {
			t.Errorf("LookupTool(%q) returned nil", name)
		}
	}
}

// --- Helpers ---

// createTestPlan creates a minimal, parseable Terraform plan JSON in a temp dir.
func createTestPlan(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	plan := map[string]interface{}{
		"format_version":    "1.2",
		"terraform_version": "1.5.0",
		"resource_changes": []map[string]interface{}{
			{
				"address":       "aws_s3_bucket.test",
				"type":          "aws_s3_bucket",
				"name":          "test",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": map[string]interface{}{
					"actions": []string{"create"},
					"after": map[string]interface{}{
						"bucket": "test-bucket",
					},
					"before": nil,
				},
			},
			{
				"address":       "aws_security_group.web",
				"type":          "aws_security_group",
				"name":          "web",
				"provider_name": "registry.terraform.io/hashicorp/aws",
				"change": map[string]interface{}{
					"actions": []string{"create"},
					"after": map[string]interface{}{
						"name": "web-sg",
						"ingress": []map[string]interface{}{
							{"from_port": 0, "to_port": 0, "protocol": "-1", "cidr_blocks": []string{"0.0.0.0/0"}},
						},
					},
					"before": nil,
				},
			},
		},
	}

	data, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatalf("marshal test plan: %v", err)
	}

	planPath := filepath.Join(dir, "plan.json")
	if err := os.WriteFile(planPath, data, 0644); err != nil {
		t.Fatalf("write test plan: %v", err)
	}

	return dir
}
