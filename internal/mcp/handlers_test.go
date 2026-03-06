package mcp

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"testing"
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
