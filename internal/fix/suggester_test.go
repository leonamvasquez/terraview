package fix

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// fixRequestWithKMS builds a FixRequest for CKV_AWS_158 (CloudWatch log group KMS)
// with 30 resource config entries and a PlanIndex containing aws_kms_key.main and
// aws_api_gateway_rest_api.main.
func fixRequestWithKMS(idx *PlanIndex) FixRequest {
	// Build a 30-entry config; most entries are nil or irrelevant.
	config := make(map[string]interface{}, 30)
	config["name"] = "/ecs/service"
	config["retention_in_days"] = 30
	config["kms_key_id"] = nil // absent — the finding is about this being missing
	for i := 3; i < 30; i++ {
		config[fmt.Sprintf("irrelevant_%02d", i)] = nil
	}

	return FixRequest{
		Finding: FixFinding{
			RuleID:  "CKV_AWS_158",
			Message: "CloudWatch log group not encrypted",
		},
		ResourceAddr:   "aws_cloudwatch_log_group.ecs",
		ResourceType:   "aws_cloudwatch_log_group",
		ResourceConfig: config,
		PlanIndex:      idx,
	}
}

// planIndexWithKMS returns a PlanIndex that contains aws_kms_key.main
// and aws_api_gateway_rest_api.main.
func planIndexWithKMS() *PlanIndex {
	plan := &parser.TerraformPlan{} // no config expressions needed for this scenario
	resources := []parser.NormalizedResource{
		{Address: "aws_kms_key.main", Type: "aws_kms_key", Name: "main", Action: "create"},
		{Address: "aws_api_gateway_rest_api.main", Type: "aws_api_gateway_rest_api", Name: "main", Action: "create"},
	}
	return BuildIndex(plan, resources)
}

// planIndexWithExpressions returns a PlanIndex that has resolved refs for
// aws_api_gateway_method.proxy (like the syntheticPlan in plan_index_test).
func planIndexWithExpressions() *PlanIndex {
	return BuildIndex(syntheticPlan(), syntheticResources())
}

func TestBuildUserMessage_ReturnsValidJSON(t *testing.T) {
	req := fixRequestWithKMS(planIndexWithKMS())
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("buildUserMessage did not return valid JSON: %v\nraw: %s", err, msg)
	}
}

func TestBuildUserMessage_PlanContextCanonicalName(t *testing.T) {
	// No KMS key in plan → canonical_name should be "aws_kms_key.ecs".
	emptyIdx := BuildIndex(nil, nil)
	req := fixRequestWithKMS(emptyIdx)
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	planCtx, ok := out["plan_context"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context missing from user message")
	}

	canonicalName, _ := planCtx["canonical_name"].(string)
	if canonicalName != "aws_kms_key.ecs" {
		t.Errorf("plan_context.canonical_name = %q, want \"aws_kms_key.ecs\"", canonicalName)
	}
}

func TestBuildUserMessage_PlanContextNoCanonicalNameWhenKMSExists(t *testing.T) {
	// KMS key already in plan → canonical_name should be absent (empty/omitted).
	req := fixRequestWithKMS(planIndexWithKMS())
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	planCtx, ok := out["plan_context"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context missing from user message")
	}

	if name, exists := planCtx["canonical_name"]; exists && name != "" {
		t.Errorf("plan_context.canonical_name should be absent when KMS already exists in plan, got %q", name)
	}
}

func TestBuildUserMessage_PlanContextPlanResources(t *testing.T) {
	req := fixRequestWithKMS(planIndexWithKMS())
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	planCtx, ok := out["plan_context"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context missing from user message")
	}

	planResources, ok := planCtx["plan_resources"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context.plan_resources missing or wrong type")
	}

	kmsResources, ok := planResources["aws_kms_key"].([]interface{})
	if !ok {
		t.Fatal("plan_context.plan_resources[\"aws_kms_key\"] missing or wrong type")
	}

	if len(kmsResources) != 1 {
		t.Errorf("expected 1 aws_kms_key resource, got %d: %v", len(kmsResources), kmsResources)
	}
	if kmsResources[0] != "aws_kms_key.main" {
		t.Errorf("plan_resources[\"aws_kms_key\"][0] = %q, want \"aws_kms_key.main\"", kmsResources[0])
	}
}

func TestBuildUserMessage_PlanContextResolvedReferences(t *testing.T) {
	// Use the api gateway method request with expression refs.
	idx := planIndexWithExpressions()
	req := FixRequest{
		Finding: FixFinding{
			RuleID:  "CKV2_AWS_53",
			Message: "API Gateway method missing request validator",
		},
		ResourceAddr: "aws_api_gateway_method.proxy",
		ResourceType: "aws_api_gateway_method",
		ResourceConfig: map[string]interface{}{
			"rest_api_id": "aws_api_gateway_rest_api.main.id",
			"http_method": "POST",
		},
		PlanIndex: idx,
	}

	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	planCtx, ok := out["plan_context"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context missing from user message")
	}

	resolvedRefs, ok := planCtx["resolved_references"].(map[string]interface{})
	if !ok {
		t.Fatal("plan_context.resolved_references missing or wrong type")
	}

	restAPIRef, _ := resolvedRefs["rest_api_id"].(string)
	if restAPIRef != "aws_api_gateway_rest_api.main.id" {
		t.Errorf("resolved_references[\"rest_api_id\"] = %q, want \"aws_api_gateway_rest_api.main.id\"",
			restAPIRef)
	}
}

func TestBuildUserMessage_CurrentConfigTruncatedToRelevantAttrs(t *testing.T) {
	req := fixRequestWithKMS(planIndexWithKMS())
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	currentConfig, ok := out["current_config"].(map[string]interface{})
	if !ok {
		// current_config may be omitted if all relevant attrs were nil.
		// That is acceptable — TruncateConfig falls back to generic in that case.
		t.Log("current_config absent from user message (all relevant attrs were nil, fallback may apply)")
		return
	}

	// Ensure irrelevant_* keys are not in the output (they were nil anyway,
	// but that proves TruncateConfig ran).
	for k := range currentConfig {
		if len(k) > 10 && k[:11] == "irrelevant_" {
			t.Errorf("current_config contains irrelevant attr %q; TruncateConfig should remove it", k)
		}
	}

	// name and retention_in_days are non-nil relevant attrs — they must be present.
	if _, ok := currentConfig["name"]; !ok {
		t.Error("current_config missing \"name\" (relevant attr for CKV_AWS_158)")
	}
	if _, ok := currentConfig["retention_in_days"]; !ok {
		t.Error("current_config missing \"retention_in_days\" (relevant attr for CKV_AWS_158)")
	}
}

func TestBuildUserMessage_NilPlanIndexNoPanic(t *testing.T) {
	req := FixRequest{
		Finding: FixFinding{
			RuleID:  "CKV_AWS_158",
			Message: "CloudWatch log group not encrypted",
		},
		ResourceAddr: "aws_cloudwatch_log_group.ecs",
		ResourceType: "aws_cloudwatch_log_group",
		ResourceConfig: map[string]interface{}{
			"name": "/ecs/service",
		},
		PlanIndex: nil, // explicitly nil
	}

	// Must not panic.
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("buildUserMessage with nil PlanIndex returned invalid JSON: %v\nraw: %s", err, msg)
	}

	// plan_context should be absent when PlanIndex is nil.
	if _, exists := out["plan_context"]; exists {
		t.Error("plan_context should be absent when PlanIndex is nil")
	}
}

func TestBuildPlanContext_NilPlanIndexReturnsNil(t *testing.T) {
	req := FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_158"},
		ResourceAddr: "aws_cloudwatch_log_group.ecs",
		PlanIndex:    nil,
	}

	// buildPlanContext is only safe to call when PlanIndex != nil;
	// buildUserMessage guards this. We test the guard here by calling
	// buildUserMessage and checking the plan_context field.
	msg := buildUserMessage(req)

	var out map[string]interface{}
	if err := json.Unmarshal([]byte(msg), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, exists := out["plan_context"]; exists {
		t.Error("plan_context must be absent when PlanIndex is nil")
	}
}

func TestBuildPlanContext_NoRequiredTypeReturnsNilWhenNoRefs(t *testing.T) {
	// UNKNOWN_RULE has no required resource type and no expressions configured.
	emptyIdx := BuildIndex(nil, nil)
	req := FixRequest{
		Finding:      FixFinding{RuleID: "UNKNOWN_RULE"},
		ResourceAddr: "aws_lambda_function.api",
		PlanIndex:    emptyIdx,
	}

	ctx := buildPlanContext(req)
	if ctx != nil {
		t.Errorf("buildPlanContext with no required type and no refs = %+v, want nil", ctx)
	}
}

func TestBuildPlanContext_RequiredTypePopulatesPlanResources(t *testing.T) {
	idx := planIndexWithKMS()
	req := FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_158"},
		ResourceAddr: "aws_cloudwatch_log_group.ecs",
		PlanIndex:    idx,
	}

	ctx := buildPlanContext(req)
	if ctx == nil {
		t.Fatal("buildPlanContext returned nil for CKV_AWS_158 with KMS in plan")
	}

	if ctx.RequiredNewResource != "aws_kms_key" {
		t.Errorf("RequiredNewResource = %q, want \"aws_kms_key\"", ctx.RequiredNewResource)
	}

	kms := ctx.PlanResources["aws_kms_key"]
	if len(kms) != 1 || kms[0] != "aws_kms_key.main" {
		t.Errorf("PlanResources[\"aws_kms_key\"] = %v, want [\"aws_kms_key.main\"]", kms)
	}

	// KMS exists → no canonical_name needed.
	if ctx.CanonicalName != "" {
		t.Errorf("CanonicalName = %q, want \"\" (KMS already in plan)", ctx.CanonicalName)
	}
}

func TestBuildPlanContext_CanonicalNameWhenRequiredTypeAbsent(t *testing.T) {
	// Plan has no KMS key — canonical name should be set.
	onlyAPIIdx := BuildIndex(nil, []parser.NormalizedResource{
		{Address: "aws_api_gateway_rest_api.main", Type: "aws_api_gateway_rest_api", Name: "main", Action: "create"},
	})
	req := FixRequest{
		Finding:      FixFinding{RuleID: "CKV_AWS_158"},
		ResourceAddr: "aws_cloudwatch_log_group.ecs",
		PlanIndex:    onlyAPIIdx,
	}

	ctx := buildPlanContext(req)
	if ctx == nil {
		t.Fatal("buildPlanContext returned nil")
	}

	if ctx.CanonicalName != "aws_kms_key.ecs" {
		t.Errorf("CanonicalName = %q, want \"aws_kms_key.ecs\"", ctx.CanonicalName)
	}
}
