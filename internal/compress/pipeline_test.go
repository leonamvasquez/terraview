package compress

import (
	"context"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/feature"
	"github.com/leonamvasquez/terraview/internal/riskvec"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// mockLLMClient is a deterministic mock for testing.
type mockLLMClient struct {
	callCount atomic.Int64
	responses map[string]aicache.Response
	err       error
}

func newMockClient() *mockLLMClient {
	return &mockLLMClient{
		responses: map[string]aicache.Response{
			"aws_security_group": {
				RiskCategories:    []string{"security"},
				Severity:          "HIGH",
				ArchitecturalRisk: "Security group allows unrestricted inbound access",
				Remediation:       "Restrict CIDR blocks to known IP ranges",
				Confidence:        0.95,
			},
			"aws_s3_bucket": {
				RiskCategories:    []string{"security", "compliance"},
				Severity:          "HIGH",
				ArchitecturalRisk: "S3 bucket lacks encryption and public access controls",
				Remediation:       "Enable SSE-S3 or SSE-KMS encryption and block public access",
				Confidence:        0.9,
			},
			"aws_iam_policy": {
				RiskCategories:    []string{"security"},
				Severity:          "CRITICAL",
				ArchitecturalRisk: "IAM policy grants wildcard permissions",
				Remediation:       "Apply least-privilege principle",
				Confidence:        0.98,
			},
		},
	}
}

func (m *mockLLMClient) AnalyzeCompressed(_ context.Context, payload CompressedPayload) (aicache.Response, error) {
	m.callCount.Add(1)
	if m.err != nil {
		return aicache.Response{}, m.err
	}
	if resp, ok := m.responses[payload.ResourceType]; ok {
		return resp, nil
	}
	return aicache.Response{
		RiskCategories:    []string{"best-practice"},
		Severity:          "LOW",
		ArchitecturalRisk: fmt.Sprintf("Generic risk for %s", payload.ResourceType),
		Remediation:       "Review resource configuration",
		Confidence:        0.5,
	}, nil
}

func TestPipeline_SkipZeroRisk(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 2)

	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "null_resource.test",
				Provider:     "null",
				ResourceType: "null_resource",
			},
			RiskVector: riskvec.RiskVector{Total: 0},
		},
	}

	results, stats := pipeline.Run(context.Background(), scored, nil)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if !results[0].Skipped {
		t.Error("expected resource to be skipped (zero risk)")
	}
	if results[0].SkipReason != "risk-score-zero" {
		t.Errorf("expected skip reason 'risk-score-zero', got %q", results[0].SkipReason)
	}
	if stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", stats.Skipped)
	}
	if client.callCount.Load() != 0 {
		t.Error("AI should not be called for zero-risk resources")
	}
}

func TestPipeline_SkipBelowThreshold(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	policy := DefaultPolicy()
	policy.MinRiskScore = 3
	pipeline := NewPipeline(client, cache, policy, 2)

	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_instance.test",
				Provider:     "aws",
				ResourceType: "aws_instance",
			},
			RiskVector: riskvec.RiskVector{Network: 1, Total: 1},
		},
	}

	results, _ := pipeline.Run(context.Background(), scored, nil)

	if !results[0].Skipped {
		t.Error("expected resource to be skipped (below threshold)")
	}
	if client.callCount.Load() != 0 {
		t.Error("AI should not be called for below-threshold resources")
	}
}

func TestPipeline_InvokeWhenRiskAboveThreshold(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 2)

	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_security_group.open",
				Provider:     "aws",
				ResourceType: "aws_security_group",
				Flags:        []string{"wildcard-cidr"},
			},
			RiskVector: riskvec.RiskVector{Network: 3, Governance: 1, Total: 4},
		},
	}

	results, stats := pipeline.Run(context.Background(), scored, nil)

	if results[0].Skipped {
		t.Error("expected resource to be processed, not skipped")
	}
	if results[0].Error != nil {
		t.Errorf("unexpected error: %v", results[0].Error)
	}
	if results[0].Response.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", results[0].Response.Severity)
	}
	if stats.Processed != 1 {
		t.Errorf("expected 1 processed, got %d", stats.Processed)
	}
	if client.callCount.Load() != 1 {
		t.Errorf("expected 1 AI call, got %d", client.callCount.Load())
	}
}

func TestPipeline_CachePreventsDuplicateCalls(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 1) // single worker for determinism

	// Two identical resources (same type, provider, risk vector, flags)
	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_security_group.sg1",
				Provider:     "aws",
				ResourceType: "aws_security_group",
				Flags:        []string{"wildcard-cidr"},
			},
			RiskVector: riskvec.RiskVector{Network: 3, Total: 3},
		},
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_security_group.sg2",
				Provider:     "aws",
				ResourceType: "aws_security_group",
				Flags:        []string{"wildcard-cidr"},
			},
			RiskVector: riskvec.RiskVector{Network: 3, Total: 3},
		},
	}

	results, stats := pipeline.Run(context.Background(), scored, nil)

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// Both should succeed
	for i, r := range results {
		if r.Error != nil {
			t.Errorf("result %d: unexpected error: %v", i, r.Error)
		}
		if r.Skipped {
			t.Errorf("result %d: should not be skipped", i)
		}
	}

	// Client should only be called ONCE (second uses cache)
	if calls := client.callCount.Load(); calls != 1 {
		t.Errorf("expected 1 AI call (cached duplicate), got %d", calls)
	}
	if stats.CacheHits < 1 {
		t.Errorf("expected at least 1 cache hit, got %d", stats.CacheHits)
	}
}

func TestPipeline_SkipScannerCritical(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 2)

	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_iam_policy.admin",
				Provider:     "aws",
				ResourceType: "aws_iam_policy",
			},
			RiskVector: riskvec.RiskVector{Identity: 3, Total: 3},
		},
	}

	scannerFindings := []rules.Finding{
		{
			Resource: "aws_iam_policy.admin",
			Severity: "CRITICAL",
			Source:   "scanner:checkov",
		},
	}

	results, _ := pipeline.Run(context.Background(), scored, scannerFindings)

	if !results[0].Skipped {
		t.Error("expected resource to be skipped (scanner already found CRITICAL)")
	}
	if results[0].SkipReason != "scanner-critical-exists" {
		t.Errorf("expected skip reason 'scanner-critical-exists', got %q", results[0].SkipReason)
	}
}

func TestBuildPayload(t *testing.T) {
	sr := riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"no-tags", "wildcard-cidr"},
		},
		RiskVector: riskvec.RiskVector{
			Network:       3,
			Encryption:    0,
			Identity:      0,
			Governance:    1,
			Observability: 0,
		},
	}

	payload := BuildPayload(&sr)

	if payload.ResourceType != "aws_security_group" {
		t.Errorf("expected resource_type 'aws_security_group', got %q", payload.ResourceType)
	}
	if payload.RiskVector.Network != 3 {
		t.Errorf("expected network 3, got %d", payload.RiskVector.Network)
	}
	if len(payload.Flags) != 2 {
		t.Errorf("expected 2 flags, got %d", len(payload.Flags))
	}
}

func TestPayloadJSON_UnderTokenLimit(t *testing.T) {
	sr := riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"no-tags", "wildcard-cidr", "public-access"},
		},
		RiskVector: riskvec.RiskVector{
			Network:       3,
			Encryption:    2,
			Identity:      1,
			Governance:    1,
			Observability: 1,
		},
	}

	jsonStr, err := PayloadJSON(&sr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Rough token estimate: 1 token ~ 4 chars
	estimatedTokens := len(jsonStr) / 4
	if estimatedTokens > 300 {
		t.Errorf("payload exceeds 300 token estimate: ~%d tokens (%d chars)", estimatedTokens, len(jsonStr))
	}

	// Verify it's valid JSON
	var parsed CompressedPayload
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Errorf("payload is not valid JSON: %v", err)
	}
}

func TestPayloadJSON_NoRawTerraformAttributes(t *testing.T) {
	sr := riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_db_instance",
			Provider:     "aws",
			Flags:        []string{"public-access", "unencrypted"},
		},
		RiskVector: riskvec.RiskVector{
			Network:    2,
			Encryption: 3,
		},
	}

	jsonStr, err := PayloadJSON(&sr)
	if err != nil {
		t.Fatal(err)
	}

	// Ensure no terraform-specific attributes leak
	forbidden := []string{"values", "before_values", "address", "action", "provider_name"}
	for _, word := range forbidden {
		if containsStr(jsonStr, word) {
			t.Errorf("payload should not contain raw terraform attribute %q: %s", word, jsonStr)
		}
	}
}

func TestToFindings(t *testing.T) {
	results := []Result{
		{
			ResourceID: "aws_security_group.open",
			Response: aicache.Response{
				RiskCategories:    []string{"security"},
				Severity:          "HIGH",
				ArchitecturalRisk: "open SG",
				Remediation:       "fix it",
				Confidence:        0.9,
			},
		},
		{
			ResourceID: "null_resource.test",
			Skipped:    true,
			SkipReason: "risk-score-zero",
		},
	}

	scored := []riskvec.ScoredResource{
		{Features: feature.ResourceFeatures{ResourceID: "aws_security_group.open"}},
		{Features: feature.ResourceFeatures{ResourceID: "null_resource.test"}},
	}

	findings := ToFindings(results, scored, "openrouter")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (skipped excluded), got %d", len(findings))
	}

	f := findings[0]
	if f.Resource != "aws_security_group.open" {
		t.Errorf("expected resource aws_security_group.open, got %q", f.Resource)
	}
	if f.Source != "ai/openrouter" {
		t.Errorf("expected source ai/openrouter, got %q", f.Source)
	}
	if f.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", f.Severity)
	}
}

func TestPipeline_ErrorHandling(t *testing.T) {
	client := &mockLLMClient{
		err:       fmt.Errorf("connection refused"),
		responses: map[string]aicache.Response{},
	}
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 2)

	scored := []riskvec.ScoredResource{
		{
			Features: feature.ResourceFeatures{
				ResourceID:   "aws_instance.test",
				Provider:     "aws",
				ResourceType: "aws_instance",
			},
			RiskVector: riskvec.RiskVector{Network: 2, Total: 2},
		},
	}

	results, stats := pipeline.Run(context.Background(), scored, nil)

	if results[0].Error == nil {
		t.Error("expected error from failing client")
	}
	if stats.Errors != 1 {
		t.Errorf("expected 1 error, got %d", stats.Errors)
	}
}

func TestPipeline_MixedSkipAndProcess(t *testing.T) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 2)

	scored := []riskvec.ScoredResource{
		{ // Skipped: zero risk
			Features:   feature.ResourceFeatures{ResourceID: "null_resource.a", Provider: "null", ResourceType: "null_resource"},
			RiskVector: riskvec.RiskVector{Total: 0},
		},
		{ // Processed: high risk
			Features:   feature.ResourceFeatures{ResourceID: "aws_security_group.b", Provider: "aws", ResourceType: "aws_security_group"},
			RiskVector: riskvec.RiskVector{Network: 3, Total: 3},
		},
		{ // Skipped: below threshold
			Features:   feature.ResourceFeatures{ResourceID: "aws_instance.c", Provider: "aws", ResourceType: "aws_instance"},
			RiskVector: riskvec.RiskVector{Network: 1, Total: 1},
		},
	}

	results, stats := pipeline.Run(context.Background(), scored, nil)

	if !results[0].Skipped {
		t.Error("resource a should be skipped")
	}
	if results[1].Skipped {
		t.Error("resource b should be processed")
	}
	if !results[2].Skipped {
		t.Error("resource c should be skipped")
	}
	if stats.Total != 3 {
		t.Errorf("expected total 3, got %d", stats.Total)
	}
	if stats.Skipped != 2 {
		t.Errorf("expected 2 skipped, got %d", stats.Skipped)
	}
	if stats.Processed != 1 {
		t.Errorf("expected 1 processed, got %d", stats.Processed)
	}
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
