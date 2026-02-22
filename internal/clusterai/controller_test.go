package clusterai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/cluster"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ────────────────────── Mock Provider ──────────────────────

type mockProvider struct {
	callCount atomic.Int64
	responses map[string]string // mode → raw response
	err       error
}

func newMockProvider() *mockProvider {
	enrichResp, _ := json.Marshal(EnrichmentResponse{
		RemediationImprovements: "Apply least-privilege IAM policies and enable encryption at rest",
		ArchitecturalNotes:      "Cluster has multiple security-sensitive resources needing hardening",
		Confidence:              0.92,
	})
	fullResp, _ := json.Marshal(FullAnalysisResponse{
		RiskCategories:    []string{"security"},
		Severity:          "HIGH",
		ArchitecturalRisk: "Unrestricted network access combined with missing encryption",
		Remediation:       "Restrict CIDR blocks and enable server-side encryption",
		Confidence:        0.95,
	})

	return &mockProvider{
		responses: map[string]string{
			"enrichment_only": string(enrichResp),
			"full_analysis":   string(fullResp),
		},
	}
}

func (m *mockProvider) Name() string { return "mock" }

func (m *mockProvider) Validate(_ context.Context) error { return nil }

func (m *mockProvider) Analyze(_ context.Context, req ai.Request) (ai.Completion, error) {
	m.callCount.Add(1)
	if m.err != nil {
		return ai.Completion{}, m.err
	}

	mode, _ := req.Summary["mode"].(string)
	resp, ok := m.responses[mode]
	if !ok {
		resp = m.responses["enrichment_only"]
	}

	return ai.Completion{
		Summary:  resp,
		Model:    "mock-model",
		Provider: "mock",
	}, nil
}

// ────────────────────── Cluster Builders ──────────────────────

func makeCluster(id string, findings []rules.Finding, sources []string) cluster.RiskCluster {
	resources := []string{id}
	return cluster.RiskCluster{
		ID:          id,
		Resources:   resources,
		Findings:    findings,
		Sources:     sources,
		Severity:    highestSev(findings),
		SourceCount: len(sources),
	}
}

func highestSev(findings []rules.Finding) string {
	rank := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	best := "INFO"
	bestR := 0
	for _, f := range findings {
		if r := rank[f.Severity]; r > bestR {
			bestR = r
			best = f.Severity
		}
	}
	return best
}

func makeFinding(sev, resource, source, category, msg string) rules.Finding {
	return rules.Finding{
		RuleID:   fmt.Sprintf("TEST-%s", sev),
		Severity: sev,
		Resource: resource,
		Source:   source,
		Category: category,
		Message:  msg,
	}
}

// ────────────────────── Test: Cluster Generation ──────────────

func TestClusterGeneration(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("HIGH", "aws_security_group.open", "scanner:checkov", "security", "SG allows 0.0.0.0/0"),
		makeFinding("MEDIUM", "aws_security_group.open", "scanner:checkov", "security", "SG missing tags"),
		makeFinding("HIGH", "aws_s3_bucket.data", "scanner:checkov", "security", "S3 bucket unencrypted"),
	}

	builder := cluster.NewBuilder()
	result := builder.Build(findings)

	if len(result.Clusters) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(result.Clusters))
	}

	if result.TotalFindings != 3 {
		t.Errorf("expected 3 total findings, got %d", result.TotalFindings)
	}
}

// ────────────────────── Test: Mode Selection ──────────────────

func TestDetermineMode_EnrichmentOnly_HighScannerFindings(t *testing.T) {
	// >=5 HIGH findings from scanner only → enrichment_only
	var findings []rules.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security",
			fmt.Sprintf("Finding %d: SG allows unrestricted access", i)))
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})

	mode := DetermineMode(&rc)
	if mode != ModeEnrichmentOnly {
		t.Errorf("expected enrichment_only for >=5 HIGH scanner findings, got %s", mode)
	}
}

func TestDetermineMode_EnrichmentOnly_MixedSources(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "Scanner found issue"),
		makeFinding("MEDIUM", "aws_sg.open", "ai/openrouter", "security", "AI found issue"),
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov", "ai/openrouter"})

	mode := DetermineMode(&rc)
	if mode != ModeEnrichmentOnly {
		t.Errorf("expected enrichment_only for mixed sources, got %s", mode)
	}
}

func TestDetermineMode_FullAnalysis_NoScannerFindings(t *testing.T) {
	// No scanner findings but risk flags detected → full_analysis
	findings := []rules.Finding{
		makeFinding("HIGH", "aws_instance.web", "ai/gemini", "security", "Risk detected via AI only"),
	}
	rc := makeCluster("aws_instance.web", findings, []string{"ai/gemini"})

	mode := DetermineMode(&rc)
	if mode != ModeFullAnalysis {
		t.Errorf("expected full_analysis for AI-only findings, got %s", mode)
	}
}

func TestDetermineMode_Skip_LowSeverityOnly(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("LOW", "null_resource.test", "scanner:checkov", "best-practice", "Low severity issue"),
		makeFinding("INFO", "null_resource.test", "scanner:checkov", "best-practice", "Info only"),
	}
	rc := makeCluster("null_resource.test", findings, []string{"scanner:checkov"})

	mode := DetermineMode(&rc)
	if mode != ModeSkip {
		t.Errorf("expected skip for LOW/INFO only cluster, got %s", mode)
	}
}

func TestDetermineMode_EnrichmentOnly_ScannerMediumFindings(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("MEDIUM", "aws_s3.bucket", "scanner:checkov", "compliance", "S3 versioning disabled"),
	}
	rc := makeCluster("aws_s3_bucket.data", findings, []string{"scanner:checkov"})

	mode := DetermineMode(&rc)
	if mode != ModeEnrichmentOnly {
		t.Errorf("expected enrichment_only for MEDIUM scanner findings, got %s", mode)
	}
}

// ────────────────────── Test: Cluster Hash ──────────────────

func TestClusterHash_Deterministic(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG open"),
		makeFinding("MEDIUM", "aws_sg.open", "scanner:checkov", "compliance", "Missing tags"),
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})

	hash1 := ClusterHash(&rc)
	hash2 := ClusterHash(&rc)

	if hash1 != hash2 {
		t.Errorf("hash not deterministic: %q != %q", hash1, hash2)
	}
	if len(hash1) != 64 { // SHA256 hex length
		t.Errorf("expected 64 char hex hash, got %d", len(hash1))
	}
}

func TestClusterHash_DifferentClusters(t *testing.T) {
	rc1 := makeCluster("aws_security_group.open",
		[]rules.Finding{makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "open")},
		[]string{"scanner:checkov"})

	rc2 := makeCluster("aws_s3_bucket.data",
		[]rules.Finding{makeFinding("HIGH", "aws_s3.data", "scanner:checkov", "security", "unencrypted")},
		[]string{"scanner:checkov"})

	if ClusterHash(&rc1) == ClusterHash(&rc2) {
		t.Error("different clusters should have different hashes")
	}
}

// ────────────────────── Test: Cache Reuse ──────────────────

func TestCache_ReusePreventsSecondAICall(t *testing.T) {
	provider := newMockProvider()
	cache := NewClusterCache()
	ctrl := NewController(provider, cache, 1)

	findings := []rules.Finding{
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG open to 0.0.0.0/0"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG missing tags"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG allows all egress"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG unrestricted ingress"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG wide open"),
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})
	clusters := []cluster.RiskCluster{rc}

	// First run
	results1, _ := ctrl.Run(context.Background(), clusters)
	callsAfterFirst := provider.callCount.Load()

	if results1[0].Error != nil {
		t.Fatalf("unexpected error: %v", results1[0].Error)
	}

	// Second run — should use cache
	results2, stats2 := ctrl.Run(context.Background(), clusters)
	callsAfterSecond := provider.callCount.Load()

	if callsAfterSecond != callsAfterFirst {
		t.Errorf("expected no additional AI calls (cached), but got %d extra", callsAfterSecond-callsAfterFirst)
	}
	if !results2[0].CacheHit {
		t.Error("expected cache hit on second run")
	}
	if stats2.CacheHits != 1 {
		t.Errorf("expected 1 cache hit, got %d", stats2.CacheHits)
	}
}

// ────────────────────── Test: Explain Does Not Trigger AI ──────

func TestExplain_DoesNotTriggerAI(t *testing.T) {
	provider := newMockProvider()
	cache := NewClusterCache()
	ctrl := NewController(provider, cache, 1)

	// Pre-populate cache with results
	findings := []rules.Finding{
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG open"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG wide"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG unrestricted"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG no tags"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "SG missing ACL"),
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})

	// Run once to populate cache
	ctrl.Run(context.Background(), []cluster.RiskCluster{rc})
	callsAfterRun := provider.callCount.Load()

	// Now simulate --explain: just reuse cached results
	summary := GenerateExplainSummary(cache)
	callsAfterExplain := provider.callCount.Load()

	if callsAfterExplain != callsAfterRun {
		t.Errorf("explain triggered %d additional AI calls", callsAfterExplain-callsAfterRun)
	}
	if summary == "" {
		t.Error("expected non-empty explain summary from cache")
	}
}

// ────────────────────── Test: Controller Run ──────────────────

func TestController_SkipsLowSeverity(t *testing.T) {
	provider := newMockProvider()
	ctrl := NewController(provider, nil, 2)

	rc := makeCluster("null_resource.test",
		[]rules.Finding{makeFinding("LOW", "null_resource.test", "scanner:checkov", "best-practice", "Low issue")},
		[]string{"scanner:checkov"})

	results, stats := ctrl.Run(context.Background(), []cluster.RiskCluster{rc})

	if !isSkipped(results[0]) {
		t.Error("expected cluster to be skipped")
	}
	if stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", stats.Skipped)
	}
	if provider.callCount.Load() != 0 {
		t.Error("AI should not be called for low-severity clusters")
	}
}

func TestController_EnrichmentMode(t *testing.T) {
	provider := newMockProvider()
	ctrl := NewController(provider, nil, 2)

	var findings []rules.Finding
	for i := 0; i < 5; i++ {
		findings = append(findings, makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security",
			fmt.Sprintf("issue %d", i)))
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})

	results, stats := ctrl.Run(context.Background(), []cluster.RiskCluster{rc})

	if results[0].Mode != ModeEnrichmentOnly {
		t.Errorf("expected enrichment_only mode, got %s", results[0].Mode)
	}
	if results[0].Enrichment == nil {
		t.Fatal("expected enrichment response")
	}
	if results[0].Enrichment.Confidence <= 0 {
		t.Error("expected positive confidence")
	}
	if stats.Enriched != 1 {
		t.Errorf("expected 1 enriched, got %d", stats.Enriched)
	}
}

func TestController_FullAnalysisMode(t *testing.T) {
	provider := newMockProvider()
	ctrl := NewController(provider, nil, 2)

	findings := []rules.Finding{
		makeFinding("HIGH", "aws_instance.web", "ai/gemini", "security", "Network risk detected"),
	}
	rc := makeCluster("aws_instance.web", findings, []string{"ai/gemini"})

	results, stats := ctrl.Run(context.Background(), []cluster.RiskCluster{rc})

	if results[0].Mode != ModeFullAnalysis {
		t.Errorf("expected full_analysis mode, got %s", results[0].Mode)
	}
	if results[0].FullResult == nil {
		t.Fatal("expected full analysis response")
	}
	if results[0].FullResult.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", results[0].FullResult.Severity)
	}
	if stats.FullAnalysis != 1 {
		t.Errorf("expected 1 full analysis, got %d", stats.FullAnalysis)
	}
}

func TestController_ErrorHandling(t *testing.T) {
	provider := &mockProvider{
		err:       fmt.Errorf("connection refused"),
		responses: map[string]string{},
	}
	ctrl := NewController(provider, nil, 2)

	findings := []rules.Finding{
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "issue"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "issue2"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "issue3"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "issue4"),
		makeFinding("HIGH", "aws_sg.open", "scanner:checkov", "security", "issue5"),
	}
	rc := makeCluster("aws_security_group.open", findings, []string{"scanner:checkov"})

	results, stats := ctrl.Run(context.Background(), []cluster.RiskCluster{rc})

	if results[0].Error == nil {
		t.Error("expected error from failing provider")
	}
	if stats.Errors != 1 {
		t.Errorf("expected 1 error, got %d", stats.Errors)
	}
}

func TestController_MixedClusters(t *testing.T) {
	provider := newMockProvider()
	ctrl := NewController(provider, nil, 2)

	clusters := []cluster.RiskCluster{
		// Skipped: LOW only
		makeCluster("null_resource.skip",
			[]rules.Finding{makeFinding("LOW", "null_resource.skip", "scanner:checkov", "best-practice", "low")},
			[]string{"scanner:checkov"}),

		// Enrichment: >=5 HIGH from scanner
		makeCluster("aws_security_group.enrich",
			func() []rules.Finding {
				var f []rules.Finding
				for i := 0; i < 5; i++ {
					f = append(f, makeFinding("HIGH", "aws_sg.enrich", "scanner:checkov", "security", fmt.Sprintf("h%d", i)))
				}
				return f
			}(),
			[]string{"scanner:checkov"}),

		// Full analysis: AI only source
		makeCluster("aws_instance.full",
			[]rules.Finding{makeFinding("HIGH", "aws_instance.full", "ai/openrouter", "security", "risk")},
			[]string{"ai/openrouter"}),
	}

	results, stats := ctrl.Run(context.Background(), clusters)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	if !isSkipped(results[0]) {
		t.Error("cluster 0 should be skipped")
	}
	if results[1].Mode != ModeEnrichmentOnly {
		t.Errorf("cluster 1 should be enrichment_only, got %s", results[1].Mode)
	}
	if results[2].Mode != ModeFullAnalysis {
		t.Errorf("cluster 2 should be full_analysis, got %s", results[2].Mode)
	}

	if stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", stats.Skipped)
	}
	if stats.Enriched != 1 {
		t.Errorf("expected 1 enriched, got %d", stats.Enriched)
	}
	if stats.FullAnalysis != 1 {
		t.Errorf("expected 1 full analysis, got %d", stats.FullAnalysis)
	}
}

// ────────────────────── Test: ToFindings ──────────────────

func TestToFindings(t *testing.T) {
	results := []ClusterResult{
		{
			ClusterID: "aws_security_group.open",
			Mode:      ModeEnrichmentOnly,
			Enrichment: &EnrichmentResponse{
				RemediationImprovements: "Apply least-privilege IAM",
				ArchitecturalNotes:      "Cluster needs hardening",
				Confidence:              0.9,
			},
		},
		{
			ClusterID: "aws_instance.web",
			Mode:      ModeFullAnalysis,
			FullResult: &FullAnalysisResponse{
				RiskCategories:    []string{"security"},
				Severity:          "HIGH",
				ArchitecturalRisk: "Unrestricted access",
				Remediation:       "Restrict CIDR blocks",
				Confidence:        0.95,
			},
		},
		{
			ClusterID:  "null_resource.test",
			Mode:       ModeSkip,
			SkipReason: "low-severity-only",
		},
	}

	clusters := []cluster.RiskCluster{
		{ID: "aws_security_group.open", Resources: []string{"aws_security_group.open"}},
		{ID: "aws_instance.web", Resources: []string{"aws_instance.web"}},
		{ID: "null_resource.test", Resources: []string{"null_resource.test"}},
	}

	findings := ToFindings(results, clusters, "openrouter")

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings (skipped excluded), got %d", len(findings))
	}

	// Enrichment finding
	if findings[0].Severity != "INFO" {
		t.Errorf("enrichment finding should be INFO, got %q", findings[0].Severity)
	}
	if !strings.Contains(findings[0].Source, "ai/openrouter") {
		t.Errorf("expected source ai/openrouter, got %q", findings[0].Source)
	}

	// Full analysis finding
	if findings[1].Severity != "HIGH" {
		t.Errorf("full analysis finding should be HIGH, got %q", findings[1].Severity)
	}
	if findings[1].Category != "security" {
		t.Errorf("expected category security, got %q", findings[1].Category)
	}
}

// ────────────────────── Test: Concurrency Safety ──────────────

func TestCache_ConcurrencySafety(t *testing.T) {
	cache := NewClusterCache()
	var wg sync.WaitGroup
	const goroutines = 250

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("cluster-%d", n%10)
			if _, ok := cache.Get(key); !ok {
				cache.Put(key, CachedClusterResult{
					Mode: ModeEnrichmentOnly,
					Enrichment: &EnrichmentResponse{
						RemediationImprovements: "fix it",
						Confidence:              0.9,
					},
				})
			}
		}(i)
	}

	wg.Wait()

	_, _, size := cache.Stats()
	if size != 10 {
		t.Errorf("expected 10 unique keys, got %d", size)
	}
}

// ────────────────────── Test: Helper Functions ──────────────

func TestDetectClusterProvider(t *testing.T) {
	tests := []struct {
		id       string
		resources []string
		want     string
	}{
		{"aws_security_group.open", []string{"aws_security_group.open"}, "aws"},
		{"azurerm_virtual_machine.vm", []string{"azurerm_virtual_machine.vm"}, "azure"},
		{"google_compute_instance.web", []string{"google_compute_instance.web"}, "gcp"},
		{"null_resource.test", []string{"null_resource.test"}, "unknown"},
	}

	for _, tt := range tests {
		rc := cluster.RiskCluster{ID: tt.id, Resources: tt.resources}
		got := detectClusterProvider(&rc)
		if got != tt.want {
			t.Errorf("detectClusterProvider(%q) = %q, want %q", tt.id, got, tt.want)
		}
	}
}

func TestDetectClusterType(t *testing.T) {
	rc := cluster.RiskCluster{ID: "aws_security_group.open"}
	got := detectClusterType(&rc)
	if got != "aws_security_group" {
		t.Errorf("expected aws_security_group, got %q", got)
	}
}

func TestSeverityDistribution(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("HIGH", "r", "s", "c", "m"),
		makeFinding("HIGH", "r", "s", "c", "m"),
		makeFinding("MEDIUM", "r", "s", "c", "m"),
		makeFinding("LOW", "r", "s", "c", "m"),
	}
	dist := severityDistribution(findings)
	if dist["HIGH"] != 2 {
		t.Errorf("expected HIGH=2, got %d", dist["HIGH"])
	}
	if dist["MEDIUM"] != 1 {
		t.Errorf("expected MEDIUM=1, got %d", dist["MEDIUM"])
	}
}

func TestCollectCategories(t *testing.T) {
	findings := []rules.Finding{
		makeFinding("HIGH", "r", "s", "security", "m"),
		makeFinding("HIGH", "r", "s", "compliance", "m"),
		makeFinding("HIGH", "r", "s", "security", "m"),
	}
	cats := collectCategories(findings)
	if len(cats) != 2 {
		t.Errorf("expected 2 unique categories, got %d", len(cats))
	}
}

func TestGenerateExplainSummary(t *testing.T) {
	cache := NewClusterCache()
	cache.Put("key1", CachedClusterResult{
		Mode: ModeEnrichmentOnly,
		Enrichment: &EnrichmentResponse{
			RemediationImprovements: "fix it",
			ArchitecturalNotes:      "needs hardening",
			Confidence:              0.9,
		},
	})
	cache.Put("key2", CachedClusterResult{
		Mode: ModeFullAnalysis,
		FullResult: &FullAnalysisResponse{
			Severity:          "HIGH",
			ArchitecturalRisk: "open access",
			Remediation:       "close it",
			Confidence:        0.95,
		},
	})

	summary := GenerateExplainSummary(cache)
	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if !strings.Contains(summary, "enriched") && !strings.Contains(summary, "analyzed") {
		t.Error("summary should mention enriched/analyzed counts")
	}
}

func isSkipped(r ClusterResult) bool {
	return r.Mode == ModeSkip
}
