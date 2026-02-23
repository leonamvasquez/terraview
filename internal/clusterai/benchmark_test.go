package clusterai

import (
	"context"
	"fmt"
	"testing"

	"github.com/leonamvasquez/terraview/internal/cluster"
	"github.com/leonamvasquez/terraview/internal/rules"
)

// ────────────────────── Benchmark: 10k Findings ──────────────

func BenchmarkController_10kFindings(b *testing.B) {
	provider := newMockProvider()

	// Generate 10k findings across 200 clusters (50 findings each)
	var allFindings []rules.Finding
	for i := 0; i < 200; i++ {
		resType := "aws_security_group"
		switch i % 3 {
		case 1:
			resType = "aws_s3_bucket"
		case 2:
			resType = "aws_instance"
		}
		resource := fmt.Sprintf("%s.resource_%d", resType, i)

		for j := 0; j < 50; j++ {
			sev := "HIGH"
			if j%5 == 0 {
				sev = "CRITICAL"
			} else if j%3 == 0 {
				sev = "MEDIUM"
			}
			allFindings = append(allFindings, rules.Finding{
				RuleID:   fmt.Sprintf("TEST-%d-%d", i, j),
				Severity: sev,
				Resource: resource,
				Source:   "scanner:checkov",
				Category: "security",
				Message:  fmt.Sprintf("Finding %d for %s: unrestricted access detected", j, resource),
			})
		}
	}

	builder := cluster.NewBuilder()
	result := builder.Build(allFindings)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ctrl := NewController(provider, nil, 4)
		ctrl.Run(context.Background(), result.Clusters)
	}
}

// ────────────────────── Benchmark: ClusterHash ──────────────

func BenchmarkClusterHash(b *testing.B) {
	var findings []rules.Finding
	for i := 0; i < 50; i++ {
		findings = append(findings, rules.Finding{
			RuleID:   fmt.Sprintf("BENCH-%d", i),
			Severity: "HIGH",
			Resource: "aws_security_group.bench",
			Source:   "scanner:checkov",
			Category: "security",
			Message:  fmt.Sprintf("Finding %d: security issue", i),
		})
	}
	rc := makeCluster("aws_security_group.bench", findings, []string{"scanner:checkov"})

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ClusterHash(&rc)
	}
}

// ────────────────────── Benchmark: DetermineMode ──────────────

func BenchmarkDetermineMode(b *testing.B) {
	var findings []rules.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, rules.Finding{
			RuleID:   fmt.Sprintf("BENCH-%d", i),
			Severity: "HIGH",
			Resource: "aws_sg.bench",
			Source:   "scanner:checkov",
			Category: "security",
			Message:  fmt.Sprintf("Finding %d", i),
		})
	}
	rc := makeCluster("aws_security_group.bench", findings, []string{"scanner:checkov"})

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		DetermineMode(&rc)
	}
}

// ────────────────────── Benchmark: Cache Operations ──────────

func BenchmarkCache_PutGet(b *testing.B) {
	cache := NewClusterCache()
	cached := CachedClusterResult{
		Mode: ModeEnrichmentOnly,
		Enrichment: &EnrichmentResponse{
			RemediationImprovements: "fix it",
			Confidence:              0.9,
		},
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		key := fmt.Sprintf("key-%d", n%1000)
		cache.Put(key, cached)
		cache.Get(key)
	}
}

// ────────────────────── Benchmark: ToFindings ──────────────

func BenchmarkToFindings(b *testing.B) {
	var results []ClusterResult
	var clusters []cluster.RiskCluster
	for i := 0; i < 100; i++ {
		id := fmt.Sprintf("aws_security_group.resource_%d", i)
		if i%2 == 0 {
			results = append(results, ClusterResult{
				ClusterID: id,
				Mode:      ModeEnrichmentOnly,
				Enrichment: &EnrichmentResponse{
					RemediationImprovements: "Apply least-privilege IAM",
					ArchitecturalNotes:      "Needs hardening",
					Confidence:              0.9,
				},
			})
		} else {
			results = append(results, ClusterResult{
				ClusterID: id,
				Mode:      ModeFullAnalysis,
				FullResult: &FullAnalysisResponse{
					RiskCategories:    []string{"security"},
					Severity:          "HIGH",
					ArchitecturalRisk: "Unrestricted access",
					Remediation:       "Restrict CIDRs",
					Confidence:        0.95,
				},
			})
		}
		clusters = append(clusters, cluster.RiskCluster{
			ID:        id,
			Resources: []string{id},
		})
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		ToFindings(results, clusters, "openrouter")
	}
}
