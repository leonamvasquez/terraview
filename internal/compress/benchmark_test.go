package compress

import (
	"context"
	"fmt"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aicache"
	"github.com/leonamvasquez/terraview/internal/feature"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/riskvec"
)

// BenchmarkPipeline_10kResources verifies O(n) behavior with 10k resources.
func BenchmarkPipeline_10kResources(b *testing.B) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 8)

	scored := generate10kResources()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Reset cache for each iteration to measure worst case
		cache = aicache.NewCache()
		pipeline = NewPipeline(client, cache, DefaultPolicy(), 8)
		pipeline.Run(context.Background(), scored, nil)
	}
}

// BenchmarkPipeline_10kResources_Cached measures performance with fully cached responses.
func BenchmarkPipeline_10kResources_Cached(b *testing.B) {
	client := newMockClient()
	cache := aicache.NewCache()
	pipeline := NewPipeline(client, cache, DefaultPolicy(), 8)

	scored := generate10kResources()

	// Warm up cache
	pipeline.Run(context.Background(), scored, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pipeline.Run(context.Background(), scored, nil)
	}
}

// BenchmarkFeatureExtraction_10k measures feature extraction for 10k resources.
func BenchmarkFeatureExtraction_10k(b *testing.B) {
	resources := generate10kNormalizedResources()
	ext := feature.NewExtractor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ext.Extract(resources)
	}
}

// BenchmarkRiskScoring_10k measures risk vector scoring for 10k features.
func BenchmarkRiskScoring_10k(b *testing.B) {
	resources := generate10kNormalizedResources()
	ext := feature.NewExtractor()
	features := ext.Extract(resources)
	scorer := riskvec.NewScorer()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.Score(features)
	}
}

// BenchmarkHashKey measures hash computation performance.
func BenchmarkHashKey(b *testing.B) {
	sr := riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"no-tags", "public-access", "wildcard-cidr"},
		},
		RiskVector: riskvec.RiskVector{Network: 3, Governance: 1},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aicache.HashKey(&sr)
	}
}

func generate10kResources() []riskvec.ScoredResource {
	types := []string{
		"aws_security_group", "aws_s3_bucket", "aws_instance",
		"aws_iam_policy", "aws_db_instance", "aws_ebs_volume",
		"azurerm_virtual_machine", "google_compute_instance",
	}

	scored := make([]riskvec.ScoredResource, 10000)
	for i := 0; i < 10000; i++ {
		rt := types[i%len(types)]
		risk := (i % 4) // 0-3, cycles through different risk levels

		scored[i] = riskvec.ScoredResource{
			Features: feature.ResourceFeatures{
				ResourceID:   fmt.Sprintf("%s.resource_%d", rt, i),
				Provider:     "aws",
				ResourceType: rt,
				Flags:        []string{"no-tags"},
			},
			RiskVector: riskvec.RiskVector{
				Network: risk,
				Total:   risk,
			},
		}
	}
	return scored
}

func generate10kNormalizedResources() []parser.NormalizedResource {
	types := []string{
		"aws_security_group", "aws_s3_bucket", "aws_instance",
		"aws_iam_policy", "aws_db_instance", "aws_ebs_volume",
		"azurerm_virtual_machine", "google_compute_instance",
	}

	resources := make([]parser.NormalizedResource, 10000)
	for i := 0; i < 10000; i++ {
		rt := types[i%len(types)]
		resources[i] = parser.NormalizedResource{
			Address:  fmt.Sprintf("%s.resource_%d", rt, i),
			Type:     rt,
			Name:     fmt.Sprintf("resource_%d", i),
			Provider: "aws",
			Values: map[string]interface{}{
				"tags": map[string]interface{}{"env": "test"},
			},
		}
	}
	return resources
}
