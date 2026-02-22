package aicache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/leonamvasquez/terraview/internal/feature"
	"github.com/leonamvasquez/terraview/internal/riskvec"
)

func TestHashKey_Deterministic(t *testing.T) {
	sr := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"wildcard-cidr", "no-tags"},
		},
		RiskVector: riskvec.RiskVector{Network: 3, Governance: 1},
	}

	key1 := HashKey(sr)
	key2 := HashKey(sr)

	if key1 != key2 {
		t.Errorf("hash keys should be deterministic: %q != %q", key1, key2)
	}
	if len(key1) != 64 { // SHA256 hex length
		t.Errorf("expected SHA256 hex (64 chars), got %d chars", len(key1))
	}
}

func TestHashKey_FlagsSorted(t *testing.T) {
	sr1 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"wildcard-cidr", "no-tags"},
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	sr2 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
			Flags:        []string{"no-tags", "wildcard-cidr"},
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	if HashKey(sr1) != HashKey(sr2) {
		t.Error("hash keys should be identical regardless of flag order")
	}
}

func TestHashKey_DifferentResources(t *testing.T) {
	sr1 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_security_group",
			Provider:     "aws",
		},
		RiskVector: riskvec.RiskVector{Network: 3},
	}

	sr2 := &riskvec.ScoredResource{
		Features: feature.ResourceFeatures{
			ResourceType: "aws_s3_bucket",
			Provider:     "aws",
		},
		RiskVector: riskvec.RiskVector{Encryption: 3},
	}

	if HashKey(sr1) == HashKey(sr2) {
		t.Error("different resources should have different hash keys")
	}
}

func TestCache_PutGet(t *testing.T) {
	cache := NewCache()
	key := "test-key"
	resp := Response{
		Severity:          "HIGH",
		ArchitecturalRisk: "test risk",
		RiskCategories:    []string{"security"},
		Confidence:        0.95,
	}

	cache.Put(key, resp)
	got, ok := cache.Get(key)

	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", got.Severity)
	}
}

func TestCache_Miss(t *testing.T) {
	cache := NewCache()
	_, ok := cache.Get("nonexistent")
	if ok {
		t.Error("expected cache miss for nonexistent key")
	}
}

func TestGetOrCompute_Hit(t *testing.T) {
	cache := NewCache()
	key := "pre-cached"
	expected := Response{Severity: "LOW", Confidence: 0.8}
	cache.Put(key, expected)

	callCount := 0
	got, cached, err := cache.GetOrCompute(key, func() (Response, error) {
		callCount++
		return Response{Severity: "HIGH"}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cached {
		t.Error("expected cache hit flag to be true")
	}
	if callCount != 0 {
		t.Error("compute function should not be called on cache hit")
	}
	if got.Severity != "LOW" {
		t.Errorf("expected cached severity LOW, got %q", got.Severity)
	}
}

func TestGetOrCompute_Miss(t *testing.T) {
	cache := NewCache()

	got, cached, err := cache.GetOrCompute("new-key", func() (Response, error) {
		return Response{Severity: "CRITICAL", Confidence: 0.99}, nil
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cached {
		t.Error("expected cache miss flag to be false")
	}
	if got.Severity != "CRITICAL" {
		t.Errorf("expected computed severity CRITICAL, got %q", got.Severity)
	}

	// Should be cached now
	cachedResp, ok := cache.Get("new-key")
	if !ok {
		t.Fatal("expected value to be cached after compute")
	}
	if cachedResp.Severity != "CRITICAL" {
		t.Errorf("expected cached severity CRITICAL, got %q", cachedResp.Severity)
	}
}

func TestGetOrCompute_Error(t *testing.T) {
	cache := NewCache()

	_, _, err := cache.GetOrCompute("err-key", func() (Response, error) {
		return Response{}, fmt.Errorf("provider unavailable")
	})

	if err == nil {
		t.Fatal("expected error from compute function")
	}

	// Should NOT be cached on error
	_, ok := cache.Get("err-key")
	if ok {
		t.Error("error responses should not be cached")
	}
}

func TestCache_ConcurrencySafety(t *testing.T) {
	cache := NewCache()
	var wg sync.WaitGroup
	const goroutines = 250

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", n%10) // 10 unique keys
			cache.GetOrCompute(key, func() (Response, error) {
				return Response{
					Severity:   "HIGH",
					Confidence: float64(n) / float64(goroutines),
				}, nil
			})
		}(i)
	}

	wg.Wait()

	_, _, size := cache.Stats()
	if size != 10 {
		t.Errorf("expected 10 unique keys, got %d", size)
	}
}

func TestCache_Stats(t *testing.T) {
	cache := NewCache()
	cache.Put("k1", Response{Severity: "LOW"})
	cache.Get("k1") // hit
	cache.Get("k2") // miss
	cache.Get("k1") // hit

	hits, misses, size := cache.Stats()
	if hits != 2 {
		t.Errorf("expected 2 hits, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
}
