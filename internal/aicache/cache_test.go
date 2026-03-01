package aicache

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestDiskCache_HitWithoutProvider(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// First cache instance: store a value
	dc1 := NewDiskCache(path, "claude", "sonnet", 24)
	dc1.Put("key1", `{"findings":[],"summary":"all good"}`)

	// Second cache instance: same provider/model, should hit
	dc2 := NewDiskCache(path, "claude", "sonnet", 24)
	got, ok := dc2.Get("key1")
	if !ok {
		t.Fatal("expected cache hit on second instance with same provider/model")
	}
	if got != `{"findings":[],"summary":"all good"}` {
		t.Errorf("unexpected cached value: %q", got)
	}

	// Third cache instance: different provider, should miss
	dc3 := NewDiskCache(path, "ollama", "llama3.1:8b", 24)
	_, ok = dc3.Get("key1")
	if ok {
		t.Error("expected cache miss for different provider")
	}
}

func TestDiskCache_TTLExpiration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	now := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)

	// Store entry with a fixed "now"
	dc1 := NewDiskCache(path, "claude", "sonnet", 24)
	dc1.now = func() time.Time { return now }
	dc1.Put("key1", `{"findings":[],"summary":"cached"}`)

	// Read within TTL (12 hours later)
	dc2 := NewDiskCache(path, "claude", "sonnet", 24)
	dc2.now = func() time.Time { return now.Add(12 * time.Hour) }
	_, ok := dc2.Get("key1")
	if !ok {
		t.Fatal("expected cache hit within TTL")
	}

	// Read after TTL (25 hours later)
	dc3 := NewDiskCache(path, "claude", "sonnet", 24)
	dc3.now = func() time.Time { return now.Add(25 * time.Hour) }
	_, ok = dc3.Get("key1")
	if ok {
		t.Error("expected cache miss after TTL expiration")
	}
}

func TestDiskCache_PersistsToDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	dc := NewDiskCache(path, "ollama", "llama3.1:8b", 24)
	dc.Put("abc", "test-value")

	// Verify file was written
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cache file not written: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("cache file is empty")
	}
}

func TestDiskCache_Stats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	dc := NewDiskCache(path, "claude", "sonnet", 24)
	dc.Put("k1", "v1")
	dc.Get("k1") // hit
	dc.Get("k2") // miss

	hits, misses, size := dc.Stats()
	if hits != 1 {
		t.Errorf("expected 1 hit, got %d", hits)
	}
	if misses != 1 {
		t.Errorf("expected 1 miss, got %d", misses)
	}
	if size != 1 {
		t.Errorf("expected size 1, got %d", size)
	}
}

func TestAnalysisKey_Deterministic(t *testing.T) {
	data := []byte(`[{"type":"aws_s3_bucket"}]`)
	k1 := AnalysisKey(data, "claude", "sonnet")
	k2 := AnalysisKey(data, "claude", "sonnet")
	if k1 != k2 {
		t.Errorf("analysis keys should be deterministic: %q != %q", k1, k2)
	}

	// Different provider = different key
	k3 := AnalysisKey(data, "ollama", "sonnet")
	if k1 == k3 {
		t.Error("different providers should produce different keys")
	}
}

func TestClearDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	dc := NewDiskCache(path, "claude", "sonnet", 24)
	dc.Put("k1", "v1")

	if err := ClearDisk(path); err != nil {
		t.Fatalf("ClearDisk failed: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("cache file should be deleted after ClearDisk")
	}

	// Clear on non-existent file should not error
	if err := ClearDisk(path); err != nil {
		t.Errorf("ClearDisk on non-existent file should not error: %v", err)
	}
}

func TestDiskStats(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cache.json")

	// No file yet
	_, _, _, _, err := DiskStats(path)
	if err == nil {
		t.Error("expected error for non-existent file")
	}

	// Write some entries
	dc := NewDiskCache(path, "claude", "sonnet", 24)
	now := time.Date(2025, 6, 15, 10, 0, 0, 0, time.UTC)
	dc.now = func() time.Time { return now }
	dc.Put("k1", "v1")
	dc.now = func() time.Time { return now.Add(2 * time.Hour) }
	dc.Put("k2", "v2")

	entries, fileSize, oldest, newest, err := DiskStats(path)
	if err != nil {
		t.Fatalf("DiskStats failed: %v", err)
	}
	if entries != 2 {
		t.Errorf("expected 2 entries, got %d", entries)
	}
	if fileSize == 0 {
		t.Error("expected non-zero file size")
	}
	if !oldest.Equal(now) {
		t.Errorf("expected oldest=%v, got %v", now, oldest)
	}
	if !newest.Equal(now.Add(2 * time.Hour)) {
		t.Errorf("expected newest=%v, got %v", now.Add(2*time.Hour), newest)
	}
}
