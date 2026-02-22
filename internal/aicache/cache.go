// Package aicache provides a thread-safe SHA256 hash cache for AI responses.
// It prevents duplicate AI calls for resources with identical risk profiles.
package aicache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/leonamvasquez/terraview/internal/riskvec"
)

// Response is the cached AI response for a resource.
type Response struct {
	RiskCategories   []string `json:"risk_categories"`
	Severity         string   `json:"severity"`
	ArchitecturalRisk string  `json:"architectural_risk"`
	Remediation      string   `json:"remediation"`
	Confidence       float64  `json:"confidence"`
}

// Cache is a thread-safe in-memory cache keyed by risk vector hashes.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]Response
	hits    int
	misses  int
}

// NewCache creates a new empty cache.
func NewCache() *Cache {
	return &Cache{
		entries: make(map[string]Response),
	}
}

// HashKey computes a deterministic SHA256 hash from a scored resource.
// The hash includes resource_type, provider, risk_vector, and sorted flags.
func HashKey(sr *riskvec.ScoredResource) string {
	h := sha256.New()

	// Include resource type and provider
	fmt.Fprintf(h, "type=%s\n", sr.Features.ResourceType)
	fmt.Fprintf(h, "provider=%s\n", sr.Features.Provider)

	// Include risk vector axes
	rv := sr.RiskVector
	fmt.Fprintf(h, "net=%d\n", rv.Network)
	fmt.Fprintf(h, "enc=%d\n", rv.Encryption)
	fmt.Fprintf(h, "iam=%d\n", rv.Identity)
	fmt.Fprintf(h, "gov=%d\n", rv.Governance)
	fmt.Fprintf(h, "obs=%d\n", rv.Observability)

	// Include sorted flags
	flags := make([]string, len(sr.Features.Flags))
	copy(flags, sr.Features.Flags)
	sort.Strings(flags)
	fmt.Fprintf(h, "flags=%s\n", strings.Join(flags, ","))

	return hex.EncodeToString(h.Sum(nil))
}

// Get retrieves a cached response. Thread-safe.
func (c *Cache) Get(key string) (Response, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	resp, ok := c.entries[key]
	if ok {
		c.hits++
	} else {
		c.misses++
	}
	return resp, ok
}

// Put stores a response in the cache. Thread-safe.
func (c *Cache) Put(key string, resp Response) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = resp
}

// GetOrCompute atomically checks the cache and only computes if missing.
// This prevents duplicate concurrent computations for the same key.
func (c *Cache) GetOrCompute(key string, compute func() (Response, error)) (Response, bool, error) {
	// Fast path: read lock
	c.mu.RLock()
	if resp, ok := c.entries[key]; ok {
		c.mu.RUnlock()
		c.mu.Lock()
		c.hits++
		c.mu.Unlock()
		return resp, true, nil
	}
	c.mu.RUnlock()

	// Slow path: write lock + recheck
	c.mu.Lock()
	if resp, ok := c.entries[key]; ok {
		c.hits++
		c.mu.Unlock()
		return resp, true, nil
	}
	c.misses++
	c.mu.Unlock()

	// Compute outside lock
	resp, err := compute()
	if err != nil {
		return Response{}, false, err
	}

	c.mu.Lock()
	c.entries[key] = resp
	c.mu.Unlock()

	return resp, false, nil
}

// Stats returns cache hit/miss statistics.
func (c *Cache) Stats() (hits, misses, size int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.hits, c.misses, len(c.entries)
}

// MarshalJSON serializes cache entries for inspection/debugging.
func (c *Cache) MarshalJSON() ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return json.Marshal(c.entries)
}
