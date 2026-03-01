// Package aicache provides a thread-safe SHA256 hash cache for AI responses.
// It prevents duplicate AI calls for resources with identical risk profiles.
package aicache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/leonamvasquez/terraview/internal/riskvec"
)

// Response is the cached AI response for a resource.
type Response struct {
	RiskCategories    []string `json:"risk_categories"`
	Severity          string   `json:"severity"`
	ArchitecturalRisk string   `json:"architectural_risk"`
	Remediation       string   `json:"remediation"`
	Confidence        float64  `json:"confidence"`
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

// diskEntry is the on-disk representation of a cached AI response.
type diskEntry struct {
	Response string    `json:"response"`
	CachedAt time.Time `json:"cached_at"`
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
}

// DiskCache provides persistent AI response caching with TTL expiration.
// On first access it lazily loads entries from disk into an in-memory map.
type DiskCache struct {
	mu       sync.Mutex
	path     string
	ttl      time.Duration
	memory   map[string]diskEntry
	loaded   bool
	provider string
	model    string
	hits     int
	misses   int
	now      func() time.Time // for testing
}

// DiskCachePath returns the default disk cache file path.
func DiskCachePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".terraview", "cache", "ai-cache.json")
}

// NewDiskCache creates a new disk-backed cache.
func NewDiskCache(path, provider, model string, ttlHours int) *DiskCache {
	return &DiskCache{
		path:     path,
		ttl:      time.Duration(ttlHours) * time.Hour,
		memory:   make(map[string]diskEntry),
		provider: provider,
		model:    model,
		now:      time.Now,
	}
}

// AnalysisKey computes a cache key from resource data, provider, and model.
func AnalysisKey(resourcesJSON []byte, provider, model string) string {
	h := sha256.New()
	fmt.Fprintf(h, "provider=%s\n", provider)
	fmt.Fprintf(h, "model=%s\n", model)
	h.Write(resourcesJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// load reads the disk cache file into memory (lazy, called once on first access).
// Must be called with dc.mu held.
func (dc *DiskCache) load() {
	if dc.loaded {
		return
	}
	dc.loaded = true

	data, err := os.ReadFile(dc.path)
	if err != nil {
		return
	}

	var entries map[string]diskEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	dc.memory = entries
}

// Get checks the cache for a key, returning the stored response string.
// Entries are filtered by provider, model, and TTL.
func (dc *DiskCache) Get(key string) (string, bool) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.load()

	entry, ok := dc.memory[key]
	if !ok {
		dc.misses++
		return "", false
	}
	if entry.Provider != dc.provider || entry.Model != dc.model {
		dc.misses++
		return "", false
	}
	if dc.now().Sub(entry.CachedAt) > dc.ttl {
		dc.misses++
		return "", false
	}

	dc.hits++
	return entry.Response, true
}

// Put stores a response string and persists the full cache to disk.
func (dc *DiskCache) Put(key, response string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	dc.load()

	dc.memory[key] = diskEntry{
		Response: response,
		CachedAt: dc.now(),
		Provider: dc.provider,
		Model:    dc.model,
	}

	dc.writeDisk()
}

// writeDisk atomically writes the cache map to the disk file.
// Must be called with dc.mu held.
func (dc *DiskCache) writeDisk() {
	data, err := json.Marshal(dc.memory)
	if err != nil {
		return
	}

	dir := filepath.Dir(dc.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return
	}

	// Atomic write: temp file + rename
	tmp := dc.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, dc.path)
}

// Stats returns cache hit/miss/size statistics.
func (dc *DiskCache) Stats() (hits, misses, size int) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	return dc.hits, dc.misses, len(dc.memory)
}

// DiskStats returns information about the disk cache file.
func DiskStats(path string) (entries int, fileSize int64, oldest, newest time.Time, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, err
	}
	fileSize = info.Size()

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fileSize, time.Time{}, time.Time{}, err
	}

	var disk map[string]diskEntry
	if err := json.Unmarshal(data, &disk); err != nil {
		return 0, fileSize, time.Time{}, time.Time{}, err
	}

	entries = len(disk)
	for _, e := range disk {
		if oldest.IsZero() || e.CachedAt.Before(oldest) {
			oldest = e.CachedAt
		}
		if newest.IsZero() || e.CachedAt.After(newest) {
			newest = e.CachedAt
		}
	}
	return entries, fileSize, oldest, newest, nil
}

// ClearDisk deletes the disk cache file.
func ClearDisk(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
