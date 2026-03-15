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

// diskEntry is the legacy representation of a cache entry (old format).
// Kept only for reading statistics from the legacy ai-cache.json file.
type diskEntry struct {
	Response string    `json:"response"`
	CachedAt time.Time `json:"cached_at"`
	Provider string    `json:"provider"`
	Model    string    `json:"model"`
}

// CacheMeta stores metadata for a disk cache entry.
// Each entry has a .meta file with these fields and a .json file with the response.
type CacheMeta struct {
	CreatedAt time.Time `json:"created_at"`
	PlanHash  string    `json:"plan_hash"`
	Provider  string    `json:"provider"`
	Model     string    `json:"model"`
	Scanner   string    `json:"scanner"`
	TTLHours  int       `json:"ttl_hours"`
}

// DiskCache implements persistent AI response cache with content hashing.
// Each entry is stored as <hash>.json + <hash>.meta in the cache directory.
type DiskCache struct {
	mu       sync.Mutex
	dir      string
	ttl      time.Duration
	provider string
	model    string
	scanner  string
	hits     int
	misses   int
	now      func() time.Time // injectable for tests
}

// DiskCacheDir returns the default disk cache directory.
func DiskCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.TempDir()
	}
	return filepath.Join(home, ".terraview", "cache")
}

// DiskCachePath returns the legacy cache file path (ai-cache.json).
// Deprecated: use DiskCacheDir for the new hash-based format.
func DiskCachePath() string {
	return filepath.Join(DiskCacheDir(), "ai-cache.json")
}

// PlanHash computes the SHA-256 of the plan content for use as a cache key.
func PlanHash(planData []byte) string {
	sum := sha256.Sum256(planData)
	return hex.EncodeToString(sum[:])
}

// NewDiskCache creates a new disk cache with content hashing.
// dir is the cache directory (e.g., ~/.terraview/cache/).
func NewDiskCache(dir, provider, model, scanner string, ttlHours int) *DiskCache {
	return &DiskCache{
		dir:      dir,
		ttl:      time.Duration(ttlHours) * time.Hour,
		provider: provider,
		model:    model,
		scanner:  scanner,
		now:      time.Now,
	}
}

// AnalysisKey computes a legacy cache key from data, provider, and model.
// Deprecated: use PlanHash for the new content-hash-based format.
func AnalysisKey(resourcesJSON []byte, provider, model string) string {
	h := sha256.New()
	fmt.Fprintf(h, "provider=%s\n", provider)
	fmt.Fprintf(h, "model=%s\n", model)
	h.Write(resourcesJSON)
	return hex.EncodeToString(h.Sum(nil))
}

// metaPath returns the metadata file path for a plan hash.
func (dc *DiskCache) metaPath(planHash string) string {
	return filepath.Join(dc.dir, planHash+".meta")
}

// dataPath returns the data file path for a plan hash.
func (dc *DiskCache) dataPath(planHash string) string {
	return filepath.Join(dc.dir, planHash+".json")
}

// Get checks the cache for a plan hash, returning the stored response.
// Checks: file existence, provider/model match, and TTL.
func (dc *DiskCache) Get(planHash string) (string, bool) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	// Read metadata
	metaData, err := os.ReadFile(dc.metaPath(planHash))
	if err != nil {
		dc.misses++
		return "", false
	}

	var meta CacheMeta
	if err := json.Unmarshal(metaData, &meta); err != nil {
		dc.misses++
		return "", false
	}

	// Check provider and model
	if meta.Provider != dc.provider || meta.Model != dc.model {
		dc.misses++
		return "", false
	}

	// Check TTL
	if dc.now().Sub(meta.CreatedAt) > dc.ttl {
		dc.misses++
		return "", false
	}

	// Read response data
	data, err := os.ReadFile(dc.dataPath(planHash))
	if err != nil {
		dc.misses++
		return "", false
	}

	dc.hits++
	return string(data), true
}

// Put stores a response and its metadata to disk atomically.
func (dc *DiskCache) Put(planHash, response string) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	if err := os.MkdirAll(dc.dir, 0755); err != nil {
		return
	}

	meta := CacheMeta{
		CreatedAt: dc.now(),
		PlanHash:  planHash,
		Provider:  dc.provider,
		Model:     dc.model,
		Scanner:   dc.scanner,
		TTLHours:  int(dc.ttl.Hours()),
	}

	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return
	}

	// Atomic write: temp file + rename
	metaTmp := dc.metaPath(planHash) + ".tmp"
	if err := os.WriteFile(metaTmp, metaJSON, 0600); err != nil {
		return
	}
	if err := os.Rename(metaTmp, dc.metaPath(planHash)); err != nil {
		os.Remove(metaTmp)
		return
	}

	dataTmp := dc.dataPath(planHash) + ".tmp"
	if err := os.WriteFile(dataTmp, []byte(response), 0600); err != nil {
		return
	}
	if err := os.Rename(dataTmp, dc.dataPath(planHash)); err != nil {
		os.Remove(dataTmp)
		return
	}
}

// Stats returns hit/miss/size statistics for the current session.
func (dc *DiskCache) Stats() (hits, misses, size int) {
	dc.mu.Lock()
	defer dc.mu.Unlock()
	entries, _ := filepath.Glob(filepath.Join(dc.dir, "*.meta"))
	return dc.hits, dc.misses, len(entries)
}

// DiskStats returns information about the disk cache (entries, size, dates).
// dir is the cache directory (e.g., ~/.terraview/cache/).
func DiskStats(dir string) (entries int, totalSize int64, oldest, newest time.Time, err error) {
	metas, globErr := filepath.Glob(filepath.Join(dir, "*.meta"))
	if globErr != nil {
		return 0, 0, time.Time{}, time.Time{}, globErr
	}

	// If no .meta files, check legacy format (ai-cache.json)
	if len(metas) == 0 {
		legacyPath := filepath.Join(dir, "ai-cache.json")
		return legacyDiskStats(legacyPath)
	}

	entries = len(metas)
	for _, mp := range metas {
		if info, statErr := os.Stat(mp); statErr == nil {
			totalSize += info.Size()
		}
		// Add size of corresponding .json
		jp := strings.TrimSuffix(mp, ".meta") + ".json"
		if info, statErr := os.Stat(jp); statErr == nil {
			totalSize += info.Size()
		}
		// Read metadata for dates
		data, readErr := os.ReadFile(mp)
		if readErr != nil {
			continue
		}
		var meta CacheMeta
		if json.Unmarshal(data, &meta) != nil {
			continue
		}
		if oldest.IsZero() || meta.CreatedAt.Before(oldest) {
			oldest = meta.CreatedAt
		}
		if newest.IsZero() || meta.CreatedAt.After(newest) {
			newest = meta.CreatedAt
		}
	}

	return entries, totalSize, oldest, newest, nil
}

// legacyDiskStats reads statistics from the old format (ai-cache.json).
func legacyDiskStats(path string) (int, int64, time.Time, time.Time, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, time.Time{}, time.Time{}, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, info.Size(), time.Time{}, time.Time{}, err
	}

	var disk map[string]diskEntry
	if err := json.Unmarshal(data, &disk); err != nil {
		return 0, info.Size(), time.Time{}, time.Time{}, err
	}

	var oldest, newest time.Time
	for _, e := range disk {
		if oldest.IsZero() || e.CachedAt.Before(oldest) {
			oldest = e.CachedAt
		}
		if newest.IsZero() || e.CachedAt.After(newest) {
			newest = e.CachedAt
		}
	}
	return len(disk), info.Size(), oldest, newest, nil
}

// ClearDisk removes all cache files from the directory.
// Removes .json, .meta, and .tmp files generated by the cache.
func ClearDisk(dir string) error {
	// Clear new format files
	for _, pattern := range []string{"*.json", "*.meta", "*.tmp"} {
		files, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			continue
		}
		for _, f := range files {
			os.Remove(f)
		}
	}
	return nil
}

// LookupPlanHash checks if a cache entry exists for the given plan hash.
// Returns the entry metadata or an error if not found.
func LookupPlanHash(dir, planHash string) (*CacheMeta, error) {
	metaPath := filepath.Join(dir, planHash+".meta")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}

	var meta CacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// ListEntries returns the metadata of all cache entries in the directory.
func ListEntries(dir string) ([]CacheMeta, error) {
	metas, err := filepath.Glob(filepath.Join(dir, "*.meta"))
	if err != nil {
		return nil, err
	}

	entries := make([]CacheMeta, 0, len(metas))
	for _, mp := range metas {
		data, err := os.ReadFile(mp)
		if err != nil {
			continue
		}
		var meta CacheMeta
		if json.Unmarshal(data, &meta) != nil {
			continue
		}
		entries = append(entries, meta)
	}
	return entries, nil
}
