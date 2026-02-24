package bininstaller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/leonamvasquez/terraview/internal/platform"
)

// CacheEntry records metadata about an installed scanner binary.
type CacheEntry struct {
	Version     string    `json:"version"`
	Path        string    `json:"path"`
	InstalledAt time.Time `json:"installed_at"`
	Platform    string    `json:"platform"`
}

// Cache persists scanner install metadata to ~/.terraview/scanners.json.
type Cache struct {
	Scanners map[string]CacheEntry `json:"scanners"`
	mu       sync.Mutex
}

// cachePath returns the absolute path to the cache file.
func cachePath() string {
	p, _ := platform.Detect()
	return filepath.Join(filepath.Dir(p.InstallDir()), "scanners.json")
}

// LoadCache reads the cache from disk. Returns an empty cache on error.
func LoadCache() *Cache {
	c := &Cache{Scanners: make(map[string]CacheEntry)}
	data, err := os.ReadFile(cachePath())
	if err != nil {
		return c
	}
	_ = json.Unmarshal(data, c)
	if c.Scanners == nil {
		c.Scanners = make(map[string]CacheEntry)
	}
	return c
}

// Save writes the cache to disk.
func (c *Cache) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	path := cachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Set records an install result in the cache.
func (c *Cache) Set(result InstallResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !result.Installed {
		return
	}
	p, _ := platform.Detect()
	c.Scanners[result.Scanner] = CacheEntry{
		Version:     result.Version,
		Path:        result.Path,
		InstalledAt: time.Now(),
		Platform:    p.String(),
	}
}

// Get returns the cache entry for a scanner, if present.
func (c *Cache) Get(name string) (CacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.Scanners[name]
	return e, ok
}

// IsInstalled checks if a scanner is in the cache and the binary still exists.
func (c *Cache) IsInstalled(name string) bool {
	entry, ok := c.Get(name)
	if !ok {
		return false
	}
	_, err := os.Stat(entry.Path)
	return err == nil
}

// NeedsUpdate checks whether the cached version differs from the given version.
func (c *Cache) NeedsUpdate(name, latestVersion string) bool {
	entry, ok := c.Get(name)
	if !ok {
		return true
	}
	return entry.Version != latestVersion
}

// Remove deletes a scanner entry from the cache.
func (c *Cache) Remove(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.Scanners, name)
}

// All returns a copy of all cache entries.
func (c *Cache) All() map[string]CacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make(map[string]CacheEntry, len(c.Scanners))
	for k, v := range c.Scanners {
		cp[k] = v
	}
	return cp
}
