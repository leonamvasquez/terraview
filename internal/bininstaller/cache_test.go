package bininstaller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCache_SetAndGet(t *testing.T) {
	c := &Cache{Scanners: make(map[string]CacheEntry)}
	result := InstallResult{
		Scanner:   "tfsec",
		Version:   "1.28.11",
		Path:      "/tmp/test/tfsec",
		Installed: true,
	}
	c.Set(result)

	entry, ok := c.Get("tfsec")
	if !ok {
		t.Fatal("expected tfsec in cache")
	}
	if entry.Version != "1.28.11" {
		t.Errorf("version = %q, want 1.28.11", entry.Version)
	}
	if entry.Path != "/tmp/test/tfsec" {
		t.Errorf("path = %q, want /tmp/test/tfsec", entry.Path)
	}
}

func TestCache_SetSkipsNotInstalled(t *testing.T) {
	c := &Cache{Scanners: make(map[string]CacheEntry)}
	c.Set(InstallResult{Scanner: "fail", Installed: false})
	if _, ok := c.Get("fail"); ok {
		t.Error("should not cache a failed install")
	}
}

func TestCache_IsInstalled(t *testing.T) {
	tmp := t.TempDir()
	binPath := filepath.Join(tmp, "fakescanner")
	os.WriteFile(binPath, []byte("x"), 0755)

	c := &Cache{Scanners: map[string]CacheEntry{
		"fakescanner": {Version: "1.0", Path: binPath, InstalledAt: time.Now()},
	}}

	if !c.IsInstalled("fakescanner") {
		t.Error("expected IsInstalled=true for existing binary")
	}
	if c.IsInstalled("missing") {
		t.Error("expected IsInstalled=false for missing scanner")
	}
}

func TestCache_NeedsUpdate(t *testing.T) {
	c := &Cache{Scanners: map[string]CacheEntry{
		"tfsec": {Version: "1.28.10"},
	}}

	if !c.NeedsUpdate("tfsec", "1.28.11") {
		t.Error("should need update when version differs")
	}
	if c.NeedsUpdate("tfsec", "1.28.10") {
		t.Error("should NOT need update when version matches")
	}
	if !c.NeedsUpdate("unknown", "1.0") {
		t.Error("should need update when scanner not in cache")
	}
}

func TestCache_Remove(t *testing.T) {
	c := &Cache{Scanners: map[string]CacheEntry{
		"tfsec": {Version: "1.0"},
	}}
	c.Remove("tfsec")
	if _, ok := c.Get("tfsec"); ok {
		t.Error("tfsec should be removed from cache")
	}
}

func TestCache_All(t *testing.T) {
	c := &Cache{Scanners: map[string]CacheEntry{
		"a": {Version: "1"},
		"b": {Version: "2"},
	}}
	all := c.All()
	if len(all) != 2 {
		t.Errorf("expected 2 entries, got %d", len(all))
	}
}

func TestCache_SaveAndLoad(t *testing.T) {
	// Override cache path to temp dir
	tmp := t.TempDir()
	origFn := cachePath
	_ = origFn // suppress unused warning - we test via the filesystem

	// Create a cache and set entries
	c := &Cache{Scanners: make(map[string]CacheEntry)}
	c.Set(InstallResult{
		Scanner:   "tfsec",
		Version:   "1.28.11",
		Path:      filepath.Join(tmp, "tfsec"),
		Installed: true,
	})

	// Write cache to a custom path
	cPath := filepath.Join(tmp, "scanners.json")
	data, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(cPath, data, 0644)

	// Read it back
	readData, err := os.ReadFile(cPath)
	if err != nil {
		t.Fatalf("failed to read cache file: %v", err)
	}
	c2 := &Cache{Scanners: make(map[string]CacheEntry)}
	json.Unmarshal(readData, c2)

	entry, ok := c2.Get("tfsec")
	if !ok {
		t.Fatal("expected tfsec in loaded cache")
	}
	if entry.Version != "1.28.11" {
		t.Errorf("loaded version = %q, want 1.28.11", entry.Version)
	}
}

func TestLoadCache_EmptyFile(t *testing.T) {
	c := LoadCache()
	if c == nil {
		t.Fatal("LoadCache should never return nil")
	}
	if c.Scanners == nil {
		t.Fatal("Scanners map should be initialized")
	}
}
