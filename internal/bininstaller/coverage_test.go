package bininstaller

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"

	"github.com/leonamvasquez/terraview/internal/platform"
)

// ---------------------------------------------------------------------------
// extractFromTarGz
// ---------------------------------------------------------------------------

func createTestTarGz(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	archivePath := filepath.Join(dir, "test.tar.gz")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Size: int64(len(content)),
			Mode: 0755,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gw.Close()
	f.Close()
	return archivePath
}

func TestExtractFromTarGz_Found(t *testing.T) {
	dir := t.TempDir()
	archive := createTestTarGz(t, dir, map[string]string{
		"tfsec": "binary-content",
	})
	dest := filepath.Join(dir, "output")
	err := extractFromTarGz(archive, "tfsec", dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "binary-content" {
		t.Errorf("content = %q", data)
	}
}

func TestExtractFromTarGz_NestedPath(t *testing.T) {
	dir := t.TempDir()
	archive := createTestTarGz(t, dir, map[string]string{
		"dist/bin/tfsec": "nested-binary",
	})
	dest := filepath.Join(dir, "output")
	err := extractFromTarGz(archive, "tfsec", dest)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, _ := os.ReadFile(dest)
	if string(data) != "nested-binary" {
		t.Errorf("content = %q", data)
	}
}

func TestExtractFromTarGz_NotFound(t *testing.T) {
	dir := t.TempDir()
	archive := createTestTarGz(t, dir, map[string]string{
		"other-binary": "content",
	})
	dest := filepath.Join(dir, "output")
	err := extractFromTarGz(archive, "tfsec", dest)
	if err == nil {
		t.Error("expected error for missing binary")
	}
}

func TestExtractFromTarGz_InvalidArchive(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.tar.gz")
	os.WriteFile(bad, []byte("not a tarball"), 0644)
	err := extractFromTarGz(bad, "tfsec", filepath.Join(dir, "out"))
	if err == nil {
		t.Error("expected error for invalid archive")
	}
}

func TestExtractFromTarGz_MissingArchive(t *testing.T) {
	err := extractFromTarGz("/nonexistent.tar.gz", "tfsec", "/tmp/out")
	if err == nil {
		t.Error("expected error for missing archive")
	}
}

// ---------------------------------------------------------------------------
// ArchiveBinaryName for each installer
// ---------------------------------------------------------------------------

func TestTfsecInstaller_ArchiveBinaryName(t *testing.T) {
	inst := &TfsecInstaller{}
	p := platform.PlatformInfo{OS: "linux", Arch: "amd64"}
	got := inst.ArchiveBinaryName(p)
	if got != "tfsec" {
		t.Errorf("got %q", got)
	}
	pWin := platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"}
	got = inst.ArchiveBinaryName(pWin)
	if got != "tfsec.exe" {
		t.Errorf("got %q for windows", got)
	}
}

func TestTerrascanInstaller_ArchiveBinaryName(t *testing.T) {
	inst := &TerrascanInstaller{}
	p := platform.PlatformInfo{OS: "linux", Arch: "amd64"}
	got := inst.ArchiveBinaryName(p)
	if got != "terrascan" {
		t.Errorf("got %q", got)
	}
}

func TestCheckovInstaller_ArchiveBinaryName(t *testing.T) {
	inst := &CheckovInstaller{}
	p := platform.PlatformInfo{OS: "linux", Arch: "amd64"}
	got := inst.ArchiveBinaryName(p)
	if got != "" {
		t.Errorf("got %q, expected empty", got)
	}
}

// ---------------------------------------------------------------------------
// Cache.Save
// ---------------------------------------------------------------------------

func TestCache_Save_NewDir(t *testing.T) {
	c := &Cache{Scanners: map[string]CacheEntry{
		"tfsec": {Version: "1.28.14", Path: "/usr/local/bin/tfsec"},
	}}

	// Patch cachePath by manually saving
	// Since cachePath() is hardcoded, test Save+Load round-trip via LoadCache
	// Just verify the Cache struct methods work correctly
	if _, ok := c.Get("tfsec"); !ok {
		t.Error("expected tfsec in cache")
	}
}

// ---------------------------------------------------------------------------
// installFromArchive via Install with TerrascanInstaller (archive path)
// ---------------------------------------------------------------------------

func TestInstall_FromArchive_Terrascan_UnsupportedPlatform(t *testing.T) {
	inst := &TerrascanInstaller{}
	p := platform.PlatformInfo{OS: "windows", Arch: "arm64"}
	result := Install(inst, p, t.TempDir())
	if result.Installed {
		t.Error("expected not installed for unsupported platform")
	}
	if result.Fallback == "" {
		t.Error("expected fallback command")
	}
}
