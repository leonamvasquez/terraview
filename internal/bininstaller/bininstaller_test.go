package bininstaller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/platform"
)

func testPlatform(os, arch string) platform.PlatformInfo {
	ext := ""
	if os == "windows" {
		ext = ".exe"
	}
	return platform.PlatformInfo{OS: os, Arch: arch, BinaryExt: ext}
}

// --- URL mapping tests ---

func TestTfsecInstaller_DownloadURL(t *testing.T) {
	inst := &TfsecInstaller{}
	tests := []struct {
		os, arch string
		contains string
	}{
		{"linux", "amd64", "tfsec-linux-amd64"},
		{"linux", "arm64", "tfsec-linux-arm64"},
		{"darwin", "amd64", "tfsec-darwin-amd64"},
		{"darwin", "arm64", "tfsec-darwin-arm64"},
		{"windows", "amd64", "tfsec-windows-amd64.exe"},
	}
	for _, tc := range tests {
		p := testPlatform(tc.os, tc.arch)
		url := inst.DownloadURL(p, "1.28.11")
		if !strings.Contains(url, tc.contains) {
			t.Errorf("tfsec URL for %s/%s = %q, want contains %q", tc.os, tc.arch, url, tc.contains)
		}
		if !strings.HasPrefix(url, "https://") {
			t.Errorf("URL should start with https://, got %q", url)
		}
	}
}

func TestTerrascanInstaller_DownloadURL(t *testing.T) {
	inst := &TerrascanInstaller{}
	tests := []struct {
		os, arch string
		contains string
	}{
		{"linux", "amd64", "Linux_x86_64"},
		{"linux", "arm64", "Linux_arm64"},
		{"darwin", "amd64", "Darwin_x86_64"},
		{"darwin", "arm64", "Darwin_arm64"},
		{"windows", "amd64", "Windows_x86_64"},
	}
	for _, tc := range tests {
		p := testPlatform(tc.os, tc.arch)
		url := inst.DownloadURL(p, "1.19.9")
		if !strings.Contains(url, tc.contains) {
			t.Errorf("terrascan URL for %s/%s = %q, want contains %q", tc.os, tc.arch, url, tc.contains)
		}
	}
}

func TestKICSInstaller_DownloadURL(t *testing.T) {
	inst := &KICSInstaller{}
	tests := []struct {
		os, arch string
		contains string
	}{
		{"linux", "amd64", "kics_2.1.3_linux_amd64"},
		{"linux", "arm64", "kics_2.1.3_linux_arm64"},
		{"darwin", "amd64", "kics_2.1.3_darwin_amd64"},
		{"darwin", "arm64", "kics_2.1.3_darwin_arm64"},
		{"windows", "amd64", "kics_2.1.3_windows_amd64"},
	}
	for _, tc := range tests {
		p := testPlatform(tc.os, tc.arch)
		url := inst.DownloadURL(p, "2.1.3")
		if !strings.Contains(url, tc.contains) {
			t.Errorf("kics URL for %s/%s = %q, want contains %q", tc.os, tc.arch, url, tc.contains)
		}
	}
}

func TestCheckovInstaller_NoDirectBinary(t *testing.T) {
	inst := &CheckovInstaller{}
	p := testPlatform("linux", "amd64")
	url := inst.DownloadURL(p, "3.0.0")
	if url != "" {
		t.Errorf("Checkov should have no download URL, got %q", url)
	}
	if inst.SupportsDirectBinary() {
		t.Error("Checkov should not support direct binary")
	}
	fb := inst.FallbackCommand(p)
	if !strings.Contains(fb, "pip") {
		t.Errorf("Checkov fallback should mention pip, got %q", fb)
	}
}

// --- Install path tests ---

func TestInstall_CorrectPathByOS(t *testing.T) {
	content := "fake binary"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	// Mock installer that returns our test server URL
	mock := &mockInstaller{
		name:    "mockscanner",
		url:     srv.URL + "/mock-binary",
		version: "1.0.0",
	}

	installDir := filepath.Join(t.TempDir(), "test-bin")

	tests := []struct {
		os   string
		want string
	}{
		{"linux", filepath.Join(installDir, "mockscanner")},
		{"darwin", filepath.Join(installDir, "mockscanner")},
		{"windows", filepath.Join(installDir, "mockscanner.exe")},
	}

	for _, tc := range tests {
		p := testPlatform(tc.os, "amd64")
		dir := filepath.Join(installDir, tc.os)
		result := Install(mock, p, dir)
		if !result.Installed {
			t.Errorf("OS=%s: install failed: %s", tc.os, result.Error)
			continue
		}
		expectedName := p.BinaryName("mockscanner")
		if !strings.HasSuffix(result.Path, expectedName) {
			t.Errorf("OS=%s: path %q should end with %q", tc.os, result.Path, expectedName)
		}
	}
}

func TestInstall_CustomDir(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("binary"))
	}))
	defer srv.Close()

	mock := &mockInstaller{
		name:    "test",
		url:     srv.URL + "/bin",
		version: "1.0",
	}

	customDir := filepath.Join(t.TempDir(), "custom", "scanners")
	p := testPlatform(runtime.GOOS, runtime.GOARCH)
	result := Install(mock, p, customDir)
	if !result.Installed {
		t.Fatalf("install failed: %s", result.Error)
	}
	if !strings.HasPrefix(result.Path, customDir) {
		t.Errorf("path %q should be under %q", result.Path, customDir)
	}
}

func TestInstall_ExecutablePermission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permission test")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("binary"))
	}))
	defer srv.Close()

	mock := &mockInstaller{
		name:    "exectest",
		url:     srv.URL + "/bin",
		version: "1.0",
	}

	p := testPlatform(runtime.GOOS, runtime.GOARCH)
	result := Install(mock, p, t.TempDir())
	if !result.Installed {
		t.Fatalf("install failed: %s", result.Error)
	}

	info, err := os.Stat(result.Path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if info.Mode()&0111 == 0 {
		t.Error("binary should have executable permission")
	}
}

func TestInstall_FallbackForCheckov(t *testing.T) {
	inst := &CheckovInstaller{}
	p := testPlatform("linux", "amd64")
	result := Install(inst, p, t.TempDir())
	if result.Installed {
		t.Error("Checkov should not install as direct binary")
	}
	if result.Fallback == "" {
		t.Error("Checkov should return a fallback command")
	}
}

func TestAllInstallers(t *testing.T) {
	all := AllInstallers()
	if len(all) != 4 {
		t.Errorf("expected 4 installers, got %d", len(all))
	}
	names := make(map[string]bool)
	for _, inst := range all {
		names[inst.Name()] = true
	}
	for _, expected := range []string{"checkov", "tfsec", "terrascan", "kics"} {
		if !names[expected] {
			t.Errorf("missing installer for %q", expected)
		}
	}
}

func TestInstallerFor(t *testing.T) {
	inst := InstallerFor("tfsec")
	if inst == nil {
		t.Fatal("expected tfsec installer, got nil")
	}
	if inst.Name() != "tfsec" {
		t.Errorf("expected tfsec, got %q", inst.Name())
	}
	if InstallerFor("unknown") != nil {
		t.Error("unknown scanner should return nil")
	}
}

// --- Mock installer ---

type mockInstaller struct {
	name    string
	url     string
	version string
}

func (m *mockInstaller) Name() string { return m.name }
func (m *mockInstaller) LatestVersion() string { return m.version }
func (m *mockInstaller) IsArchive() bool { return false }
func (m *mockInstaller) SupportsDirectBinary() bool { return true }
func (m *mockInstaller) ArchiveBinaryName(_ platform.PlatformInfo) string { return "" }
func (m *mockInstaller) FallbackCommand(_ platform.PlatformInfo) string { return "" }
func (m *mockInstaller) DownloadURL(_ platform.PlatformInfo, _ string) string { return m.url }
