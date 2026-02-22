package bininstaller

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/platform"
)

// allPlatforms returns the 5 supported OS/ARCH combinations.
func allPlatforms() []platform.PlatformInfo {
	return []platform.PlatformInfo{
		{OS: "linux", Arch: "amd64", BinaryExt: ""},
		{OS: "linux", Arch: "arm64", BinaryExt: ""},
		{OS: "darwin", Arch: "amd64", BinaryExt: ""},
		{OS: "darwin", Arch: "arm64", BinaryExt: ""},
		{OS: "windows", Arch: "amd64", BinaryExt: ".exe"},
	}
}

// --- URL mapping tests: every installer x every platform ---

func TestCrossPlatform_TfsecURLsAllPlatforms(t *testing.T) {
	inst := &TfsecInstaller{}
	for _, p := range allPlatforms() {
		url := inst.DownloadURL(p, inst.LatestVersion())
		if url == "" {
			t.Errorf("tfsec: no URL for %s", p.String())
			continue
		}
		if !strings.HasPrefix(url, "https://github.com/aquasecurity/tfsec/releases/download/") {
			t.Errorf("tfsec URL for %s has wrong prefix: %s", p.String(), url)
		}
		// Windows uses a tarball; linux/darwin use direct binaries
		if p.OS == "windows" && !strings.HasSuffix(url, ".tar.gz") {
			t.Errorf("tfsec URL for windows should end in .tar.gz: %s", url)
		}
		if p.OS != "windows" && strings.HasSuffix(url, ".tar.gz") {
			t.Errorf("tfsec URL for %s should NOT end in .tar.gz: %s", p.String(), url)
		}
		if strings.HasSuffix(url, ".exe") {
			t.Errorf("tfsec URL should never end in .exe (windows uses tarball): %s", url)
		}
	}
}

func TestCrossPlatform_TerrascanURLsAllPlatforms(t *testing.T) {
	inst := &TerrascanInstaller{}
	for _, p := range allPlatforms() {
		url := inst.DownloadURL(p, inst.LatestVersion())
		if url == "" {
			t.Errorf("terrascan: no URL for %s", p.String())
			continue
		}
		if !strings.HasPrefix(url, "https://github.com/tenable/terrascan/releases/download/") {
			t.Errorf("terrascan URL for %s has wrong prefix: %s", p.String(), url)
		}
		if !strings.HasSuffix(url, ".tar.gz") {
			t.Errorf("terrascan URL for %s should end in .tar.gz: %s", p.String(), url)
		}
	}
}

func TestCrossPlatform_KICSNoURLAnyPlatform(t *testing.T) {
	// KICS no longer ships pre-built binaries — should behave like checkov.
	inst := &KICSInstaller{}
	for _, p := range allPlatforms() {
		url := inst.DownloadURL(p, inst.LatestVersion())
		if url != "" {
			t.Errorf("kics should have no URL for %s, got %s", p.String(), url)
		}
		fb := inst.FallbackCommand(p)
		if fb == "" {
			t.Errorf("kics should have a fallback for %s", p.String())
		}
	}
}

func TestCrossPlatform_CheckovNoURLAnyPlatform(t *testing.T) {
	inst := &CheckovInstaller{}
	for _, p := range allPlatforms() {
		url := inst.DownloadURL(p, "3.0.0")
		if url != "" {
			t.Errorf("checkov should have no URL for %s, got %s", p.String(), url)
		}
		fb := inst.FallbackCommand(p)
		if fb == "" {
			t.Errorf("checkov should have a fallback for %s", p.String())
		}
	}
}

// --- No unmapped platforms ---

func TestCrossPlatform_NoUnmappedPlatforms(t *testing.T) {
	// Only installers that actually ship binaries should be tested here.
	binaryInstallers := []BinaryInstaller{
		&TfsecInstaller{},
		&TerrascanInstaller{},
	}

	for _, inst := range binaryInstallers {
		for _, p := range allPlatforms() {
			url := inst.DownloadURL(p, inst.LatestVersion())
			if url == "" {
				t.Errorf("%s has no download URL for %s — this platform is unmapped",
					inst.Name(), p.String())
			}
		}
	}
}

// --- Binary name correctness per platform ---

func TestCrossPlatform_BinaryNames(t *testing.T) {
	tests := []struct {
		os, arch string
		wantExt  bool
	}{
		{"linux", "amd64", false},
		{"linux", "arm64", false},
		{"darwin", "amd64", false},
		{"darwin", "arm64", false},
		{"windows", "amd64", true},
	}

	for _, tc := range tests {
		p := platform.PlatformInfo{OS: tc.os, Arch: tc.arch}
		if tc.wantExt {
			p.BinaryExt = ".exe"
		}

		for _, name := range []string{"tfsec", "terrascan", "kics"} {
			bn := p.BinaryName(name)
			if tc.wantExt && !strings.HasSuffix(bn, ".exe") {
				t.Errorf("%s/%s: binary name %q should end in .exe", tc.os, tc.arch, bn)
			}
			if !tc.wantExt && strings.HasSuffix(bn, ".exe") {
				t.Errorf("%s/%s: binary name %q should NOT end in .exe", tc.os, tc.arch, bn)
			}
		}
	}
}

// --- Full install flow per OS (mocked HTTP) ---

func TestCrossPlatform_InstallFlowAllOS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("mock-binary-content"))
	}))
	defer srv.Close()

	for _, p := range allPlatforms() {
		t.Run(p.String(), func(t *testing.T) {
			mock := &mockInstaller{
				name:    "crosstest",
				url:     srv.URL + "/bin",
				version: "1.0.0",
			}

			installDir := filepath.Join(t.TempDir(), p.OS, p.Arch)
			result := Install(mock, p, installDir)

			if !result.Installed {
				t.Fatalf("install failed for %s: %s", p.String(), result.Error)
			}

			expectedName := p.BinaryName("crosstest")
			if !strings.HasSuffix(result.Path, expectedName) {
				t.Errorf("path %q should end with %q", result.Path, expectedName)
			}

			// Verify file exists
			if _, err := os.Stat(result.Path); err != nil {
				t.Errorf("installed binary does not exist at %q", result.Path)
			}

			// Verify file content
			data, _ := os.ReadFile(result.Path)
			if string(data) != "mock-binary-content" {
				t.Errorf("binary content mismatch")
			}
		})
	}
}

// --- Fallback strategy tests ---

func TestCrossPlatform_FallbackWhenNoURL(t *testing.T) {
	inst := &CheckovInstaller{}
	for _, p := range allPlatforms() {
		result := Install(inst, p, t.TempDir())
		if result.Installed {
			t.Errorf("checkov should not install as binary on %s", p.String())
		}
		if result.Fallback == "" {
			t.Errorf("checkov should provide fallback on %s", p.String())
		}
		if result.Error == "" {
			t.Errorf("checkov should have error message on %s", p.String())
		}
	}
}

func TestCrossPlatform_FallbackMessages(t *testing.T) {
	installers := AllInstallers()
	for _, inst := range installers {
		for _, p := range allPlatforms() {
			fb := inst.FallbackCommand(p)
			if fb == "" {
				t.Errorf("%s should have a fallback command for %s", inst.Name(), p.String())
			}
			// macOS should mention brew
			if p.OS == "darwin" && !strings.Contains(fb, "brew") {
				t.Errorf("%s fallback for macOS should mention brew, got %q",
					inst.Name(), fb)
			}
		}
	}
}

// --- Version string tests ---

func TestCrossPlatform_VersionStrings(t *testing.T) {
	installers := []BinaryInstaller{
		&TfsecInstaller{},
		&TerrascanInstaller{},
		&KICSInstaller{},
	}
	for _, inst := range installers {
		v := inst.LatestVersion()
		if v == "" {
			t.Errorf("%s should have a non-empty latest version", inst.Name())
		}
		// Ensure version doesn't start with "v" (the v prefix is added in URL)
		if strings.HasPrefix(v, "v") {
			t.Errorf("%s version should not start with 'v': %s", inst.Name(), v)
		}
	}
	// Checkov version is empty (pip-managed)
	ci := &CheckovInstaller{}
	if ci.LatestVersion() != "" {
		t.Errorf("checkov version should be empty, got %q", ci.LatestVersion())
	}
}

// --- InstallerFor lookup completeness ---

func TestCrossPlatform_InstallerForAll(t *testing.T) {
	names := []string{"checkov", "tfsec", "terrascan", "kics"}
	for _, name := range names {
		inst := InstallerFor(name)
		if inst == nil {
			t.Errorf("InstallerFor(%q) returned nil", name)
			continue
		}
		if inst.Name() != name {
			t.Errorf("InstallerFor(%q).Name() = %q", name, inst.Name())
		}
	}
}

// --- Archive vs direct binary checks ---

func TestCrossPlatform_ArchiveFlags(t *testing.T) {
	tests := []struct {
		name    string
		archive bool
		direct  bool
	}{
		{"tfsec", false, true},
		{"terrascan", true, true},
		{"kics", false, false},
		{"checkov", false, false},
	}
	for _, tc := range tests {
		inst := InstallerFor(tc.name)
		if inst == nil {
			t.Fatalf("InstallerFor(%q) returned nil", tc.name)
		}
		if inst.IsArchive() != tc.archive {
			t.Errorf("%s: IsArchive()=%v, want %v", tc.name, inst.IsArchive(), tc.archive)
		}
		if inst.SupportsDirectBinary() != tc.direct {
			t.Errorf("%s: SupportsDirectBinary()=%v, want %v", tc.name, inst.SupportsDirectBinary(), tc.direct)
		}
	}
}
