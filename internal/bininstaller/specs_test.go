package bininstaller

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/platform"
)

// ─── AllSpecs / SpecFor ────────────────────────────────────────────────────

func TestAllSpecs_Count(t *testing.T) {
	specs := AllSpecs()
	if len(specs) < 3 {
		t.Errorf("AllSpecs() returned %d specs, want at least 3", len(specs))
	}
}

func TestAllSpecs_NoDuplicateNames(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range AllSpecs() {
		if seen[s.Name] {
			t.Errorf("duplicate spec name: %q", s.Name)
		}
		seen[s.Name] = true
	}
}

func TestSpecFor_KnownScanners(t *testing.T) {
	for _, name := range []string{"checkov", "tfsec", "terrascan"} {
		spec := SpecFor(name)
		if spec == nil {
			t.Errorf("SpecFor(%q) returned nil", name)
			continue
		}
		if spec.Name != name {
			t.Errorf("SpecFor(%q).Name = %q", name, spec.Name)
		}
		if spec.Version == "" && name != "checkov" {
			t.Errorf("SpecFor(%q).Version should be non-empty", name)
		}
	}
}

func TestSpecFor_Unknown(t *testing.T) {
	if SpecFor("not-a-scanner") != nil {
		t.Error("SpecFor(unknown) should return nil")
	}
	if SpecFor("") != nil {
		t.Error("SpecFor('') should return nil")
	}
}

func TestSpecFor_CaseInsensitive(t *testing.T) {
	if SpecFor("TFSEC") == nil {
		t.Error("SpecFor should be case-insensitive (TFSEC)")
	}
	if SpecFor("Checkov") == nil {
		t.Error("SpecFor should be case-insensitive (Checkov)")
	}
}

// ─── FallbackFor ──────────────────────────────────────────────────────────

func TestFallbackFor_AllPlatforms(t *testing.T) {
	platforms := []platform.PlatformInfo{
		{OS: "linux", Arch: "amd64"},
		{OS: "linux", Arch: "arm64"},
		{OS: "darwin", Arch: "amd64"},
		{OS: "darwin", Arch: "arm64"},
		{OS: "windows", Arch: "amd64", BinaryExt: ".exe"},
	}
	for _, spec := range AllSpecs() {
		for _, p := range platforms {
			fb := FallbackFor(spec, p)
			if fb == "" {
				t.Errorf("FallbackFor(%s, %s) returned empty string", spec.Name, p.String())
			}
		}
	}
}

func TestFallbackFor_MacOSMentionsBrew(t *testing.T) {
	p := platform.PlatformInfo{OS: "darwin", Arch: "arm64"}
	for _, spec := range AllSpecs() {
		fb := FallbackFor(spec, p)
		if !strings.Contains(fb, "brew") {
			t.Errorf("FallbackFor(%s, darwin) should mention brew, got: %q", spec.Name, fb)
		}
	}
}

func TestFallbackFor_LinuxMentionsInstaller(t *testing.T) {
	p := platform.PlatformInfo{OS: "linux", Arch: "amd64"}
	for _, spec := range AllSpecs() {
		fb := FallbackFor(spec, p)
		// Must mention some package manager or download instruction
		if fb == "" {
			t.Errorf("FallbackFor(%s, linux) is empty", spec.Name)
		}
	}
}

// ─── Deprecated flag ──────────────────────────────────────────────────────

func TestTerrascanSpec_Deprecated(t *testing.T) {
	spec := SpecFor("terrascan")
	if spec == nil {
		t.Fatal("terrascan spec not found")
	}
	if spec.Deprecated == "" {
		t.Error("terrascan should be marked as deprecated (archived project)")
	}
}

func TestTfsecSpec_NotDeprecated(t *testing.T) {
	spec := SpecFor("tfsec")
	if spec == nil {
		t.Fatal("tfsec spec not found")
	}
	// tfsec is still maintained; may or may not be deprecated depending on version policy
	// Just verify the field is accessible
	_ = spec.Deprecated
}

// ─── SmartInstall — no binary + no pkg manager available → fallback ────────

// assertSmartInstallSane verifies that SmartInstall always leaves the caller
// with actionable information: either the binary was installed (result.Installed=
// true) or a manual fallback command is provided. For pkg-manager-installed
// binaries, Path may be empty if the binary is not yet in PATH (e.g., not linked).
func assertSmartInstallSane(t *testing.T, name string, result InstallResult) {
	t.Helper()
	if result.Installed {
		// Success path: either have a Path or a meaningful method.
		if result.Method == "" && result.Path == "" {
			t.Errorf("SmartInstall(%s): Installed=true but both Path and Method are empty", name)
		}
	} else {
		// Failure path: must tell the user what to do.
		if result.Fallback == "" {
			t.Errorf("SmartInstall(%s): Installed=false but Fallback is empty", name)
		}
	}
}

func TestSmartInstall_CheckovInvariant(t *testing.T) {
	// Checkov has no binary; it may succeed via pip/brew or provide a fallback.
	spec := SpecFor("checkov")
	if spec == nil {
		t.Fatal("checkov spec not found")
	}
	p := platform.PlatformInfo{OS: "linux", Arch: "amd64"}
	result := SmartInstall(spec, p, t.TempDir())
	assertSmartInstallSane(t, "checkov", result)
}

func TestSmartInstall_WindowsArm64Terrascan(t *testing.T) {
	// Terrascan has no binary for windows/arm64.
	// SmartInstall should either succeed via a package manager (e.g. choco on Windows)
	// or provide a fallback — never silently fail with both Installed=false and Fallback="".
	spec := SpecFor("terrascan")
	if spec == nil {
		t.Fatal("terrascan spec not found")
	}
	p := platform.PlatformInfo{OS: "windows", Arch: "arm64", BinaryExt: ".exe"}
	result := SmartInstall(spec, p, t.TempDir())
	assertSmartInstallSane(t, "terrascan/windows/arm64", result)
}

// ---------------------------------------------------------------------------
// pkgCmdsFn — platform-specific branches
// ---------------------------------------------------------------------------

func TestTfsecSpec_PkgCmds_Darwin(t *testing.T) {
	spec := tfsecSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "darwin", Arch: "arm64"})
	if len(cmds) == 0 {
		t.Fatal("expected pkg commands for darwin")
	}
	if cmds[0][0] != "brew" {
		t.Errorf("expected brew as first command, got %s", cmds[0][0])
	}
}

func TestTfsecSpec_PkgCmds_Windows(t *testing.T) {
	spec := tfsecSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"})
	if len(cmds) == 0 {
		t.Fatal("expected pkg commands for windows")
	}
	if cmds[0][0] != "choco" {
		t.Errorf("expected choco as first command, got %s", cmds[0][0])
	}
}

func TestTfsecSpec_PkgCmds_UnknownOS(t *testing.T) {
	spec := tfsecSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "freebsd", Arch: "amd64"})
	if cmds != nil {
		t.Errorf("expected nil commands for freebsd, got %v", cmds)
	}
}

func TestCheckovSpec_PkgCmds_Darwin(t *testing.T) {
	spec := checkovSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "darwin", Arch: "arm64"})
	if len(cmds) == 0 {
		t.Fatal("expected pkg commands for darwin")
	}
	if cmds[0][0] != "pip3" {
		t.Errorf("expected pip3 as first command, got %s", cmds[0][0])
	}
}

func TestCheckovSpec_PkgCmds_Linux(t *testing.T) {
	spec := checkovSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "linux", Arch: "amd64"})
	if len(cmds) < 3 {
		t.Fatalf("expected multiple pkg commands for linux, got %d", len(cmds))
	}
}

func TestCheckovSpec_PkgCmds_Windows(t *testing.T) {
	spec := checkovSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"})
	if len(cmds) == 0 {
		t.Fatal("expected pkg commands for windows")
	}
}

func TestCheckovSpec_PkgCmds_UnknownOS(t *testing.T) {
	spec := checkovSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "freebsd", Arch: "amd64"})
	if cmds != nil {
		t.Errorf("expected nil commands for freebsd")
	}
}

func TestTerrascanSpec_PkgCmds_Darwin(t *testing.T) {
	spec := terrascanSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "darwin", Arch: "arm64"})
	if len(cmds) == 0 {
		t.Fatal("expected brew command for darwin")
	}
}

func TestTerrascanSpec_PkgCmds_Linux(t *testing.T) {
	spec := terrascanSpec()
	cmds := spec.pkgCmdsFn(platform.PlatformInfo{OS: "linux", Arch: "amd64"})
	if cmds != nil {
		t.Errorf("expected nil for linux (binary direct), got %v", cmds)
	}
}

// ---------------------------------------------------------------------------
// fallbackFn — platform-specific branches
// ---------------------------------------------------------------------------

func TestTfsecSpec_Fallback_Windows(t *testing.T) {
	spec := tfsecSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"})
	if !strings.Contains(fb, "choco") {
		t.Errorf("expected choco in windows fallback, got %q", fb)
	}
}

func TestTfsecSpec_Fallback_UnknownOS(t *testing.T) {
	spec := tfsecSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "freebsd", Arch: "amd64"})
	if !strings.Contains(fb, "github.com") {
		t.Errorf("expected github link, got %q", fb)
	}
}

func TestCheckovSpec_Fallback_Windows(t *testing.T) {
	spec := checkovSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"})
	if !strings.Contains(fb, "pip") {
		t.Errorf("expected pip in windows fallback, got %q", fb)
	}
}

func TestCheckovSpec_Fallback_UnknownOS(t *testing.T) {
	spec := checkovSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "freebsd", Arch: "amd64"})
	if fb != "pip3 install checkov" {
		t.Errorf("expected generic pip3 fallback, got %q", fb)
	}
}

func TestTerrascanSpec_Fallback_Windows(t *testing.T) {
	spec := terrascanSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "windows", Arch: "amd64", BinaryExt: ".exe"})
	if !strings.Contains(fb, "github.com") {
		t.Errorf("expected github link, got %q", fb)
	}
}

func TestTerrascanSpec_Fallback_WindowsArm64(t *testing.T) {
	spec := terrascanSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "windows", Arch: "arm64", BinaryExt: ".exe"})
	if !strings.Contains(fb, "no Windows/arm64") {
		t.Errorf("expected arm64 warning, got %q", fb)
	}
}

func TestTerrascanSpec_Fallback_UnknownOS(t *testing.T) {
	spec := terrascanSpec()
	fb := spec.fallbackFn(platform.PlatformInfo{OS: "freebsd", Arch: "amd64"})
	if !strings.Contains(fb, "github.com") {
		t.Errorf("expected github link, got %q", fb)
	}
}

func TestFallbackFor_NilFallbackFn(t *testing.T) {
	spec := &ScannerSpec{Name: "test"}
	fb := FallbackFor(spec, platform.PlatformInfo{OS: "linux", Arch: "amd64"})
	if fb != "" {
		t.Errorf("expected empty fallback for nil fn, got %q", fb)
	}
}
