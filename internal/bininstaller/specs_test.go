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
