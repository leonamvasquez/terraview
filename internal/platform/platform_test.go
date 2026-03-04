package platform

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestDetect_CurrentPlatform(t *testing.T) {
	p, err := Detect()
	if err != nil {
		t.Fatalf("unexpected error on current platform: %v", err)
	}
	if p.OS != runtime.GOOS {
		t.Errorf("expected OS %q, got %q", runtime.GOOS, p.OS)
	}
	if p.Arch != runtime.GOARCH {
		t.Errorf("expected Arch %q, got %q", runtime.GOARCH, p.Arch)
	}
}

func TestDetect_AllSupported(t *testing.T) {
	tests := []struct {
		os, arch string
		ext      string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"darwin", "amd64", ""},
		{"darwin", "arm64", ""},
		{"windows", "amd64", ".exe"},
	}
	for _, tc := range tests {
		p, err := detect(tc.os, tc.arch)
		if err != nil {
			t.Errorf("detect(%q, %q) unexpected error: %v", tc.os, tc.arch, err)
			continue
		}
		if p.OS != tc.os {
			t.Errorf("detect(%q, %q).OS = %q, want %q", tc.os, tc.arch, p.OS, tc.os)
		}
		if p.Arch != tc.arch {
			t.Errorf("detect(%q, %q).Arch = %q, want %q", tc.os, tc.arch, p.Arch, tc.arch)
		}
		if p.BinaryExt != tc.ext {
			t.Errorf("detect(%q, %q).BinaryExt = %q, want %q", tc.os, tc.arch, p.BinaryExt, tc.ext)
		}
	}
}

func TestDetect_Unsupported(t *testing.T) {
	tests := []struct{ os, arch string }{
		{"freebsd", "amd64"},
		{"linux", "386"},
		{"windows", "arm64"},
		{"plan9", "amd64"},
	}
	for _, tc := range tests {
		_, err := detect(tc.os, tc.arch)
		if err == nil {
			t.Errorf("detect(%q, %q) expected error, got nil", tc.os, tc.arch)
		}
	}
}

func TestIsSupported(t *testing.T) {
	if !IsSupported("linux", "amd64") {
		t.Error("linux/amd64 should be supported")
	}
	if !IsSupported("darwin", "arm64") {
		t.Error("darwin/arm64 should be supported")
	}
	if IsSupported("freebsd", "amd64") {
		t.Error("freebsd/amd64 should NOT be supported")
	}
}

func TestSupportedPlatforms(t *testing.T) {
	platforms := SupportedPlatforms()
	if len(platforms) != 5 {
		t.Errorf("expected 5 supported platforms, got %d", len(platforms))
	}
}

func TestPlatformInfo_DisplayOS(t *testing.T) {
	tests := []struct{ os, want string }{
		{"darwin", "macOS"},
		{"linux", "Linux"},
		{"windows", "Windows"},
	}
	for _, tc := range tests {
		p := PlatformInfo{OS: tc.os}
		if got := p.DisplayOS(); got != tc.want {
			t.Errorf("DisplayOS(%q) = %q, want %q", tc.os, got, tc.want)
		}
	}
}

func TestPlatformInfo_DisplayArch(t *testing.T) {
	tests := []struct{ arch, want string }{
		{"amd64", "x86_64"},
		{"arm64", "ARM64 (Apple Silicon / Graviton)"},
	}
	for _, tc := range tests {
		p := PlatformInfo{Arch: tc.arch}
		if got := p.DisplayArch(); !strings.Contains(got, tc.want[:4]) {
			t.Errorf("DisplayArch(%q) = %q, want contains %q", tc.arch, got, tc.want[:4])
		}
	}
}

func TestPlatformInfo_DisplayArch_UnknownArch(t *testing.T) {
	p := PlatformInfo{Arch: "mips64"}
	got := p.DisplayArch()
	if got != "mips64" {
		t.Errorf("DisplayArch(mips64) = %q, want %q", got, "mips64")
	}
}

func TestPlatformInfo_DisplayOS_Unknown(t *testing.T) {
	p := PlatformInfo{OS: "freebsd"}
	got := p.DisplayOS()
	if got != "freebsd" {
		t.Errorf("DisplayOS(freebsd) = %q, want %q", got, "freebsd")
	}
}

func TestPlatformInfo_String(t *testing.T) {
	p := PlatformInfo{OS: "darwin", Arch: "arm64"}
	if got := p.String(); got != "darwin/arm64" {
		t.Errorf("String() = %q, want %q", got, "darwin/arm64")
	}
}

func TestPlatformInfo_BinaryName(t *testing.T) {
	unix := PlatformInfo{OS: "linux", BinaryExt: ""}
	if got := unix.BinaryName("tfsec"); got != "tfsec" {
		t.Errorf("Unix BinaryName = %q, want %q", got, "tfsec")
	}

	win := PlatformInfo{OS: "windows", BinaryExt: ".exe"}
	if got := win.BinaryName("tfsec"); got != "tfsec.exe" {
		t.Errorf("Windows BinaryName = %q, want %q", got, "tfsec.exe")
	}
}

func TestPlatformInfo_InstallDir(t *testing.T) {
	// Override home dir for test
	original := userHomeDir
	defer func() { userHomeDir = original }()

	userHomeDir = func() string { return "/home/testuser" }

	unix := PlatformInfo{OS: "linux"}
	got := unix.InstallDir()
	if got != "/home/testuser/.terraview/bin" {
		t.Errorf("Unix install dir = %q, want %q", got, "/home/testuser/.terraview/bin")
	}

	win := PlatformInfo{OS: "windows"}
	got = win.InstallDir()
	if got != "/home/testuser\\.terraview\\bin" {
		t.Errorf("Windows install dir = %q, want %q", got, "/home/testuser\\.terraview\\bin")
	}
}

func TestInstallDir_UsesRealHome(t *testing.T) {
	p, _ := Detect()
	dir := p.InstallDir()
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(dir, home) {
		t.Errorf("InstallDir %q does not start with home %q", dir, home)
	}
}
