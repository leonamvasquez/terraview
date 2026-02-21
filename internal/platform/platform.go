package platform

import (
	"fmt"
	"os"
	"runtime"
)

// PlatformInfo holds the detected OS, architecture and platform-specific details.
type PlatformInfo struct {
	OS        string // "linux", "darwin", "windows"
	Arch      string // "amd64", "arm64"
	BinaryExt string // "" on Unix, ".exe" on Windows
}

// validCombinations lists all supported OS/ARCH pairs.
var validCombinations = map[string]bool{
	"linux/amd64":   true,
	"linux/arm64":   true,
	"darwin/amd64":  true,
	"darwin/arm64":  true,
	"windows/amd64": true,
}

// Detect returns the current platform information.
// Returns an error if the OS/ARCH combination is not supported.
func Detect() (PlatformInfo, error) {
	return detect(runtime.GOOS, runtime.GOARCH)
}

// detect is the internal implementation that accepts explicit OS/ARCH values
// (used for testing).
func detect(goos, goarch string) (PlatformInfo, error) {
	key := goos + "/" + goarch
	if !validCombinations[key] {
		return PlatformInfo{}, fmt.Errorf("unsupported platform: %s/%s. Supported: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64", goos, goarch)
	}

	ext := ""
	if goos == "windows" {
		ext = ".exe"
	}

	return PlatformInfo{
		OS:        goos,
		Arch:      goarch,
		BinaryExt: ext,
	}, nil
}

// IsSupported checks if a given OS/ARCH combination is supported.
func IsSupported(goos, goarch string) bool {
	return validCombinations[goos+"/"+goarch]
}

// SupportedPlatforms returns all supported OS/ARCH pairs.
func SupportedPlatforms() []string {
	platforms := make([]string, 0, len(validCombinations))
	for k := range validCombinations {
		platforms = append(platforms, k)
	}
	return platforms
}

// DisplayOS returns a human-friendly OS name.
func (p PlatformInfo) DisplayOS() string {
	switch p.OS {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	default:
		return p.OS
	}
}

// DisplayArch returns a human-friendly architecture name.
func (p PlatformInfo) DisplayArch() string {
	switch p.Arch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "ARM64 (Apple Silicon / Graviton)"
	default:
		return p.Arch
	}
}

// String returns a compact "OS/Arch" representation.
func (p PlatformInfo) String() string {
	return p.OS + "/" + p.Arch
}

// BinaryName returns the binary name with the correct extension for the platform.
func (p PlatformInfo) BinaryName(name string) string {
	return name + p.BinaryExt
}

// InstallDir returns the default scanner binary install directory.
// Unix:    ~/.terraview/bin
// Windows: %USERPROFILE%\.terraview\bin
func (p PlatformInfo) InstallDir() string {
	home := userHomeDir()
	if p.OS == "windows" {
		return home + "\\.terraview\\bin"
	}
	return home + "/.terraview/bin"
}

// userHomeDir returns the user home directory (testable via override).
var userHomeDir = defaultHomeDir

func defaultHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/tmp"
	}
	return home
}
