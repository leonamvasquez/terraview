package bininstaller

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/downloader"
	"github.com/leonamvasquez/terraview/internal/platform"
)

// BinaryInstaller installs a scanner binary for any supported platform.
type BinaryInstaller interface {
	// Name returns the scanner name (e.g., "trivy").
	Name() string
	// DownloadURL returns the release URL for the given platform and version.
	// Returns empty string if the platform is not supported.
	DownloadURL(p platform.PlatformInfo, version string) string
	// LatestVersion returns the latest release version tag (e.g., "1.28.11").
	LatestVersion() string
	// IsArchive returns true if the download is a tar.gz that needs extraction.
	IsArchive() bool
	// ArchiveBinaryName returns the name of the binary inside the archive.
	ArchiveBinaryName(p platform.PlatformInfo) string
	// SupportsDirectBinary returns true if direct binary install is available.
	SupportsDirectBinary() bool
	// FallbackCommand returns a fallback install command (e.g., "pip install checkov").
	FallbackCommand(p platform.PlatformInfo) string
}

// InstallResult holds the outcome of an install attempt.
type InstallResult struct {
	Scanner   string `json:"scanner"`
	Version   string `json:"version"`
	Path      string `json:"path"`
	Installed bool   `json:"installed"`
	Method    string `json:"method,omitempty"` // "binary", "brew", "pip3", etc.
	Fallback  string `json:"fallback,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Install downloads and installs a scanner binary for the current platform.
// If installDir is empty, uses PlatformInfo.InstallDir().
func Install(installer BinaryInstaller, p platform.PlatformInfo, installDir string) InstallResult {
	name := installer.Name()
	version := installer.LatestVersion()

	if installDir == "" {
		installDir = p.InstallDir()
	}

	url := installer.DownloadURL(p, version)
	if url == "" {
		// No binary available for this platform — return fallback
		fb := installer.FallbackCommand(p)
		return InstallResult{
			Scanner:  name,
			Version:  version,
			Fallback: fb,
			Error:    fmt.Sprintf("no binary available for %s. %s", p.String(), fb),
		}
	}

	// Determine destination path
	binaryName := p.BinaryName(name)
	destPath := filepath.Join(installDir, binaryName)

	// Create install dir
	if err := os.MkdirAll(installDir, 0755); err != nil {
		return InstallResult{
			Scanner: name,
			Version: version,
			Error:   fmt.Sprintf("failed to create install dir: %v", err),
		}
	}

	// Auto-detect archive from URL when installer.IsArchive() is false but URL ends in .tar.gz
	isArchive := installer.IsArchive() || strings.HasSuffix(url, ".tar.gz")

	if isArchive {
		return installFromArchive(installer, p, url, destPath, name, version)
	}
	return installDirect(url, destPath, name, version, p)
}

func installDirect(url, destPath, name, version string, p platform.PlatformInfo) InstallResult {
	_, err := downloader.Download(url, destPath, downloader.DefaultOptions())
	if err != nil {
		return InstallResult{
			Scanner: name,
			Version: version,
			Error:   fmt.Sprintf("download failed: %v", err),
		}
	}

	// Set executable permission on Unix
	if p.OS != "windows" {
		_ = os.Chmod(destPath, 0755)
	}

	return InstallResult{
		Scanner:   name,
		Version:   version,
		Path:      destPath,
		Installed: true,
		Method:    "binary",
	}
}

func installFromArchive(installer BinaryInstaller, p platform.PlatformInfo, url, destPath, name, version string) InstallResult {
	// Download to temp file
	tmpFile, err := os.CreateTemp("", name+"-*.tar.gz")
	if err != nil {
		return InstallResult{
			Scanner: name,
			Version: version,
			Error:   fmt.Sprintf("failed to create temp file: %v", err),
		}
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	_, err = downloader.Download(url, tmpPath, downloader.DefaultOptions())
	if err != nil {
		return InstallResult{
			Scanner: name,
			Version: version,
			Error:   fmt.Sprintf("download failed: %v", err),
		}
	}

	// Extract target binary from archive
	targetName := installer.ArchiveBinaryName(p)
	err = extractFromTarGz(tmpPath, targetName, destPath)
	if err != nil {
		return InstallResult{
			Scanner: name,
			Version: version,
			Error:   fmt.Sprintf("extraction failed: %v", err),
		}
	}

	// Set executable permission on Unix
	if p.OS != "windows" {
		_ = os.Chmod(destPath, 0755)
	}

	return InstallResult{
		Scanner:   name,
		Version:   version,
		Path:      destPath,
		Installed: true,
		Method:    "binary",
	}
}

// extractFromTarGz extracts a specific file from a .tar.gz archive.
func extractFromTarGz(archivePath, targetName, destPath string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open archive: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}

		// Match by base name (archives may have nested paths)
		base := filepath.Base(header.Name)
		if base == targetName || header.Name == targetName {
			out, err := os.Create(destPath)
			if err != nil {
				return fmt.Errorf("create dest: %w", err)
			}
			const maxBinarySize = 256 * 1024 * 1024 // 256 MB
			_, copyErr := io.CopyN(out, tr, maxBinarySize)
			out.Close()
			if copyErr != nil && copyErr != io.EOF {
				return fmt.Errorf("copy: %w", copyErr)
			}
			return nil
		}
	}
	return fmt.Errorf("binary %q not found in archive", targetName)
}

// ---------------------------------------------------------------------------
// Scanner-specific installers
// ---------------------------------------------------------------------------

// TrivyInstaller installs the Trivy binary.
// Ref: https://github.com/aquasecurity/trivy
// Archives: trivy_{version}_{OS}-{arch}.tar.gz
//
//	OS: Linux, macOS  (windows ships only a .zip — not supported for direct install)
//	arch: 64bit (amd64), ARM64 (arm64)
type TrivyInstaller struct{}

func (t *TrivyInstaller) Name() string               { return "trivy" }
func (t *TrivyInstaller) LatestVersion() string      { return "0.71.0" }
func (t *TrivyInstaller) IsArchive() bool            { return true }
func (t *TrivyInstaller) SupportsDirectBinary() bool { return true }
func (t *TrivyInstaller) ArchiveBinaryName(p platform.PlatformInfo) string {
	return p.BinaryName("trivy")
}
func (t *TrivyInstaller) FallbackCommand(p platform.PlatformInfo) string {
	switch p.OS {
	case "darwin":
		return "brew install trivy"
	case "linux":
		return fmt.Sprintf("curl -L https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_Linux-64bit.tar.gz | tar xz trivy && sudo mv trivy /usr/local/bin/", t.LatestVersion(), t.LatestVersion())
	case "windows":
		return "choco install trivy  (or: scoop install trivy)"
	}
	return "https://github.com/aquasecurity/trivy/releases"
}

func (t *TrivyInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// trivy naming: trivy_0.71.0_Linux-64bit.tar.gz
	//               trivy_0.71.0_Linux-ARM64.tar.gz
	//               trivy_0.71.0_macOS-ARM64.tar.gz
	// Windows ships only a .zip, which the archive extractor does not support —
	// Windows falls back to package managers (choco/scoop).
	osName := map[string]string{
		"darwin": "macOS",
		"linux":  "Linux",
	}[p.OS]
	if osName == "" {
		return ""
	}
	archName := map[string]string{
		"amd64": "64bit",
		"arm64": "ARM64",
	}[p.Arch]
	if archName == "" {
		return ""
	}
	return fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/trivy_%s_%s-%s.tar.gz",
		version, version, osName, archName)
}

// TerrascanInstaller installs Terrascan binary.
// Ref: https://github.com/tenable/terrascan (archived Nov 2025, last release v1.19.9)
// Archives: terrascan_{version}_{OS}_{arch}.tar.gz
//
//	OS: Darwin, Linux  (Title-cased)
//	arch: arm64, x86_64 (amd64 mapped to x86_64)
//
// NOT available: Windows/arm64
type TerrascanInstaller struct{}

func (t *TerrascanInstaller) Name() string               { return "terrascan" }
func (t *TerrascanInstaller) LatestVersion() string      { return "1.19.9" }
func (t *TerrascanInstaller) IsArchive() bool            { return true }
func (t *TerrascanInstaller) SupportsDirectBinary() bool { return true }
func (t *TerrascanInstaller) FallbackCommand(p platform.PlatformInfo) string {
	switch p.OS {
	case "darwin":
		return "brew install terrascan"
	case "linux":
		return "curl -L https://github.com/tenable/terrascan/releases/download/v1.19.9/terrascan_1.19.9_Linux_x86_64.tar.gz | tar xz && sudo mv terrascan /usr/local/bin/"
	case "windows":
		if p.Arch == "arm64" {
			return "terrascan has no Windows/arm64 release — see https://github.com/tenable/terrascan/releases"
		}
		return "Download from https://github.com/tenable/terrascan/releases"
	}
	return "https://github.com/tenable/terrascan/releases"
}

func (t *TerrascanInstaller) ArchiveBinaryName(p platform.PlatformInfo) string {
	return p.BinaryName("terrascan")
}

func (t *TerrascanInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// terrascan naming: terrascan_1.19.9_Darwin_arm64.tar.gz
	//                   terrascan_1.19.9_Linux_x86_64.tar.gz
	//                   terrascan_1.19.9_Windows_x86_64.tar.gz
	// NO Windows/arm64 release.
	if p.OS == "windows" && p.Arch == "arm64" {
		return "" // not available
	}
	osName := map[string]string{
		"darwin":  "Darwin",
		"linux":   "Linux",
		"windows": "Windows",
	}[p.OS]
	if osName == "" {
		return ""
	}
	archName := p.Arch
	if archName == "amd64" {
		archName = "x86_64"
	}
	return fmt.Sprintf("https://github.com/tenable/terrascan/releases/download/v%s/terrascan_%s_%s_%s.tar.gz",
		version, version, osName, archName)
}

// CheckovInstaller handles Checkov — Python-only, no direct binary download.
// Ref: https://www.checkov.io/2.Basics/Installing%20Checkov.html
// Install via: pip3/pip, brew (macOS/Linux), choco (Windows).
type CheckovInstaller struct{}

func (c *CheckovInstaller) Name() string                                     { return "checkov" }
func (c *CheckovInstaller) LatestVersion() string                            { return "" }
func (c *CheckovInstaller) IsArchive() bool                                  { return false }
func (c *CheckovInstaller) SupportsDirectBinary() bool                       { return false }
func (c *CheckovInstaller) ArchiveBinaryName(_ platform.PlatformInfo) string { return "" }

func (c *CheckovInstaller) DownloadURL(_ platform.PlatformInfo, _ string) string {
	// Checkov has no standalone binary — requires Python/pip
	return ""
}

func (c *CheckovInstaller) FallbackCommand(p platform.PlatformInfo) string {
	switch p.OS {
	case "darwin":
		return "pip3 install checkov  (or: brew install checkov)"
	case "linux":
		return "pip3 install checkov"
	case "windows":
		return "pip install checkov  (or: choco install checkov)"
	}
	return "pip3 install checkov"
}

// AllInstallers returns all scanner installers.
func AllInstallers() []BinaryInstaller {
	return []BinaryInstaller{
		&CheckovInstaller{},
		&TrivyInstaller{},
		&TerrascanInstaller{},
	}
}

// InstallerFor returns the installer for a named scanner, or nil.
func InstallerFor(name string) BinaryInstaller {
	lower := strings.ToLower(name)
	for _, inst := range AllInstallers() {
		if inst.Name() == lower {
			return inst
		}
	}
	return nil
}
