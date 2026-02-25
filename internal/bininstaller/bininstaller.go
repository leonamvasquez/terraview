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
	// Name returns the scanner name (e.g., "tfsec").
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
			_, copyErr := io.Copy(out, tr)
			out.Close()
			if copyErr != nil {
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

// TfsecInstaller installs tfsec binary.
// Ref: https://github.com/aquasecurity/tfsec
// Archives available for all platforms: tfsec_{version}_{os}_{arch}.tar.gz
// Direct binaries: tfsec-{os}-{arch} (linux/darwin only)
type TfsecInstaller struct{}

func (t *TfsecInstaller) Name() string               { return "tfsec" }
func (t *TfsecInstaller) LatestVersion() string      { return "1.28.14" }
func (t *TfsecInstaller) IsArchive() bool            { return false } // auto-detected from URL below
func (t *TfsecInstaller) SupportsDirectBinary() bool { return true }
func (t *TfsecInstaller) ArchiveBinaryName(p platform.PlatformInfo) string {
	return p.BinaryName("tfsec")
}
func (t *TfsecInstaller) FallbackCommand(p platform.PlatformInfo) string {
	switch p.OS {
	case "darwin":
		return "brew install tfsec"
	case "linux":
		return fmt.Sprintf("curl -Lo tfsec https://github.com/aquasecurity/tfsec/releases/download/v%s/tfsec-linux-%s && chmod +x tfsec && sudo mv tfsec /usr/local/bin/", t.LatestVersion(), p.Arch)
	case "windows":
		return "choco install tfsec  (or: scoop install tfsec)"
	}
	return "https://github.com/aquasecurity/tfsec/releases"
}

func (t *TfsecInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// Linux/Darwin: direct binary (no extraction needed)
	//   https://github.com/aquasecurity/tfsec/releases/download/v1.28.14/tfsec-linux-amd64
	// Windows: tarball (no .exe standalone binary on releases page)
	//   https://github.com/aquasecurity/tfsec/releases/download/v1.28.14/tfsec_1.28.14_windows_amd64.tar.gz
	switch p.OS {
	case "linux", "darwin":
		return fmt.Sprintf("https://github.com/aquasecurity/tfsec/releases/download/v%s/tfsec-%s-%s",
			version, p.OS, p.Arch)
	case "windows":
		// Windows archives exist for amd64 and arm64
		return fmt.Sprintf("https://github.com/aquasecurity/tfsec/releases/download/v%s/tfsec_%s_%s_%s.tar.gz",
			version, version, p.OS, p.Arch)
	}
	return ""
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
		&TfsecInstaller{},
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
