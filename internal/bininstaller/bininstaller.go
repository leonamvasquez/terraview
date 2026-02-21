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

	if installer.IsArchive() {
		return installFromArchive(installer, p, url, installDir, destPath, name, version)
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
		os.Chmod(destPath, 0755)
	}

	return InstallResult{
		Scanner:   name,
		Version:   version,
		Path:      destPath,
		Installed: true,
	}
}

func installFromArchive(installer BinaryInstaller, p platform.PlatformInfo, url, installDir, destPath, name, version string) InstallResult {
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
		os.Chmod(destPath, 0755)
	}

	return InstallResult{
		Scanner:   name,
		Version:   version,
		Path:      destPath,
		Installed: true,
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
			defer out.Close()
			if _, err := io.Copy(out, tr); err != nil {
				return fmt.Errorf("copy: %w", err)
			}
			return nil
		}
	}
	return fmt.Errorf("binary %q not found in archive", targetName)
}

// ---------------------------------------------------------------------------
// Scanner-specific installers
// ---------------------------------------------------------------------------

// TfsecInstaller installs tfsec/trivy binary.
type TfsecInstaller struct{}

func (t *TfsecInstaller) Name() string { return "tfsec" }
func (t *TfsecInstaller) LatestVersion() string { return "1.28.11" }
func (t *TfsecInstaller) IsArchive() bool { return false }
func (t *TfsecInstaller) SupportsDirectBinary() bool { return true }
func (t *TfsecInstaller) ArchiveBinaryName(_ platform.PlatformInfo) string { return "" }
func (t *TfsecInstaller) FallbackCommand(p platform.PlatformInfo) string {
	if p.OS == "darwin" {
		return "brew install tfsec"
	}
	return "Download from https://github.com/aquasecurity/tfsec/releases"
}

func (t *TfsecInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// tfsec naming: tfsec-linux-amd64, tfsec-darwin-arm64, tfsec-windows-amd64.exe
	ext := ""
	if p.OS == "windows" {
		ext = ".exe"
	}
	return fmt.Sprintf("https://github.com/aquasecurity/tfsec/releases/download/v%s/tfsec-%s-%s%s",
		version, p.OS, p.Arch, ext)
}

// TerrascanInstaller installs Terrascan binary.
type TerrascanInstaller struct{}

func (t *TerrascanInstaller) Name() string { return "terrascan" }
func (t *TerrascanInstaller) LatestVersion() string { return "1.19.9" }
func (t *TerrascanInstaller) IsArchive() bool { return true }
func (t *TerrascanInstaller) SupportsDirectBinary() bool { return true }
func (t *TerrascanInstaller) FallbackCommand(p platform.PlatformInfo) string {
	if p.OS == "darwin" {
		return "brew install terrascan"
	}
	return "Download from https://github.com/tenable/terrascan/releases"
}

func (t *TerrascanInstaller) ArchiveBinaryName(p platform.PlatformInfo) string {
	return p.BinaryName("terrascan")
}

func (t *TerrascanInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// terrascan naming: terrascan_1.19.9_Linux_x86_64.tar.gz
	osName := strings.Title(p.OS)
	if p.OS == "darwin" {
		osName = "Darwin"
	}
	archName := p.Arch
	if archName == "amd64" {
		archName = "x86_64"
	}
	return fmt.Sprintf("https://github.com/tenable/terrascan/releases/download/v%s/terrascan_%s_%s_%s.tar.gz",
		version, version, osName, archName)
}

// KICSInstaller installs KICS binary.
type KICSInstaller struct{}

func (k *KICSInstaller) Name() string { return "kics" }
func (k *KICSInstaller) LatestVersion() string { return "2.1.3" }
func (k *KICSInstaller) IsArchive() bool { return true }
func (k *KICSInstaller) SupportsDirectBinary() bool { return true }
func (k *KICSInstaller) FallbackCommand(p platform.PlatformInfo) string {
	if p.OS == "darwin" {
		return "brew install kics"
	}
	return "Download from https://github.com/Checkmarx/kics/releases"
}

func (k *KICSInstaller) ArchiveBinaryName(p platform.PlatformInfo) string {
	return p.BinaryName("kics")
}

func (k *KICSInstaller) DownloadURL(p platform.PlatformInfo, version string) string {
	// KICS naming: kics_2.1.3_linux_amd64.tar.gz
	// Windows: kics_2.1.3_windows_amd64.tar.gz (no .exe, it's inside archive)
	return fmt.Sprintf("https://github.com/Checkmarx/kics/releases/download/v%s/kics_%s_%s_%s.tar.gz",
		version, version, p.OS, p.Arch)
}

// CheckovInstaller handles Checkov — Python-only, no direct binary download.
type CheckovInstaller struct{}

func (c *CheckovInstaller) Name() string { return "checkov" }
func (c *CheckovInstaller) LatestVersion() string { return "" }
func (c *CheckovInstaller) IsArchive() bool { return false }
func (c *CheckovInstaller) SupportsDirectBinary() bool { return false }
func (c *CheckovInstaller) ArchiveBinaryName(_ platform.PlatformInfo) string { return "" }

func (c *CheckovInstaller) DownloadURL(_ platform.PlatformInfo, _ string) string {
	// Checkov has no standalone binary — requires Python/pip
	return ""
}

func (c *CheckovInstaller) FallbackCommand(p platform.PlatformInfo) string {
	if p.OS == "darwin" {
		return "brew install checkov (or: pip install checkov)"
	}
	return "pip install checkov"
}

// AllInstallers returns all scanner installers.
func AllInstallers() []BinaryInstaller {
	return []BinaryInstaller{
		&CheckovInstaller{},
		&TfsecInstaller{},
		&TerrascanInstaller{},
		&KICSInstaller{},
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
