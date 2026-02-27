package cmd

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/spf13/cobra"
)

const (
	githubRepo = "leonamvasquez/terraview"
	binaryName = "terraview"
)

var githubAPIURL = "https://api.github.com/repos/" + githubRepo + "/releases/latest"

var forceUpdate bool

var upgradeCmd = &cobra.Command{
	Use:   "upgrade",
	Short: "Upgrade terraview to the latest version",
	Long: `Downloads and installs the latest version of terraview from GitHub Releases.

Detects your OS and architecture automatically.
Also updates bundled assets (prompts and rules).

Examples:
  terraview upgrade              # upgrade if newer version available
  terraview upgrade --force      # force reinstall even if up to date`,
	RunE: runUpdate,
}

func init() {
	upgradeCmd.Flags().BoolVar(&forceUpdate, "force", false, "Force update even if already on latest version")
}

// githubRelease represents the GitHub API response for a release.
type githubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []githubAsset `json:"assets"`
}

// githubAsset represents a single asset in a GitHub release.
type githubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func runUpdate(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println("Checking for updates...")

	// 1. Fetch latest release info
	release, err := fetchLatestRelease()
	if err != nil {
		return fmt.Errorf("failed to check for updates: %w", err)
	}

	latestVersion := release.TagName
	currentVersion := Version

	fmt.Printf("  Current version: %s\n", currentVersion)
	fmt.Printf("  Latest version:  %s\n", latestVersion)

	// 2. Compare versions
	if !forceUpdate && normalizeVersion(currentVersion) == normalizeVersion(latestVersion) {
		fmt.Println()
		fmt.Println("Already up to date.")
		return nil
	}

	fmt.Println()
	if forceUpdate {
		fmt.Println("Force updating...")
	} else {
		fmt.Printf("Updating %s -> %s ...\n", currentVersion, latestVersion)
	}

	// 3. Find the right binary asset for this OS/arch
	osName := runtime.GOOS
	archName := runtime.GOARCH
	binaryAssetName := fmt.Sprintf("%s-%s-%s.tar.gz", binaryName, osName, archName)
	assetsAssetName := "terraview-assets.tar.gz"

	binaryURL := findAssetURL(release, binaryAssetName)
	if binaryURL == "" {
		return fmt.Errorf("no release asset found for %s/%s (looked for %s)", osName, archName, binaryAssetName)
	}

	// 4. Download to temp dir
	tmpDir, err := os.MkdirTemp("", "terraview-update-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Download binary
	downloadSpinner := output.NewSpinner(fmt.Sprintf("Downloading %s...", binaryAssetName))
	downloadSpinner.Start()
	binaryTarPath := filepath.Join(tmpDir, "binary.tar.gz")
	if err := downloadFile(binaryURL, binaryTarPath); err != nil {
		downloadSpinner.Stop(false)
		return fmt.Errorf("failed to download binary: %w", err)
	}
	downloadSpinner.Stop(true)

	// Extract binary from tarball
	extractedBinary, err := extractBinaryFromTar(binaryTarPath, tmpDir)
	if err != nil {
		return fmt.Errorf("failed to extract binary: %w", err)
	}

	// 5. Download and update assets
	assetsURL := findAssetURL(release, assetsAssetName)
	if assetsURL != "" {
		assetsSpinner := output.NewSpinner(fmt.Sprintf("Downloading %s...", assetsAssetName))
		assetsSpinner.Start()
		assetsTarPath := filepath.Join(tmpDir, "assets.tar.gz")
		if err := downloadFile(assetsURL, assetsTarPath); err != nil {
			assetsSpinner.Stop(false)
			fmt.Fprintf(os.Stderr, "  WARNING: failed to download assets: %v\n", err)
		} else {
			assetsSpinner.Stop(true)
			assetsDir := getAssetsDir()
			if err := extractTarGz(assetsTarPath, assetsDir); err != nil {
				fmt.Fprintf(os.Stderr, "  WARNING: failed to extract assets: %v\n", err)
			} else {
				fmt.Printf("  Assets updated: %s\n", assetsDir)
			}
		}
	}

	// 6. Replace the current binary
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to determine current binary path: %w", err)
	}
	currentBinary, err = filepath.EvalSymlinks(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to resolve binary path: %w", err)
	}

	fmt.Printf("  Replacing %s ...\n", currentBinary)
	if err := replaceBinary(extractedBinary, currentBinary); err != nil {
		hint := "\n\n  Try: sudo terraview upgrade"
		if runtime.GOOS == "windows" {
			hint = "\n\n  Try running from an elevated (Administrator) terminal"
		}
		return fmt.Errorf("failed to replace binary: %w%s", err, hint)
	}

	fmt.Println()
	fmt.Printf("Updated to %s successfully.\n", latestVersion)
	return nil
}

func fetchLatestRelease() (*githubRelease, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	req, err := http.NewRequest("GET", githubAPIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "terraview/"+Version)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach GitHub API: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no releases found for %s", githubRepo)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to parse GitHub API response: %w", err)
	}

	if release.TagName == "" {
		return nil, fmt.Errorf("no tag_name in release response")
	}

	return &release, nil
}

func findAssetURL(release *githubRelease, name string) string {
	for _, asset := range release.Assets {
		if asset.Name == name {
			return asset.BrowserDownloadURL
		}
	}
	return ""
}

func downloadFile(url, dest string) error {
	client := &http.Client{
		Timeout: 120 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func extractBinaryFromTar(tarPath, destDir string) (string, error) {
	f, err := os.Open(tarPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}

		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Look for the binary (filename starts with "terraview")
		baseName := filepath.Base(header.Name)
		if strings.HasPrefix(baseName, binaryName) {
			destName := binaryName
			if runtime.GOOS == "windows" {
				destName += ".exe"
			}
			destPath := filepath.Join(destDir, destName)
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY, 0755)
			if err != nil {
				return "", err
			}

			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return "", err
			}
			out.Close()
			return destPath, nil
		}
	}

	return "", fmt.Errorf("binary not found in archive")
}

func extractTarGz(tarPath, destDir string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		// Prevent path traversal
		if !strings.HasPrefix(filepath.Clean(target), filepath.Clean(destDir)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			out.Close()
		}
	}

	return nil
}

func replaceBinary(newBinary, currentBinary string) error {
	// Rename strategy: rename old, copy new, remove old
	backupPath := currentBinary + ".bak"

	// Remove any previous backup
	os.Remove(backupPath)

	// Rename current binary to backup
	if err := os.Rename(currentBinary, backupPath); err != nil {
		return fmt.Errorf("failed to backup current binary: %w", err)
	}

	// Copy new binary to the target path
	src, err := os.Open(newBinary)
	if err != nil {
		// Restore backup
		_ = os.Rename(backupPath, currentBinary)
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(currentBinary, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		// Restore backup
		_ = os.Rename(backupPath, currentBinary)
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		_ = os.Remove(currentBinary)
		_ = os.Rename(backupPath, currentBinary)
		return err
	}

	// Remove backup
	_ = os.Remove(backupPath)
	return nil
}

func getAssetsDir() string {
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		return filepath.Join(homeDir, ".terraview")
	}
	return ".terraview"
}

func normalizeVersion(v string) string {
	return strings.TrimPrefix(strings.TrimSpace(v), "v")
}
