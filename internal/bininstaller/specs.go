package bininstaller

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/leonamvasquez/terraview/internal/platform"
)

// ScannerSpec describes how to install a scanner across all platforms.
// SmartInstall tries: 1) direct binary download, 2) package manager, 3) fallback message.
type ScannerSpec struct {
	Name       string
	Version    string
	Deprecated string // non-empty means show a warning (e.g., archived project)

	// binaryInst handles direct binary/archive downloads (may be nil).
	binaryInst BinaryInstaller

	// pkgCmdsFn returns ordered list of package manager commands to try.
	// Each []string is a full exec.Command: e.g. ["brew", "install", "tfsec"].
	// The first element is also used as the manager name shown in output.
	pkgCmdsFn func(p platform.PlatformInfo) [][]string

	// fallbackFn returns a human-readable manual install hint.
	fallbackFn func(p platform.PlatformInfo) string
}

// ─────────────────────────────────────────────────────────────
// Registry
// ─────────────────────────────────────────────────────────────

var allScannerSpecs = []*ScannerSpec{
	checkovSpec(),
	tfsecSpec(),
	terrascanSpec(),
	kicsSpec(),
}

// AllSpecs returns specs for all known scanners.
func AllSpecs() []*ScannerSpec { return allScannerSpecs }

// SpecFor returns the spec for a scanner by name (case-insensitive), or nil.
func SpecFor(name string) *ScannerSpec {
	lower := strings.ToLower(name)
	for _, s := range allScannerSpecs {
		if s.Name == lower {
			return s
		}
	}
	return nil
}

// FallbackFor returns a human-readable install hint for the given spec and platform.
func FallbackFor(spec *ScannerSpec, p platform.PlatformInfo) string {
	if spec.fallbackFn != nil {
		return spec.fallbackFn(p)
	}
	return ""
}

// ─────────────────────────────────────────────────────────────
// SmartInstall
// ─────────────────────────────────────────────────────────────

// SmartInstall attempts to install a scanner using the best available method.
//
// Priority:
//  1. Direct binary download (if available for this platform)
//  2. Package manager (brew, pip3, pip, choco, scoop — first one found in PATH)
//  3. Returns Fallback field with manual install instructions
//
// Package manager commands are executed with live output streamed to the terminal
// so the user can see installation progress.
func SmartInstall(spec *ScannerSpec, p platform.PlatformInfo, installDir string) InstallResult {
	name := spec.Name
	version := spec.Version

	// ── 1. Direct binary download ─────────────────────────────
	if spec.binaryInst != nil && spec.binaryInst.SupportsDirectBinary() {
		url := spec.binaryInst.DownloadURL(p, version)
		if url != "" {
			result := Install(spec.binaryInst, p, installDir)
			if result.Installed {
				return result
			}
			// Binary download failed — fall through to package manager
		}
	}

	// ── 2. Package manager ────────────────────────────────────
	if spec.pkgCmdsFn != nil {
		cmds := spec.pkgCmdsFn(p)
		for _, cmdAndArgs := range cmds {
			if len(cmdAndArgs) == 0 {
				continue
			}
			manager := cmdAndArgs[0]

			// Check if this package manager is available
			if _, err := exec.LookPath(manager); err != nil {
				continue
			}

			// Show which manager is being used.
			// For composite commands (sh -c "..."), display the script content
			// and extract the real tool name for the result label.
			displayCmd := strings.Join(cmdAndArgs, " ")
			if manager == "sh" && len(cmdAndArgs) >= 3 && cmdAndArgs[1] == "-c" {
				displayCmd = cmdAndArgs[2]
				// Use first meaningful token as manager label (e.g. "apt-get" from
				// "apt-get update && apt-get install -y python3-pip && pip3 install checkov")
				for _, tok := range strings.Fields(cmdAndArgs[2]) {
					if tok != "sudo" && tok != "&&" {
						manager = tok
						break
					}
				}
			}
			fmt.Printf("    → %s\n", displayCmd)

			// Run with live output so the user sees progress
			cmd := exec.Command(cmdAndArgs[0], cmdAndArgs[1:]...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err != nil {
				// This manager failed — try the next one
				fmt.Printf("    [!] %s exited with error: %v\n", manager, err)
				continue
			}

			// Try to resolve the binary path in the updated PATH.
			installedPath, _ := exec.LookPath(name)
			return InstallResult{
				Scanner:   name,
				Version:   version,
				Installed: installedPath != "",
				Method:    manager,
				Path:      installedPath,
				// If no path found (e.g., not linked), surface a fallback so the
				// user knows what to do.
				Fallback: func() string {
					if installedPath != "" {
						return ""
					}
					if spec.fallbackFn != nil {
						return spec.fallbackFn(p)
					}
					return ""
				}(),
				Error: func() string {
					if installedPath != "" {
						return ""
					}
					return fmt.Sprintf("%s installed but binary not found in PATH — it may need to be linked", manager)
				}(),
			}
		}
	}

	// ── 3. Nothing worked — return fallback ───────────────────
	fb := ""
	if spec.fallbackFn != nil {
		fb = spec.fallbackFn(p)
	}
	return InstallResult{
		Scanner:  name,
		Version:  version,
		Fallback: fb,
		Error:    fmt.Sprintf("no automatic installation method available for %s/%s", p.OS, p.Arch),
	}
}

// ─────────────────────────────────────────────────────────────
// Scanner spec definitions
// ─────────────────────────────────────────────────────────────

// tfsecSpec — https://github.com/aquasecurity/tfsec
// Binaries: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64
// Package managers: brew (macOS/Linux), choco/scoop (Windows)
func tfsecSpec() *ScannerSpec {
	return &ScannerSpec{
		Name:       "tfsec",
		Version:    "1.28.14",
		binaryInst: &TfsecInstaller{},
		pkgCmdsFn: func(p platform.PlatformInfo) [][]string {
			switch p.OS {
			case "darwin", "linux":
				return [][]string{
					{"brew", "install", "tfsec"},
				}
			case "windows":
				return [][]string{
					{"choco", "install", "tfsec", "-y"},
					{"scoop", "install", "tfsec"},
				}
			}
			return nil
		},
		fallbackFn: func(p platform.PlatformInfo) string {
			switch p.OS {
			case "darwin", "linux":
				return "brew install tfsec  (or: https://github.com/aquasecurity/tfsec/releases)"
			case "windows":
				return "choco install tfsec  (or: scoop install tfsec)"
			}
			return "https://github.com/aquasecurity/tfsec/releases"
		},
	}
}

// checkovSpec — https://www.checkov.io/2.Basics/Installing%20Checkov.html
// No binary downloads — Python package only.
// Package managers: pip3/pip (all), brew (macOS/Linux), choco (Windows)
func checkovSpec() *ScannerSpec {
	return &ScannerSpec{
		Name:    "checkov",
		Version: "latest",
		pkgCmdsFn: func(p platform.PlatformInfo) [][]string {
			switch p.OS {
			case "darwin":
				return [][]string{
					{"pip3", "install", "checkov"},
					{"brew", "install", "checkov"},
					{"pip", "install", "checkov"},
				}
			case "linux":
				return [][]string{
					{"pip3", "install", "checkov"},
					{"pip", "install", "checkov"},
					// If neither pip3 nor pip are available, try installing them
					// via the system package manager first, then install checkov.
					{"sh", "-c", "apt-get update -qq && apt-get install -y -qq python3-pip && pip3 install --break-system-packages checkov"},
					{"sh", "-c", "dnf install -y python3-pip && pip3 install checkov"},
					{"sh", "-c", "apk add --no-cache py3-pip && pip3 install checkov"},
					{"brew", "install", "checkov"},
				}
			case "windows":
				return [][]string{
					{"pip", "install", "checkov"},
					{"pip3", "install", "checkov"},
					{"choco", "install", "checkov", "-y"},
				}
			}
			return nil
		},
		fallbackFn: func(p platform.PlatformInfo) string {
			switch p.OS {
			case "darwin":
				return "pip3 install checkov  (or: brew install checkov)"
			case "linux":
				return "pip3 install checkov  (or: apt-get install -y python3-pip && pip3 install checkov)"
			case "windows":
				return "pip install checkov  (or: choco install checkov)"
			}
			return "pip3 install checkov"
		},
	}
}

// terrascanSpec — https://github.com/tenable/terrascan (archived Nov 2025, v1.19.9 is last release)
// Binaries: darwin/arm64, darwin/amd64(x86_64), linux/arm64, linux/amd64(x86_64), windows/amd64
// NOT available: windows/arm64
func terrascanSpec() *ScannerSpec {
	return &ScannerSpec{
		Name:       "terrascan",
		Version:    "1.19.9",
		Deprecated: "⚠  terrascan archived by Tenable (Nov 2025) — still functional, no longer maintained",
		binaryInst: &TerrascanInstaller{},
		pkgCmdsFn: func(p platform.PlatformInfo) [][]string {
			// Binary downloads cover all supported platforms.
			// Brew is a fallback for macOS if the binary download fails.
			if p.OS == "darwin" {
				return [][]string{{"brew", "install", "terrascan"}}
			}
			return nil
		},
		fallbackFn: func(p platform.PlatformInfo) string {
			switch p.OS {
			case "darwin":
				return "brew install terrascan"
			case "linux":
				return "curl -L https://github.com/tenable/terrascan/releases/download/v1.19.9/terrascan_1.19.9_Linux_x86_64.tar.gz | tar xz && sudo mv terrascan /usr/local/bin/"
			case "windows":
				if p.Arch == "arm64" {
					return "terrascan has no Windows/arm64 release — see https://github.com/tenable/terrascan/releases"
				}
				return "Download from https://github.com/tenable/terrascan/releases/tag/v1.19.9"
			}
			return "https://github.com/tenable/terrascan/releases"
		},
	}
}

// kicsSpec — https://docs.kics.io/latest/getting-started/
// KICS no longer ships pre-built binaries since v2.x.
// Install via: brew (macOS/Linux), Docker (all platforms — not automated).
func kicsSpec() *ScannerSpec {
	return &ScannerSpec{
		Name:    "kics",
		Version: "2.1.19",
		pkgCmdsFn: func(p platform.PlatformInfo) [][]string {
			switch p.OS {
			case "darwin":
				return [][]string{{"brew", "install", "kics"}}
			case "linux":
				// brew first (Linuxbrew), then Go install as fallback for
				// containers/servers where brew isn't available.
				return [][]string{
					{"brew", "install", "kics"},
					{"go", "install", "github.com/Checkmarx/kics/v2@latest"},
				}
			}
			// Windows: no brew, no binary — Docker only (not auto-installed)
			return nil
		},
		fallbackFn: func(p platform.PlatformInfo) string {
			switch p.OS {
			case "darwin":
				return "brew install kics  (or: docker run checkmarx/kics)"
			case "linux":
				return "brew install kics  (or: go install github.com/Checkmarx/kics/v2@latest, or: docker run checkmarx/kics)"
			case "windows":
				return "docker run checkmarx/kics  (docs: https://docs.kics.io/latest/getting-started/)"
			}
			return "docker run checkmarx/kics"
		},
	}
}
