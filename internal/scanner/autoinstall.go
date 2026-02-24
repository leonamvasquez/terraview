package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/bininstaller"
	"github.com/leonamvasquez/terraview/internal/platform"
)

// EnsureBinDirInPath adds ~/.terraview/bin to the process PATH
// so that exec.LookPath and exec.Command find installed scanner binaries.
// Safe to call multiple times — skips if already present.
func EnsureBinDirInPath() {
	p, err := platform.Detect()
	if err != nil {
		return
	}
	binDir := p.InstallDir()
	currentPath := os.Getenv("PATH")
	sep := string(os.PathListSeparator)

	// Check if already in PATH
	for _, dir := range strings.Split(currentPath, sep) {
		if dir == binDir {
			return
		}
	}

	// Prepend so terraview-installed binaries take precedence
	os.Setenv("PATH", binDir+sep+currentPath)
}

// binaryInBinDir checks if a scanner binary exists in ~/.terraview/bin/.
func binaryInBinDir(name string) bool {
	p, err := platform.Detect()
	if err != nil {
		return false
	}
	binPath := filepath.Join(p.InstallDir(), p.BinaryName(name))
	_, statErr := os.Stat(binPath)
	return statErr == nil
}

// AutoInstallScanner attempts to install a scanner using the best available method
// for the current platform (binary download, package manager, or fallback message).
func AutoInstallScanner(name string) bininstaller.InstallResult {
	spec := bininstaller.SpecFor(name)
	if spec == nil {
		return bininstaller.InstallResult{
			Scanner: name,
			Error:   "no installer available for " + name,
		}
	}
	p, err := platform.Detect()
	if err != nil {
		return bininstaller.InstallResult{
			Scanner: name,
			Error:   "platform detection failed: " + err.Error(),
		}
	}
	result := bininstaller.SmartInstall(spec, p, "")
	if result.Installed {
		// Update cache
		cache := bininstaller.LoadCache()
		cache.Set(result)
		cache.Save()
		// Ensure the install dir is in PATH for subsequent commands
		EnsureBinDirInPath()
	}
	return result
}

// InstallMissing installs all missing scanners using SmartInstall (binary + pkg manager).
// If force is true, reinstalls even if already cached.
// Returns results for each scanner.
func (m *ScannerManager) InstallMissing(force bool) []bininstaller.InstallResult {
	EnsureBinDirInPath()
	cache := bininstaller.LoadCache()
	p, _ := platform.Detect()
	results := make([]bininstaller.InstallResult, 0, len(bininstaller.AllSpecs()))

	for _, spec := range bininstaller.AllSpecs() {
		name := spec.Name

		// Skip if already installed and not forcing
		if !force {
			s, ok := m.Get(name)
			if ok && s.Available() {
				continue
			}
			if cache.IsInstalled(name) {
				continue
			}
		}

		result := bininstaller.SmartInstall(spec, p, "")
		if result.Installed {
			cache.Set(result)
		}
		results = append(results, result)
	}

	cache.Save()
	return results
}
