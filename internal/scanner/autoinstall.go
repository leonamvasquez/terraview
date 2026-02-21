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

// AutoInstallScanner attempts to download and install a scanner binary
// for the current platform. Returns the install result.
func AutoInstallScanner(name string) bininstaller.InstallResult {
	inst := bininstaller.InstallerFor(name)
	if inst == nil {
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
	result := bininstaller.Install(inst, p, "")
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

// InstallMissing installs all missing scanner binaries.
// If force is true, reinstalls even if already cached.
// Returns results for each scanner.
func (m *ScannerManager) InstallMissing(force bool) []bininstaller.InstallResult {
	EnsureBinDirInPath()
	cache := bininstaller.LoadCache()
	var results []bininstaller.InstallResult

	for _, inst := range bininstaller.AllInstallers() {
		name := inst.Name()

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

		if !inst.SupportsDirectBinary() {
			p, _ := platform.Detect()
			results = append(results, bininstaller.InstallResult{
				Scanner:  name,
				Fallback: inst.FallbackCommand(p),
			})
			continue
		}

		p, _ := platform.Detect()
		result := bininstaller.Install(inst, p, "")
		if result.Installed {
			cache.Set(result)
		}
		results = append(results, result)
	}

	cache.Save()
	return results
}
