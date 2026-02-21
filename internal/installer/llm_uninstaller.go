package installer

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// Uninstaller handles Ollama removal.
type Uninstaller struct {
	writer io.Writer
}

// NewUninstaller creates a new Uninstaller.
func NewUninstaller(w io.Writer) *Uninstaller {
	return &Uninstaller{writer: w}
}

// UninstallResult holds the outcome of the uninstall operation.
type UninstallResult struct {
	WasInstalled   bool
	BinaryRemoved  bool
	DataRemoved    bool
	ServiceStopped bool
}

// Uninstall removes Ollama binary and data directories.
func (u *Uninstaller) Uninstall() (*UninstallResult, error) {
	result := &UninstallResult{}

	// 1. Check if installed
	if !OllamaInstalled() {
		u.log("Ollama is not installed. Nothing to do.")
		return result, nil
	}
	result.WasInstalled = true

	// 2. Stop service if running
	if OllamaRunning() {
		u.log("Stopping Ollama service...")
		if err := u.stopService(); err != nil {
			u.log("WARNING: Could not stop service: %v", err)
		} else {
			result.ServiceStopped = true
			u.log("Service stopped.")
		}
	}

	// 3. Find and remove binary
	binaryPath, err := exec.LookPath("ollama")
	if err == nil {
		u.log("Removing binary: %s", binaryPath)
		if err := os.Remove(binaryPath); err != nil {
			if os.IsPermission(err) {
				u.log("Permission denied. Try: sudo terraview uninstall llm")
				return result, fmt.Errorf("cannot remove %s: permission denied", binaryPath)
			}
			u.log("WARNING: Could not remove binary: %v", err)
		} else {
			result.BinaryRemoved = true
			u.log("Binary removed.")
		}
	}

	// 4. Remove data directories
	dataDirs := u.ollamaDataDirs()
	for _, dir := range dataDirs {
		if fi, err := os.Stat(dir); err == nil && fi.IsDir() {
			u.log("Removing data directory: %s", dir)
			if err := os.RemoveAll(dir); err != nil {
				u.log("WARNING: Could not remove %s: %v", dir, err)
			} else {
				result.DataRemoved = true
			}
		}
	}

	return result, nil
}

// stopService attempts to stop the Ollama service.
func (u *Uninstaller) stopService() error {
	switch runtime.GOOS {
	case "darwin":
		// Try pkill first (works for both manual and launchd)
		_ = exec.Command("pkill", "-f", "ollama").Run()
	case "linux":
		// Try systemctl first, then pkill
		if err := exec.Command("systemctl", "stop", "ollama").Run(); err != nil {
			_ = exec.Command("pkill", "-f", "ollama").Run()
		}
	case "windows":
		// Use taskkill on Windows
		_ = exec.Command("taskkill", "/F", "/IM", "ollama.exe").Run()
	}
	return nil
}

// ollamaDataDirs returns known Ollama data directories for the current OS.
func (u *Uninstaller) ollamaDataDirs() []string {
	var dirs []string

	home, _ := os.UserHomeDir()

	switch runtime.GOOS {
	case "darwin":
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".ollama"))
		}
	case "linux":
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".ollama"))
		}
		dirs = append(dirs, "/usr/share/ollama")
	case "windows":
		// Ollama stores data in %LOCALAPPDATA%\Ollama and %USERPROFILE%\.ollama
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			dirs = append(dirs, filepath.Join(localAppData, "Ollama"))
		}
		if home != "" {
			dirs = append(dirs, filepath.Join(home, ".ollama"))
		}
	}

	// Also check OLLAMA_MODELS env
	if modelsDir := os.Getenv("OLLAMA_MODELS"); modelsDir != "" {
		dirs = append(dirs, modelsDir)
	}

	return dirs
}

// ListModels returns currently installed Ollama models.
func ListModels() ([]string, error) {
	out, err := exec.Command("ollama", "list").Output()
	if err != nil {
		return nil, err
	}

	var models []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] != "NAME" {
			models = append(models, fields[0])
		}
	}
	return models, nil
}

func (u *Uninstaller) log(format string, args ...interface{}) {
	fmt.Fprintf(u.writer, format+"\n", args...)
}
