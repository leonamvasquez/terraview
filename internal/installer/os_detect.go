package installer

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

// SystemInfo holds detected OS and architecture information.
type SystemInfo struct {
	OS   string // "linux", "darwin"
	Arch string // "amd64", "arm64"
}

// DetectSystem returns the current OS and architecture.
// Returns an error if the platform is not supported.
func DetectSystem() (SystemInfo, error) {
	info := SystemInfo{
		OS:   runtime.GOOS,
		Arch: runtime.GOARCH,
	}

	switch info.OS {
	case "linux", "darwin":
		// supported
	default:
		return info, fmt.Errorf("unsupported operating system: %s (supported: linux, darwin)", info.OS)
	}

	switch info.Arch {
	case "amd64", "arm64":
		// supported
	default:
		return info, fmt.Errorf("unsupported architecture: %s (supported: amd64, arm64)", info.Arch)
	}

	return info, nil
}

// DisplayOS returns a human-friendly OS name.
func (s SystemInfo) DisplayOS() string {
	switch s.OS {
	case "darwin":
		return "macOS"
	case "linux":
		return "Linux"
	default:
		return s.OS
	}
}

// OllamaInstalled checks if ollama binary is available in PATH.
func OllamaInstalled() bool {
	_, err := exec.LookPath("ollama")
	return err == nil
}

// OllamaVersion returns the installed ollama version string, or empty if not installed.
func OllamaVersion() string {
	// Use --version flag; only capture stdout to avoid MLX warnings from stderr.
	cmd := exec.Command("ollama", "--version")
	out, err := cmd.Output() // Output() captures only stdout
	if err != nil {
		return ""
	}

	// Output format: "ollama version is X.Y.Z"
	line := strings.TrimSpace(string(out))
	if idx := strings.LastIndex(line, " "); idx != -1 {
		return line[idx+1:]
	}
	return line
}

// OllamaRunning checks if the ollama service is responding.
func OllamaRunning() bool {
	out, err := exec.Command("ollama", "list").CombinedOutput()
	if err != nil {
		_ = out
		return false
	}
	return true
}
