package installer

import "os/exec"

// OllamaInstalled checks if ollama binary is available in PATH.
func OllamaInstalled() bool {
	_, err := exec.LookPath("ollama")
	return err == nil
}
