package installer

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/leonamvasquez/terraview/internal/util"
)

const (
	ollamaInstallURL = "https://ollama.ai/install.sh"
	defaultModel     = "llama3.1:8b"
	downloadTimeout  = 60 * time.Second
	pullTimeout      = 10 * time.Minute
)

// Result represents the outcome of an installation step.
type Result struct {
	AlreadyInstalled bool
	Version          string
	ModelPulled      bool
	Validated        bool
}

// Installer handles Ollama installation and setup.
type Installer struct {
	model  string
	writer io.Writer
}

// NewInstaller creates a new Installer with the given model and output writer.
func NewInstaller(model string, w io.Writer) *Installer {
	if model == "" {
		model = defaultModel
	}
	return &Installer{model: model, writer: w}
}

// Install runs the full installation flow: detect, install, start, pull, validate.
func (inst *Installer) Install(ctx context.Context) (*Result, error) {
	result := &Result{}

	// 1. Detect system
	sys, err := DetectSystem()
	if err != nil {
		return nil, err
	}
	inst.log("Checking system compatibility...")
	inst.log("Detected: %s %s\n", sys.DisplayOS(), sys.Arch)

	// 2. Check if already installed
	if OllamaInstalled() {
		version := OllamaVersion()
		result.AlreadyInstalled = true
		result.Version = version
		inst.log("Ollama already installed: %s", version)

		// Even if installed, ensure service is running and model is pulled
		if err := inst.ensureRunning(ctx); err != nil {
			return nil, fmt.Errorf("failed to start ollama service: %w", err)
		}

		if err := inst.ensureModel(ctx); err != nil {
			return nil, fmt.Errorf("failed to pull model: %w", err)
		}

		if err := inst.validate(ctx); err != nil {
			return nil, err
		}
		result.ModelPulled = true
		result.Validated = true
		return result, nil
	}

	// 3. Install Ollama
	inst.log("Ollama not found.")
	inst.log("Installing Ollama...\n")

	if err := inst.downloadAndInstall(ctx, sys); err != nil {
		return nil, fmt.Errorf("installation failed: %w", err)
	}

	// Verify installation succeeded
	if !OllamaInstalled() {
		return nil, fmt.Errorf("ollama binary not found after installation — check your PATH")
	}

	result.Version = OllamaVersion()
	inst.log("Installed: %s\n", result.Version)

	// 4. Start service
	if err := inst.ensureRunning(ctx); err != nil {
		return nil, fmt.Errorf("failed to start ollama service: %w", err)
	}

	// 5. Pull model
	if err := inst.ensureModel(ctx); err != nil {
		return nil, fmt.Errorf("failed to pull model: %w", err)
	}
	result.ModelPulled = true

	// 6. Validate
	if err := inst.validate(ctx); err != nil {
		return nil, err
	}
	result.Validated = true

	return result, nil
}

// downloadAndInstall downloads and installs Ollama for the current platform.
func (inst *Installer) downloadAndInstall(ctx context.Context, _ SystemInfo) error {
	if runtime.GOOS == "windows" {
		return inst.installWindows(ctx)
	}
	return inst.installUnix(ctx)
}

// installUnix downloads the official install script and executes it.
func (inst *Installer) installUnix(ctx context.Context) error {
	inst.log("Downloading installer from %s ...", ollamaInstallURL)

	dlCtx, cancel := context.WithTimeout(ctx, downloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(dlCtx, "GET", ollamaInstallURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download installer: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("installer download returned status %d", resp.StatusCode)
	}

	// Read full script into memory for inspection
	scriptBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return fmt.Errorf("failed to read installer script: %w", err)
	}

	script := string(scriptBytes)

	// Basic validation: must look like a shell script
	if !strings.HasPrefix(script, "#!/") {
		return fmt.Errorf("downloaded content does not look like a valid shell script")
	}

	inst.log("Running installer (may require sudo password)...")

	// Execute via sh — the official Ollama script handles sudo internally
	cmd := exec.CommandContext(ctx, "sh", "-c", script)
	cmd.Stdout = inst.writer
	cmd.Stderr = inst.writer
	cmd.Stdin = os.Stdin // allow sudo password prompt

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("installer script failed: %w", err)
	}

	return nil
}

// installWindows attempts to install Ollama on Windows via winget.
func (inst *Installer) installWindows(ctx context.Context) error {
	// Try winget first (available on Windows 10 1709+ and Windows 11)
	if _, err := exec.LookPath("winget"); err == nil {
		inst.log("Installing Ollama via winget...")
		cmd := exec.CommandContext(ctx, "winget", "install", "--id", "Ollama.Ollama", "--accept-source-agreements", "--accept-package-agreements")
		cmd.Stdout = inst.writer
		cmd.Stderr = inst.writer
		if err := cmd.Run(); err == nil {
			return nil
		}
		inst.log("winget installation failed, trying direct download...")
	}

	// Fallback: guide user to manual install
	return fmt.Errorf("automatic installation on Windows requires winget.\n\n" +
		"  Please install Ollama manually:\n" +
		"    1. Download from https://ollama.com/download/windows\n" +
		"    2. Run the installer\n" +
		"    3. Re-run 'terraview install llm'")
}

// ensureRunning starts the ollama service if it's not already responding.
func (inst *Installer) ensureRunning(ctx context.Context) error {
	if OllamaRunning() {
		inst.log("Ollama service is running.")
		return nil
	}

	inst.log("Starting Ollama service...")

	// Start ollama serve in background
	cmd := exec.Command("ollama", "serve")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		// On macOS, Ollama may run as a launchd service — try the app approach
		inst.log("Background start attempted, waiting for service...")
	}

	// Wait for the service to become ready (up to 30 seconds)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if OllamaRunning() {
			inst.log("Ollama service is ready.")
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(1 * time.Second):
		}
	}

	return fmt.Errorf("ollama service did not start within 30 seconds — try running 'ollama serve' manually")
}

// ensureModel pulls the configured model if not already available.
func (inst *Installer) ensureModel(ctx context.Context) error {
	// Check if model is already available
	if inst.modelAvailable() {
		inst.log("Model %s already available.", inst.model)
		return nil
	}

	inst.log("Pulling model %s ...", inst.model)
	inst.log("This may take several minutes on first run.\n")

	pullCtx, cancel := context.WithTimeout(ctx, pullTimeout)
	defer cancel()

	cmd := exec.CommandContext(pullCtx, "ollama", "pull", inst.model)

	// Capture stderr separately for error reporting
	var stderrBuf strings.Builder

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start model pull: %w", err)
	}

	// Read stderr in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			stderrBuf.WriteString(line)
			stderrBuf.WriteString("\n")
			// Show stderr lines that contain actual errors, skip warnings
			if (strings.Contains(line, "Error") || strings.Contains(line, "error")) &&
				!strings.Contains(line, "WARN") {
				fmt.Fprintf(inst.writer, "  %s\n", line)
			}
		}
	}()

	// Read stdout for progress
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "%") || strings.Contains(line, "pulling") ||
			strings.Contains(line, "success") || strings.Contains(line, "verifying") ||
			strings.Contains(line, "Error") || strings.Contains(line, "error") {
			fmt.Fprintf(inst.writer, "  %s\n", line)
		}
	}

	<-done // wait for stderr goroutine

	if err := cmd.Wait(); err != nil {
		errMsg := strings.TrimSpace(stderrBuf.String())
		if errMsg != "" {
			return fmt.Errorf("model pull failed: %s", errMsg)
		}
		return fmt.Errorf("model pull failed: %w", err)
	}

	inst.log("Model %s pulled successfully.", inst.model)
	return nil
}

// modelAvailable checks if the model is already downloaded.
func (inst *Installer) modelAvailable() bool {
	out, err := exec.Command("ollama", "list").CombinedOutput()
	if err != nil {
		return false
	}

	// Normalize model name for comparison (e.g. "llama3.1:8b" matches "llama3.1:8b")
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 && strings.EqualFold(fields[0], inst.model) {
			return true
		}
	}
	return false
}

// validate runs a health check against the installed Ollama.
func (inst *Installer) validate(ctx context.Context) error {
	inst.log("\nValidating installation...")

	healthClient := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", util.DefaultOllamaURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	resp, err := healthClient.Do(req)
	if err != nil {
		return fmt.Errorf("validation failed: ollama API not responding at localhost:11434: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("validation failed: ollama API returned status %d", resp.StatusCode)
	}

	return nil
}

func (inst *Installer) log(format string, args ...interface{}) {
	fmt.Fprintf(inst.writer, format+"\n", args...)
}
