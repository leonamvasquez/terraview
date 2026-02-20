package runtime

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/leonam/terraview/internal/installer"
)

const (
	ollamaStartTimeout = 30 * time.Second
	ollamaStopTimeout  = 10 * time.Second
	ollamaHealthURL    = "http://localhost:11434/api/tags"
)

// OllamaLifecycle manages the Ollama process lifecycle.
// It starts Ollama only when needed and stops it after use.
type OllamaLifecycle struct {
	limits  ResourceLimits
	baseURL string
	cmd     *exec.Cmd
	managed bool // true if we started the process (so we should stop it)
}

// NewOllamaLifecycle creates a new lifecycle manager.
func NewOllamaLifecycle(limits ResourceLimits, baseURL string) *OllamaLifecycle {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &OllamaLifecycle{
		limits:  limits,
		baseURL: baseURL,
	}
}

// Ensure verifies Ollama is installed, checks resources, and starts the service if needed.
// Returns a cleanup function that MUST be called (typically via defer) to stop the process.
func (lc *OllamaLifecycle) Ensure(ctx context.Context) (cleanup func(), err error) {
	// 1. Verify installation
	if !installer.OllamaInstalled() {
		return noop, fmt.Errorf("ollama is not installed — run 'terraview install llm' first")
	}

	// 2. Check resources
	res, err := CheckResources(lc.limits)
	if err != nil {
		return noop, err
	}

	fmt.Fprintf(os.Stderr, "[terraview] System: %d MB free / %d MB total, %d CPUs, load %.2f\n",
		res.AvailableMemoryMB, res.TotalMemoryMB, res.CPUCount, res.LoadAverage)

	// 3. Check if already running
	if lc.isHealthy(ctx) {
		fmt.Fprintf(os.Stderr, "[terraview] Ollama already running.\n")
		lc.managed = false
		return noop, nil
	}

	// 4. Start process
	fmt.Fprintf(os.Stderr, "[terraview] Starting Ollama (temporary)...\n")
	if err := lc.start(ctx); err != nil {
		return noop, fmt.Errorf("failed to start ollama: %w", err)
	}

	lc.managed = true
	return lc.stop, nil
}

// start launches ollama serve as a child process.
func (lc *OllamaLifecycle) start(ctx context.Context) error {
	lc.cmd = exec.Command("ollama", "serve")
	lc.cmd.Stdout = nil
	lc.cmd.Stderr = nil

	// Set process group so we can kill the whole tree
	lc.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Apply thread limits via environment
	if lc.limits.MaxThreads > 0 {
		env := os.Environ()
		env = append(env, fmt.Sprintf("OLLAMA_NUM_PARALLEL=%d", 1))
		env = append(env, fmt.Sprintf("GOMAXPROCS=%d", lc.limits.MaxThreads))
		lc.cmd.Env = env
	}

	if err := lc.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start ollama serve: %w", err)
	}

	// Wait for healthy
	deadline := time.Now().Add(ollamaStartTimeout)
	for time.Now().Before(deadline) {
		if lc.isHealthy(ctx) {
			fmt.Fprintf(os.Stderr, "[terraview] Ollama started (PID %d).\n", lc.cmd.Process.Pid)
			return nil
		}
		select {
		case <-ctx.Done():
			lc.kill()
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}

	lc.kill()
	return fmt.Errorf("ollama did not become ready within %v", ollamaStartTimeout)
}

// stop gracefully shuts down the Ollama process we started.
func (lc *OllamaLifecycle) stop() {
	if lc.cmd == nil || lc.cmd.Process == nil || !lc.managed {
		return
	}

	fmt.Fprintf(os.Stderr, "[terraview] Stopping Ollama (PID %d)...\n", lc.cmd.Process.Pid)

	// Send SIGTERM to process group
	pgid, err := syscall.Getpgid(lc.cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = lc.cmd.Process.Signal(syscall.SIGTERM)
	}

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- lc.cmd.Wait()
	}()

	select {
	case <-done:
		fmt.Fprintf(os.Stderr, "[terraview] Ollama stopped.\n")
	case <-time.After(ollamaStopTimeout):
		// Force kill
		if pgid, err := syscall.Getpgid(lc.cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = lc.cmd.Process.Kill()
		}
		<-done
		fmt.Fprintf(os.Stderr, "[terraview] Ollama force-killed.\n")
	}

	lc.cmd = nil
}

// kill immediately kills the process (used during startup failures).
func (lc *OllamaLifecycle) kill() {
	if lc.cmd != nil && lc.cmd.Process != nil {
		if pgid, err := syscall.Getpgid(lc.cmd.Process.Pid); err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		} else {
			_ = lc.cmd.Process.Kill()
		}
		_ = lc.cmd.Wait()
		lc.cmd = nil
	}
}

// isHealthy checks if Ollama API is responding.
func (lc *OllamaLifecycle) isHealthy(ctx context.Context) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", lc.baseURL+"/api/tags", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func noop() {}
