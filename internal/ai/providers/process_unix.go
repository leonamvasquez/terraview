//go:build !windows

package providers

import (
	"os/exec"
	"syscall"
)

// setProcessGroup configures the command to run in its own process group
// and sets cmd.Cancel to kill the entire group on context cancellation.
// This prevents orphaned child processes (e.g., Node spawned by gemini-cli).
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil {
			return syscall.Kill(-pgid, syscall.SIGKILL)
		}
		return cmd.Process.Kill()
	}
}
