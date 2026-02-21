//go:build windows

package runtime

import "os/exec"

// setSysProcAttr is a no-op on Windows (no process groups via Setpgid).
func setSysProcAttr(_ *exec.Cmd) {}

// terminateProcess kills the process on Windows.
// Windows does not support SIGTERM; Process.Kill is used instead.
func terminateProcess(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}

// killProcess forcefully kills the process on Windows.
func killProcess(cmd *exec.Cmd) error {
	return cmd.Process.Kill()
}
