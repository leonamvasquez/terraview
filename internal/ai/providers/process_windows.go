//go:build windows

package providers

import "os/exec"

// setProcessGroup is a no-op on Windows (no POSIX process groups).
func setProcessGroup(_ *exec.Cmd) {}
