//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

// signalsToNotify returns the signals to listen for during installation.
var signalsToNotify = []os.Signal{os.Interrupt, syscall.SIGTERM}
