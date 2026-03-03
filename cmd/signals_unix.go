//go:build !windows

package cmd

import (
	"os"
	"syscall"
)

var signalsToNotify = []os.Signal{os.Interrupt, syscall.SIGTERM}
