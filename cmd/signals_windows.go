//go:build windows

package cmd

import "os"

// On Windows, only os.Interrupt (Ctrl+C) is supported.
var signalsToNotify = []os.Signal{os.Interrupt}
