//go:build windows

package cmd

import "os"

// signalsToNotify returns the signals to listen for during installation.
// On Windows, only os.Interrupt (Ctrl+C) is supported.
var signalsToNotify = []os.Signal{os.Interrupt}
