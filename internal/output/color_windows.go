//go:build windows

package output

import (
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	enableVirtualTerminalProcessing()
}

// enableVirtualTerminalProcessing enables ANSI escape code support
// on Windows 10+ consoles by setting ENABLE_VIRTUAL_TERMINAL_PROCESSING.
func enableVirtualTerminalProcessing() {
	enableVTForHandle(os.Stdout)
	enableVTForHandle(os.Stderr)
}

func enableVTForHandle(f *os.File) {
	handle := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return // not a console (e.g. pipe/file)
	}
	_ = windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
