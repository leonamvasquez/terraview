package cmd

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ANSI escape codes
const (
	ansiHideCursor  = "\033[?25l"
	ansiShowCursor  = "\033[?25h"
	ansiClearLine   = "\033[2K\r"
	ansiMoveUp      = "\033[A"
	ansiReset       = "\033[0m"
	ansiBold        = "\033[1m"
	ansiDim         = "\033[2m"
	ansiCyan        = "\033[36m"
	ansiGreen       = "\033[32m"
	ansiYellow      = "\033[33m"
	ansiRed         = "\033[31m"
	ansiBgCyan      = "\033[46m"
	ansiBlack       = "\033[30m"
	ansiWhite       = "\033[37m"
)

// selectItem represents a single item in a selector list.
type selectItem struct {
	Label    string // main label shown
	Detail   string // secondary info shown dimmed (e.g. key status)
	Value    string // internal value returned on selection
	IsActive bool   // true = mark with ★
}

// runSelector displays an interactive arrow-key selector and returns the
// chosen item's Value, or ("", false) if cancelled (ESC / Ctrl+C).
// Falls back to a numbered prompt if stdin is not a terminal.
func runSelector(title string, items []selectItem, defaultIndex int) (string, bool) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return runSelectorFallback(title, items)
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return runSelectorFallback(title, items)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck

	cursor := defaultIndex
	if cursor < 0 || cursor >= len(items) {
		cursor = 0
	}

	// Hide cursor during interaction
	fmt.Print(ansiHideCursor)
	defer fmt.Print(ansiShowCursor)

	renderList(title, items, cursor)

	buf := make([]byte, 8)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			clearList(items)
			return "", false
		}

		switch {
		case n == 1 && (buf[0] == 13 || buf[0] == 10): // Enter / Return
			clearList(items)
			return items[cursor].Value, true

		case n == 1 && buf[0] == 27: // lone ESC
			clearList(items)
			return "", false

		case n == 1 && buf[0] == 3: // Ctrl+C
			clearList(items)
			fmt.Println()
			os.Exit(130)

		case n >= 3 && buf[0] == 27 && buf[1] == 91: // ESC [ ...
			switch buf[2] {
			case 65: // ↑ Up
				if cursor > 0 {
					cursor--
				} else {
					cursor = len(items) - 1 // wrap around
				}
			case 66: // ↓ Down
				if cursor < len(items)-1 {
					cursor++
				} else {
					cursor = 0 // wrap around
				}
			}
			rerenderList(title, items, cursor)
		}
	}
}

func renderList(title string, items []selectItem, cursor int) {
	fmt.Printf("\n%s%s%s\n\n", ansiBold, title, ansiReset)
	for i, item := range items {
		printItem(i, item, cursor)
	}
	fmt.Printf("\n%s  ↑↓ navegar  Enter selecionar  ESC cancelar%s\n", ansiDim, ansiReset)
}

func rerenderList(title string, items []selectItem, cursor int) {
	// Move up past: hint line + blank + items + blank + title + blank
	total := len(items) + 4
	for i := 0; i < total; i++ {
		fmt.Print(ansiMoveUp)
	}
	renderList(title, items, cursor)
}

func clearList(items []selectItem) {
	total := len(items) + 4
	for i := 0; i < total; i++ {
		fmt.Print(ansiClearLine)
		if i < total-1 {
			fmt.Print(ansiMoveUp)
		}
	}
	fmt.Print(ansiClearLine)
}

func printItem(i int, item selectItem, cursor int) {
	active := ""
	if item.IsActive {
		active = ansiGreen + " ★" + ansiReset
	}

	if i == cursor {
		// Selected row: cyan background
		label := fmt.Sprintf(" %s%s%-18s%s", ansiBold, ansiCyan, item.Label, ansiReset)
		detail := ""
		if item.Detail != "" {
			detail = fmt.Sprintf("  %s%s%s", ansiDim, item.Detail, ansiReset)
		}
		fmt.Printf("  ▶ %s%s%s\n", label, active, detail)
	} else {
		label := fmt.Sprintf("%-18s", item.Label)
		detail := ""
		if item.Detail != "" {
			detail = fmt.Sprintf("  %s%s%s", ansiDim, item.Detail, ansiReset)
		}
		fmt.Printf("    %s%s%s\n", label, active, detail)
	}
}

// runSelectorFallback is used when stdin is not a terminal (e.g. pipe/CI).
func runSelectorFallback(title string, items []selectItem) (string, bool) {
	fmt.Printf("\n%s\n\n", title)
	for i, item := range items {
		marker := " "
		if item.IsActive {
			marker = "★"
		}
		fmt.Printf("  %s %d) %s", marker, i+1, item.Label)
		if item.Detail != "" {
			fmt.Printf("  [%s]", item.Detail)
		}
		fmt.Println()
	}
	fmt.Printf("\nEscolha (1-%d) ou 0 para cancelar: ", len(items))

	var choice int
	if _, err := fmt.Scan(&choice); err != nil || choice == 0 {
		return "", false
	}
	if choice < 1 || choice > len(items) {
		return "", false
	}
	return items[choice-1].Value, true
}
