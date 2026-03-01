package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/leonamvasquez/terraview/internal/output"
	"golang.org/x/term"
)

func strContainsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// ANSI escape codes — use via the package-level vars which respect --no-color.
var (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

// disableCmdColors clears ANSI codes used by cmd package when --no-color is set.
func disableCmdColors() {
	if !output.ColorEnabled {
		ansiReset = ""
		ansiBold = ""
		ansiDim = ""
		ansiCyan = ""
		ansiGreen = ""
		ansiYellow = ""
		ansiRed = ""
	}
}

// selectItem represents a single item in a selector list.
type selectItem struct {
	Label    string // main label shown
	Detail   string // secondary info shown dimmed (e.g. key status)
	Value    string // internal value returned on selection
	IsActive bool   // true = mark with ★
}

// rawPrint writes to stdout interpreting \n as \r\n (required in raw terminal mode).
func rawPrint(s string) {
	os.Stdout.WriteString(strings.ReplaceAll(s, "\n", "\r\n")) //nolint:errcheck
}

// runSelector displays an interactive arrow-key selector and returns the
// chosen item's Value, or ("", false) if canceled (ESC / Ctrl+C).
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

	// Hide cursor, render initial list
	rawPrint("\033[?25l") // hide cursor
	renderList(title, items, cursor)

	buf := make([]byte, 8)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			rawPrint("\033[?25h\r\n") // show cursor
			return "", false
		}

		switch {
		case n == 1 && (buf[0] == 13 || buf[0] == 10): // Enter
			rawPrint("\033[?25h") // show cursor
			eraseList(len(items))
			return items[cursor].Value, true

		case n == 1 && buf[0] == 27: // lone ESC
			rawPrint("\033[?25h")
			eraseList(len(items))
			return "", false

		case n == 1 && buf[0] == 3: // Ctrl+C
			rawPrint("\033[?25h\r\n")
			term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck
			os.Exit(130)

		case n >= 3 && buf[0] == 27 && buf[1] == 91: // ESC [ ...
			switch buf[2] {
			case 65: // ↑ Up
				if cursor > 0 {
					cursor--
				} else {
					cursor = len(items) - 1
				}
			case 66: // ↓ Down
				if cursor < len(items)-1 {
					cursor++
				} else {
					cursor = 0
				}
			}
			// Move cursor back to top of list and redraw
			// Lines drawn: blank + title + blank + N items + blank + hint = N+5
			moveUp(len(items) + 5)
			renderList(title, items, cursor)
		}
	}
}

// renderList draws the full selector UI.
func renderList(title string, items []selectItem, cursor int) {
	rawPrint("\n")
	rawPrint(ansiBold + title + ansiReset + "\n")
	rawPrint("\n")
	for i, item := range items {
		printItem(i, item, cursor)
	}
	rawPrint("\n")
	rawPrint(ansiDim + "  ↑↓ navegar    Enter confirmar    ESC cancelar" + ansiReset + "\n")
}

// eraseList removes the provider selector UI (N items + 5 fixed lines).
func eraseList(n int) {
	eraseLines(n + 5)
}

// moveUp moves the terminal cursor up n lines.
func moveUp(n int) {
	for i := 0; i < n; i++ {
		rawPrint("\033[A")
	}
}

func printItem(i int, item selectItem, cursor int) {
	star := ""
	if item.IsActive {
		star = " " + ansiGreen + "★" + ansiReset
	}

	if i == cursor {
		label := ansiBold + ansiCyan + " ▶ " + item.Label + ansiReset + star
		detail := ""
		if item.Detail != "" {
			detail = "  " + ansiDim + item.Detail + ansiReset
		}
		rawPrint(label + detail + "\n")
	} else {
		label := "   " + item.Label + star
		detail := ""
		if item.Detail != "" {
			detail = "  " + ansiDim + item.Detail + ansiReset
		}
		rawPrint(label + detail + "\n")
	}
}

// runFilterSelector is like runSelector but adds a live text filter at the top.
// As the user types, the list is filtered by substring. Enter confirms the
// highlighted item (or the raw typed text if nothing matches).
func runFilterSelector(title string, allItems []selectItem, defaultIndex int) (string, bool) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return runSelectorFallback(title, allItems)
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return runSelectorFallback(title, allItems)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck

	query := ""
	cursor := defaultIndex
	if cursor < 0 || cursor >= len(allItems) {
		cursor = 0
	}

	rawPrint("\033[?25l") // hide cursor

	filtered := filterItems(allItems, query)
	prevLines := renderFilterList(title, filtered, query, cursor)

	buf := make([]byte, 8)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			rawPrint("\033[?25h\r\n")
			return "", false
		}

		switch {
		case n == 1 && (buf[0] == 13 || buf[0] == 10): // Enter
			rawPrint("\033[?25h")
			eraseLines(prevLines)
			if len(filtered) > 0 {
				return filtered[cursor].Value, true
			}
			if query != "" {
				return query, true // typed model not in list
			}
			return "", false

		case n == 1 && buf[0] == 27: // lone ESC
			rawPrint("\033[?25h")
			eraseLines(prevLines)
			return "", false

		case n == 1 && buf[0] == 3: // Ctrl+C
			rawPrint("\033[?25h\r\n")
			term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck
			os.Exit(130)

		case n == 1 && (buf[0] == 127 || buf[0] == 8): // Backspace
			if len(query) > 0 {
				query = query[:len(query)-1]
				filtered = filterItems(allItems, query)
				if cursor >= len(filtered) {
					cursor = len(filtered) - 1
					if cursor < 0 {
						cursor = 0
					}
				}
				eraseLines(prevLines)
				prevLines = renderFilterList(title, filtered, query, cursor)
			}

		case n >= 3 && buf[0] == 27 && buf[1] == 91: // ESC [ ...
			switch buf[2] {
			case 65: // ↑
				if len(filtered) > 0 {
					if cursor > 0 {
						cursor--
					} else {
						cursor = len(filtered) - 1
					}
				}
			case 66: // ↓
				if len(filtered) > 0 {
					if cursor < len(filtered)-1 {
						cursor++
					} else {
						cursor = 0
					}
				}
			}
			eraseLines(prevLines)
			prevLines = renderFilterList(title, filtered, query, cursor)

		case n == 1 && buf[0] >= 32 && buf[0] < 127: // printable ASCII
			query += string(buf[0])
			filtered = filterItems(allItems, query)
			cursor = 0
			eraseLines(prevLines)
			prevLines = renderFilterList(title, filtered, query, cursor)
		}
	}
}

func filterItems(items []selectItem, query string) []selectItem {
	if query == "" {
		return items
	}
	result := make([]selectItem, 0, len(items))
	for _, item := range items {
		if strContainsFold(item.Label, query) {
			result = append(result, item)
		}
	}
	return result
}

func renderFilterList(title string, filtered []selectItem, query string, cursor int) int {
	lines := 0
	rawPrint("\n")
	lines++
	rawPrint(ansiBold + title + ansiReset + "\n")
	lines++
	rawPrint("\n")
	lines++
	// Input line
	rawPrint("  " + ansiBold + "> " + ansiReset + query + "█" + "\n")
	lines++
	rawPrint("\n")
	lines++
	if len(filtered) == 0 {
		rawPrint(ansiDim + "  " + pick("(no results — Enter to use typed text)", "(nenhum resultado — Enter para usar o texto digitado)") + ansiReset + "\n")
		lines++
	} else {
		for i, item := range filtered {
			printItem(i, item, cursor)
			lines++
		}
	}
	rawPrint("\n")
	lines++
	rawPrint(ansiDim + "  ↑↓ navegar    Enter confirmar    ESC cancelar    ← apagar" + ansiReset + "\n")
	lines++
	return lines
}

func eraseLines(n int) {
	for i := 0; i < n; i++ {
		rawPrint("\033[2K\r")
		if i < n-1 {
			rawPrint("\033[A")
		}
	}
	rawPrint("\033[2K\r")
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
	fmt.Printf("\n"+pick("Choose (1-%d) or 0 to cancel: ", "Escolha (1-%d) ou 0 para cancelar: "), len(items))

	var choice int
	if _, err := fmt.Scan(&choice); err != nil || choice == 0 {
		return "", false
	}
	if choice < 1 || choice > len(items) {
		return "", false
	}
	return items[choice-1].Value, true
}
