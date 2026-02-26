package output

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

// ── Global spinner manager ─────────────────────────────────────────────
// Only ONE spinner renders at a time. When a new spinner starts while
// another is already running, the previous one is silently paused (its
// goroutine keeps ticking but skips writes). When the top spinner stops,
// the previous one resumes rendering.

var (
	spinMgr  spinnerManager
	stderrMu sync.Mutex // guards raw writes to stderr
)

type spinnerManager struct {
	mu    sync.Mutex
	stack []*Spinner // top = last element = renders
}

func (m *spinnerManager) push(s *Spinner) {
	m.mu.Lock()
	m.stack = append(m.stack, s)
	m.mu.Unlock()
}

func (m *spinnerManager) pop(s *Spinner) {
	m.mu.Lock()
	for i := len(m.stack) - 1; i >= 0; i-- {
		if m.stack[i] == s {
			m.stack = append(m.stack[:i], m.stack[i+1:]...)
			break
		}
	}
	m.mu.Unlock()
}

func (m *spinnerManager) isActive(s *Spinner) bool {
	m.mu.Lock()
	active := len(m.stack) > 0 && m.stack[len(m.stack)-1] == s
	m.mu.Unlock()
	return active
}

// ── Spinner ────────────────────────────────────────────────────────────

// Spinner displays an animated spinner in the terminal while a long-running
// operation is executing. It respects the global ColorEnabled flag.
type Spinner struct {
	message  string
	frames   []string
	interval time.Duration

	mu      sync.Mutex
	running bool
	done    chan struct{}
}

// Unicode braille-dot frames (smooth rotation).
var unicodeFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// ASCII fallback frames for --no-color / dumb terminals.
var asciiFrames = []string{"|", "/", "-", "\\"}

// NewSpinner creates a Spinner with the given status message.
func NewSpinner(message string) *Spinner {
	frames := unicodeFrames
	if !ColorEnabled {
		frames = asciiFrames
	}
	return &Spinner{
		message:  message,
		frames:   frames,
		interval: 80 * time.Millisecond,
	}
}

// Start begins the spinner animation in a background goroutine.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.done = make(chan struct{})
	s.mu.Unlock()

	spinMgr.push(s)
	go s.loop()
}

// Stop halts the spinner and prints a final status line.
func (s *Spinner) Stop(success bool) {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	spinMgr.pop(s)

	mark := colorize(bold+green, "✓")
	if !success {
		mark = colorize(bold+red, "✗")
	}
	final := fmt.Sprintf("%s %s %s\n", Prefix(), s.message, mark)

	stderrMu.Lock()
	writeRaw(clearLineSeq() + final)
	stderrMu.Unlock()
}

// loop runs the animation until Stop is called.
func (s *Spinner) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	i := 0
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			// Only the topmost spinner renders; others silently wait.
			if !spinMgr.isActive(s) {
				continue
			}

			frame := s.frames[i%len(s.frames)]
			if ColorEnabled {
				frame = colorize(bold+cyan, frame)
			}
			line := fmt.Sprintf("%s %s %s", Prefix(), frame, s.message)
			line = truncateToTermWidth(line)

			stderrMu.Lock()
			writeRaw(clearLineSeq() + line)
			stderrMu.Unlock()

			i++
		}
	}
}

// clearLineSeq returns the escape sequence to move cursor to column 0
// and erase the entire line.
func clearLineSeq() string {
	if ColorEnabled {
		return "\r\033[K"
	}
	return "\r" + strings.Repeat(" ", termWidth()-1) + "\r"
}

// writeRaw does a single os.Stderr.Write so the kernel sees one write(2)
// syscall, making the output atomic at the file-descriptor level.
func writeRaw(s string) {
	os.Stderr.WriteString(s) //nolint:errcheck
}

// termWidth returns the current terminal width, or 80 as a safe fallback.
func termWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
	if err != nil || w <= 0 {
		return 80
	}
	return w
}

// truncateToTermWidth truncates s so its visible (non-ANSI) length fits within
// the terminal width. It strips characters from the end when necessary.
func truncateToTermWidth(s string) string {
	tw := termWidth() - 1 // leave 1 col margin to avoid wrap on some terminals
	if tw <= 0 {
		return s
	}

	visible := 0
	inEsc := false
	cutIdx := len(s)
	for i, r := range s {
		if inEsc {
			if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
				inEsc = false
			}
			continue
		}
		if r == '\033' {
			inEsc = true
			continue
		}
		visible++
		if visible > tw {
			cutIdx = i
			break
		}
	}
	return s[:cutIdx]
}

// SpinWhile is a convenience helper that runs fn while displaying a spinner.
// It returns the values returned by fn. The spinner is stopped automatically
// with the appropriate success/failure indicator.
//
// Usage:
//
//	result, err := output.SpinWhile("Running terraform plan...", func() (string, error) {
//	    return e.runSilent("plan", "-out=tfplan")
//	})
func SpinWhile[T any](message string, fn func() (T, error)) (T, error) {
	s := NewSpinner(message)
	s.Start()
	result, err := fn()
	s.Stop(err == nil)
	return result, err
}

// SpinWhileE is like SpinWhile but for functions that return only an error.
func SpinWhileE(message string, fn func() error) error {
	s := NewSpinner(message)
	s.Start()
	err := fn()
	s.Stop(err == nil)
	return err
}
