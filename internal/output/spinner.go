package output

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Spinner displays an animated spinner in the terminal while a long-running
// operation is executing. It respects the global ColorEnabled flag:
// when colors are enabled it uses braille-dot frames; otherwise it falls
// back to a simple ASCII rotation.
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
// The message is displayed next to the animated spinner, e.g.:
//
//	[terraview] ⠹ Running terraform plan...
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
// It is safe to call Start multiple times; only the first call takes effect.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.done = make(chan struct{})
	s.mu.Unlock()

	go s.loop()
}

// Stop halts the spinner and prints a final status line.
// If success is true the line ends with ✓; otherwise ✗.
func (s *Spinner) Stop(success bool) {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	close(s.done)
	s.mu.Unlock()

	// Clear the spinner line and print final status
	clearLine()

	mark := colorize(bold+green, "✓")
	if !success {
		mark = colorize(bold+red, "✗")
	}
	fmt.Fprintf(os.Stderr, "%s %s %s\n", Prefix(), s.message, mark)
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
			frame := s.frames[i%len(s.frames)]
			if ColorEnabled {
				frame = colorize(bold+cyan, frame)
			}
			clearLine()
			fmt.Fprintf(os.Stderr, "%s %s %s", Prefix(), frame, s.message)
			i++
		}
	}
}

// clearLine moves the cursor to column 0 and clears the entire line.
func clearLine() {
	if ColorEnabled {
		fmt.Fprintf(os.Stderr, "\r\033[K")
	} else {
		fmt.Fprintf(os.Stderr, "\r")
	}
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
