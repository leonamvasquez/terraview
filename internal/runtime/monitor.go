package runtime

import (
	"context"
	"fmt"
	"os"
	"time"
)

const monitorInterval = 3 * time.Second

// Monitor watches resource usage during LLM execution and cancels if limits are exceeded.
type Monitor struct {
	limits   ResourceLimits
	cancelFn context.CancelFunc
	done     chan struct{}
}

// NewMonitor creates a resource monitor that will cancel the context if limits are exceeded.
func NewMonitor(limits ResourceLimits, cancel context.CancelFunc) *Monitor {
	return &Monitor{
		limits:   limits,
		cancelFn: cancel,
		done:     make(chan struct{}),
	}
}

// Start begins monitoring in a goroutine. Call Stop() when done.
func (m *Monitor) Start(ctx context.Context) {
	go m.run(ctx)
}

// Stop signals the monitor to stop.
func (m *Monitor) Stop() {
	select {
	case <-m.done:
		// already stopped
	default:
		close(m.done)
	}
}

func (m *Monitor) run(ctx context.Context) {
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			if err := m.check(); err != nil {
				fmt.Fprintf(os.Stderr, "[terraview] Resource limit exceeded: %v\n", err)
				fmt.Fprintf(os.Stderr, "[terraview] Cancelling LLM execution to protect system stability.\n")
				m.cancelFn()
				return
			}
		}
	}
}

func (m *Monitor) check() error {
	res, err := measureResources()
	if err != nil {
		return nil // can't measure, don't kill
	}

	if m.limits.MaxMemoryMB > 0 {
		usedMB := res.TotalMemoryMB - res.AvailableMemoryMB
		if usedMB > m.limits.MaxMemoryMB {
			return fmt.Errorf("memory usage %d MB exceeds limit of %d MB", usedMB, m.limits.MaxMemoryMB)
		}
	}

	if m.limits.MinFreeMemoryMB > 0 && res.AvailableMemoryMB < m.limits.MinFreeMemoryMB {
		return fmt.Errorf("free memory %d MB below minimum of %d MB", res.AvailableMemoryMB, m.limits.MinFreeMemoryMB)
	}

	return nil
}
