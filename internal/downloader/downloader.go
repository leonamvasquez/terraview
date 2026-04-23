package downloader

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Options configures a download operation.
type Options struct {
	// Timeout for the HTTP request. Default: 5 minutes.
	Timeout time.Duration
	// ExpectedSHA256 is the optional hex-encoded SHA256 checksum of the file.
	// If set, the downloaded file is verified against this hash.
	ExpectedSHA256 string
}

// DefaultOptions returns sensible defaults.
func DefaultOptions() Options {
	return Options{
		Timeout: 5 * time.Minute,
	}
}

// Download fetches a URL and saves it to destination.
// Parent directories are created automatically.
// Returns the number of bytes written and any error.
func Download(url, destination string, opts Options) (int64, error) {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Minute
	}

	client := &http.Client{Timeout: opts.Timeout}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("download failed: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download failed: HTTP %d from %s", resp.StatusCode, url)
	}

	// Ensure parent directory exists (cross-platform)
	dir := filepath.Dir(destination)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return 0, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	out, err := os.Create(destination)
	if err != nil {
		return 0, fmt.Errorf("failed to create file %s: %w", destination, err)
	}
	defer out.Close()

	// If checksum verification is requested, use a TeeReader
	var written int64
	if opts.ExpectedSHA256 != "" {
		hasher := sha256.New()
		tee := io.TeeReader(resp.Body, hasher)
		written, err = io.Copy(out, tee)
		if err != nil {
			os.Remove(destination)
			return 0, fmt.Errorf("download write failed: %w", err)
		}
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != opts.ExpectedSHA256 {
			os.Remove(destination)
			return 0, fmt.Errorf("checksum mismatch: expected %s, got %s", opts.ExpectedSHA256, actual)
		}
	} else {
		written, err = io.Copy(out, resp.Body)
		if err != nil {
			os.Remove(destination)
			return 0, fmt.Errorf("download write failed: %w", err)
		}
	}

	return written, nil
}
