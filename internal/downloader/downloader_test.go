package downloader

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownload_Success(t *testing.T) {
	content := "hello world binary content"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "subdir", "testfile")
	n, err := Download(srv.URL, dest, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != int64(len(content)) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}

	data, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(data) != content {
		t.Errorf("expected %q, got %q", content, string(data))
	}
}

func TestDownload_HTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "testfile")
	_, err := Download(srv.URL, dest, DefaultOptions())
	if err == nil {
		t.Fatal("expected error for 404, got nil")
	}
}

func TestDownload_ChecksumValid(t *testing.T) {
	content := "verified content"
	h := sha256.Sum256([]byte(content))
	expected := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "verified")
	opts := DefaultOptions()
	opts.ExpectedSHA256 = expected

	_, err := Download(srv.URL, dest, opts)
	if err != nil {
		t.Fatalf("unexpected error with valid checksum: %v", err)
	}
}

func TestDownload_ChecksumInvalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "bad-checksum")
	opts := DefaultOptions()
	opts.ExpectedSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"

	_, err := Download(srv.URL, dest, opts)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}

	// File should be cleaned up on checksum failure
	if Exists(dest) {
		t.Error("file should be removed on checksum failure")
	}
}

func TestDownload_CreatesParentDirs(t *testing.T) {
	content := "nested dir test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	// Deep nested path
	dest := filepath.Join(t.TempDir(), "a", "b", "c", "file.bin")
	_, err := Download(srv.URL, dest, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !Exists(dest) {
		t.Error("file should exist after download")
	}
}

func TestDownload_WindowsPathSeparator(t *testing.T) {
	content := "windows path test"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(content))
	}))
	defer srv.Close()

	// Use filepath.Join which handles OS-specific separators
	dest := filepath.Join(t.TempDir(), "win-test", "binary.exe")
	_, err := Download(srv.URL, dest, DefaultOptions())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !Exists(dest) {
		t.Error("file should exist")
	}
}

func TestExists(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "exists-test")
	if Exists(tmp) {
		t.Error("file should not exist before creation")
	}
	os.WriteFile(tmp, []byte("x"), 0644)
	if !Exists(tmp) {
		t.Error("file should exist after creation")
	}
}

func TestDownload_InvalidURL(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "invalid")
	_, err := Download("http://localhost:1/nonexistent", dest, DefaultOptions())
	if err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

// ---------------------------------------------------------------------------
// Download with zero Timeout (default 5min branch)
// ---------------------------------------------------------------------------

func TestDownload_ZeroTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello zero timeout"))
	}))
	defer ts.Close()

	dest := filepath.Join(t.TempDir(), "zero-timeout.bin")
	opts := Options{Timeout: 0} // should default to 5 min
	n, err := Download(ts.URL, dest, opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != int64(len("hello zero timeout")) {
		t.Errorf("expected %d bytes, got %d", len("hello zero timeout"), n)
	}
}

// ---------------------------------------------------------------------------
// Download to a read-only parent (MkdirAll fail)
// ---------------------------------------------------------------------------

func TestDownload_ReadOnlyParent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
	}))
	defer ts.Close()

	roDir := filepath.Join(t.TempDir(), "readonly")
	os.MkdirAll(roDir, 0555)
	defer os.Chmod(roDir, 0755)

	dest := filepath.Join(roDir, "subdir", "file.bin")
	_, err := Download(ts.URL, dest, DefaultOptions())
	if err == nil {
		t.Fatal("expected error for read-only parent dir")
	}
}
