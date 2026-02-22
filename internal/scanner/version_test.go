package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// makeFakeVersionBinary creates a temporary shell script (Unix) that writes
// the given output to stdout and exits with the given code.
func makeFakeVersionBinary(t *testing.T, output string, exitCode int) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("version detection tests use shell scripts; skipped on Windows")
	}

	dir := t.TempDir()

	// Write output to a data file so the script can cat it (avoids shell quoting issues).
	dataFile := filepath.Join(dir, "output.txt")
	if err := os.WriteFile(dataFile, []byte(output), 0o644); err != nil {
		t.Fatalf("could not write output file: %v", err)
	}

	binPath := filepath.Join(dir, "fakebin")
	script := fmt.Sprintf("#!/bin/sh\ncat %q\nexit %d\n", dataFile, exitCode)
	if err := os.WriteFile(binPath, []byte(script), 0o755); err != nil {
		t.Fatalf("could not write fake binary: %v", err)
	}
	return binPath
}

// ─── semver extraction from multi-line output ─────────────────────────────

// TestGetCommandVersionArgs_BannerBeforeVersion simulates tfsec, which prints
// a multi-line banner before the actual version number.
func TestGetCommandVersionArgs_BannerBeforeVersion(t *testing.T) {
	output := "======================================================\n" +
		"tfsec is joining the Trivy family\n" +
		"\n" +
		"tfsec will continue to remain available\n" +
		"======================================================\n" +
		"v1.28.11\n"

	bin := makeFakeVersionBinary(t, output, 0)
	got := getCommandVersionArgs(bin)
	if got != "v1.28.11" {
		t.Errorf("getCommandVersionArgs with banner: got %q, want %q", got, "v1.28.11")
	}
}

// TestGetCommandVersionArgs_SubcommandStyle simulates tools like terrascan
// which report version via a subcommand: "terrascan version" → "Keeping ... 2.1.19".
func TestGetCommandVersionArgs_SubcommandStyle(t *testing.T) {
	output := "Keeping Infrastructure as Code Secure 2.1.19\n"
	bin := makeFakeVersionBinary(t, output, 0)
	got := getCommandVersionArgs(bin)
	if got != "2.1.19" {
		t.Errorf("getCommandVersionArgs subcommand style: got %q, want %q", got, "2.1.19")
	}
}

// TestGetCommandVersionArgs_PrefixedVersion simulates "version: v1.19.9" (terrascan).
func TestGetCommandVersionArgs_PrefixedVersion(t *testing.T) {
	output := "version: v1.19.9\n"
	bin := makeFakeVersionBinary(t, output, 0)
	got := getCommandVersionArgs(bin)
	if got != "v1.19.9" {
		t.Errorf("getCommandVersionArgs prefixed: got %q, want %q", got, "v1.19.9")
	}
}

// TestGetCommandVersionArgs_PlainVersion simulates a clean single-line version.
func TestGetCommandVersionArgs_PlainVersion(t *testing.T) {
	output := "3.2.504\n"
	bin := makeFakeVersionBinary(t, output, 0)
	got := getCommandVersionArgs(bin)
	if got != "3.2.504" {
		t.Errorf("getCommandVersionArgs plain: got %q, want %q", got, "3.2.504")
	}
}

// TestGetCommandVersionArgs_NonZeroExitStillExtractsVersion verifies that a
// non-zero exit code does not prevent version extraction (some tools exit 1
// even when printing a valid version).
func TestGetCommandVersionArgs_NonZeroExitStillExtractsVersion(t *testing.T) {
	output := "v2.3.4\n"
	bin := makeFakeVersionBinary(t, output, 1)
	got := getCommandVersionArgs(bin)
	if got != "v2.3.4" {
		t.Errorf("getCommandVersionArgs non-zero exit: got %q, want %q", got, "v2.3.4")
	}
}

// TestGetCommandVersionArgs_MissingBinary returns empty string for a binary
// that does not exist.
func TestGetCommandVersionArgs_MissingBinary(t *testing.T) {
	got := getCommandVersionArgs("/nonexistent/path/to/binary-that-does-not-exist")
	if got != "" {
		t.Errorf("missing binary should return '', got %q", got)
	}
}

// TestGetCommandVersionArgs_NoVersionInOutput returns the last non-empty line
// when no semver pattern is found.
func TestGetCommandVersionArgs_NoVersionInOutput(t *testing.T) {
	output := "usage: tool [options]\nrun 'tool help' for info\n"
	bin := makeFakeVersionBinary(t, output, 0)
	got := getCommandVersionArgs(bin)
	// Must not be empty (falls back to last non-empty line)
	if got == "" {
		t.Error("fallback should return last non-empty line, got empty string")
	}
}
