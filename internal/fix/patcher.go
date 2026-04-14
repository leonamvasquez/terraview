package fix

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// ApplyToFile replaces the resource block at loc with newHCL and writes the
// result back to the file. The original file is overwritten atomically via a
// temp-file swap to prevent partial writes on failure.
func ApplyToFile(loc *Location, newHCL string) error {
	data, err := os.ReadFile(loc.File)
	if err != nil {
		return fmt.Errorf("read %s: %w", loc.File, err)
	}

	lines := strings.Split(string(data), "\n")

	// Normalise the new HCL: strip trailing blank lines, split into lines.
	newLines := strings.Split(strings.TrimRight(newHCL, "\n\r "), "\n")

	// Reconstruct file: before-block + newHCL + after-block
	before := lines[:loc.StartLine-1]
	after := lines[loc.EndLine:] // loc.EndLine is 1-based; slice is 0-based

	result := make([]string, 0, len(before)+len(newLines)+len(after))
	result = append(result, before...)
	result = append(result, newLines...)
	result = append(result, after...)

	return writeAtomic(loc.File, []byte(strings.Join(result, "\n")))
}

// AppendToFile appends one or more HCL blocks to the end of path, separated by
// a blank line. Used for prerequisites (new resources required by the fix).
func AppendToFile(path string, blocks []string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s for append: %w", path, err)
	}
	defer f.Close()

	for _, block := range blocks {
		if _, err := fmt.Fprintf(f, "\n%s\n", strings.TrimSpace(block)); err != nil {
			return err
		}
	}
	return nil
}

// BackupFile copies src to src+".tvfix.bak". Returns the backup path.
func BackupFile(src string) (string, error) {
	bak := src + ".tvfix.bak"
	in, err := os.Open(src)
	if err != nil {
		return "", fmt.Errorf("open for backup: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(bak, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return "", fmt.Errorf("create backup: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return "", fmt.Errorf("copy backup: %w", err)
	}
	return bak, nil
}

// RestoreBackup copies bakPath back to the original file and removes the backup.
func RestoreBackup(bakPath string) error {
	orig := strings.TrimSuffix(bakPath, ".tvfix.bak")
	in, err := os.Open(bakPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(orig, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("restore backup: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("restore copy: %w", err)
	}
	_ = os.Remove(bakPath)
	return nil
}

// writeAtomic writes data to a temp file alongside dst, then renames it. This
// ensures the file is never left in a partially-written state.
func writeAtomic(dst string, data []byte) error {
	tmp := dst + ".tvfix.tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
