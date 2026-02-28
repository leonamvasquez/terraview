package util

// Truncate shortens s to at most max characters, appending "..." if truncated.
// The returned string is guaranteed to be at most max characters long.
func Truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return "..."[:max]
	}
	return s[:max-3] + "..."
}
