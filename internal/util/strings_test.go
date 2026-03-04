package util

import "testing"

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"hello world", 3, "..."},
		{"hello world", 2, ".."},
		{"hello world", 1, "."},
		{"hello world", 0, ""},
		{"", 5, ""},
		{"ab", 5, "ab"},
		{"abcdefghij", 7, "abcd..."},
	}
	for _, tc := range tests {
		t.Run(tc.s+"_"+string(rune('0'+tc.max)), func(t *testing.T) {
			got := Truncate(tc.s, tc.max)
			if got != tc.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tc.s, tc.max, got, tc.want)
			}
			if len(got) > tc.max {
				t.Errorf("Truncate result longer than max: len=%d, max=%d", len(got), tc.max)
			}
		})
	}
}
