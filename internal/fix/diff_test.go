package fix

import (
	"testing"
)

func TestUnifiedDiff_NoChange(t *testing.T) {
	lines := []string{"a", "b", "c"}
	got := unifiedDiff(lines, lines)
	for _, l := range got {
		if l.Kind != diffContext {
			t.Errorf("expected all context lines, got kind=%d text=%q", l.Kind, l.Text)
		}
	}
}

func TestUnifiedDiff_SingleLineAdd(t *testing.T) {
	old := []string{"resource \"aws_s3_bucket\" \"b\" {", "}"}
	new := []string{"resource \"aws_s3_bucket\" \"b\" {", "  force_destroy = true", "}"}
	got := unifiedDiff(old, new)

	var adds, removes, ctx int
	for _, l := range got {
		switch l.Kind {
		case diffAdd:
			adds++
		case diffRemove:
			removes++
		case diffContext:
			ctx++
		}
	}
	if adds != 1 {
		t.Errorf("expected 1 add, got %d", adds)
	}
	if removes != 0 {
		t.Errorf("expected 0 removes, got %d", removes)
	}
	if ctx < 2 {
		t.Errorf("expected at least 2 context lines, got %d", ctx)
	}
}

func TestUnifiedDiff_AttributeChange(t *testing.T) {
	old := []string{
		"resource \"aws_s3_bucket\" \"b\" {",
		"  acl = \"public-read\"",
		"}",
	}
	new := []string{
		"resource \"aws_s3_bucket\" \"b\" {",
		"  acl = \"private\"",
		"}",
	}
	got := unifiedDiff(old, new)

	var adds, removes int
	for _, l := range got {
		if l.Kind == diffAdd {
			adds++
		}
		if l.Kind == diffRemove {
			removes++
		}
	}
	if adds == 0 || removes == 0 {
		t.Errorf("expected both adds and removes, got adds=%d removes=%d", adds, removes)
	}
}

func TestUnifiedDiff_ContextTrimmed(t *testing.T) {
	// 10 unchanged lines, then 1 changed, then 10 unchanged.
	// With ctx=3, only 3 lines before and after the change should appear.
	old := make([]string, 21)
	new := make([]string, 21)
	for i := range old {
		old[i] = "line"
		new[i] = "line"
	}
	old[10] = "old-value"
	new[10] = "new-value"

	got := unifiedDiff(old, new)
	// We expect: 3 context + 1 remove + 1 add + 3 context = 8 lines max.
	if len(got) > 8 {
		t.Errorf("expected at most 8 lines with ctx=3, got %d", len(got))
	}
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"a\nb\nc\n", 3},
		{"a\nb\nc", 3},
		{"", 0},
		{"single", 1},
	}
	for _, tc := range cases {
		got := splitLines(tc.in)
		if len(got) != tc.want {
			t.Errorf("splitLines(%q): got %d lines, want %d", tc.in, len(got), tc.want)
		}
	}
}
