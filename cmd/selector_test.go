package cmd

import (
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/output"
)

// ---------------------------------------------------------------------------
// disableCmdColors
// ---------------------------------------------------------------------------

func TestDisableCmdColors_WhenColorDisabled(t *testing.T) {
	// Save original ANSI state and restore at end.
	origReset := ansiReset
	origBold := ansiBold
	origDim := ansiDim
	origCyan := ansiCyan
	origGreen := ansiGreen
	origYellow := ansiYellow
	origRed := ansiRed
	defer func() {
		ansiReset = origReset
		ansiBold = origBold
		ansiDim = origDim
		ansiCyan = origCyan
		ansiGreen = origGreen
		ansiYellow = origYellow
		ansiRed = origRed
	}()

	// Restore ANSI codes to known values first.
	ansiReset = "\033[0m"
	ansiBold = "\033[1m"

	origColorEnabled := output.ColorEnabled
	defer func() { output.ColorEnabled = origColorEnabled }()

	output.ColorEnabled = false
	disableCmdColors()

	if ansiReset != "" {
		t.Errorf("ansiReset should be empty when colors disabled, got %q", ansiReset)
	}
	if ansiBold != "" {
		t.Errorf("ansiBold should be empty when colors disabled, got %q", ansiBold)
	}
	if ansiDim != "" {
		t.Errorf("ansiDim should be empty when colors disabled, got %q", ansiDim)
	}
	if ansiCyan != "" {
		t.Errorf("ansiCyan should be empty when colors disabled, got %q", ansiCyan)
	}
	if ansiGreen != "" {
		t.Errorf("ansiGreen should be empty when colors disabled, got %q", ansiGreen)
	}
	if ansiYellow != "" {
		t.Errorf("ansiYellow should be empty when colors disabled, got %q", ansiYellow)
	}
	if ansiRed != "" {
		t.Errorf("ansiRed should be empty when colors disabled, got %q", ansiRed)
	}
}

func TestDisableCmdColors_WhenColorEnabled(t *testing.T) {
	origReset := ansiReset
	defer func() { ansiReset = origReset }()
	ansiReset = "\033[0m"

	origColorEnabled := output.ColorEnabled
	defer func() { output.ColorEnabled = origColorEnabled }()

	output.ColorEnabled = true
	disableCmdColors()

	// Colors should NOT be cleared when ColorEnabled is true.
	if ansiReset == "" {
		t.Error("ansiReset should remain non-empty when colors are enabled")
	}
}

// ---------------------------------------------------------------------------
// printItem
// ---------------------------------------------------------------------------

func TestPrintItem_NonSelected(t *testing.T) {
	item := selectItem{Label: "Gemini", Detail: "google", Value: "gemini"}
	out := captureStdout(func() {
		printItem(0, item, 99) // cursor=99 means item 0 is not selected
	})
	if !strings.Contains(out, "Gemini") {
		t.Errorf("expected 'Gemini' in output, got %q", out)
	}
	// Non-selected items should NOT contain the arrow marker.
	if strings.Contains(out, "▶") {
		t.Errorf("non-selected item should not contain '▶', got %q", out)
	}
}

func TestPrintItem_Selected(t *testing.T) {
	item := selectItem{Label: "Claude", Value: "claude"}
	out := captureStdout(func() {
		printItem(0, item, 0) // cursor=0 = this item is selected
	})
	if !strings.Contains(out, "Claude") {
		t.Errorf("expected 'Claude' in output, got %q", out)
	}
	if !strings.Contains(out, "▶") {
		t.Errorf("selected item should contain '▶', got %q", out)
	}
}

func TestPrintItem_ActiveStar(t *testing.T) {
	item := selectItem{Label: "Ollama", Value: "ollama", IsActive: true}
	out := captureStdout(func() {
		printItem(0, item, 99)
	})
	if !strings.Contains(out, "★") {
		t.Errorf("active item should contain '★', got %q", out)
	}
}

func TestPrintItem_InactiveNoStar(t *testing.T) {
	item := selectItem{Label: "OpenAI", Value: "openai", IsActive: false}
	out := captureStdout(func() {
		printItem(0, item, 99)
	})
	if strings.Contains(out, "★") {
		t.Errorf("inactive item should not contain '★', got %q", out)
	}
}

func TestPrintItem_WithDetail(t *testing.T) {
	item := selectItem{Label: "OpenRouter", Detail: "api key required", Value: "openrouter"}
	out := captureStdout(func() {
		printItem(0, item, 99)
	})
	if !strings.Contains(out, "api key required") {
		t.Errorf("expected detail in output, got %q", out)
	}
}

func TestPrintItem_WithoutDetail(t *testing.T) {
	item := selectItem{Label: "Gemini", Value: "gemini"}
	// Should not panic or include empty detail section.
	captureStdout(func() {
		printItem(0, item, 99)
	})
}

// ---------------------------------------------------------------------------
// renderList
// ---------------------------------------------------------------------------

func TestRenderList_ContainsTitle(t *testing.T) {
	items := []selectItem{
		{Label: "checkov", Value: "checkov"},
		{Label: "tfsec", Value: "tfsec"},
	}
	out := captureStdout(func() {
		renderList("Choose scanner", items, 0)
	})
	if !strings.Contains(out, "Choose scanner") {
		t.Errorf("expected title 'Choose scanner', got %q", out)
	}
}

func TestRenderList_ContainsItems(t *testing.T) {
	items := []selectItem{
		{Label: "checkov", Value: "checkov"},
		{Label: "tfsec", Value: "tfsec"},
		{Label: "terrascan", Value: "terrascan"},
	}
	out := captureStdout(func() {
		renderList("Pick one", items, 1)
	})
	for _, item := range items {
		if !strings.Contains(out, item.Label) {
			t.Errorf("expected %q in list output, got %q", item.Label, out)
		}
	}
}

func TestRenderList_ContainsNavigationHint(t *testing.T) {
	items := []selectItem{{Label: "a", Value: "a"}}
	out := captureStdout(func() {
		renderList("Test", items, 0)
	})
	if !strings.Contains(out, "Enter") {
		t.Errorf("expected navigation hint with 'Enter', got %q", out)
	}
}

func TestRenderList_EmptyItems(t *testing.T) {
	// Should not panic with empty list.
	captureStdout(func() {
		renderList("Empty list", nil, 0)
	})
}

// ---------------------------------------------------------------------------
// eraseLines / moveUp
// ---------------------------------------------------------------------------

func TestEraseLines_ProducesOutput(t *testing.T) {
	out := captureStdout(func() {
		eraseLines(3)
	})
	// Should contain ANSI erase-line sequence.
	if !strings.Contains(out, "\033[2K") {
		t.Errorf("eraseLines(3) should produce ANSI erase sequences, got %q", out)
	}
}

func TestEraseLines_Zero(t *testing.T) {
	// eraseLines(0) should still write the trailing \033[2K\r
	out := captureStdout(func() {
		eraseLines(0)
	})
	if !strings.Contains(out, "\033[2K") {
		t.Errorf("eraseLines(0) should still write erase sequence, got %q", out)
	}
}

func TestMoveUp_ProducesOutput(t *testing.T) {
	out := captureStdout(func() {
		moveUp(3)
	})
	// \033[A is the ANSI cursor-up escape code.
	if !strings.Contains(out, "\033[A") {
		t.Errorf("moveUp(3) should produce cursor-up sequences, got %q", out)
	}
}

func TestMoveUp_Zero(t *testing.T) {
	// No output expected.
	out := captureStdout(func() {
		moveUp(0)
	})
	if out != "" {
		t.Errorf("moveUp(0) should produce no output, got %q", out)
	}
}

// ---------------------------------------------------------------------------
// resolveMaxResources (scan.go)
// ---------------------------------------------------------------------------

func TestResolveMaxResources_FlagTakesPriority(t *testing.T) {
	got := resolveMaxResources(50, 30)
	if got != 50 {
		t.Errorf("resolveMaxResources(50, 30) = %d, want 50", got)
	}
}

func TestResolveMaxResources_FallsBackToCfg(t *testing.T) {
	got := resolveMaxResources(0, 30)
	if got != 30 {
		t.Errorf("resolveMaxResources(0, 30) = %d, want 30", got)
	}
}

func TestResolveMaxResources_NegativeFlagFallsBack(t *testing.T) {
	got := resolveMaxResources(-1, 25)
	if got != 25 {
		t.Errorf("resolveMaxResources(-1, 25) = %d, want 25", got)
	}
}

func TestResolveMaxResources_BothZero(t *testing.T) {
	got := resolveMaxResources(0, 0)
	if got != 0 {
		t.Errorf("resolveMaxResources(0, 0) = %d, want 0", got)
	}
}

func TestResolveMaxResources_FlagPositive(t *testing.T) {
	cases := []struct{ flag, cfg, want int }{
		{1, 100, 1},
		{120, 0, 120},
		{30, 30, 30},
	}
	for _, tc := range cases {
		got := resolveMaxResources(tc.flag, tc.cfg)
		if got != tc.want {
			t.Errorf("resolveMaxResources(%d, %d) = %d, want %d", tc.flag, tc.cfg, got, tc.want)
		}
	}
}
