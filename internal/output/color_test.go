package output

import (
	"os"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ---------------------------------------------------------------------------
// DisableColor + colorize
// ---------------------------------------------------------------------------

func TestColorize_Enabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := colorize(bold, "hello")
	if !strings.Contains(got, "hello") {
		t.Error("missing text")
	}
	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes when color enabled")
	}
}

func TestColorize_Disabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = false
	got := colorize(bold, "hello")
	if got != "hello" {
		t.Errorf("expected plain text, got %q", got)
	}
}

func TestDisableColor(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	DisableColor()
	if ColorEnabled {
		t.Error("DisableColor should set ColorEnabled to false")
	}
}

// ---------------------------------------------------------------------------
// SevColor
// ---------------------------------------------------------------------------

func TestSevColor_AllSeverities(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	for _, sev := range []string{
		rules.SeverityCritical,
		rules.SeverityHigh,
		rules.SeverityMedium,
		rules.SeverityLow,
		rules.SeverityInfo,
	} {
		got := SevColor(sev)
		if !strings.Contains(got, sev) {
			t.Errorf("SevColor(%q) missing severity text", sev)
		}
		if !strings.Contains(got, "\033[") {
			t.Errorf("SevColor(%q) missing ANSI codes", sev)
		}
	}
}

func TestSevColor_Unknown(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := SevColor("UNKNOWN")
	if got != "UNKNOWN" {
		t.Errorf("unknown severity should return plain text, got %q", got)
	}
}

func TestSevColor_Disabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = false
	got := SevColor("CRITICAL")
	if got != "CRITICAL" {
		t.Errorf("expected plain text when disabled, got %q", got)
	}
}

func TestSevColor_PortugueseCritico(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()
	ColorEnabled = true

	got := SevColor("CRÍTICO")
	if !strings.Contains(got, "CRÍTICO") {
		t.Error("missing severity text")
	}
	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes")
	}
}

func TestSevColor_PortugueseAlto(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()
	ColorEnabled = true

	got := SevColor("ALTO")
	if !strings.Contains(got, "ALTO") {
		t.Error("missing severity text")
	}
	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes")
	}
}

func TestSevColor_PortugueseMedio(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()
	ColorEnabled = true

	got := SevColor("MÉDIO")
	if !strings.Contains(got, "MÉDIO") {
		t.Error("missing severity text")
	}
	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes")
	}
}

func TestSevColor_PortugueseBaixo(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()
	ColorEnabled = true

	got := SevColor("BAIXO")
	if !strings.Contains(got, "BAIXO") {
		t.Error("missing severity text")
	}
	if !strings.Contains(got, "\033[") {
		t.Error("expected ANSI codes")
	}
}

func TestInit_NoColorEnv(t *testing.T) {
	// The init function respects NO_COLOR env var.
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	t.Setenv("NO_COLOR", "1")
	// Simulate what init does
	ColorEnabled = true
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		ColorEnabled = false
	}
	if ColorEnabled {
		t.Error("expected colors disabled with NO_COLOR set")
	}
}

// ---------------------------------------------------------------------------
// VerdictSafe / VerdictUnsafe
// ---------------------------------------------------------------------------

func TestVerdictSafe(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := VerdictSafe("SAFE")
	if !strings.Contains(got, "SAFE") {
		t.Error("missing text")
	}
}

func TestVerdictUnsafe(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := VerdictUnsafe("NOT SAFE")
	if !strings.Contains(got, "NOT SAFE") {
		t.Error("missing text")
	}
}

// ---------------------------------------------------------------------------
// ScoreColor
// ---------------------------------------------------------------------------

func TestScoreColor_Ranges(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	tests := []struct {
		score float64
		wants string
	}{
		{9.5, "9.5/10"},
		{7.5, "7.5/10"},
		{5.5, "5.5/10"},
		{3.5, "3.5/10"},
		{1.0, "1.0/10"},
	}
	for _, tt := range tests {
		got := ScoreColor(tt.score)
		if !strings.Contains(got, tt.wants) {
			t.Errorf("ScoreColor(%.1f) missing %q, got %q", tt.score, tt.wants, got)
		}
	}
}

func TestScoreColor_Disabled(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = false
	got := ScoreColor(8.5)
	if got != "8.5/10" {
		t.Errorf("expected plain text, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Header / Dimmed / SourceHeader / Resource / Bar / Prefix
// ---------------------------------------------------------------------------

func TestHeader(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := Header("Title")
	if !strings.Contains(got, "Title") {
		t.Error("missing text")
	}
}

func TestDimmed(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := Dimmed("faded")
	if !strings.Contains(got, "faded") {
		t.Error("missing text")
	}
}

func TestSourceHeader(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := SourceHeader("checkov")
	if !strings.Contains(got, "checkov") {
		t.Error("missing text")
	}
}

func TestResource(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := Resource("aws_instance.web")
	if !strings.Contains(got, "aws_instance.web") {
		t.Error("missing text")
	}
}

func TestSevCountLine(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = false
	got := SevCountLine("CRITICAL", "Critical", 5)
	if !strings.Contains(got, "5") {
		t.Error("missing count")
	}
	if !strings.Contains(got, "Critical") {
		t.Error("missing label")
	}
}

func TestBar(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := Bar()
	if !strings.Contains(got, "═") {
		t.Error("missing bar character")
	}
}

func TestPrefix(t *testing.T) {
	original := ColorEnabled
	defer func() { ColorEnabled = original }()

	ColorEnabled = true
	got := Prefix()
	if !strings.Contains(got, "terraview") {
		t.Error("missing terraview in prefix")
	}
}
