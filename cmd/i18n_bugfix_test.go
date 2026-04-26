package cmd

// Tests for BUG-003 through BUG-008 (Batch 12b i18n fixes).
// Each test verifies the default-English / --br-Portuguese duality introduced
// by the fix. None of these tests require a real Terraform plan, scanner
// binary, or AI provider.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/history"
	"github.com/leonamvasquez/terraview/internal/i18n"
)

// ── BUG-003: history formatter strings ───────────────────────────────────────

func TestBUG003_HistoryTitle_Default(t *testing.T) {
	i18n.SetLang("en")
	var buf bytes.Buffer
	history.FormatTrendOutput(&buf, nil, "myproj", 5)
	out := buf.String()
	if strings.Contains(out, "Tendência") || strings.Contains(out, "Nenhum") {
		t.Errorf("BUG-003: default output should be English, got pt-BR: %s", out)
	}
	if !strings.Contains(out, "No data") {
		t.Errorf("BUG-003: expected 'No data' in default output, got: %s", out)
	}
}

func TestBUG003_HistoryTitle_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	t.Cleanup(func() { i18n.SetLang("en") })
	var buf bytes.Buffer
	history.FormatTrendOutput(&buf, nil, "myproj", 5)
	out := buf.String()
	if !strings.Contains(out, "Nenhum") {
		t.Errorf("BUG-003: expected pt-BR message with --br, got: %s", out)
	}
}

func TestBUG003_CompareTitle_Default(t *testing.T) {
	i18n.SetLang("en")
	cr := history.CompareTwoScans("Previous", history.ScanRecord{}, history.ScanRecord{})
	var buf bytes.Buffer
	history.FormatCompareOutput(&buf, cr, "myproj")
	out := buf.String()
	if strings.Contains(out, "Comparação") {
		t.Errorf("BUG-003: default compare output should be English, got: %s", out)
	}
	if !strings.Contains(out, "Comparison") {
		t.Errorf("BUG-003: expected 'Comparison' in default output, got: %s", out)
	}
}

func TestBUG003_CompareColNow_Default(t *testing.T) {
	i18n.SetLang("en")
	cr := history.CompareTwoScans("Previous", history.ScanRecord{}, history.ScanRecord{})
	var buf bytes.Buffer
	history.FormatCompareOutput(&buf, cr, "myproj")
	out := buf.String()
	if strings.Contains(out, "Agora") {
		t.Errorf("BUG-003: 'Agora' column header should not appear in default EN output, got: %s", out)
	}
	if !strings.Contains(out, "Now") {
		t.Errorf("BUG-003: expected 'Now' column header in default EN output, got: %s", out)
	}
}

// ── BUG-004: status --br ──────────────────────────────────────────────────────

func TestBUG004_StatusHeader_Default(t *testing.T) {
	i18n.SetLang("en")
	ls := &history.LastScan{Scanner: "checkov"}
	out := captureStatus(func() {
		printStatusHeader(ls, "/tmp/myproj")
	})
	if strings.Contains(out, "No projeto:") || strings.Contains(out, "Último scan:") {
		t.Errorf("BUG-004: default status header should be English, got pt-BR: %s", out)
	}
	if !strings.Contains(out, "On project:") {
		t.Errorf("BUG-004: expected 'On project:' in default output, got: %s", out)
	}
}

func TestBUG004_StatusHeader_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	t.Cleanup(func() { i18n.SetLang("en") })
	ls := &history.LastScan{Scanner: "checkov"}
	out := captureStatus(func() {
		printStatusHeader(ls, "/tmp/myproj")
	})
	if !strings.Contains(out, "No projeto:") {
		t.Errorf("BUG-004: expected 'No projeto:' with --br, got: %s", out)
	}
}

// ── BUG-006: fix plan "Effort:" label ────────────────────────────────────────

func TestBUG006_FixEffortLabel_Default(t *testing.T) {
	i18n.SetLang("en")
	label := i18n.T().FixEffort
	if label != "Effort" {
		t.Errorf("BUG-006: default FixEffort should be 'Effort', got %q", label)
	}
}

func TestBUG006_FixEffortLabel_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	t.Cleanup(func() { i18n.SetLang("en") })
	label := i18n.T().FixEffort
	if label != "Esforço" {
		t.Errorf("BUG-006: pt-BR FixEffort should be 'Esforço', got %q", label)
	}
}

// ── BUG-007: explain parser accepts pt-BR keys ────────────────────────────────

func TestBUG007_NormalizeMapKeys_AcceptsPTBR(t *testing.T) {
	m := map[string]interface{}{
		"arquitetura": "microservices",
		"componentes": []interface{}{},
		"conexões":    []interface{}{"a -> b"},
		"padrões":     []interface{}{"HA"},
		"visão geral": "overview text",
	}
	normalized := normalizeMapKeys(m)

	if _, ok := normalized["architecture"]; !ok {
		t.Error("BUG-007: 'arquitetura' should be normalized to 'architecture'")
	}
	if _, ok := normalized["components"]; !ok {
		t.Error("BUG-007: 'componentes' should be normalized to 'components'")
	}
	if _, ok := normalized["connections"]; !ok {
		t.Error("BUG-007: 'conexões' should be normalized to 'connections'")
	}
	if _, ok := normalized["patterns"]; !ok {
		t.Error("BUG-007: 'padrões' should be normalized to 'patterns'")
	}
	if _, ok := normalized["overview"]; !ok {
		t.Error("BUG-007: 'visão geral' should be normalized to 'overview'")
	}
}

func TestBUG007_InfraExplFromMap_PTBRKeys(t *testing.T) {
	m := map[string]interface{}{
		"visao geral": "Minha infraestrutura",
		"arquitetura": "monolito",
		"componentes": []interface{}{
			map[string]interface{}{
				"recurso":    "aws_instance.web",
				"finalidade": "servidor web",
				"papel":      "frontend",
			},
		},
		"conexões": []interface{}{"web -> db"},
		"padrões":  []interface{}{"HA"},
	}
	expl := infraExplFromMap(m)

	if expl.Overview != "Minha infraestrutura" {
		t.Errorf("BUG-007: Overview = %q, want 'Minha infraestrutura'", expl.Overview)
	}
	if expl.Architecture != "monolito" {
		t.Errorf("BUG-007: Architecture = %q, want 'monolito'", expl.Architecture)
	}
	if len(expl.Components) != 1 {
		t.Fatalf("BUG-007: expected 1 component, got %d", len(expl.Components))
	}
	if expl.Components[0].Resource != "aws_instance.web" {
		t.Errorf("BUG-007: Component.Resource = %q, want 'aws_instance.web'", expl.Components[0].Resource)
	}
	if expl.Components[0].Purpose != "servidor web" {
		t.Errorf("BUG-007: Component.Purpose = %q, want 'servidor web'", expl.Components[0].Purpose)
	}
	if len(expl.Connections) != 1 || expl.Connections[0] != "web -> db" {
		t.Errorf("BUG-007: Connections = %v, want ['web -> db']", expl.Connections)
	}
}

func TestBUG007_ParseInfraExplanation_NoUnableToParse(t *testing.T) {
	// Simulate a pt-BR LLM response with Portuguese keys (worst case).
	raw := `{"visao geral":"Infraestrutura AWS","arquitetura":"monolito","componentes":[],"conexoes":[],"padroes":[]}`
	expl := parseInfraExplanation(raw)
	if expl.Overview == "Unable to parse structured response" {
		t.Error("BUG-007: parseInfraExplanation should not return 'Unable to parse' for pt-BR keyed JSON")
	}
	if expl.Overview != "Infraestrutura AWS" {
		t.Errorf("BUG-007: Overview = %q, want 'Infraestrutura AWS'", expl.Overview)
	}
}

// ── BUG-008: setup detects CLI providers ─────────────────────────────────────

func TestBUG008_CommandAvailable_NotInstalled(t *testing.T) {
	// Replace execLookPath with a stub that always fails.
	orig := execLookPath
	t.Cleanup(func() { execLookPath = orig })
	execLookPath = func(name string) (string, error) {
		return "", &notFoundError{name: name}
	}

	if commandAvailable("nonexistent-binary") {
		t.Error("BUG-008: commandAvailable should return false for missing binary")
	}
}

func TestBUG008_CommandAvailable_Installed(t *testing.T) {
	// Replace execLookPath with a stub that succeeds.
	orig := execLookPath
	t.Cleanup(func() { execLookPath = orig })
	execLookPath = func(name string) (string, error) {
		return "/usr/local/bin/" + name, nil
	}

	if !commandAvailable("gemini") {
		t.Error("BUG-008: commandAvailable should return true when binary is found")
	}
	if !commandAvailable("claude") {
		t.Error("BUG-008: commandAvailable should return true when binary is found")
	}
}

// notFoundError satisfies the error interface for the lookup stub.
type notFoundError struct{ name string }

func (e *notFoundError) Error() string { return e.name + ": not found" }
