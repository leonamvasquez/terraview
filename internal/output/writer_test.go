package output

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/leonamvasquez/terraview/internal/aggregator"
	"github.com/leonamvasquez/terraview/internal/blast"
	"github.com/leonamvasquez/terraview/internal/explain"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scoring"
	"github.com/leonamvasquez/terraview/internal/util"
)

// ---------------------------------------------------------------------------
// WriterConfig helpers
// ---------------------------------------------------------------------------

func TestWriterConfig_IsBR(t *testing.T) {
	tests := []struct {
		lang string
		want bool
	}{
		{"pt-BR", true},
		{"en", false},
		{"", false},
		{"pt-br", false}, // case-sensitive
	}
	for _, tt := range tests {
		c := WriterConfig{Lang: tt.lang}
		if got := c.IsBR(); got != tt.want {
			t.Errorf("IsBR(%q) = %v, want %v", tt.lang, got, tt.want)
		}
	}
}

func TestWriterConfig_IsJSON(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{FormatJSON, true},
		{FormatPretty, false},
		{FormatCompact, false},
		{"", false},
	}
	for _, tt := range tests {
		c := WriterConfig{Format: tt.format}
		if got := c.IsJSON(); got != tt.want {
			t.Errorf("IsJSON(%q) = %v, want %v", tt.format, got, tt.want)
		}
	}
}

func TestWriterConfig_IsCompact(t *testing.T) {
	tests := []struct {
		format string
		want   bool
	}{
		{FormatCompact, true},
		{FormatPretty, false},
		{FormatJSON, false},
		{"", false},
	}
	for _, tt := range tests {
		c := WriterConfig{Format: tt.format}
		if got := c.IsCompact(); got != tt.want {
			t.Errorf("IsCompact(%q) = %v, want %v", tt.format, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// i18n.SevLabel (replaces sevBR)
// ---------------------------------------------------------------------------

func TestSevLabel_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")

	tests := []struct {
		sev  string
		want string
	}{
		{"CRITICAL", "CRÍTICO"},
		{"HIGH", "ALTO"},
		{"MEDIUM", "MÉDIO"},
		{"LOW", "BAIXO"},
		{"INFO", "INFO"},
		{"UNKNOWN", "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := i18n.SevLabel(tt.sev); got != tt.want {
			t.Errorf("SevLabel(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

func TestSevLabel_EN(t *testing.T) {
	i18n.SetLang("")

	tests := []struct {
		sev  string
		want string
	}{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"INFO", "INFO"},
		{"UNKNOWN", "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := i18n.SevLabel(tt.sev); got != tt.want {
			t.Errorf("SevLabel(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// translateReason
// ---------------------------------------------------------------------------

func TestTranslateReason(t *testing.T) {
	tests := []struct {
		reason string
		want   string
	}{
		{"No issues found", "Nenhum problema encontrado"},
		{"No CRITICAL or HIGH severity issues", "Nenhum achado CRÍTICO ou ALTO"},
		{"3 CRITICAL finding(s) detected", "3 achado(s) CRÍTICO(S) detectado(s)"},
		{"5 HIGH finding(s) detected (strict mode)", "5 achado(s) ALTO(S) detectado(s) (modo estrito)"},
		{"No CRITICAL issues found (2 HIGH — use --strict to block)", "Nenhum achado CRÍTICO encontrado (2 ALTO(S) — use --strict para bloquear)"},
		{"Some unknown reason", "Some unknown reason"}, // passthrough
	}
	for _, tt := range tests {
		if got := translateReason(tt.reason); got != tt.want {
			t.Errorf("translateReason(%q)\ngot  %q\nwant %q", tt.reason, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// groupBySeverity
// ---------------------------------------------------------------------------

func TestGroupBySeverity(t *testing.T) {
	findings := []rules.Finding{
		{Severity: "CRITICAL", RuleID: "R1"},
		{Severity: "HIGH", RuleID: "R2"},
		{Severity: "CRITICAL", RuleID: "R3"},
		{Severity: "LOW", RuleID: "R4"},
	}
	groups := groupBySeverity(findings)

	if len(groups["CRITICAL"]) != 2 {
		t.Errorf("expected 2 CRITICAL, got %d", len(groups["CRITICAL"]))
	}
	if len(groups["HIGH"]) != 1 {
		t.Errorf("expected 1 HIGH, got %d", len(groups["HIGH"]))
	}
	if len(groups["LOW"]) != 1 {
		t.Errorf("expected 1 LOW, got %d", len(groups["LOW"]))
	}
	if len(groups["MEDIUM"]) != 0 {
		t.Errorf("expected 0 MEDIUM, got %d", len(groups["MEDIUM"]))
	}
}

func TestGroupBySeverity_Empty(t *testing.T) {
	groups := groupBySeverity(nil)
	if len(groups) != 0 {
		t.Errorf("expected empty map, got %d groups", len(groups))
	}
}

// ---------------------------------------------------------------------------
// groupBySource
// ---------------------------------------------------------------------------

func TestGroupBySource(t *testing.T) {
	findings := []rules.Finding{
		{Source: "scanner:checkov", RuleID: "R1"},
		{Source: "scanner:tfsec", RuleID: "R2"},
		{Source: "scanner:checkov", RuleID: "R3"},
		{Source: "llm", RuleID: "R4"},
	}
	groups := groupBySource(findings)

	if len(groups["CHECKOV"]) != 2 {
		t.Errorf("expected 2 CHECKOV, got %d", len(groups["CHECKOV"]))
	}
	if len(groups["TFSEC"]) != 1 {
		t.Errorf("expected 1 TFSEC, got %d", len(groups["TFSEC"]))
	}
	if len(groups["AI"]) != 1 {
		t.Errorf("expected 1 AI, got %d", len(groups["AI"]))
	}
}

// ---------------------------------------------------------------------------
// sourceLabel
// ---------------------------------------------------------------------------

func TestSourceLabel(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"scanner:checkov", "CHECKOV"},
		{"scanner:tfsec", "TFSEC"},
		{"scanner:checkov+tfsec", "CHECKOV+TFSEC"},
		{"llm", "AI"},
		{"ai", "AI"},
		{"external:sarif", "SARIF (import)"},
		{"", "AI"},
		{"custom-source", "custom-source"},
	}
	for _, tt := range tests {
		if got := sourceLabel(tt.source); got != tt.want {
			t.Errorf("sourceLabel(%q) = %q, want %q", tt.source, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// findingsPerResource
// ---------------------------------------------------------------------------

func TestFindingsPerResource(t *testing.T) {
	tests := []struct {
		findings, resources int
		want                int
	}{
		{10, 5, 2},
		{3, 10, 0},
		{0, 10, 0},
		{10, 0, 0}, // division by zero guard
		{0, 0, 0},
	}
	for _, tt := range tests {
		if got := findingsPerResource(tt.findings, tt.resources); got != tt.want {
			t.Errorf("findingsPerResource(%d, %d) = %d, want %d", tt.findings, tt.resources, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		s    string
		max  int
		want string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 8, "hello..."},
		{"abcdef", 3, "..."},
		{"", 10, ""},
	}
	for _, tt := range tests {
		if got := util.Truncate(tt.s, tt.max); got != tt.want {
			t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.max, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// scoreEmoji
// ---------------------------------------------------------------------------

func TestScoreEmoji(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{10.0, "🟢"},
		{9.0, "🟢"},
		{8.5, "🟡"},
		{7.0, "🟡"},
		{6.5, "🟠"},
		{5.0, "🟠"},
		{4.9, "🔴"},
		{0.0, "🔴"},
	}
	for _, tt := range tests {
		if got := scoreEmoji(tt.score); got != tt.want {
			t.Errorf("scoreEmoji(%.1f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// severityIcon
// ---------------------------------------------------------------------------

func TestSeverityIcon(t *testing.T) {
	tests := []struct {
		sev  string
		want string
	}{
		{rules.SeverityCritical, "🔴"},
		{rules.SeverityHigh, "🟠"},
		{rules.SeverityMedium, "🟡"},
		{rules.SeverityLow, "🔵"},
		{rules.SeverityInfo, "⚪"},
		{"UNKNOWN", "⚪"},
	}
	for _, tt := range tests {
		if got := severityIcon(tt.sev); got != tt.want {
			t.Errorf("severityIcon(%q) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}

// ---------------------------------------------------------------------------
// NewWriterWithConfig
// ---------------------------------------------------------------------------

func TestNewWriterWithConfig(t *testing.T) {
	cfg := WriterConfig{Format: FormatJSON, Lang: "pt-BR"}
	w := NewWriterWithConfig(cfg)
	if w == nil {
		t.Fatal("expected non-nil writer")
	}
	if w.config.Format != FormatJSON {
		t.Errorf("expected format %q, got %q", FormatJSON, w.config.Format)
	}
	if !w.config.IsBR() {
		t.Error("expected IsBR() true")
	}
}

// ---------------------------------------------------------------------------
// WriteJSON
// ---------------------------------------------------------------------------

func TestWriteJSON_Success(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 2,
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "HIGH", Resource: "aws_instance.web", Message: "test"},
		},
		SeverityCounts: map[string]int{"HIGH": 1},
		Score:          scoring.Score{OverallScore: 7.5},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.json")

	if err := w.WriteJSON(result, path); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	var loaded aggregator.ReviewResult
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if loaded.PlanFile != "plan.json" {
		t.Errorf("expected plan_file 'plan.json', got %q", loaded.PlanFile)
	}
	if len(loaded.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(loaded.Findings))
	}
}

func TestWriteJSON_InvalidPath(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{}
	err := w.WriteJSON(result, "/nonexistent/dir/file.json")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

// ---------------------------------------------------------------------------
// WriteMarkdown
// ---------------------------------------------------------------------------

func TestWriteMarkdown_Success(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 5,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE", Reasons: []string{"No issues found"}, Confidence: "high"},
		Findings:       nil,
		Score:          scoring.Score{SecurityScore: 9.0, ComplianceScore: 8.5, MaintainabilityScore: 9.5, OverallScore: 9.0},
		Summary:        "All good",
		SeverityCounts: map[string]int{},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.md")

	if err := w.WriteMarkdown(result, path); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "# Terraform Plan Review") {
		t.Error("expected English header in markdown")
	}
	if !strings.Contains(md, "**SAFE**") {
		t.Error("expected SAFE verdict in markdown")
	}
	if !strings.Contains(md, "No Issues Found") {
		t.Error("expected 'No Issues Found' section")
	}
}

func TestWriteMarkdown_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty, Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 3,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE", Reasons: []string{"No issues found"}, Confidence: "medium"},
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "CRITICAL", Category: "security", Resource: "aws_instance.web", Message: "Public SSH", Source: "scanner:checkov"},
		},
		Score:          scoring.Score{SecurityScore: 3.0, ComplianceScore: 5.0, MaintainabilityScore: 7.0, OverallScore: 4.5},
		Summary:        "Problemas encontrados",
		SeverityCounts: map[string]int{"CRITICAL": 1},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.md")

	if err := w.WriteMarkdown(result, path); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "# Revisão do Plano Terraform") {
		t.Error("expected Portuguese header")
	}
	if !strings.Contains(md, "**NÃO SEGURO**") {
		t.Error("expected NÃO SEGURO verdict")
	}
	if !strings.Contains(md, "CRÍTICO") {
		t.Error("expected CRÍTICO severity label")
	}
	if !strings.Contains(md, "Nenhum problema encontrado") {
		t.Error("expected translated reason")
	}
}

func TestWriteMarkdown_WithFindings(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 10,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE", Confidence: "high"},
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "CRITICAL", Category: "security", Resource: "aws_instance.web", Message: "Public SSH access", Remediation: "Close port 22", Source: "scanner:checkov"},
			{RuleID: "TAG001", Severity: "MEDIUM", Category: "compliance", Resource: "aws_s3_bucket.data", Message: "Missing tags", Source: "llm"},
		},
		Score:          scoring.Score{SecurityScore: 4.0, ComplianceScore: 6.0, MaintainabilityScore: 8.0, OverallScore: 5.5},
		Summary:        "Issues detected",
		SeverityCounts: map[string]int{"CRITICAL": 1, "MEDIUM": 1},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.md")

	if err := w.WriteMarkdown(result, path); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	md := string(data)
	if !strings.Contains(md, "Detailed Findings") {
		t.Error("expected Detailed Findings section")
	}
	if !strings.Contains(md, "Public SSH access") {
		t.Error("expected finding message in output")
	}
	if !strings.Contains(md, "Close port 22") {
		t.Error("expected remediation in output")
	}
	if !strings.Contains(md, "SEC001") {
		t.Error("expected rule ID in output")
	}
}

func TestWriteMarkdown_WithDiagram(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE", Confidence: "high"},
		Score:          scoring.Score{OverallScore: 10.0},
		Diagram:        "  AWS Infrastructure\n  └─ VPC",
		SeverityCounts: map[string]int{},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.md")

	if err := w.WriteMarkdown(result, path); err != nil {
		t.Fatalf("WriteMarkdown failed: %v", err)
	}

	data, _ := os.ReadFile(path)
	md := string(data)

	if !strings.Contains(md, "Infrastructure Diagram") {
		t.Error("expected diagram section header")
	}
	if !strings.Contains(md, "AWS Infrastructure") {
		t.Error("expected diagram content in markdown")
	}
}

func TestWriteMarkdown_WithExplanation(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE", Confidence: "high"},
		Score:          scoring.Score{OverallScore: 9.0},
		Explanation: &explain.Explanation{
			Summary:     "Plan creates an EC2 instance",
			Changes:     []string{"New EC2 instance"},
			Risks:       []string{"Public IP exposure"},
			Suggestions: []string{"Add security group"},
			RiskLevel:   "medium",
		},
		SeverityCounts: map[string]int{},
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "review.md")
	w.WriteMarkdown(result, path)
	data, _ := os.ReadFile(path)
	md := string(data)

	if !strings.Contains(md, "AI Explanation") {
		t.Error("expected AI Explanation section")
	}
	if !strings.Contains(md, "Plan creates an EC2 instance") {
		t.Error("expected summary in explanation")
	}
	if !strings.Contains(md, "Public IP exposure") {
		t.Error("expected risk in explanation")
	}
	if !strings.Contains(md, "Add security group") {
		t.Error("expected suggestion in explanation")
	}
}

func TestWriteMarkdown_InvalidPath(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{}
	err := w.WriteMarkdown(result, "/nonexistent/dir/review.md")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

// ---------------------------------------------------------------------------
// renderMarkdown building blocks
// ---------------------------------------------------------------------------

func TestRenderMarkdown_ScoreTable(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		Score: scoring.Score{
			SecurityScore:        9.5,
			ComplianceScore:      7.2,
			MaintainabilityScore: 5.0,
			OverallScore:         7.2,
		},
		Verdict:        aggregator.Verdict{Safe: true, Confidence: "high"},
		SeverityCounts: map[string]int{},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "Quality Score") {
		t.Error("expected Quality Score header")
	}
	if !strings.Contains(md, "🟢") {
		t.Error("expected green emoji for score >= 9")
	}
	if !strings.Contains(md, "🟡") {
		t.Error("expected yellow emoji for score >= 7")
	}
	if !strings.Contains(md, "🟠") {
		t.Error("expected orange emoji for score >= 5")
	}
}

func TestRenderMarkdown_Footer(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{})
	result := aggregator.ReviewResult{
		ExitCode:       1,
		Verdict:        aggregator.Verdict{Safe: false, Confidence: "high"},
		SeverityCounts: map[string]int{},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "terraview") {
		t.Error("expected terraview link in footer")
	}
	if !strings.Contains(md, "Exit code: 1") {
		t.Error("expected exit code in footer")
	}
}

// ---------------------------------------------------------------------------
// renderMarkdown — BR with explanation, diagram, findings
// ---------------------------------------------------------------------------

func TestRenderMarkdown_BR_WithExplanation(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	w := NewWriterWithConfig(WriterConfig{Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 3,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SEGURO", Reasons: []string{"No issues found"}, Confidence: "high"},
		Explanation: &explain.Explanation{
			Summary:     "Plano cria EC2",
			Changes:     []string{"Nova instância"},
			Risks:       []string{"IP público"},
			Suggestions: []string{"Security group"},
			RiskLevel:   "baixo",
		},
		Score:          scoring.Score{SecurityScore: 9.0, OverallScore: 9.0},
		SeverityCounts: map[string]int{},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "Revisão do Plano Terraform") {
		t.Error("expected BR header")
	}
	if !strings.Contains(md, "Explicação IA") {
		t.Error("expected BR AI explanation section")
	}
	if !strings.Contains(md, "Mudanças") {
		t.Error("expected BR Changes section")
	}
	if !strings.Contains(md, "Riscos") {
		t.Error("expected BR Risks section")
	}
	if !strings.Contains(md, "Sugestões") {
		t.Error("expected BR Suggestions section")
	}
	if !strings.Contains(md, "Nível de Risco") {
		t.Error("expected BR risk level label")
	}
	if !strings.Contains(md, "SEGURO") {
		t.Error("expected BR safe verdict")
	}
	if !strings.Contains(md, "Nenhum problema encontrado") {
		t.Error("expected translated reason")
	}
	if !strings.Contains(md, "Confiança") {
		t.Error("expected BR confidence label")
	}
}

func TestRenderMarkdown_BR_WithFindings(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	w := NewWriterWithConfig(WriterConfig{Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		PlanFile:       "plan.json",
		TotalResources: 5,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NÃO SEGURO", Confidence: "high"},
		Findings: []rules.Finding{
			{RuleID: "SEC001", Severity: "CRITICAL", Category: "security", Resource: "aws_instance.web", Message: "SSH aberto", Remediation: "Fechar porta 22", Source: "scanner:checkov"},
			{RuleID: "TAG001", Severity: "LOW", Category: "compliance", Resource: "aws_s3_bucket.data", Message: "Tags ausentes", Source: "llm"},
		},
		Score:          scoring.Score{SecurityScore: 3.0, OverallScore: 4.5},
		Summary:        "Achados detectados",
		SeverityCounts: map[string]int{"CRITICAL": 1, "LOW": 1},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "Achados Detalhados") {
		t.Error("expected BR detailed findings section")
	}
	if !strings.Contains(md, "CRÍTICO") {
		t.Error("expected BR CRITICO label")
	}
	if !strings.Contains(md, "BAIXO") {
		t.Error("expected BR BAIXO label")
	}
	if !strings.Contains(md, "Remediação") {
		t.Error("expected BR remediation label")
	}
	if !strings.Contains(md, "Visão Geral dos Achados") {
		t.Error("expected BR findings overview")
	}
	if !strings.Contains(md, "Score de Qualidade") {
		t.Error("expected BR quality score header")
	}
}

func TestRenderMarkdown_BR_NoFindings(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		Verdict:        aggregator.Verdict{Safe: true, Confidence: "high"},
		SeverityCounts: map[string]int{},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "Nenhum Problema Encontrado") {
		t.Error("expected BR no issues section")
	}
}

func TestRenderMarkdown_WithDiagramBR(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		Verdict:        aggregator.Verdict{Safe: true, Confidence: "high"},
		Diagram:        "  AWS Infra\n  └─ VPC",
		SeverityCounts: map[string]int{},
	}
	md := w.renderMarkdown(result)

	if !strings.Contains(md, "Diagrama de Infraestrutura") {
		t.Error("expected BR diagram section")
	}
}

// ---------------------------------------------------------------------------
// PrintSummary / printCompact / printFull — stdout capture tests
// ---------------------------------------------------------------------------

// captureStdout captures fmt.Printf / fmt.Println output by redirecting os.Stdout.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	fn()

	w.Close()
	os.Stdout = old

	data, _ := io.ReadAll(r)
	return string(data)
}

func TestPrintSummary_JSON_NoOutput(t *testing.T) {
	w := NewWriterWithConfig(WriterConfig{Format: FormatJSON})
	result := aggregator.ReviewResult{
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		SeverityCounts: map[string]int{},
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })
	if out != "" {
		t.Errorf("expected no output for JSON format, got %q", out)
	}
}

func TestPrintCompact_Safe_EN(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatCompact})
	result := aggregator.ReviewResult{
		TotalResources: 10,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 9.0},
		Findings:       []rules.Finding{{Severity: "LOW"}},
		SeverityCounts: map[string]int{"LOW": 1},
		ExitCode:       0,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "terraview:") {
		t.Error("expected 'terraview:' prefix")
	}
	if !strings.Contains(out, "SAFE") {
		t.Error("expected SAFE label")
	}
	if !strings.Contains(out, "1 findings / 10 resources") {
		t.Error("expected finding/resource ratio")
	}
	if !strings.Contains(out, "score=") {
		t.Error("expected score=")
	}
	if !strings.Contains(out, "LOW:1") {
		t.Error("expected severity counts in brackets")
	}
}

func TestPrintCompact_Unsafe_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatCompact, Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		TotalResources: 5,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE"},
		Score:          scoring.Score{OverallScore: 3.0},
		Findings:       []rules.Finding{{Severity: "CRITICAL"}, {Severity: "HIGH"}},
		SeverityCounts: map[string]int{"CRITICAL": 1, "HIGH": 1},
		ExitCode:       2,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "NÃO SEGURO") {
		t.Error("expected NÃO SEGURO label in pt-BR")
	}
	if !strings.Contains(out, "2 achados / 5 recursos") {
		t.Error("expected BR finding/resource ratio")
	}
	if !strings.Contains(out, "CRÍTICO:1") {
		t.Error("expected BR severity label CRÍTICO")
	}
}

func TestPrintCompact_NoSeverityCounts(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatCompact})
	result := aggregator.ReviewResult{
		TotalResources: 3,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		SeverityCounts: map[string]int{},
		ExitCode:       0,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if strings.Contains(out, "[") {
		t.Error("expected no severity bracket when counts are empty")
	}
}

func TestPrintFull_Safe_EN(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		TotalResources: 5,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE", Reasons: []string{"No issues found"}, Confidence: "high"},
		Score:          scoring.Score{SecurityScore: 9.0, ComplianceScore: 8.0, MaintainabilityScore: 9.5, OverallScore: 8.8},
		SeverityCounts: map[string]int{},
		ExitCode:       0,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "VERDICT: SAFE TO APPLY") {
		t.Error("expected EN safe verdict")
	}
	if !strings.Contains(out, "No issues found") {
		t.Error("expected reason in output")
	}
	if !strings.Contains(out, "Resources analyzed: 5") {
		t.Error("expected resources count")
	}
	if !strings.Contains(out, "Security Score:") {
		t.Error("expected Security Score label")
	}
	if !strings.Contains(out, "Overall Score:") {
		t.Error("expected Overall Score label")
	}
	if !strings.Contains(out, "Exit code: 0") {
		t.Error("expected exit code")
	}
}

func TestPrintFull_Unsafe_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty, Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		TotalResources: 3,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE", Reasons: []string{"3 CRITICAL finding(s) detected"}, Confidence: "high"},
		Findings: []rules.Finding{
			{Severity: "CRITICAL", Source: "scanner:checkov", Resource: "aws_instance.web", Message: "Public SSH"},
			{Severity: "CRITICAL", Source: "llm", Resource: "aws_s3_bucket.data", Message: "No encryption"},
			{Severity: "CRITICAL", Source: "scanner:checkov", Resource: "aws_rds.main", Message: "Public RDS"},
		},
		Score:          scoring.Score{SecurityScore: 2.0, ComplianceScore: 4.0, MaintainabilityScore: 6.0, OverallScore: 3.5},
		SeverityCounts: map[string]int{"CRITICAL": 3},
		ExitCode:       2,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "VEREDITO: NÃO SEGURO") {
		t.Error("expected BR unsafe verdict")
	}
	if !strings.Contains(out, "Recursos analisados: 3") {
		t.Error("expected BR resource count")
	}
	if !strings.Contains(out, "CRÍTICO") {
		t.Error("expected BR severity label")
	}
	if !strings.Contains(out, "Score Segurança:") {
		t.Error("expected BR security score label")
	}
	if !strings.Contains(out, "Score Geral:") {
		t.Error("expected BR overall score label")
	}
	if !strings.Contains(out, "Código de saída: 2") {
		t.Error("expected BR exit code label")
	}
}

func TestPrintFull_WithDiagram(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		TotalResources: 1,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 10.0},
		Diagram:        "  AWS Infrastructure\n  └─ VPC",
		SeverityCounts: map[string]int{},
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "AWS Infrastructure") {
		t.Error("expected diagram in output")
	}
}

func TestPrintFull_WithExplanation(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		TotalResources: 2,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 9.0},
		Explanation: &explain.Explanation{
			Summary:     "Creates an EC2 instance",
			Risks:       []string{"Public IP"},
			Suggestions: []string{"Add SG rule"},
		},
		SeverityCounts: map[string]int{},
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "AI Explanation:") {
		t.Error("expected AI Explanation label")
	}
	if !strings.Contains(out, "Creates an EC2 instance") {
		t.Error("expected summary")
	}
	if !strings.Contains(out, "Public IP") {
		t.Error("expected risk")
	}
	if !strings.Contains(out, "Add SG rule") {
		t.Error("expected suggestion")
	}
}

func TestPrintFull_WithExplanation_BR(t *testing.T) {
	i18n.SetLang("pt-BR")
	defer i18n.SetLang("")
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty, Lang: "pt-BR"})
	result := aggregator.ReviewResult{
		TotalResources: 2,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 9.0},
		Explanation: &explain.Explanation{
			Summary:     "Cria uma instância EC2",
			Risks:       []string{"IP público"},
			Suggestions: []string{"Adicionar SG"},
		},
		SeverityCounts: map[string]int{},
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "Explicação IA:") {
		t.Error("expected BR explanation label")
	}
	if !strings.Contains(out, "Riscos:") {
		t.Error("expected BR risks label")
	}
	if !strings.Contains(out, "Sugestões:") {
		t.Error("expected BR suggestions label")
	}
}

func TestPrintFull_WithBlastRadius(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		TotalResources: 2,
		Verdict:        aggregator.Verdict{Safe: true, Label: "SAFE"},
		Score:          scoring.Score{OverallScore: 8.0},
		BlastRadius: &blast.BlastResult{
			Impacts: []blast.Impact{
				{Resource: "aws_instance.web", Action: "create", TotalAffected: 3, RiskLevel: "high"},
			},
			Summary: "3 resources affected",
		},
		SeverityCounts: map[string]int{},
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "3 resources affected") {
		t.Error("expected blast radius in output")
	}
}

func TestPrintFull_FindingsGroupedBySource(t *testing.T) {
	ColorEnabled = false
	defer func() { ColorEnabled = true }()

	w := NewWriterWithConfig(WriterConfig{Format: FormatPretty})
	result := aggregator.ReviewResult{
		TotalResources: 5,
		Verdict:        aggregator.Verdict{Safe: false, Label: "NOT SAFE"},
		Score:          scoring.Score{OverallScore: 5.0},
		Findings: []rules.Finding{
			{Severity: "HIGH", Source: "scanner:checkov", Resource: "aws_instance.web", Message: "Public SSH access enabled on instance"},
			{Severity: "MEDIUM", Source: "llm", Resource: "aws_s3.data", Message: "No versioning"},
		},
		SeverityCounts: map[string]int{"HIGH": 1, "MEDIUM": 1},
		ExitCode:       1,
	}
	out := captureStdout(t, func() { w.PrintSummary(result) })

	if !strings.Contains(out, "CHECKOV") {
		t.Error("expected CHECKOV source header")
	}
	if !strings.Contains(out, "AI") {
		t.Error("expected AI source header")
	}
	if !strings.Contains(out, "aws_instance.web") {
		t.Error("expected resource name")
	}
}
