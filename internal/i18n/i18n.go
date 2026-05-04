// Package i18n provides centralized localization for Terraview CLI output.
//
// Two languages are supported: English (default) and Brazilian Portuguese (--br).
// Call SetLang("pt-BR") at program start to activate Portuguese.
package i18n

import "sync/atomic"

// Messages holds all user-facing strings for a single language.
type Messages struct {
	// Warnings
	WarnImportFailed      string
	WarnAIProviderUnavail string
	WarnExplainUnavail    string
	WarnExplainFailed     string
	WarnPromptsNotFound   string
	WarnPromptsLoadFailed string
	WarnOllamaUnavail     string
	WarnAIProviderFailed  string
	WarnAIReviewFailed    string

	// Pipeline
	AnalyzingAI string
	AISkipped   string

	// Cluster
	ClusterHeader        string
	ClusterNoRisk        string
	ClusterSources       string
	ClusterSourcesLblFmt string // "   %s: %s | Findings: %d"
	ClusterEntryFmt      string // "%s Cluster #%d: %s (risk: %.0f, %s)"

	// Severity
	SevCritical string
	SevHigh     string
	SevMedium   string
	SevLow      string
	SevInfo     string

	// Output — section headers shared between printFull and renderMarkdown
	LblAIExplanation string
	LblRisks         string
	LblSuggestions   string
	LblExitCode      string
	LblFindings      string // used in "(%d findings)" / "(%d achados)"
	LblResources     string // "Resources analyzed" / "Recursos analisados"
	LblTotalFindings string // "Total findings" / "Total de achados"
	LblAIQuality     string // "AI analysis" / "Análise IA"

	// History formatter
	HistoryTitle   string // "Scan History — %s" / "Histórico de Scans — %s"
	HistoryNoScans string // "No scans found." / "Nenhum scan encontrado."
	HistoryColDate string // "Date" / "Data"
	TrendTitle     string // "Trend — %s (last %d scans)" / "Tendência — %s (últimos %d scans)"
	TrendNoData    string // "No data for trend." / "Nenhum dado para tendência."
	CompareTitle   string // "Comparison — %s" / "Comparação — %s"
	CompareColNow  string // "Now" / "Agora"

	// Fix
	FixEffort           string // "Effort" / "Esforço"
	FixActionApply      string // "Apply" / "Aplicar"
	FixActionReject     string // "Reject" / "Rejeitar"
	FixActionSkip       string // "Skip" / "Pular"
	FixActionQuit       string // "Quit" / "Sair"
	FixAppliedTo        string // "Applied to" / "Aplicado em"
	FixRejected         string // "Rejected" / "Rejeitado"
	FixSkipped          string // "Skipped" / "Ignorado"
	FixSessionEnded     string // "Session ended." / "Sessão encerrada."
	FixApplyError       string // "Error applying fix" / "Erro ao aplicar"
	FixCannotLocateFile string // "Could not locate .tf file — copy the HCL manually." / "Não foi possível localizar o arquivo .tf — copie o HCL manualmente."
	FixCoveredByBatch   string // "covered by previous batch on the same resource — no new application required" / "coberto pelo batch anterior no mesmo recurso — não requer nova aplicação"
	FixAdvisoryHeader   string // "Points of attention (manual review recommended):" / "Pontos de atenção (revisão manual recomendada):"
	FixFileNotFound     string // "⚠ .tf file not found in %s" / "⚠ arquivo .tf não localizado em %s"
	FixNoChanges        string // "(no changes detected)" / "(sem alterações detectadas)"
	FixSummaryApplied   string // "applied" / "aplicado(s)"
	FixSummaryRejected  string // "rejected" / "rejeitado(s)"
	FixSummarySkipped   string // "skipped" / "ignorado(s)"
	FixSummaryHint      string // "Tip: run %s to validate modified files." / "Dica: execute %s para verificar os arquivos modificados."
	FixHCLUnbalanced    string // "generated HCL has unbalanced delimiters ({}, [] or ()) — fix rejected to avoid file corruption" / pt-BR equiv

	// Status
	StatusOnProject    string // "On project:" / "No projeto:"
	StatusLastScan     string // "Last scan:" / "Último scan:"
	StatusOpenFindings string // "Open findings:" / "Achados abertos:"
}

// active holds the currently selected language. 0 = EN, 1 = BR.
var active atomic.Int32

var en = Messages{
	WarnImportFailed:      "WARNING: Failed to import findings from %s: %v",
	WarnAIProviderUnavail: "WARNING: AI provider for %s not available: %v",
	WarnExplainUnavail:    "WARNING: AI provider for --explain not available: %v",
	WarnExplainFailed:     "WARNING: AI explanation failed: %v",
	WarnPromptsNotFound:   "WARNING: Prompts directory not found. Skipping AI analysis.",
	WarnPromptsLoadFailed: "WARNING: Failed to load prompts (%v). Skipping AI analysis.",
	WarnOllamaUnavail:     "WARNING: Ollama not available (%v). Skipping AI analysis.",
	WarnAIProviderFailed:  "WARNING: AI provider %q not available (%v). Skipping AI analysis.",
	WarnAIReviewFailed:    "WARNING: AI review failed (%v). Continuing with scanner findings only.",

	AnalyzingAI: "Analyzing infrastructure with AI...",
	AISkipped:   "AI analysis skipped",

	ClusterHeader:        "Risk Clusters: %s",
	ClusterNoRisk:        "No risk clusters identified.",
	ClusterSources:       "Sources",
	ClusterSourcesLblFmt: "   %s: %s | Findings: %d",
	ClusterEntryFmt:      "%s Cluster #%d: %s (risk: %.0f, %s)",

	SevCritical: "CRITICAL",
	SevHigh:     "HIGH",
	SevMedium:   "MEDIUM",
	SevLow:      "LOW",
	SevInfo:     "INFO",

	LblAIExplanation: "AI Explanation",
	LblRisks:         "Risks",
	LblSuggestions:   "Suggestions",
	LblExitCode:      "Exit code",
	LblFindings:      "findings",
	LblResources:     "Resources analyzed",
	LblTotalFindings: "Total findings",
	LblAIQuality:     "AI analysis",

	HistoryTitle:   "Scan History — %s",
	HistoryNoScans: "No scans found.",
	HistoryColDate: "Date",
	TrendTitle:     "Trend — %s (last %d scans)",
	TrendNoData:    "No data for trend.",
	CompareTitle:   "Comparison — %s",
	CompareColNow:  "Now",

	FixEffort:           "Effort",
	FixActionApply:      "Apply",
	FixActionReject:     "Reject",
	FixActionSkip:       "Skip",
	FixActionQuit:       "Quit",
	FixAppliedTo:        "Applied to",
	FixRejected:         "Rejected",
	FixSkipped:          "Skipped",
	FixSessionEnded:     "Session ended.",
	FixApplyError:       "Error applying fix",
	FixCannotLocateFile: "Could not locate .tf file — copy the HCL manually.",
	FixCoveredByBatch:   "covered by previous batch on the same resource — no new application required",
	FixAdvisoryHeader:   "Points of attention (manual review recommended):",
	FixFileNotFound:     "⚠ .tf file not found in %s",
	FixNoChanges:        "(no changes detected)",
	FixSummaryApplied:   "applied",
	FixSummaryRejected:  "rejected",
	FixSummarySkipped:   "skipped",
	FixSummaryHint:      "Tip: run %s to validate modified files.",
	FixHCLUnbalanced:    "generated HCL has unbalanced delimiters ({}, [] or ()) — fix rejected to avoid file corruption",

	StatusOnProject:    "On project:",
	StatusLastScan:     "Last scan:",
	StatusOpenFindings: "Open findings:",
}

var br = Messages{
	WarnImportFailed:      "AVISO: Falha ao importar achados de %s: %v",
	WarnAIProviderUnavail: "AVISO: Provider de IA para %s não disponível: %v",
	WarnExplainUnavail:    "AVISO: Provider de IA para --explain não disponível: %v",
	WarnExplainFailed:     "AVISO: Explicação IA falhou: %v",
	WarnPromptsNotFound:   "AVISO: Diretório de prompts não encontrado. Ignorando análise IA.",
	WarnPromptsLoadFailed: "AVISO: Falha ao carregar prompts (%v). Ignorando análise IA.",
	WarnOllamaUnavail:     "AVISO: Ollama não disponível (%v). Ignorando análise IA.",
	WarnAIProviderFailed:  "AVISO: Provider de IA %q não disponível (%v). Ignorando análise IA.",
	WarnAIReviewFailed:    "AVISO: Revisão IA falhou (%v). Continuando apenas com achados do scanner.",

	AnalyzingAI: "Analisando infraestrutura com IA...",
	AISkipped:   "Análise IA ignorada",

	ClusterHeader:        "Clusters de Risco: %s",
	ClusterNoRisk:        "Nenhum cluster de risco identificado.",
	ClusterSources:       "Fontes",
	ClusterSourcesLblFmt: "   %s: %s | Achados: %d",
	ClusterEntryFmt:      "%s Cluster #%d: %s (risco: %.0f, %s)",

	SevCritical: "CRÍTICO",
	SevHigh:     "ALTO",
	SevMedium:   "MÉDIO",
	SevLow:      "BAIXO",
	SevInfo:     "INFO",

	LblAIExplanation: "Explicação IA",
	LblRisks:         "Riscos",
	LblSuggestions:   "Sugestões",
	LblExitCode:      "Código de saída",
	LblFindings:      "achados",
	LblResources:     "Recursos analisados",
	LblTotalFindings: "Total de achados",
	LblAIQuality:     "Análise IA",

	HistoryTitle:   "Histórico de Scans — %s",
	HistoryNoScans: "Nenhum scan encontrado.",
	HistoryColDate: "Data",
	TrendTitle:     "Tendência — %s (últimos %d scans)",
	TrendNoData:    "Nenhum dado para tendência.",
	CompareTitle:   "Comparação — %s",
	CompareColNow:  "Agora",

	FixEffort:           "Esforço",
	FixActionApply:      "Aplicar",
	FixActionReject:     "Rejeitar",
	FixActionSkip:       "Pular",
	FixActionQuit:       "Sair",
	FixAppliedTo:        "Aplicado em",
	FixRejected:         "Rejeitado",
	FixSkipped:          "Ignorado",
	FixSessionEnded:     "Sessão encerrada.",
	FixApplyError:       "Erro ao aplicar",
	FixCannotLocateFile: "Não foi possível localizar o arquivo .tf — copie o HCL manualmente.",
	FixCoveredByBatch:   "coberto pelo batch anterior no mesmo recurso — não requer nova aplicação",
	FixAdvisoryHeader:   "Pontos de atenção (revisão manual recomendada):",
	FixFileNotFound:     "⚠ arquivo .tf não localizado em %s",
	FixNoChanges:        "(sem alterações detectadas)",
	FixSummaryApplied:   "aplicado(s)",
	FixSummaryRejected:  "rejeitado(s)",
	FixSummarySkipped:   "ignorado(s)",
	FixSummaryHint:      "Dica: execute %s para verificar os arquivos modificados.",
	FixHCLUnbalanced:    "HCL gerado tem delimitadores desbalanceados ({}, [] ou ()) — fix rejeitado para evitar corrupção do arquivo",

	StatusOnProject:    "No projeto:",
	StatusLastScan:     "Último scan:",
	StatusOpenFindings: "Achados abertos:",
}

// SetLang selects the active language. Use "pt-BR" for Portuguese.
func SetLang(lang string) {
	if lang == "pt-BR" {
		active.Store(1)
	} else {
		active.Store(0)
	}
}

// IsBR returns true if the active language is Brazilian Portuguese.
func IsBR() bool {
	return active.Load() == 1
}

// T returns the active message set.
func T() *Messages {
	if active.Load() == 1 {
		return &br
	}
	return &en
}

// SevLabel translates a severity string (CRITICAL, HIGH, etc.) to the active language.
func SevLabel(sev string) string {
	m := T()
	switch sev {
	case "CRITICAL":
		return m.SevCritical
	case "HIGH":
		return m.SevHigh
	case "MEDIUM":
		return m.SevMedium
	case "LOW":
		return m.SevLow
	case "INFO":
		return m.SevInfo
	default:
		return sev
	}
}
