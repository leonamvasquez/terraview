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
