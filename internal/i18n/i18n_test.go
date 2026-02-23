package i18n

import "testing"

func TestDefaultIsEN(t *testing.T) {
	SetLang("")
	if IsBR() {
		t.Error("default should be EN")
	}
	msgs := T()
	if msgs.SevCritical != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", msgs.SevCritical)
	}
}

func TestSetLangBR(t *testing.T) {
	SetLang("pt-BR")
	defer SetLang("")
	if !IsBR() {
		t.Error("should be BR")
	}
	msgs := T()
	if msgs.SevCritical != "CRÍTICO" {
		t.Errorf("expected CRÍTICO, got %s", msgs.SevCritical)
	}
	if msgs.ClusterNoRisk != "Nenhum cluster de risco identificado." {
		t.Errorf("wrong BR cluster string: %s", msgs.ClusterNoRisk)
	}
}

func TestSetLangEN(t *testing.T) {
	SetLang("pt-BR")
	SetLang("en")
	if IsBR() {
		t.Error("should be EN after switching back")
	}
	msgs := T()
	if msgs.SevHigh != "HIGH" {
		t.Errorf("expected HIGH, got %s", msgs.SevHigh)
	}
}

func TestAllBRFieldsNonEmpty(t *testing.T) {
	SetLang("pt-BR")
	defer SetLang("")
	msgs := T()
	checks := map[string]string{
		"WarnImportFailed":      msgs.WarnImportFailed,
		"WarnAIProviderUnavail": msgs.WarnAIProviderUnavail,
		"WarnExplainUnavail":    msgs.WarnExplainUnavail,
		"WarnExplainFailed":     msgs.WarnExplainFailed,
		"WarnPromptsNotFound":   msgs.WarnPromptsNotFound,
		"WarnPromptsLoadFailed": msgs.WarnPromptsLoadFailed,
		"WarnOllamaUnavail":     msgs.WarnOllamaUnavail,
		"WarnAIProviderFailed":  msgs.WarnAIProviderFailed,
		"WarnAIReviewFailed":    msgs.WarnAIReviewFailed,
		"AnalyzingAI":           msgs.AnalyzingAI,
		"AISkipped":             msgs.AISkipped,
		"ClusterHeader":         msgs.ClusterHeader,
		"ClusterNoRisk":         msgs.ClusterNoRisk,
		"ClusterSources":        msgs.ClusterSources,
		"SevCritical":           msgs.SevCritical,
		"SevHigh":               msgs.SevHigh,
		"SevMedium":             msgs.SevMedium,
		"SevLow":                msgs.SevLow,
	}
	for field, val := range checks {
		if val == "" {
			t.Errorf("BR message %s is empty", field)
		}
	}
}

func TestNoENStringInBR(t *testing.T) {
	SetLang("pt-BR")
	defer SetLang("")
	msgs := T()
	if msgs.WarnImportFailed == en.WarnImportFailed {
		t.Error("BR WarnImportFailed should differ from EN")
	}
	if msgs.ClusterNoRisk == en.ClusterNoRisk {
		t.Error("BR ClusterNoRisk should differ from EN")
	}
}
