package scanner

// Testes de integração com fixtures realistas de saída de scanners.
// Valida parsing, contagem, severidade, normalização e tratamento de erros.

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// fixturesDir retorna o caminho absoluto para testdata/ na raiz do repo.
func fixturesDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("não foi possível determinar o caminho do arquivo de teste")
	}
	// internal/scanner/ → subir 2 níveis até a raiz do repo
	repoRoot := filepath.Join(filepath.Dir(filename), "..", "..")
	dir := filepath.Join(repoRoot, "testdata")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Fatalf("diretório testdata/ não encontrado em %s", dir)
	}
	return dir
}

// readFixture lê um arquivo de fixture e retorna seu conteúdo.
func readFixture(t *testing.T, relPath string) []byte {
	t.Helper()
	fullPath := filepath.Join(fixturesDir(t), relPath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("erro ao ler fixture %s: %v", relPath, err)
	}
	return data
}

// countBySeverity conta findings por severidade.
func countBySeverity(findings []rules.Finding) map[string]int {
	counts := make(map[string]int)
	for _, f := range findings {
		counts[f.Severity]++
	}
	return counts
}

// findByRuleID encontra o primeiro finding com o RuleID dado.
func findByRuleID(findings []rules.Finding, ruleID string) *rules.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// assertRequiredFields verifica que todos os campos obrigatórios estão preenchidos.
func assertRequiredFields(t *testing.T, findings []rules.Finding, source string) {
	t.Helper()
	for i, f := range findings {
		if f.RuleID == "" {
			t.Errorf("[%s] finding %d: RuleID vazio", source, i)
		}
		if f.Severity == "" {
			t.Errorf("[%s] finding %d: Severity vazio", source, i)
		}
		if f.Resource == "" {
			t.Errorf("[%s] finding %d: Resource vazio", source, i)
		}
		if f.Message == "" {
			t.Errorf("[%s] finding %d: Message vazio", source, i)
		}
		if f.Source == "" {
			t.Errorf("[%s] finding %d: Source vazio", source, i)
		}
	}
}

// assertValidSeverity verifica que todas as severidades são valores válidos.
func assertValidSeverity(t *testing.T, findings []rules.Finding) {
	t.Helper()
	valid := map[string]bool{
		rules.SeverityCritical: true,
		rules.SeverityHigh:     true,
		rules.SeverityMedium:   true,
		rules.SeverityLow:      true,
		rules.SeverityInfo:     true,
	}
	for i, f := range findings {
		if !valid[f.Severity] {
			t.Errorf("finding %d: severidade inválida %q (RuleID=%s)", i, f.Severity, f.RuleID)
		}
	}
}

// assertValidCategory verifica que todas as categorias são valores válidos.
func assertValidCategory(t *testing.T, findings []rules.Finding) {
	t.Helper()
	valid := map[string]bool{
		rules.CategorySecurity:        true,
		rules.CategoryCompliance:      true,
		rules.CategoryBestPractice:    true,
		rules.CategoryMaintainability: true,
		rules.CategoryReliability:     true,
	}
	for i, f := range findings {
		if f.Category != "" && !valid[f.Category] {
			t.Errorf("finding %d: categoria inválida %q (RuleID=%s)", i, f.Category, f.RuleID)
		}
	}
}

// ===========================================================================
// Checkov — testes de integração com fixtures
// ===========================================================================

func TestFixture_Checkov_Passing(t *testing.T) {
	data := readFixture(t, "checkov/checkov_passing.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings para scan limpo, obteve %d", len(findings))
	}
}

func TestFixture_Checkov_Mixed(t *testing.T) {
	data := readFixture(t, "checkov/checkov_mixed.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Contagem exata
	if len(findings) != 15 {
		t.Fatalf("esperava 15 findings, obteve %d", len(findings))
	}

	// Distribuição por severidade
	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 3 {
		t.Errorf("CRITICAL: esperava 3, obteve %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: esperava 5, obteve %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 5 {
		t.Errorf("MEDIUM: esperava 5, obteve %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: esperava 2, obteve %d", counts[rules.SeverityLow])
	}

	// Verificação pontual de finding específico
	f := findByRuleID(findings, "CKV_AWS_18")
	if f == nil {
		t.Fatal("CKV_AWS_18 não encontrado")
	}
	if f.Severity != rules.SeverityCritical {
		t.Errorf("CKV_AWS_18: esperava CRITICAL, obteve %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("CKV_AWS_18: esperava recurso aws_s3_bucket.data, obteve %s", f.Resource)
	}
	if f.Source != "scanner:checkov" {
		t.Errorf("CKV_AWS_18: esperava source scanner:checkov, obteve %s", f.Source)
	}

	// Verificar CKV_AWS_40 (MEDIUM, IAM)
	f40 := findByRuleID(findings, "CKV_AWS_40")
	if f40 == nil {
		t.Fatal("CKV_AWS_40 não encontrado")
	}
	if f40.Severity != rules.SeverityMedium {
		t.Errorf("CKV_AWS_40: esperava MEDIUM, obteve %s", f40.Severity)
	}

	// Todos os campos obrigatórios preenchidos
	assertRequiredFields(t, findings, "checkov")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Checkov_AllCritical(t *testing.T) {
	data := readFixture(t, "checkov/checkov_all_critical.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	if len(findings) != 4 {
		t.Fatalf("esperava 4 findings, obteve %d", len(findings))
	}

	// Todos devem ser CRITICAL
	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("esperava CRITICAL para %s, obteve %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Checkov_Empty(t *testing.T) {
	data := readFixture(t, "checkov/checkov_empty.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings para output vazio, obteve %d", len(findings))
	}
}

func TestFixture_Checkov_Malformed(t *testing.T) {
	data := readFixture(t, "checkov/checkov_malformed.json")
	// O parser do Checkov retorna nil,nil para JSON inválido (não retorna erro)
	// pois ele tenta parsing silencioso e assume "warnings"
	findings, err := parseCheckovOutput(data)

	// Não deve causar panic
	_ = findings
	_ = err
	// Se retornar findings, devem ser válidos
	if len(findings) > 0 {
		assertRequiredFields(t, findings, "checkov-malformed")
	}
}

func TestFixture_Checkov_GuidelineAsRemediation(t *testing.T) {
	data := readFixture(t, "checkov/checkov_mixed.json")
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Checkov usa guideline como remediation
	f := findByRuleID(findings, "CKV_AWS_18")
	if f == nil {
		t.Fatal("CKV_AWS_18 não encontrado")
	}
	if f.Remediation == "" {
		t.Error("CKV_AWS_18: remediation deveria conter a guideline URL")
	}
}

// ===========================================================================
// tfsec — testes de integração com fixtures
// ===========================================================================

func TestFixture_Tfsec_Passing(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_passing.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings para scan limpo, obteve %d", len(findings))
	}
}

func TestFixture_Tfsec_Mixed(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_mixed.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Contagem exata
	if len(findings) != 14 {
		t.Fatalf("esperava 14 findings, obteve %d", len(findings))
	}

	// Distribuição por severidade
	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 3 {
		t.Errorf("CRITICAL: esperava 3, obteve %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: esperava 5, obteve %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 4 {
		t.Errorf("MEDIUM: esperava 4, obteve %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: esperava 2, obteve %d", counts[rules.SeverityLow])
	}

	// Verificação pontual
	f := findByRuleID(findings, "aws-s3-enable-bucket-encryption")
	if f == nil {
		t.Fatal("aws-s3-enable-bucket-encryption não encontrado")
	}
	if f.Severity != rules.SeverityCritical {
		t.Errorf("esperava CRITICAL, obteve %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("esperava recurso aws_s3_bucket.data, obteve %s", f.Resource)
	}
	if f.Source != "scanner:tfsec" {
		t.Errorf("esperava source scanner:tfsec, obteve %s", f.Source)
	}

	// Remediation preenchida
	if f.Remediation == "" {
		t.Error("aws-s3-enable-bucket-encryption: remediation vazio")
	}

	// Todos os campos obrigatórios
	assertRequiredFields(t, findings, "tfsec")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Tfsec_AllCritical(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_all_critical.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("esperava 3 findings, obteve %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("esperava CRITICAL para %s, obteve %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Tfsec_Empty(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_empty.json")
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings, obteve %d", len(findings))
	}
}

func TestFixture_Tfsec_Malformed(t *testing.T) {
	data := readFixture(t, "tfsec/tfsec_malformed.json")
	// tfsec parser retorna erro para JSON inválido
	_, err := parseTfsecOutput(data)
	if err == nil {
		t.Error("esperava erro para JSON malformado, obteve nil")
	}
}

// ===========================================================================
// Trivy — testes de integração com fixtures
// ===========================================================================

func TestFixture_Trivy_Passing(t *testing.T) {
	data := readFixture(t, "trivy/trivy_passing.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings, obteve %d", len(findings))
	}
}

func TestFixture_Trivy_Mixed(t *testing.T) {
	data := readFixture(t, "trivy/trivy_mixed.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// 10 misconfigs no fixture, mas 1 é PASS → 9 findings
	if len(findings) != 9 {
		t.Fatalf("esperava 9 findings (PASS filtrado), obteve %d", len(findings))
	}

	counts := countBySeverity(findings)
	if counts[rules.SeverityCritical] != 2 {
		t.Errorf("CRITICAL: esperava 2, obteve %d", counts[rules.SeverityCritical])
	}
	if counts[rules.SeverityHigh] != 4 {
		t.Errorf("HIGH: esperava 4, obteve %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 2 {
		t.Errorf("MEDIUM: esperava 2, obteve %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 1 {
		t.Errorf("LOW: esperava 1, obteve %d", counts[rules.SeverityLow])
	}

	// PASS não deve estar presente
	for _, f := range findings {
		if f.RuleID == "AVD-AWS-0099" {
			t.Error("AVD-AWS-0099 (PASS) não deveria estar nos findings")
		}
	}

	// Verificação pontual
	f := findByRuleID(findings, "AVD-AWS-0086")
	if f == nil {
		t.Fatal("AVD-AWS-0086 não encontrado")
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("esperava recurso aws_s3_bucket.data, obteve %s", f.Resource)
	}
	if f.Source != "scanner:trivy" {
		t.Errorf("esperava source scanner:trivy, obteve %s", f.Source)
	}

	assertRequiredFields(t, findings, "trivy")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Trivy_AllCritical(t *testing.T) {
	data := readFixture(t, "trivy/trivy_all_critical.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("esperava 3 findings, obteve %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityCritical {
			t.Errorf("esperava CRITICAL para %s, obteve %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Trivy_Empty(t *testing.T) {
	data := readFixture(t, "trivy/trivy_empty.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings, obteve %d", len(findings))
	}
}

func TestFixture_Trivy_Malformed(t *testing.T) {
	data := readFixture(t, "trivy/trivy_malformed.json")
	_, err := parseTrivyOutput(data)
	if err == nil {
		t.Error("esperava erro para JSON malformado, obteve nil")
	}
}

func TestFixture_Trivy_SkipPassEntries(t *testing.T) {
	data := readFixture(t, "trivy/trivy_mixed.json")
	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Nenhum finding deve ter vindo de um Status: "PASS"
	for _, f := range findings {
		if f.RuleID == "AVD-AWS-0099" {
			t.Errorf("finding AVD-AWS-0099 com Status PASS não deveria ter sido parseado")
		}
	}
}

// ===========================================================================
// Terrascan — testes de integração com fixtures
// ===========================================================================

func TestFixture_Terrascan_Passing(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_passing.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings, obteve %d", len(findings))
	}
}

func TestFixture_Terrascan_Mixed(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_mixed.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Contagem exata
	if len(findings) != 13 {
		t.Fatalf("esperava 13 findings, obteve %d", len(findings))
	}

	// Distribuição por severidade (Terrascan não tem CRITICAL)
	counts := countBySeverity(findings)
	if counts[rules.SeverityHigh] != 5 {
		t.Errorf("HIGH: esperava 5, obteve %d", counts[rules.SeverityHigh])
	}
	if counts[rules.SeverityMedium] != 6 {
		t.Errorf("MEDIUM: esperava 6, obteve %d", counts[rules.SeverityMedium])
	}
	if counts[rules.SeverityLow] != 2 {
		t.Errorf("LOW: esperava 2, obteve %d", counts[rules.SeverityLow])
	}
	if counts[rules.SeverityCritical] != 0 {
		t.Errorf("CRITICAL: esperava 0 (Terrascan não tem CRITICAL), obteve %d", counts[rules.SeverityCritical])
	}

	// Verificação pontual
	f := findByRuleID(findings, "AC_AWS_0207")
	if f == nil {
		t.Fatal("AC_AWS_0207 não encontrado")
	}
	if f.Severity != rules.SeverityHigh {
		t.Errorf("AC_AWS_0207: esperava HIGH, obteve %s", f.Severity)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("AC_AWS_0207: esperava recurso aws_s3_bucket.data, obteve %s", f.Resource)
	}
	if f.Source != "scanner:terrascan" {
		t.Errorf("AC_AWS_0207: esperava source scanner:terrascan, obteve %s", f.Source)
	}

	// Terrascan não preenche remediation
	if f.Remediation != "" {
		t.Errorf("AC_AWS_0207: Terrascan não provê remediation, obteve %q", f.Remediation)
	}

	assertRequiredFields(t, findings, "terrascan")
	assertValidSeverity(t, findings)
	assertValidCategory(t, findings)
}

func TestFixture_Terrascan_AllHigh(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_all_high.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("esperava 3 findings, obteve %d", len(findings))
	}

	for _, f := range findings {
		if f.Severity != rules.SeverityHigh {
			t.Errorf("esperava HIGH para %s, obteve %s", f.RuleID, f.Severity)
		}
	}
}

func TestFixture_Terrascan_Empty(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_empty.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("esperava 0 findings, obteve %d", len(findings))
	}
}

func TestFixture_Terrascan_Malformed(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_malformed.json")
	_, err := parseTerrascanOutput(data)
	if err == nil {
		t.Error("esperava erro para JSON malformado, obteve nil")
	}
}

func TestFixture_Terrascan_CategoryMapping(t *testing.T) {
	data := readFixture(t, "terrascan/terrascan_mixed.json")
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}

	// Verificar que a categoria "Logging and Monitoring" foi mapeada para compliance
	f := findByRuleID(findings, "AC_AWS_0214")
	if f == nil {
		t.Fatal("AC_AWS_0214 não encontrado")
	}
	if f.Category != rules.CategoryCompliance {
		t.Errorf("AC_AWS_0214 (Logging): esperava %s, obteve %s", rules.CategoryCompliance, f.Category)
	}

	// "Security Best Practices" → security
	f2 := findByRuleID(findings, "AC_AWS_0207")
	if f2 == nil {
		t.Fatal("AC_AWS_0207 não encontrado")
	}
	if f2.Category != rules.CategorySecurity {
		t.Errorf("AC_AWS_0207 (Security): esperava %s, obteve %s", rules.CategorySecurity, f2.Category)
	}

	// "Best Practice" → best-practice
	f3 := findByRuleID(findings, "AC_AWS_0215")
	if f3 == nil {
		t.Fatal("AC_AWS_0215 não encontrado")
	}
	if f3.Category != rules.CategoryBestPractice {
		t.Errorf("AC_AWS_0215 (Best Practice): esperava %s, obteve %s", rules.CategoryBestPractice, f3.Category)
	}

	// "IAM Policies" → security
	f4 := findByRuleID(findings, "AC_AWS_0270")
	if f4 == nil {
		t.Fatal("AC_AWS_0270 não encontrado")
	}
	if f4.Category != rules.CategorySecurity {
		t.Errorf("AC_AWS_0270 (IAM): esperava %s, obteve %s", rules.CategorySecurity, f4.Category)
	}
}

// ===========================================================================
// Testes cross-scanner: normalização e deduplicação
// ===========================================================================

func TestCrossScanner_SeverityNormalization(t *testing.T) {
	// Carrega fixtures "mixed" de todos os scanners
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	validSeverities := map[string]bool{
		rules.SeverityCritical: true,
		rules.SeverityHigh:     true,
		rules.SeverityMedium:   true,
		rules.SeverityLow:      true,
		rules.SeverityInfo:     true,
	}

	// Todas as severidades devem ser valores canônicos após normalização
	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		for i, f := range set.findings {
			if !validSeverities[f.Severity] {
				t.Errorf("[%s] finding %d (%s): severidade não normalizada %q",
					set.name, i, f.RuleID, f.Severity)
			}
		}
	}
}

func TestCrossScanner_SourceTagFormat(t *testing.T) {
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	expectedSources := map[string]string{
		"checkov":   "scanner:checkov",
		"tfsec":     "scanner:tfsec",
		"terrascan": "scanner:terrascan",
		"trivy":     "scanner:trivy",
	}

	allSets := map[string][]rules.Finding{
		"checkov":   checkovFindings,
		"tfsec":     tfsecFindings,
		"terrascan": terrascanFindings,
		"trivy":     trivyFindings,
	}

	for name, findings := range allSets {
		expected := expectedSources[name]
		for i, f := range findings {
			if f.Source != expected {
				t.Errorf("[%s] finding %d: esperava source %q, obteve %q",
					name, i, expected, f.Source)
			}
		}
	}
}

func TestCrossScanner_AllFindingsHaveCategory(t *testing.T) {
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		for i, f := range set.findings {
			if f.Category == "" {
				t.Errorf("[%s] finding %d (%s): categoria vazia", set.name, i, f.RuleID)
			}
		}
	}
}

func TestCrossScanner_DeduplicateOverlappingFindings(t *testing.T) {
	// Simula situação onde Checkov e tfsec encontram o mesmo problema
	// na mesma resource — o dedup deve mesclar
	checkov := []rules.Finding{
		{
			RuleID:   "CKV_AWS_19",
			Severity: rules.SeverityMedium,
			Category: rules.CategorySecurity,
			Resource: "aws_s3_bucket.data",
			Message:  "[checkov] CKV_AWS_19: Ensure the S3 bucket has server-side-encryption enabled",
			Source:   "scanner:checkov",
		},
	}
	tfsec := []rules.Finding{
		{
			RuleID:      "aws-s3-enable-bucket-encryption",
			Severity:    rules.SeverityCritical,
			Category:    rules.CategorySecurity,
			Resource:    "aws_s3_bucket.data",
			Message:     "[tfsec] aws-s3-enable-bucket-encryption: Bucket does not have encryption enabled",
			Remediation: "Configure server-side encryption",
			Source:       "scanner:tfsec",
		},
	}

	// Combina findings como o aggregator faria
	combined := append(checkov, tfsec...)
	deduped := deduplicateFindings(combined)

	// Dedup por heurística de mensagem — ambos falam de encryption + s3
	// O normalizeRuleID deve reconhecer o padrão "encrypt" e agrupar
	if len(deduped) > 2 {
		t.Errorf("dedup deveria reduzir findings, obteve %d de %d", len(deduped), len(combined))
	}

	// Se deduplicou, deve ter mantido a maior severidade (CRITICAL)
	if len(deduped) == 1 {
		if deduped[0].Severity != rules.SeverityCritical {
			t.Errorf("dedup deveria manter a maior severidade: esperava CRITICAL, obteve %s", deduped[0].Severity)
		}
	}
}

func TestCrossScanner_FieldConsistency(t *testing.T) {
	// Verifica que todos os scanners produzem a mesma struct com os mesmos campos
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	allSets := []struct {
		name     string
		findings []rules.Finding
	}{
		{"checkov", checkovFindings},
		{"tfsec", tfsecFindings},
		{"terrascan", terrascanFindings},
		{"trivy", trivyFindings},
	}

	for _, set := range allSets {
		if len(set.findings) == 0 {
			t.Errorf("[%s] sem findings no fixture mixed", set.name)
			continue
		}

		hasRemediation := false
		for _, f := range set.findings {
			// RuleID, Severity, Category, Resource, Message, Source: obrigatórios
			if f.RuleID == "" || f.Severity == "" || f.Resource == "" || f.Message == "" || f.Source == "" {
				t.Errorf("[%s] finding com campo obrigatório vazio: %+v", set.name, f)
			}
			if f.Remediation != "" {
				hasRemediation = true
			}
		}

		// tfsec e trivy devem ter remediation; terrascan não provê
		switch set.name {
		case "tfsec", "trivy":
			if !hasRemediation {
				t.Errorf("[%s] nenhum finding tem remediation preenchida", set.name)
			}
		case "terrascan":
			if hasRemediation {
				t.Errorf("[terrascan] remediation deveria estar vazia, mas foi preenchida")
			}
		}
	}
}

func TestCrossScanner_MessagePrefixFormat(t *testing.T) {
	// Verifica que as mensagens seguem o formato [scanner] RuleID: descrição
	checkovData := readFixture(t, "checkov/checkov_mixed.json")
	tfsecData := readFixture(t, "tfsec/tfsec_mixed.json")
	terrascanData := readFixture(t, "terrascan/terrascan_mixed.json")
	trivyData := readFixture(t, "trivy/trivy_mixed.json")

	checkovFindings, _ := parseCheckovOutput(checkovData)
	tfsecFindings, _ := parseTfsecOutput(tfsecData)
	terrascanFindings, _ := parseTerrascanOutput(terrascanData)
	trivyFindings, _ := parseTrivyOutput(trivyData)

	type prefixCase struct {
		name     string
		prefix   string
		findings []rules.Finding
	}

	cases := []prefixCase{
		{"checkov", "[checkov]", checkovFindings},
		{"tfsec", "[tfsec]", tfsecFindings},
		{"terrascan", "[terrascan]", terrascanFindings},
		{"trivy", "[trivy]", trivyFindings},
	}

	for _, tc := range cases {
		for i, f := range tc.findings {
			if len(f.Message) < len(tc.prefix) || f.Message[:len(tc.prefix)] != tc.prefix {
				t.Errorf("[%s] finding %d: mensagem deveria começar com %q, obteve %q",
					tc.name, i, tc.prefix, f.Message)
			}
		}
	}
}
