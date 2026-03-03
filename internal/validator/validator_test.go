package validator

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/topology"
)

// mockGraph cria um grafo de topologia com 8 recursos para testes.
func mockGraph() *topology.Graph {
	return &topology.Graph{
		Nodes: []topology.Node{
			{Address: "aws_s3_bucket.data", Type: "aws_s3_bucket", Name: "data", Action: "create", Provider: "aws"},
			{Address: "aws_s3_bucket.logs", Type: "aws_s3_bucket", Name: "logs", Action: "create", Provider: "aws"},
			{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Provider: "aws"},
			{Address: "aws_security_group.web_sg", Type: "aws_security_group", Name: "web_sg", Action: "create", Provider: "aws"},
			{Address: "aws_iam_role.lambda_exec", Type: "aws_iam_role", Name: "lambda_exec", Action: "create", Provider: "aws"},
			{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Action: "create", Provider: "aws"},
			{Address: "aws_subnet.private", Type: "aws_subnet", Name: "private", Action: "create", Provider: "aws"},
			{Address: "module.vpc.aws_nat_gateway.this", Type: "aws_nat_gateway", Name: "this", Action: "create", Provider: "aws"},
		},
		Edges: []topology.Edge{
			{From: "aws_instance.web", To: "aws_security_group.web_sg", Via: "security_groups"},
			{From: "aws_instance.web", To: "aws_subnet.private", Via: "subnet_id"},
			{From: "aws_subnet.private", To: "aws_vpc.main", Via: "vpc_id"},
		},
	}
}

// validFinding cria um finding válido para uso em testes.
func validFinding(resource, severity, category, message string) rules.Finding {
	return rules.Finding{
		RuleID:   "AI-TEST-001",
		Severity: severity,
		Category: category,
		Resource: resource,
		Message:  message,
		Source:   "ai/test",
	}
}

func TestValidateAIFindings_TodosValidos(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_instance.web", "MEDIUM", "best-practice", "Instancia sem tags"),
		validFinding("aws_iam_role.lambda_exec", "LOW", "compliance", "Role sem boundary"),
	}

	valid, discarded, report := ValidateAIFindings(findings, graph)

	if len(valid) != 3 {
		t.Errorf("esperado 3 findings validos, obteve %d", len(valid))
	}
	if len(discarded) != 0 {
		t.Errorf("esperado 0 descartados, obteve %d", len(discarded))
	}
	if report.TotalReceived != 3 {
		t.Errorf("esperado TotalReceived=3, obteve %d", report.TotalReceived)
	}
	if report.TotalValid != 3 {
		t.Errorf("esperado TotalValid=3, obteve %d", report.TotalValid)
	}
	if report.TotalDiscard != 0 {
		t.Errorf("esperado TotalDiscard=0, obteve %d", report.TotalDiscard)
	}
}

func TestValidateAIFindings_RecursoInexistente(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_rds_instance.db_prod", "CRITICAL", "security", "DB sem criptografia"),
		validFinding("aws_lambda_function.processor", "MEDIUM", "reliability", "Lambda sem DLQ"),
	}

	valid, discarded, report := ValidateAIFindings(findings, graph)

	if len(valid) != 1 {
		t.Errorf("esperado 1 finding valido, obteve %d", len(valid))
	}
	if len(discarded) != 2 {
		t.Errorf("esperado 2 descartados, obteve %d", len(discarded))
	}
	for _, d := range discarded {
		if d.Reason != ReasonResourceNotFound {
			t.Errorf("esperado motivo '%s', obteve '%s'", ReasonResourceNotFound, d.Reason)
		}
	}
	if report.TotalDiscard != 2 {
		t.Errorf("esperado TotalDiscard=2, obteve %d", report.TotalDiscard)
	}
}

func TestValidateAIFindings_TipoRecursoDivergente(t *testing.T) {
	graph := &topology.Graph{
		Nodes: []topology.Node{
			{Address: "aws_s3_bucket.foo", Type: "aws_s3_bucket_policy", Name: "foo", Action: "create", Provider: "aws"},
			{Address: "aws_instance.web", Type: "aws_instance", Name: "web", Action: "create", Provider: "aws"},
		},
	}

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.foo", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_instance.web", "MEDIUM", "best-practice", "Instancia sem tags"),
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 1 {
		t.Errorf("esperado 1 finding valido, obteve %d", len(valid))
	}
	if len(discarded) != 1 {
		t.Errorf("esperado 1 descartado, obteve %d", len(discarded))
	}
	if len(discarded) > 0 && discarded[0].Reason != ReasonResourceTypeMismatch {
		t.Errorf("esperado motivo '%s', obteve '%s'", ReasonResourceTypeMismatch, discarded[0].Reason)
	}
}

func TestValidateAIFindings_SeveridadeInvalida(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Valido"),
		validFinding("aws_instance.web", "URGENT", "security", "Severidade inventada"),
		validFinding("aws_vpc.main", "EXTREME", "security", "Outra severidade inventada"),
		validFinding("aws_iam_role.lambda_exec", "info", "compliance", "Info minusculo e valido"),
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 2 {
		t.Errorf("esperado 2 findings validos, obteve %d", len(valid))
	}
	if len(discarded) != 2 {
		t.Errorf("esperado 2 descartados, obteve %d", len(discarded))
	}
	for _, d := range discarded {
		if d.Reason != ReasonInvalidSeverity {
			t.Errorf("esperado motivo '%s', obteve '%s'", ReasonInvalidSeverity, d.Reason)
		}
	}
}

func TestValidateAIFindings_Duplicados(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_s3_bucket.data", "MEDIUM", "security", "Bucket sem criptografia"),
		validFinding("aws_s3_bucket.data", "HIGH", "compliance", "Bucket sem criptografia compliance"),
		validFinding("aws_instance.web", "LOW", "best-practice", "Tags ausentes"),
		validFinding("aws_instance.web", "LOW", "best-practice", "Tags ausentes"),
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	// primeiro s3 security, s3 compliance, primeiro instance
	if len(valid) != 3 {
		t.Errorf("esperado 3 findings validos, obteve %d", len(valid))
	}
	if len(discarded) != 2 {
		t.Errorf("esperado 2 descartados, obteve %d", len(discarded))
	}
	for _, d := range discarded {
		if d.Reason != ReasonDuplicate {
			t.Errorf("esperado motivo '%s', obteve '%s'", ReasonDuplicate, d.Reason)
		}
	}
}

func TestValidateAIFindings_CamposVazios(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Valido"),
		{
			RuleID:   "AI-TEST-002",
			Severity: "HIGH",
			Category: "security",
			Resource: "",
			Message:  "Finding sem recurso",
			Source:   "ai/test",
		},
		{
			RuleID:   "AI-TEST-003",
			Severity: "MEDIUM",
			Category: "security",
			Resource: "aws_instance.web",
			Message:  "",
			Source:   "ai/test",
		},
		{
			RuleID:   "AI-TEST-004",
			Severity: "LOW",
			Category: "security",
			Resource: "",
			Message:  "",
			Source:   "ai/test",
		},
		{
			RuleID:   "AI-TEST-005",
			Severity: "LOW",
			Category: "security",
			Resource: "   ",
			Message:  "  ",
			Source:   "ai/test",
		},
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 1 {
		t.Errorf("esperado 1 finding valido, obteve %d", len(valid))
	}
	if len(discarded) != 4 {
		t.Errorf("esperado 4 descartados, obteve %d", len(discarded))
	}
	for _, d := range discarded {
		if d.Reason != ReasonEmptyFields {
			t.Errorf("esperado motivo '%s', obteve '%s'", ReasonEmptyFields, d.Reason)
		}
	}
}

func TestValidateAIFindings_MistoValidoInvalido(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_nonexistent.ghost", "MEDIUM", "security", "Recurso fantasma"),
		validFinding("aws_instance.web", "EXTREME", "security", "Severidade inventada"),
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		{Resource: "", Severity: "HIGH", Category: "security", Message: "Sem recurso", Source: "ai/test"},
		validFinding("aws_vpc.main", "LOW", "best-practice", "VPC sem flow logs"),
		validFinding("aws_security_group.web_sg", "CRITICAL", "security", "SG aberto para 0.0.0.0"),
	}

	valid, discarded, report := ValidateAIFindings(findings, graph)

	if len(valid) != 3 {
		t.Errorf("esperado 3 findings validos, obteve %d", len(valid))
	}
	if len(discarded) != 4 {
		t.Errorf("esperado 4 descartados, obteve %d", len(discarded))
	}
	if report.TotalReceived != 7 {
		t.Errorf("esperado TotalReceived=7, obteve %d", report.TotalReceived)
	}

	validResources := make(map[string]bool)
	for _, v := range valid {
		validResources[v.Resource] = true
	}
	expectedValid := []string{"aws_s3_bucket.data", "aws_vpc.main", "aws_security_group.web_sg"}
	for _, r := range expectedValid {
		if !validResources[r] {
			t.Errorf("esperado recurso '%s' entre os validos", r)
		}
	}

	reasonCounts := make(map[DiscardReason]int)
	for _, d := range discarded {
		reasonCounts[d.Reason]++
	}
	if reasonCounts[ReasonResourceNotFound] != 1 {
		t.Errorf("esperado 1 descarte por recurso inexistente, obteve %d", reasonCounts[ReasonResourceNotFound])
	}
	if reasonCounts[ReasonInvalidSeverity] != 1 {
		t.Errorf("esperado 1 descarte por severidade invalida, obteve %d", reasonCounts[ReasonInvalidSeverity])
	}
	if reasonCounts[ReasonDuplicate] != 1 {
		t.Errorf("esperado 1 descarte por duplicata, obteve %d", reasonCounts[ReasonDuplicate])
	}
	if reasonCounts[ReasonEmptyFields] != 1 {
		t.Errorf("esperado 1 descarte por campos vazios, obteve %d", reasonCounts[ReasonEmptyFields])
	}
}

func TestValidateAIFindings_ListaVazia(t *testing.T) {
	graph := mockGraph()

	valid, discarded, report := ValidateAIFindings(nil, graph)

	if valid != nil {
		t.Errorf("esperado nil para findings validos, obteve %v", valid)
	}
	if discarded != nil {
		t.Errorf("esperado nil para descartados, obteve %v", discarded)
	}
	if report.TotalReceived != 0 {
		t.Errorf("esperado TotalReceived=0, obteve %d", report.TotalReceived)
	}
}

func TestValidateAIFindings_GrafoVazio(t *testing.T) {
	graph := &topology.Graph{}

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia"),
		validFinding("aws_instance.web", "MEDIUM", "best-practice", "Instancia sem tags"),
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 0 {
		t.Errorf("esperado 0 findings validos (grafo vazio), obteve %d", len(valid))
	}
	if len(discarded) != 2 {
		t.Errorf("esperado 2 descartados, obteve %d", len(discarded))
	}
}

func TestValidateAIFindings_RecursoModulo(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("module.vpc.aws_nat_gateway.this", "LOW", "best-practice", "NAT Gateway sem tags"),
	}

	valid, discarded, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 1 {
		t.Errorf("esperado 1 finding valido para recurso de modulo, obteve %d", len(valid))
	}
	if len(discarded) != 0 {
		t.Errorf("esperado 0 descartados, obteve %d", len(discarded))
	}
}

func TestExtractResourceType(t *testing.T) {
	tests := []struct {
		address  string
		expected string
	}{
		{"aws_s3_bucket.my_bucket", "aws_s3_bucket"},
		{"aws_instance.web", "aws_instance"},
		{"module.vpc.aws_subnet.private", "aws_subnet"},
		{"module.vpc.aws_nat_gateway.this", "aws_nat_gateway"},
		{"aws_security_group.web_sg", "aws_security_group"},
		{"", ""},
		{"single_part", ""},
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			got := extractResourceType(tt.address)
			if got != tt.expected {
				t.Errorf("extractResourceType(%q) = %q, esperado %q", tt.address, got, tt.expected)
			}
		})
	}
}

func TestDeduplicationKey(t *testing.T) {
	f1 := validFinding("aws_s3_bucket.data", "HIGH", "security", "Bucket sem criptografia")
	f2 := validFinding("aws_s3_bucket.data", "MEDIUM", "security", "Bucket sem criptografia")
	f3 := validFinding("aws_s3_bucket.data", "HIGH", "compliance", "Bucket sem criptografia")

	if deduplicationKey(f1) != deduplicationKey(f2) {
		t.Error("f1 e f2 deveriam ter a mesma chave de deduplicacao")
	}
	if deduplicationKey(f1) == deduplicationKey(f3) {
		t.Error("f1 e f3 deveriam ter chaves de deduplicacao diferentes")
	}
}

func TestCheckSeverity_CaseInsensitive(t *testing.T) {
	cases := []struct {
		severity string
		valid    bool
	}{
		{"CRITICAL", true},
		{"critical", true},
		{"Critical", true},
		{"HIGH", true},
		{"high", true},
		{"MEDIUM", true},
		{"LOW", true},
		{"INFO", true},
		{"info", true},
		{"URGENT", false},
		{"Warning", false},
		{"", false},
	}

	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			f := validFinding("aws_s3_bucket.data", tc.severity, "security", "Test")
			reason, _ := checkSeverity(f)
			isValid := reason == ""
			if isValid != tc.valid {
				t.Errorf("checkSeverity(%q): esperado valid=%v, obteve valid=%v", tc.severity, tc.valid, isValid)
			}
		})
	}
}

func TestValidateAIFindings_TodasSeveridadesValidas(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "CRITICAL", "security", "Finding critico"),
		validFinding("aws_s3_bucket.logs", "HIGH", "security", "Finding alto"),
		validFinding("aws_instance.web", "MEDIUM", "best-practice", "Finding medio"),
		validFinding("aws_vpc.main", "LOW", "compliance", "Finding baixo"),
		validFinding("aws_iam_role.lambda_exec", "INFO", "maintainability", "Finding info"),
	}

	valid, _, _ := ValidateAIFindings(findings, graph)

	if len(valid) != 5 {
		t.Errorf("esperado 5 findings validos (todas severidades), obteve %d", len(valid))
	}
}

func TestValidationReport_Completo(t *testing.T) {
	graph := mockGraph()

	findings := []rules.Finding{
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Valido 1"),
		validFinding("aws_nonexistent.x", "HIGH", "security", "Recurso fantasma"),
		validFinding("aws_s3_bucket.data", "HIGH", "security", "Valido 1"),
	}

	_, _, report := ValidateAIFindings(findings, graph)

	if report.TotalReceived != 3 {
		t.Errorf("TotalReceived: esperado 3, obteve %d", report.TotalReceived)
	}
	if report.TotalValid != 1 {
		t.Errorf("TotalValid: esperado 1, obteve %d", report.TotalValid)
	}
	if report.TotalDiscard != 2 {
		t.Errorf("TotalDiscard: esperado 2, obteve %d", report.TotalDiscard)
	}
	if len(report.Discarded) != 2 {
		t.Errorf("Discarded len: esperado 2, obteve %d", len(report.Discarded))
	}
}
