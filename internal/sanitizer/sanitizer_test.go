package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// Fixture: plano Terraform realista com múltiplos tipos de dados sensíveis
// --------------------------------------------------------------------------

// longBase64 é um blob base64 de >200 caracteres para testar a detecção.
var longBase64 = strings.Repeat("QWxndW1hIGNvaXNhIHNlbnNpdmVsIGNvZGlmaWNhZGE=", 8)

var realisticPlanJSON = `{
  "format_version": "1.1",
  "terraform_version": "1.9.0",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_db_instance.main",
          "type": "aws_db_instance",
          "name": "main",
          "values": {
            "engine": "postgres",
            "instance_class": "db.t3.micro",
            "password": "SuperSecret123!",
            "username": "admin",
            "storage_encrypted": true,
            "db_subnet_group_name": "main-subnet-group"
          }
        },
        {
          "address": "aws_iam_access_key.deployer",
          "type": "aws_iam_access_key",
          "name": "deployer",
          "values": {
            "user": "deployer",
            "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "id": "AKIAIOSFODNN7EXAMPLE",
            "status": "Active"
          }
        },
        {
          "address": "aws_instance.web",
          "type": "aws_instance",
          "name": "web",
          "values": {
            "ami": "ami-0c55b159cbfafe1f0",
            "instance_type": "t3.micro",
            "user_data": "` + longBase64 + `",
            "tags": {
              "Name": "web-server",
              "Environment": "production"
            }
          }
        },
        {
          "address": "aws_iam_policy.admin",
          "type": "aws_iam_policy",
          "name": "admin",
          "values": {
            "name": "admin-policy",
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"arn:aws-us-east-1:iam::123456789012:role/admin\"}]}"
          }
        },
        {
          "address": "tls_private_key.deploy",
          "type": "tls_private_key",
          "name": "deploy",
          "values": {
            "algorithm": "RSA",
            "rsa_bits": 4096,
            "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoLFt2Y\n-----END RSA PRIVATE KEY-----"
          }
        },
        {
          "address": "aws_secretsmanager_secret_version.db",
          "type": "aws_secretsmanager_secret_version",
          "name": "db",
          "values": {
            "secret_string": "{\"password\":\"AnotherSecret!@#\"}",
            "version_id": "v1"
          }
        },
        {
          "address": "aws_lambda_function.auth",
          "type": "aws_lambda_function",
          "name": "auth",
          "values": {
            "function_name": "auth-handler",
            "runtime": "nodejs18.x",
            "environment": {
              "variables": {
                "JWT_SECRET": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9",
                "API_ENDPOINT": "https://api.example.com"
              }
            }
          }
        },
        {
          "address": "aws_db_instance.replica",
          "type": "aws_db_instance",
          "name": "replica",
          "values": {
            "engine": "postgres",
            "instance_class": "db.t3.micro",
            "password": "SuperSecret123!",
            "username": "admin",
            "replicate_source_db": "aws_db_instance.main"
          }
        }
      ]
    }
  }
}`

// --------------------------------------------------------------------------
// Teste principal: plano completo com todos os padrões
// --------------------------------------------------------------------------

func TestSanitize_RealisticPlan(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() erro inesperado: %v", err)
	}

	// Verificar que o resultado é JSON válido
	var result map[string]interface{}
	if err := json.Unmarshal(sanitized, &result); err != nil {
		t.Fatalf("JSON sanitizado inválido: %v", err)
	}

	sanitizedStr := string(sanitized)

	// Valores que DEVEM ter sido redatados
	sensitiveValues := []string{
		"SuperSecret123!",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"-----BEGIN RSA PRIVATE KEY-----",
		longBase64,
	}

	for _, val := range sensitiveValues {
		if strings.Contains(sanitizedStr, val) {
			t.Errorf("valor sensível NÃO foi redatado: %q", truncate(val, 60))
		}
	}

	// Valores que NÃO devem ser redatados (chaves, tipos, nomes)
	preservedValues := []string{
		"aws_db_instance",
		"aws_iam_access_key",
		"aws_instance",
		"tls_private_key",
		"aws_lambda_function",
		"password",        // chave, não valor
		"secret",          // chave, não valor
		"private_key_pem", // chave, não valor
		"main",            // nome do recurso
		"deployer",        // nome do recurso
		"web",             // nome do recurso
		"ami-0c55b159cbfafe1f0",
		"t3.micro",
		"postgres",
		"production",
		"web-server",
	}

	for _, val := range preservedValues {
		if !strings.Contains(sanitizedStr, val) {
			t.Errorf("valor preservado foi removido: %q", val)
		}
	}

	// Verificar que placeholders estão presentes
	if !strings.Contains(sanitizedStr, "[REDACTED-") {
		t.Error("nenhum placeholder [REDACTED-NNN] encontrado no JSON sanitizado")
	}

	// Verificar que o manifest tem entradas
	if manifest.UniqueCount() == 0 {
		t.Error("RedactionManifest vazio — nenhuma redação registrada")
	}

	if manifest.Count() == 0 {
		t.Error("RedactionManifest sem caminhos — nenhum path registrado")
	}

	t.Logf("Redações: %d únicas, %d total", manifest.UniqueCount(), manifest.Count())
	for plac, paths := range manifest.Entries {
		t.Logf("  %s → %v", plac, paths)
	}
}

// --------------------------------------------------------------------------
// Teste: mesmo valor em múltiplos locais recebe o MESMO placeholder
// --------------------------------------------------------------------------

func TestSanitize_SameValueSamePlaceholder(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() erro: %v", err)
	}

	// "SuperSecret123!" aparece em aws_db_instance.main E aws_db_instance.replica
	// Deve ter o MESMO placeholder, com 2 caminhos no manifest

	var passwordPlaceholder string
	for plac, paths := range manifest.Entries {
		for _, p := range paths {
			if strings.Contains(p, "password") {
				if passwordPlaceholder == "" {
					passwordPlaceholder = plac
				} else if passwordPlaceholder != plac {
					t.Errorf("mesmo valor 'password' recebeu placeholders diferentes: %s vs %s", passwordPlaceholder, plac)
				}
			}
		}
	}

	if passwordPlaceholder == "" {
		t.Fatal("nenhum placeholder encontrado para campos 'password'")
	}

	// Contar ocorrências do placeholder no JSON sanitizado
	count := strings.Count(string(sanitized), passwordPlaceholder)
	if count < 2 {
		t.Errorf("placeholder %s deveria aparecer >= 2 vezes (main + replica), apareceu %d", passwordPlaceholder, count)
	}
}

// --------------------------------------------------------------------------
// Teste: estrutura JSON preservada após sanitização
// --------------------------------------------------------------------------

func TestSanitize_PreservesJSONStructure(t *testing.T) {
	sanitized, _, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() erro: %v", err)
	}

	var original, result map[string]interface{}
	if err := json.Unmarshal([]byte(realisticPlanJSON), &original); err != nil {
		t.Fatalf("parse original falhou: %v", err)
	}
	if err := json.Unmarshal(sanitized, &result); err != nil {
		t.Fatalf("parse sanitizado falhou: %v", err)
	}

	for key := range original {
		if _, ok := result[key]; !ok {
			t.Errorf("chave de primeiro nível %q ausente no resultado sanitizado", key)
		}
	}

	if result["format_version"] != original["format_version"] {
		t.Errorf("format_version alterado: %v → %v", original["format_version"], result["format_version"])
	}
	if result["terraform_version"] != original["terraform_version"] {
		t.Errorf("terraform_version alterado: %v → %v", original["terraform_version"], result["terraform_version"])
	}
}

// --------------------------------------------------------------------------
// Teste: manifest contém mapeamentos corretos
// --------------------------------------------------------------------------

func TestSanitize_ManifestCorrectMappings(t *testing.T) {
	_, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() erro: %v", err)
	}

	foundPassword := false
	foundSecret := false
	foundPEM := false

	for _, paths := range manifest.Entries {
		for _, p := range paths {
			if strings.Contains(p, "password") {
				foundPassword = true
			}
			if strings.Contains(p, "secret") {
				foundSecret = true
			}
			if strings.Contains(p, "private_key_pem") {
				foundPEM = true
			}
		}
	}

	if !foundPassword {
		t.Error("manifest não contém redação para campo 'password'")
	}
	if !foundSecret {
		t.Error("manifest não contém redação para campo 'secret'")
	}
	if !foundPEM {
		t.Error("manifest não contém redação para campo 'private_key_pem'")
	}
}

// --------------------------------------------------------------------------
// Table-driven tests: cada padrão individual
// --------------------------------------------------------------------------

func TestSanitize_PatternDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		redacted bool
	}{
		{
			name:     "campo password",
			input:    `{"password": "MyP@ssw0rd!"}`,
			redacted: true,
		},
		{
			name:     "campo secret",
			input:    `{"secret": "super-secret-value"}`,
			redacted: true,
		},
		{
			name:     "campo token",
			input:    `{"token": "ghp_abc123def456"}`,
			redacted: true,
		},
		{
			name:     "campo private_key",
			input:    `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`,
			redacted: true,
		},
		{
			name:     "campo access_key",
			input:    `{"access_key": "AKIAIOSFODNN7EXAMPLE"}`,
			redacted: true,
		},
		{
			name:     "campo secret_key",
			input:    `{"secret_key": "wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY"}`,
			redacted: true,
		},
		{
			name:     "campo api_key",
			input:    `{"api_key": "sk-abc123def456"}`,
			redacted: true,
		},
		{
			name:     "campo connection_string",
			input:    `{"connection_string": "postgresql://user:pass@host:5432/db"}`,
			redacted: true,
		},
		{
			name:     "campo certificate",
			input:    `{"certificate": "-----BEGIN CERTIFICATE-----\nMIIE..."}`,
			redacted: true,
		},
		{
			name:     "campo credentials",
			input:    `{"credentials": "{\"key\": \"val\"}"}`,
			redacted: true,
		},
		{
			name:     "campo com sensitive no nome",
			input:    `{"db_sensitive_data": "secret-value"}`,
			redacted: true,
		},
		{
			name:     "campo com password no nome composto",
			input:    `{"db_password_hash": "hashed-value"}`,
			redacted: true,
		},
		{
			name:     "valor ARN com account ID",
			input:    `{"role": "arn:aws:iam::123456789012:role/admin"}`,
			redacted: true,
		},
		{
			name:     "valor PEM private key",
			input:    `{"data": "-----BEGIN EC PRIVATE KEY-----\nMHQ..."}`,
			redacted: true,
		},
		{
			name:     "valor JWT token",
			input:    `{"auth": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}`,
			redacted: true,
		},
		{
			name:     "valor base64 longo acima de 200 chars",
			input:    `{"data": "` + strings.Repeat("QUFB", 70) + `"}`,
			redacted: true,
		},
		{
			name:     "valor normal NAO redatado",
			input:    `{"instance_type": "t3.micro"}`,
			redacted: false,
		},
		{
			name:     "campo tags NAO redatado",
			input:    `{"tags": {"Name": "my-server"}}`,
			redacted: false,
		},
		{
			name:     "AMI NAO redatada",
			input:    `{"ami": "ami-0c55b159cbfafe1f0"}`,
			redacted: false,
		},
		{
			name:     "booleano NAO redatado",
			input:    `{"encrypted": true}`,
			redacted: false,
		},
		{
			name:     "numero NAO redatado",
			input:    `{"port": 5432}`,
			redacted: false,
		},
		{
			name:     "base64 curto NAO redatado",
			input:    `{"data": "SGVsbG8gV29ybGQ="}`,
			redacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized, manifest, err := Sanitize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Sanitize() erro: %v", err)
			}

			hasRedaction := strings.Contains(string(sanitized), "[REDACTED-")
			if tt.redacted && !hasRedaction {
				t.Errorf("esperava redacao, mas nenhum placeholder encontrado.\nInput:  %s\nOutput: %s", tt.input, string(sanitized))
			}
			if !tt.redacted && hasRedaction {
				t.Errorf("NAO esperava redacao, mas placeholder encontrado.\nInput:  %s\nOutput: %s", tt.input, string(sanitized))
			}

			var result interface{}
			if err := json.Unmarshal(sanitized, &result); err != nil {
				t.Errorf("JSON sanitizado invalido: %v", err)
			}

			if tt.redacted && manifest.UniqueCount() == 0 {
				t.Error("esperava entradas no manifest, mas esta vazio")
			}
		})
	}
}

// --------------------------------------------------------------------------
// Teste: JSON invalido retorna erro
// --------------------------------------------------------------------------

func TestSanitize_InvalidJSON(t *testing.T) {
	_, _, err := Sanitize([]byte(`{invalid json}`))
	if err == nil {
		t.Error("esperava erro para JSON invalido, mas Sanitize() retornou nil")
	}
}

// --------------------------------------------------------------------------
// Teste: JSON vazio/minimo funciona sem erro
// --------------------------------------------------------------------------

func TestSanitize_EmptyObject(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(`{}`))
	if err != nil {
		t.Fatalf("Sanitize() erro para objeto vazio: %v", err)
	}
	if string(sanitized) != `{}` {
		t.Errorf("objeto vazio deveria permanecer igual, got: %s", string(sanitized))
	}
	if manifest.UniqueCount() != 0 {
		t.Error("manifest deveria estar vazio para objeto vazio")
	}
}

// --------------------------------------------------------------------------
// Teste: campos numericos/booleanos com nomes sensiveis NAO sao redatados
// --------------------------------------------------------------------------

func TestSanitize_NonStringFieldsPreserved(t *testing.T) {
	input := `{"password": 12345, "secret": true, "token": null}`
	sanitized, _, err := Sanitize([]byte(input))
	if err != nil {
		t.Fatalf("Sanitize() erro: %v", err)
	}

	if strings.Contains(string(sanitized), "[REDACTED-") {
		t.Error("valores nao-string com nomes sensiveis nao devem ser redatados")
	}
}

// --------------------------------------------------------------------------
// Teste: arrays de valores sensiveis
// --------------------------------------------------------------------------

func TestSanitize_ArrayWithSensitiveValues(t *testing.T) {
	input := `{"items": ["normal", "-----BEGIN RSA PRIVATE KEY-----\ndata", "also-normal"]}`
	sanitized, manifest, err := Sanitize([]byte(input))
	if err != nil {
		t.Fatalf("Sanitize() erro: %v", err)
	}

	sanitizedStr := string(sanitized)

	if strings.Contains(sanitizedStr, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("PEM key em array nao foi redatada")
	}

	if !strings.Contains(sanitizedStr, "normal") {
		t.Error("valor normal em array foi removido")
	}

	if manifest.UniqueCount() == 0 {
		t.Error("manifest deveria ter pelo menos 1 entrada para PEM em array")
	}
}

// --------------------------------------------------------------------------
// Teste: Session API para sanitizar maps diretamente
// --------------------------------------------------------------------------

func TestSession_SanitizeMap(t *testing.T) {
	sess := NewSession()

	// Simula NormalizedResource.Values
	values := map[string]interface{}{
		"engine":        "postgres",
		"password":      "SuperSecret123!",
		"private_key":   "-----BEGIN RSA PRIVATE KEY-----\ndata",
		"instance_type": "t3.micro",
	}

	result := sess.SanitizeMap(values, "aws_db_instance.main.values")

	// password e private_key devem ser redatados
	if v, ok := result["password"].(string); !ok || !strings.Contains(v, "[REDACTED-") {
		t.Errorf("password nao foi redatado: %v", result["password"])
	}
	if v, ok := result["private_key"].(string); !ok || !strings.Contains(v, "[REDACTED-") {
		t.Errorf("private_key nao foi redatado: %v", result["private_key"])
	}

	// engine e instance_type preservados
	if result["engine"] != "postgres" {
		t.Errorf("engine foi alterado: %v", result["engine"])
	}
	if result["instance_type"] != "t3.micro" {
		t.Errorf("instance_type foi alterado: %v", result["instance_type"])
	}

	manifest := sess.Manifest()
	if manifest.UniqueCount() < 2 {
		t.Errorf("manifest deveria ter pelo menos 2 entradas unicas, tem %d", manifest.UniqueCount())
	}
}

func TestSession_SanitizeMapNil(t *testing.T) {
	sess := NewSession()
	result := sess.SanitizeMap(nil, "test")
	if result != nil {
		t.Error("SanitizeMap(nil) deveria retornar nil")
	}
}

func TestSession_SharedPlaceholders(t *testing.T) {
	sess := NewSession()

	values1 := map[string]interface{}{"password": "shared-secret"}
	values2 := map[string]interface{}{"password": "shared-secret"}

	r1 := sess.SanitizeMap(values1, "resource1.values")
	r2 := sess.SanitizeMap(values2, "resource2.values")

	// Mesmo valor deve ter o mesmo placeholder
	if r1["password"] != r2["password"] {
		t.Errorf("mesmo valor recebeu placeholders diferentes: %v vs %v", r1["password"], r2["password"])
	}

	manifest := sess.Manifest()
	// 1 valor unico, 2 caminhos
	if manifest.UniqueCount() != 1 {
		t.Errorf("esperava 1 valor unico, got %d", manifest.UniqueCount())
	}
	if manifest.Count() != 2 {
		t.Errorf("esperava 2 caminhos totais, got %d", manifest.Count())
	}
}

// --------------------------------------------------------------------------
// Benchmark
// --------------------------------------------------------------------------

func BenchmarkSanitize(b *testing.B) {
	plan := []byte(realisticPlanJSON)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = Sanitize(plan)
	}
}

// truncate encurta uma string para exibicao em mensagens de erro.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
