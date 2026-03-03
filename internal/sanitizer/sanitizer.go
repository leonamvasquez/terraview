// Package sanitizer redige dados sensíveis de planos Terraform antes do envio
// a provedores de IA externos. Preserva a estrutura JSON, chaves, tipos de
// recurso e nomes — substituindo apenas valores que correspondam a padrões
// conhecidos de segredos (passwords, tokens, ARNs, PEM, JWT, base64 longos).
//
// Cada valor único recebe um placeholder determinístico ([REDACTED-001], etc.)
// para que relações estruturais sejam preservadas na análise da IA.
// O RedactionManifest registra tudo que foi redatado para auditoria.
package sanitizer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// RedactionManifest mapeia cada placeholder ao campo onde a redação ocorreu.
// Usado para auditoria: permite saber exatamente o que foi removido e onde.
type RedactionManifest struct {
	// Entries mapeia placeholder → lista de caminhos JSON onde o valor apareceu.
	// Exemplo: "[REDACTED-001]" → ["resources[0].values.password", "resources[1].values.db_password"]
	Entries map[string][]string
}

// Count retorna o número total de redações realizadas (não-único).
func (m *RedactionManifest) Count() int {
	total := 0
	for _, paths := range m.Entries {
		total += len(paths)
	}
	return total
}

// UniqueCount retorna o número de valores distintos redatados.
func (m *RedactionManifest) UniqueCount() int {
	return len(m.Entries)
}

// sensitiveFieldNames são nomes de campos cujos valores devem ser redatados.
// A comparação é feita em lowercase para ser case-insensitive.
var sensitiveFieldNames = map[string]bool{
	"password":          true,
	"secret":            true,
	"token":             true,
	"private_key":       true,
	"access_key":        true,
	"secret_key":        true,
	"api_key":           true,
	"connection_string": true,
	"certificate":       true,
	"credentials":       true,
}

// sensitiveFieldSubstrings são substrings que, presentes no nome do campo,
// indicam que o valor deve ser redatado.
var sensitiveFieldSubstrings = []string{
	"sensitive",
	"secret",
	"password",
	"token",
	"private_key",
}

// Padrões de regex compilados para detecção de valores sensíveis.
var (
	// AWS ARN: arn:aws[-partition]:service:region:account-id:...
	arnPattern = regexp.MustCompile(`arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:\S*:\d{12}`)

	// AWS Account ID isolado (12 dígitos exatos, delimitado por word boundary)
	awsAccountIDPattern = regexp.MustCompile(`\b\d{12}\b`)

	// PEM private key blocks
	pemPattern = regexp.MustCompile(`-----BEGIN\s[A-Z\s]*PRIVATE\sKEY-----`)

	// JWT tokens: header.payload (ambos base64url começando com eyJ)
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+`)
)

// minBase64Length é o comprimento mínimo de um blob base64 para ser redatado.
// Valores menores que isso geralmente são hashes curtos ou IDs legítimos.
const minBase64Length = 200

// base64Pattern detecta strings que parecem blobs base64 longos.
var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/=]{200,}$`)

// sanitizer mantém estado durante a redação de um plano.
type sanitizer struct {
	mu          sync.Mutex
	counter     int
	valueToPlac map[string]string // valor original → placeholder
	manifest    *RedactionManifest
}

func newSanitizer() *sanitizer {
	return &sanitizer{
		valueToPlac: make(map[string]string),
		manifest: &RedactionManifest{
			Entries: make(map[string][]string),
		},
	}
}

// placeholder retorna um placeholder determinístico para o valor dado.
// Se o mesmo valor já foi visto, retorna o mesmo placeholder.
func (s *sanitizer) placeholder(value string) string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if plac, ok := s.valueToPlac[value]; ok {
		return plac
	}

	s.counter++
	plac := fmt.Sprintf("[REDACTED-%03d]", s.counter)
	s.valueToPlac[value] = plac
	return plac
}

// redact substitui o valor pelo placeholder e registra no manifest.
func (s *sanitizer) redact(value, fieldPath string) string {
	plac := s.placeholder(value)

	s.mu.Lock()
	s.manifest.Entries[plac] = append(s.manifest.Entries[plac], fieldPath)
	s.mu.Unlock()

	return plac
}

// isSensitiveFieldName verifica se o nome do campo indica um valor sensível.
func isSensitiveFieldName(fieldName string) bool {
	lower := strings.ToLower(fieldName)

	if sensitiveFieldNames[lower] {
		return true
	}

	for _, sub := range sensitiveFieldSubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}

	return false
}

// isSensitiveValue verifica se o valor (string) corresponde a um padrão sensível.
func isSensitiveValue(value string) bool {
	if pemPattern.MatchString(value) {
		return true
	}
	if jwtPattern.MatchString(value) {
		return true
	}
	if arnPattern.MatchString(value) {
		return true
	}
	if len(value) >= minBase64Length && base64Pattern.MatchString(value) {
		return true
	}
	return false
}

// Sanitize redige dados sensíveis do JSON de um plano Terraform.
// Retorna o JSON sanitizado, o manifesto de redações e qualquer erro.
//
// A função preserva a estrutura JSON completa — chaves, tipos de recurso
// e nomes de recurso permanecem intactos. Apenas valores são substituídos.
func Sanitize(plan []byte) ([]byte, *RedactionManifest, error) {
	var data interface{}
	if err := json.Unmarshal(plan, &data); err != nil {
		return nil, nil, fmt.Errorf("falha ao decodificar JSON do plano: %w", err)
	}

	s := newSanitizer()
	sanitized := s.walk(data, "")

	result, err := json.Marshal(sanitized)
	if err != nil {
		return nil, nil, fmt.Errorf("falha ao codificar JSON sanitizado: %w", err)
	}

	return result, s.manifest, nil
}

// walk percorre recursivamente a estrutura JSON, redatando valores sensíveis.
func (s *sanitizer) walk(node interface{}, path string) interface{} {
	switch v := node.(type) {
	case map[string]interface{}:
		return s.walkMap(v, path)
	case []interface{}:
		return s.walkSlice(v, path)
	case string:
		// Verificação por valor — padrões conhecidos independente do campo
		if isSensitiveValue(v) {
			return s.redact(v, path)
		}
		return v
	default:
		return v
	}
}

// walkMap percorre um objeto JSON, verificando tanto o nome do campo quanto o valor.
func (s *sanitizer) walkMap(m map[string]interface{}, path string) map[string]interface{} {
	result := make(map[string]interface{}, len(m))

	for key, val := range m {
		fieldPath := path
		if fieldPath == "" {
			fieldPath = key
		} else {
			fieldPath = fieldPath + "." + key
		}

		// Se o nome do campo é sensível, redatar o valor (se for string)
		if isSensitiveFieldName(key) {
			if strVal, ok := val.(string); ok && strVal != "" {
				result[key] = s.redact(strVal, fieldPath)
				continue
			}
		}

		// Recursão para valores compostos ou verificação de padrão em strings
		result[key] = s.walk(val, fieldPath)
	}

	return result
}

// walkSlice percorre um array JSON.
func (s *sanitizer) walkSlice(arr []interface{}, path string) []interface{} {
	result := make([]interface{}, len(arr))
	for i, item := range arr {
		elemPath := fmt.Sprintf("%s[%d]", path, i)
		result[i] = s.walk(item, elemPath)
	}
	return result
}

// ──────────────────────────────────────────────────────────────────────────
// Session — sanitizador reutilizável para múltiplos mapas (ex.: recursos).
// Compartilha o mesmo mapeamento valor→placeholder, garantindo consistência
// entre Values e BeforeValues de todos os recursos analisados.
// ──────────────────────────────────────────────────────────────────────────

// Session encapsula um sanitizer reutilizável.
type Session struct {
	s *sanitizer
}

// NewSession cria uma nova sessão de sanitização.
func NewSession() *Session {
	return &Session{s: newSanitizer()}
}

// SanitizeMap redige valores sensíveis de um map[string]interface{} já
// deserializado (ex.: NormalizedResource.Values). basePath é o prefixo
// usado nos caminhos do manifest (ex.: "aws_instance.web.values").
func (sess *Session) SanitizeMap(data map[string]interface{}, basePath string) map[string]interface{} {
	if data == nil {
		return nil
	}
	return sess.s.walkMap(data, basePath)
}

// Manifest retorna o manifesto acumulado de todas as redações da sessão.
func (sess *Session) Manifest() *RedactionManifest {
	return sess.s.manifest
}
