// Package sanitizer redacts sensitive data from Terraform plans before sending
// them to external AI providers. It preserves JSON structure, keys, resource
// types and names — replacing only values that match known secret patterns
// (passwords, tokens, ARNs, PEM, JWT, long base64 strings).
//
// Each unique value receives a deterministic placeholder ([REDACTED-001], etc.)
// so that structural relationships are preserved for AI analysis.
// The RedactionManifest records everything that was redacted for auditing.
package sanitizer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// RedactionManifest maps each placeholder to the fields where redaction occurred.
// Used for auditing: allows knowing exactly what was removed and where.
type RedactionManifest struct {
	// Entries maps placeholder → list of JSON paths where the value appeared.
	// Example: "[REDACTED-001]" → ["resources[0].values.password", "resources[1].values.db_password"]
	Entries map[string][]string
}

// Count returns the total number of redactions performed (non-unique).
func (m *RedactionManifest) Count() int {
	total := 0
	for _, paths := range m.Entries {
		total += len(paths)
	}
	return total
}

// UniqueCount returns the number of distinct redacted values.
func (m *RedactionManifest) UniqueCount() int {
	return len(m.Entries)
}

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

var sensitiveFieldSubstrings = []string{
	"sensitive",
	"secret",
	"password",
	"token",
	"private_key",
}

var (
	// AWS ARN: arn:aws[-partition]:service:region:account-id:...
	arnPattern = regexp.MustCompile(`arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:\S*:\d{12}`)

	// PEM private key blocks
	pemPattern = regexp.MustCompile(`-----BEGIN\s[A-Z\s]*PRIVATE\sKEY-----`)

	// JWT tokens: header.payload (both base64url starting with eyJ)
	jwtPattern = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+`)
)

// minBase64Length is the minimum length of a base64 blob to be redacted.
// Values shorter than this are usually short hashes or legitimate IDs.
const minBase64Length = 200

var base64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/=]{200,}$`)

type sanitizer struct {
	mu          sync.Mutex
	counter     int
	valueToPlac map[string]string // original value → placeholder
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

func (s *sanitizer) redact(value, fieldPath string) string {
	plac := s.placeholder(value)

	s.mu.Lock()
	s.manifest.Entries[plac] = append(s.manifest.Entries[plac], fieldPath)
	s.mu.Unlock()

	return plac
}

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

// Sanitize redacts sensitive data from a Terraform plan JSON.
// Returns the sanitized JSON, the redaction manifest, and any error.
//
// The function preserves the complete JSON structure — keys, resource types
// and resource names remain intact. Only values are replaced.
func Sanitize(plan []byte) ([]byte, *RedactionManifest, error) {
	var data interface{}
	if err := json.Unmarshal(plan, &data); err != nil {
		return nil, nil, fmt.Errorf("failed to decode plan JSON: %w", err)
	}

	s := newSanitizer()
	sanitized := s.walk(data, "")

	result, err := json.Marshal(sanitized)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode sanitized JSON: %w", err)
	}

	return result, s.manifest, nil
}

func (s *sanitizer) walk(node interface{}, path string) interface{} {
	switch v := node.(type) {
	case map[string]interface{}:
		return s.walkMap(v, path)
	case []interface{}:
		return s.walkSlice(v, path)
	case string:
		// Value-based check — known patterns regardless of field name
		if isSensitiveValue(v) {
			return s.redact(v, path)
		}
		return v
	default:
		return v
	}
}

func (s *sanitizer) walkMap(m map[string]interface{}, path string) map[string]interface{} {
	result := make(map[string]interface{}, len(m))

	for key, val := range m {
		fieldPath := path
		if fieldPath == "" {
			fieldPath = key
		} else {
			fieldPath = fieldPath + "." + key
		}

		// If the field name is sensitive, redact the value (if string)
		if isSensitiveFieldName(key) {
			if strVal, ok := val.(string); ok && strVal != "" {
				result[key] = s.redact(strVal, fieldPath)
				continue
			}
		}

		// Recurse into composite values or check pattern in strings
		result[key] = s.walk(val, fieldPath)
	}

	return result
}

func (s *sanitizer) walkSlice(arr []interface{}, path string) []interface{} {
	result := make([]interface{}, len(arr))
	for i, item := range arr {
		elemPath := fmt.Sprintf("%s[%d]", path, i)
		result[i] = s.walk(item, elemPath)
	}
	return result
}

// Session encapsulates a reusable sanitizer for multiple maps.
type Session struct {
	s *sanitizer
}

// NewSession creates a new sanitization session.
func NewSession() *Session {
	return &Session{s: newSanitizer()}
}

// SanitizeMap redacts sensitive values from a deserialized map[string]interface{}
// (e.g., NormalizedResource.Values). basePath is the prefix used in manifest
// paths (e.g., "aws_instance.web.values").
func (sess *Session) SanitizeMap(data map[string]interface{}, basePath string) map[string]interface{} {
	if data == nil {
		return nil
	}
	return sess.s.walkMap(data, basePath)
}

// Manifest returns the accumulated manifest of all redactions in the session.
func (sess *Session) Manifest() *RedactionManifest {
	return sess.s.manifest
}
