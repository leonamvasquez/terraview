package sanitizer

import (
	"encoding/json"
	"strings"
	"testing"
)

// --------------------------------------------------------------------------
// Fixture: realistic Terraform plan with multiple types of sensitive data
// --------------------------------------------------------------------------

// longBase64 is a base64 blob >200 chars for testing detection.
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
// Main test: full plan with all patterns
// --------------------------------------------------------------------------

func TestSanitize_RealisticPlan(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() unexpected error: %v", err)
	}

	// Verify result is valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(sanitized, &result); err != nil {
		t.Fatalf("invalid sanitized JSON: %v", err)
	}

	sanitizedStr := string(sanitized)

	// Values that MUST have been redacted
	sensitiveValues := []string{
		"SuperSecret123!",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"-----BEGIN RSA PRIVATE KEY-----",
		longBase64,
	}

	for _, val := range sensitiveValues {
		if strings.Contains(sanitizedStr, val) {
			t.Errorf("sensitive value NOT redacted: %q", truncate(val, 60))
		}
	}

	// Values that must NOT be redacted (keys, types, names)
	preservedValues := []string{
		"aws_db_instance",
		"aws_iam_access_key",
		"aws_instance",
		"tls_private_key",
		"aws_lambda_function",
		"password",        // key, not value
		"secret",          // key, not value
		"private_key_pem", // key, not value
		"main",            // resource name
		"deployer",        // resource name
		"web",             // resource name
		"ami-0c55b159cbfafe1f0",
		"t3.micro",
		"postgres",
		"production",
		"web-server",
	}

	for _, val := range preservedValues {
		if !strings.Contains(sanitizedStr, val) {
			t.Errorf("preserved value was removed: %q", val)
		}
	}

	// Verify that placeholders are present
	if !strings.Contains(sanitizedStr, "[REDACTED-") {
		t.Error("no [REDACTED-NNN] placeholder found in sanitized JSON")
	}

	// Verify manifest has entries
	if manifest.UniqueCount() == 0 {
		t.Error("RedactionManifest empty — no redactions recorded")
	}

	if manifest.Count() == 0 {
		t.Error("RedactionManifest without paths — no paths recorded")
	}

	t.Logf("Redactions: %d unique, %d total", manifest.UniqueCount(), manifest.Count())
	for plac, paths := range manifest.Entries {
		t.Logf("  %s → %v", plac, paths)
	}
}

// --------------------------------------------------------------------------
// Test: same value at multiple locations receives the SAME placeholder
// --------------------------------------------------------------------------

func TestSanitize_SameValueSamePlaceholder(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() error: %v", err)
	}

	// "SuperSecret123!" appears in aws_db_instance.main AND aws_db_instance.replica
	// Should have the SAME placeholder, with 2 paths in the manifest

	var passwordPlaceholder string
	for plac, paths := range manifest.Entries {
		for _, p := range paths {
			if strings.Contains(p, "password") {
				if passwordPlaceholder == "" {
					passwordPlaceholder = plac
				} else if passwordPlaceholder != plac {
					t.Errorf("same 'password' value received different placeholders: %s vs %s", passwordPlaceholder, plac)
				}
			}
		}
	}

	if passwordPlaceholder == "" {
		t.Fatal("no placeholder found for 'password' fields")
	}

	// Count placeholder occurrences in sanitized JSON
	count := strings.Count(string(sanitized), passwordPlaceholder)
	if count < 2 {
		t.Errorf("placeholder %s should appear >= 2 times (main + replica), appeared %d", passwordPlaceholder, count)
	}
}

// --------------------------------------------------------------------------
// Test: JSON structure preserved after sanitization
// --------------------------------------------------------------------------

func TestSanitize_PreservesJSONStructure(t *testing.T) {
	sanitized, _, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() error: %v", err)
	}

	var original, result map[string]interface{}
	if err := json.Unmarshal([]byte(realisticPlanJSON), &original); err != nil {
		t.Fatalf("original parse failed: %v", err)
	}
	if err := json.Unmarshal(sanitized, &result); err != nil {
		t.Fatalf("sanitized parse failed: %v", err)
	}

	for key := range original {
		if _, ok := result[key]; !ok {
			t.Errorf("top-level key %q missing from sanitized result", key)
		}
	}

	if result["format_version"] != original["format_version"] {
		t.Errorf("format_version changed: %v → %v", original["format_version"], result["format_version"])
	}
	if result["terraform_version"] != original["terraform_version"] {
		t.Errorf("terraform_version changed: %v → %v", original["terraform_version"], result["terraform_version"])
	}
}

// --------------------------------------------------------------------------
// Test: manifest contains correct mappings
// --------------------------------------------------------------------------

func TestSanitize_ManifestCorrectMappings(t *testing.T) {
	_, manifest, err := Sanitize([]byte(realisticPlanJSON))
	if err != nil {
		t.Fatalf("Sanitize() error: %v", err)
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
		t.Error("manifest does not contain redaction for 'password' field")
	}
	if !foundSecret {
		t.Error("manifest does not contain redaction for 'secret' field")
	}
	if !foundPEM {
		t.Error("manifest does not contain redaction for 'private_key_pem' field")
	}
}

// --------------------------------------------------------------------------
// Table-driven tests: each individual pattern
// --------------------------------------------------------------------------

func TestSanitize_PatternDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		redacted bool
	}{
		{
			name:     "password field",
			input:    `{"password": "MyP@ssw0rd!"}`,
			redacted: true,
		},
		{
			name:     "secret field",
			input:    `{"secret": "super-secret-value"}`,
			redacted: true,
		},
		{
			name:     "token field",
			input:    `{"token": "ghp_abc123def456"}`,
			redacted: true,
		},
		{
			name:     "private_key field",
			input:    `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."}`,
			redacted: true,
		},
		{
			name:     "access_key field",
			input:    `{"access_key": "AKIAIOSFODNN7EXAMPLE"}`,
			redacted: true,
		},
		{
			name:     "secret_key field",
			input:    `{"secret_key": "wJalrXUtnFEMI/bPxRfiCYEXAMPLEKEY"}`,
			redacted: true,
		},
		{
			name:     "api_key field",
			input:    `{"api_key": "sk-abc123def456"}`,
			redacted: true,
		},
		{
			name:     "connection_string field",
			input:    `{"connection_string": "postgresql://user:pass@host:5432/db"}`,
			redacted: true,
		},
		{
			name:     "certificate field",
			input:    `{"certificate": "-----BEGIN CERTIFICATE-----\nMIIE..."}`,
			redacted: true,
		},
		{
			name:     "credentials field",
			input:    `{"credentials": "{\"key\": \"val\"}"}`,
			redacted: true,
		},
		{
			name:     "field with sensitive in name",
			input:    `{"db_sensitive_data": "secret-value"}`,
			redacted: true,
		},
		{
			name:     "field with password in compound name",
			input:    `{"db_password_hash": "hashed-value"}`,
			redacted: true,
		},
		{
			name:     "ARN value with account ID",
			input:    `{"role": "arn:aws:iam::123456789012:role/admin"}`,
			redacted: true,
		},
		{
			name:     "PEM private key value",
			input:    `{"data": "-----BEGIN EC PRIVATE KEY-----\nMHQ..."}`,
			redacted: true,
		},
		{
			name:     "JWT token value",
			input:    `{"auth": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"}`,
			redacted: true,
		},
		{
			name:     "long base64 value over 200 chars",
			input:    `{"data": "` + strings.Repeat("QUFB", 70) + `"}`,
			redacted: true,
		},
		{
			name:     "normal value NOT redacted",
			input:    `{"instance_type": "t3.micro"}`,
			redacted: false,
		},
		{
			name:     "tags field NOT redacted",
			input:    `{"tags": {"Name": "my-server"}}`,
			redacted: false,
		},
		{
			name:     "AMI NOT redacted",
			input:    `{"ami": "ami-0c55b159cbfafe1f0"}`,
			redacted: false,
		},
		{
			name:     "boolean NOT redacted",
			input:    `{"encrypted": true}`,
			redacted: false,
		},
		{
			name:     "number NOT redacted",
			input:    `{"port": 5432}`,
			redacted: false,
		},
		{
			name:     "short base64 NOT redacted",
			input:    `{"data": "SGVsbG8gV29ybGQ="}`,
			redacted: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sanitized, manifest, err := Sanitize([]byte(tt.input))
			if err != nil {
				t.Fatalf("Sanitize() error: %v", err)
			}

			hasRedaction := strings.Contains(string(sanitized), "[REDACTED-")
			if tt.redacted && !hasRedaction {
				t.Errorf("expected redaction, but no placeholder found.\nInput:  %s\nOutput: %s", tt.input, string(sanitized))
			}
			if !tt.redacted && hasRedaction {
				t.Errorf("did NOT expect redaction, but placeholder found.\nInput:  %s\nOutput: %s", tt.input, string(sanitized))
			}

			var result interface{}
			if err := json.Unmarshal(sanitized, &result); err != nil {
				t.Errorf("invalid sanitized JSON: %v", err)
			}

			if tt.redacted && manifest.UniqueCount() == 0 {
				t.Error("expected entries in manifest, but it is empty")
			}
		})
	}
}

// --------------------------------------------------------------------------
// Test: invalid JSON returns error
// --------------------------------------------------------------------------

func TestSanitize_InvalidJSON(t *testing.T) {
	_, _, err := Sanitize([]byte(`{invalid json}`))
	if err == nil {
		t.Error("expected error for invalid JSON, but Sanitize() returned nil")
	}
}

// --------------------------------------------------------------------------
// Test: empty/minimal JSON works without error
// --------------------------------------------------------------------------

func TestSanitize_EmptyObject(t *testing.T) {
	sanitized, manifest, err := Sanitize([]byte(`{}`))
	if err != nil {
		t.Fatalf("Sanitize() error for empty object: %v", err)
	}
	if string(sanitized) != `{}` {
		t.Errorf("empty object should remain unchanged, got: %s", string(sanitized))
	}
	if manifest.UniqueCount() != 0 {
		t.Error("manifest should be empty for empty object")
	}
}

// --------------------------------------------------------------------------
// Test: numeric/boolean fields with sensitive names are NOT redacted
// --------------------------------------------------------------------------

func TestSanitize_NonStringFieldsPreserved(t *testing.T) {
	input := `{"password": 12345, "secret": true, "token": null}`
	sanitized, _, err := Sanitize([]byte(input))
	if err != nil {
		t.Fatalf("Sanitize() error: %v", err)
	}

	if strings.Contains(string(sanitized), "[REDACTED-") {
		t.Error("non-string values with sensitive names should not be redacted")
	}
}

// --------------------------------------------------------------------------
// Test: arrays with sensitive values
// --------------------------------------------------------------------------

func TestSanitize_ArrayWithSensitiveValues(t *testing.T) {
	input := `{"items": ["normal", "-----BEGIN RSA PRIVATE KEY-----\ndata", "also-normal"]}`
	sanitized, manifest, err := Sanitize([]byte(input))
	if err != nil {
		t.Fatalf("Sanitize() error: %v", err)
	}

	sanitizedStr := string(sanitized)

	if strings.Contains(sanitizedStr, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Error("PEM key in array was not redacted")
	}

	if !strings.Contains(sanitizedStr, "normal") {
		t.Error("normal value in array was removed")
	}

	if manifest.UniqueCount() == 0 {
		t.Error("manifest should have at least 1 entry for PEM in array")
	}
}

// --------------------------------------------------------------------------
// Test: Session API for sanitizing maps directly
// --------------------------------------------------------------------------

func TestSession_SanitizeMap(t *testing.T) {
	sess := NewSession()

	// Simulate NormalizedResource.Values
	values := map[string]interface{}{
		"engine":        "postgres",
		"password":      "SuperSecret123!",
		"private_key":   "-----BEGIN RSA PRIVATE KEY-----\ndata",
		"instance_type": "t3.micro",
	}

	result := sess.SanitizeMap(values, "aws_db_instance.main.values")

	// password and private_key should be redacted
	if v, ok := result["password"].(string); !ok || !strings.Contains(v, "[REDACTED-") {
		t.Errorf("password was not redacted: %v", result["password"])
	}
	if v, ok := result["private_key"].(string); !ok || !strings.Contains(v, "[REDACTED-") {
		t.Errorf("private_key was not redacted: %v", result["private_key"])
	}

	// engine and instance_type preserved
	if result["engine"] != "postgres" {
		t.Errorf("engine was changed: %v", result["engine"])
	}
	if result["instance_type"] != "t3.micro" {
		t.Errorf("instance_type was changed: %v", result["instance_type"])
	}

	manifest := sess.Manifest()
	if manifest.UniqueCount() < 2 {
		t.Errorf("manifest should have at least 2 unique entries, got %d", manifest.UniqueCount())
	}
}

func TestSession_SanitizeMapNil(t *testing.T) {
	sess := NewSession()
	result := sess.SanitizeMap(nil, "test")
	if result != nil {
		t.Error("SanitizeMap(nil) should return nil")
	}
}

func TestSession_SharedPlaceholders(t *testing.T) {
	sess := NewSession()

	values1 := map[string]interface{}{"password": "shared-secret"}
	values2 := map[string]interface{}{"password": "shared-secret"}

	r1 := sess.SanitizeMap(values1, "resource1.values")
	r2 := sess.SanitizeMap(values2, "resource2.values")

	// Same value should have the same placeholder
	if r1["password"] != r2["password"] {
		t.Errorf("same value got different placeholders: %v vs %v", r1["password"], r2["password"])
	}

	manifest := sess.Manifest()
	// 1 unique value, 2 paths
	if manifest.UniqueCount() != 1 {
		t.Errorf("expected 1 unique value, got %d", manifest.UniqueCount())
	}
	if manifest.Count() != 2 {
		t.Errorf("expected 2 total paths, got %d", manifest.Count())
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

// truncate shortens a string for display in error messages.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
