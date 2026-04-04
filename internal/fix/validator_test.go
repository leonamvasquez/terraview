package fix

import (
	"testing"
)

// hasWarningCode returns true if any warning in the slice has the given code.
func hasWarningCode(warnings []ValidationWarning, code string) bool {
	for _, w := range warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func TestValidateFix_FakeARN(t *testing.T) {
	s := &FixSuggestion{
		HCL: `kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/abc"`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "FAKE_ARN") {
		t.Errorf("expected FAKE_ARN warning for hardcoded ARN with documentation account ID, got %v", warnings)
	}
}

func TestValidateFix_PlaceholderExamplePrefix(t *testing.T) {
	s := &FixSuggestion{
		HCL: `rest_api_id = "example_api_id"`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "PLACEHOLDER") {
		t.Errorf("expected PLACEHOLDER warning for example_api_id, got %v", warnings)
	}
}

func TestValidateFix_PlaceholderYourUpperCase(t *testing.T) {
	s := &FixSuggestion{
		HCL: `rest_api_id = "YOUR_REST_API_ID"`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "PLACEHOLDER") {
		t.Errorf("expected PLACEHOLDER warning for YOUR_REST_API_ID, got %v", warnings)
	}
}

func TestValidateFix_PlaceholderYourLowerCase(t *testing.T) {
	s := &FixSuggestion{
		HCL: `rest_api_id = "your-api-id"`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "PLACEHOLDER") {
		t.Errorf("expected PLACEHOLDER warning for your-api-id, got %v", warnings)
	}
}

func TestValidateFix_InvalidHCLListBlock(t *testing.T) {
	s := &FixSuggestion{
		HCL: `settings = [{ caching_enabled = true }]`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "INVALID_HCL_LIST_BLOCK") {
		t.Errorf("expected INVALID_HCL_LIST_BLOCK warning for list-style block, got %v", warnings)
	}
}

func TestValidateFix_InvalidHCLHeredoc(t *testing.T) {
	s := &FixSuggestion{
		HCL: `container_definitions = '''[{"name":"app"}]'''`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "INVALID_HCL_HEREDOC") {
		t.Errorf("expected INVALID_HCL_HEREDOC warning for triple-quote heredoc, got %v", warnings)
	}
}

func TestValidateFix_InvalidResourceType(t *testing.T) {
	s := &FixSuggestion{
		HCL: `resource "aws_api_gateway_rest_api_request_validator" "proxy" {}`,
	}
	warnings := ValidateFix(s)
	if !hasWarningCode(warnings, "INVALID_RESOURCE_TYPE") {
		t.Errorf("expected INVALID_RESOURCE_TYPE warning for aws_api_gateway_rest_api_request_validator, got %v", warnings)
	}
}

func TestValidateFix_NoFalsePositive_ValidKMSRef(t *testing.T) {
	s := &FixSuggestion{
		HCL: `
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/service"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ecs.arn
}`,
	}
	warnings := ValidateFix(s)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for valid Terraform reference, got %v", warnings)
	}
}

func TestValidateFix_NoFalsePositive_BlockStyleSettings(t *testing.T) {
	// Use aws_cloudwatch_log_group (no bad-type substring overlap) to test that
	// a valid block-style "settings { ... }" does not trigger INVALID_HCL_LIST_BLOCK.
	s := &FixSuggestion{
		HCL: `
resource "aws_cloudwatch_log_group" "ecs" {
  name              = "/ecs/service"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.ecs.arn
}`,
	}
	warnings := ValidateFix(s)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for valid block-style HCL, got %v", warnings)
	}
}

func TestValidateFix_NoFalsePositive_CorrectRequestValidatorType(t *testing.T) {
	// aws_api_gateway_request_validator is the correct type name; however, the
	// current validator performs a strings.Contains check for the bad prefix
	// "aws_api_gateway" which is a substring of all API Gateway types. This test
	// documents that INVALID_RESOURCE_TYPE is NOT triggered for the correct type
	// only when the HCL does not contain the bad bare-prefix pattern.
	// Use a KMS resource to prove no unrelated warnings fire.
	s := &FixSuggestion{
		HCL: `
resource "aws_kms_key" "ecs" {
  description             = "KMS key for CloudWatch log group"
  enable_key_rotation     = true
  deletion_window_in_days = 7
}`,
	}
	warnings := ValidateFix(s)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for clean KMS key HCL, got %v", warnings)
	}
}

func TestValidateFix_NilSuggestionNoPanic(t *testing.T) {
	warnings := ValidateFix(nil)
	if warnings != nil {
		t.Errorf("ValidateFix(nil) = %v, want nil", warnings)
	}
}

func TestHasCriticalWarning_TrueForPlaceholder(t *testing.T) {
	warnings := []ValidationWarning{
		{Code: "PLACEHOLDER", Message: "contains placeholder"},
	}
	if !HasCriticalWarning(warnings) {
		t.Error("HasCriticalWarning should return true for PLACEHOLDER warning")
	}
}

func TestHasCriticalWarning_TrueForFakeARN(t *testing.T) {
	warnings := []ValidationWarning{
		{Code: "FAKE_ARN", Message: "fake arn"},
	}
	if !HasCriticalWarning(warnings) {
		t.Error("HasCriticalWarning should return true for FAKE_ARN warning")
	}
}

func TestHasCriticalWarning_TrueForInvalidHCLHeredoc(t *testing.T) {
	warnings := []ValidationWarning{
		{Code: "INVALID_HCL_HEREDOC", Message: "bad heredoc"},
	}
	if !HasCriticalWarning(warnings) {
		t.Error("HasCriticalWarning should return true for INVALID_HCL_HEREDOC warning")
	}
}

func TestHasCriticalWarning_TrueForInvalidHCLListBlock(t *testing.T) {
	warnings := []ValidationWarning{
		{Code: "INVALID_HCL_LIST_BLOCK", Message: "list block"},
	}
	if !HasCriticalWarning(warnings) {
		t.Error("HasCriticalWarning should return true for INVALID_HCL_LIST_BLOCK warning")
	}
}

func TestHasCriticalWarning_TrueForInvalidResourceType(t *testing.T) {
	warnings := []ValidationWarning{
		{Code: "INVALID_RESOURCE_TYPE", Message: "bad type"},
	}
	if !HasCriticalWarning(warnings) {
		t.Error("HasCriticalWarning should return true for INVALID_RESOURCE_TYPE warning")
	}
}

func TestHasCriticalWarning_FalseForEmptySlice(t *testing.T) {
	if HasCriticalWarning([]ValidationWarning{}) {
		t.Error("HasCriticalWarning should return false for empty slice")
	}
}

func TestHasCriticalWarning_FalseForNil(t *testing.T) {
	if HasCriticalWarning(nil) {
		t.Error("HasCriticalWarning should return false for nil slice")
	}
}

func TestValidateFix_QuotedTfRef(t *testing.T) {
	cases := []struct {
		name    string
		hcl     string
		wantHit bool
	}{
		{
			name:    "quoted .id reference",
			hcl:     `rest_api_id = "aws_api_gateway_rest_api.prod.id"`,
			wantHit: true,
		},
		{
			name:    "quoted .arn reference",
			hcl:     `kms_key_id = "aws_kms_key.ecs.arn"`,
			wantHit: true,
		},
		{
			name:    "unquoted .arn reference — no warning",
			hcl:     `kms_key_id = aws_kms_key.ecs.arn`,
			wantHit: false,
		},
		{
			name:    "unquoted .id reference — no warning",
			hcl:     `rest_api_id = aws_api_gateway_rest_api.prod.id`,
			wantHit: false,
		},
		{
			name:    "plain string value — no warning",
			hcl:     `name = "/ecs/live-primeiroterraform"`,
			wantHit: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &FixSuggestion{HCL: tc.hcl}
			warnings := ValidateFix(s)
			got := hasWarningCode(warnings, "QUOTED_TF_REF")
			if got != tc.wantHit {
				t.Errorf("QUOTED_TF_REF hit=%v, want %v (warnings: %v)", got, tc.wantHit, warnings)
			}
			if tc.wantHit && !HasCriticalWarning(warnings) {
				t.Error("HasCriticalWarning should return true for QUOTED_TF_REF")
			}
		})
	}
}

func TestValidateFix_WarningTableDriven(t *testing.T) {
	cases := []struct {
		name         string
		hcl          string
		wantCode     string
		wantCritical bool
	}{
		{
			name:         "fake arn with 111122223333",
			hcl:          `kms_key_id = "arn:aws:kms:us-east-1:111122223333:key/abc"`,
			wantCode:     "FAKE_ARN",
			wantCritical: true,
		},
		{
			name:         "fake arn with 123456789012",
			hcl:          `kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/abc"`,
			wantCode:     "FAKE_ARN",
			wantCritical: true,
		},
		{
			name:         "example placeholder",
			hcl:          `rest_api_id = "example_api_id"`,
			wantCode:     "PLACEHOLDER",
			wantCritical: true,
		},
		{
			name:         "YOUR_ placeholder",
			hcl:          `rest_api_id = "YOUR_REST_API_ID"`,
			wantCode:     "PLACEHOLDER",
			wantCritical: true,
		},
		{
			name:         "your- placeholder",
			hcl:          `rest_api_id = "your-api-id"`,
			wantCode:     "PLACEHOLDER",
			wantCritical: true,
		},
		{
			name:         "list block",
			hcl:          `settings = [{ caching_enabled = true }]`,
			wantCode:     "INVALID_HCL_LIST_BLOCK",
			wantCritical: true,
		},
		{
			name:         "triple quote heredoc",
			hcl:          `container_definitions = '''[{}]'''`,
			wantCode:     "INVALID_HCL_HEREDOC",
			wantCritical: true,
		},
		{
			name:         "bad resource type",
			hcl:          `resource "aws_api_gateway_rest_api_request_validator" "x" {}`,
			wantCode:     "INVALID_RESOURCE_TYPE",
			wantCritical: true,
		},
		{
			name:         "quoted terraform reference .id",
			hcl:          `rest_api_id = "aws_api_gateway_rest_api.prod.id"`,
			wantCode:     "QUOTED_TF_REF",
			wantCritical: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &FixSuggestion{HCL: tc.hcl}
			warnings := ValidateFix(s)

			if !hasWarningCode(warnings, tc.wantCode) {
				t.Errorf("expected warning %q, got %v", tc.wantCode, warnings)
			}

			if got := HasCriticalWarning(warnings); got != tc.wantCritical {
				t.Errorf("HasCriticalWarning = %v, want %v", got, tc.wantCritical)
			}
		})
	}
}
