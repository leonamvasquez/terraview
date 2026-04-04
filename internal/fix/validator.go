package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// ValidationWarning describes a potential problem detected in a generated fix.
type ValidationWarning struct {
	Code    string // machine-readable code (PLACEHOLDER, INVALID_HCL, etc.)
	Message string // human-readable description
}

// ValidateFix inspects a FixSuggestion for common AI-generation defects:
//   - Placeholder strings that would break terraform apply
//   - Fake account IDs or ARNs used as literal values
//   - Invalid HCL syntax patterns
//   - Non-existent Terraform resource types
//
// Returns a (possibly empty) slice of warnings. Callers should display warnings
// to the user but should not block the fix output — the user can still review
// and correct the HCL.
func ValidateFix(s *FixSuggestion) []ValidationWarning {
	if s == nil {
		return nil
	}
	var warnings []ValidationWarning

	hcl := s.HCL
	prereqs := strings.Join(s.Prerequisites, "\n")

	// 1. Placeholder string detection
	for _, p := range placeholderPatterns {
		if p.re.MatchString(hcl) || p.re.MatchString(prereqs) {
			warnings = append(warnings, ValidationWarning{
				Code:    "PLACEHOLDER",
				Message: fmt.Sprintf("o fix contém valor placeholder (%s) — substitua pela referência Terraform real antes de aplicar", p.example),
			})
			break // one placeholder warning is enough
		}
	}

	// 2. Fake ARN detection
	if fakeARNRe.MatchString(hcl) {
		warnings = append(warnings, ValidationWarning{
			Code:    "FAKE_ARN",
			Message: "o fix contém um ARN com account ID de documentação (ex: 111122223333 ou 123456789012) — substitua pela referência Terraform real",
		})
	}

	// 3. Quoted Terraform reference (e.g. rest_api_id = "aws_foo.bar.id")
	if quotedTfRefRe.MatchString(hcl) {
		warnings = append(warnings, ValidationWarning{
			Code:    "QUOTED_TF_REF",
			Message: "o fix usa uma referência Terraform entre aspas (ex: \"aws_kms_key.main.arn\") — remova as aspas para que seja uma referência HCL válida",
		})
	}

	// 4. Invalid HCL: triple-quote heredoc
	if strings.Contains(hcl, "'''") {
		warnings = append(warnings, ValidationWarning{
			Code:    "INVALID_HCL_HEREDOC",
			Message: "o fix usa sintaxe ''' que não é HCL válido — use jsonencode() para conteúdo JSON",
		})
	}

	// 5. Invalid HCL: block written as list
	if listBlockRe.MatchString(hcl) {
		warnings = append(warnings, ValidationWarning{
			Code:    "INVALID_HCL_LIST_BLOCK",
			Message: "o fix usa 'block = [{ ... }]' — use a forma de bloco 'block { ... }' em vez disso",
		})
	}

	// 6. Non-existent resource type — use word-boundary matching to avoid
	// false positives on valid types that share a common prefix
	// (e.g. "aws_api_gateway" must not match "aws_api_gateway_rest_api").
	for _, bt := range knownBadResourceTypes {
		if containsWholeWord(hcl, bt) {
			warnings = append(warnings, ValidationWarning{
				Code:    "INVALID_RESOURCE_TYPE",
				Message: fmt.Sprintf("o fix referencia o tipo '%s' que não existe no provider AWS — verifique o nome correto do recurso", bt),
			})
		}
	}

	return warnings
}

// HasCriticalWarning returns true if any warning indicates the fix would fail
// terraform apply or terraform validate without modification.
func HasCriticalWarning(warnings []ValidationWarning) bool {
	for _, w := range warnings {
		switch w.Code {
		case "PLACEHOLDER", "FAKE_ARN", "QUOTED_TF_REF", "INVALID_HCL_HEREDOC", "INVALID_HCL_LIST_BLOCK", "INVALID_RESOURCE_TYPE":
			return true
		}
	}
	return false
}

// -- patterns ------------------------------------------------------------------

type placeholderPattern struct {
	re      *regexp.Regexp
	example string
}

var placeholderPatterns = []placeholderPattern{
	{regexp.MustCompile(`(?i)example_[a-z_]+`), `"example_api_id"`},
	{regexp.MustCompile(`YOUR_[A-Z_]+`), `"YOUR_REST_API_ID"`},
	{regexp.MustCompile(`PLACEHOLDER_[A-Z_]+`), `"PLACEHOLDER_API_ID"`},
	{regexp.MustCompile(`REPLACE_WITH_`), `"REPLACE_WITH_YOUR_..."`},
	{regexp.MustCompile(`your-[a-z][a-z0-9-]+`), `"your-kms-key-id"`},
	{regexp.MustCompile(`<[a-z][a-z_]+>`), `"<rest_api_id>"`},
	{regexp.MustCompile(`\bREGION\b|\bACCOUNT_ID\b`), `"REGION"` + " or " + `"ACCOUNT_ID"`},
	{regexp.MustCompile(`api-id-from-other-resource`), `"api-id-from-other-resource"`},
}

// quotedTfRefRe matches a Terraform reference that is incorrectly wrapped in quotes,
// e.g. rest_api_id = "aws_api_gateway_rest_api.prod.id"
// The pattern looks for = "aws_<type>.<name>.<attr>" where the value ends with .id or .arn.
var quotedTfRefRe = regexp.MustCompile(`=\s*"aws_[a-z_]+\.[a-z_][a-z0-9_.]*\.(id|arn)"`)

// fakeARNRe matches ARNs containing documentation sentinel account IDs.
var fakeARNRe = regexp.MustCompile(
	`arn:aws:[^:]+:[^:]*:(?:111122223333|123456789012|000000000000|ACCOUNT_ID|REGION)`,
)

// listBlockRe matches the pattern `word = [{` which indicates a block written
// incorrectly as an HCL list.
var listBlockRe = regexp.MustCompile(`\w+\s*=\s*\[{`)

// knownBadResourceTypes are Terraform resource type names that do not exist in
// the AWS provider but have been observed in AI-generated fixes.
// Each entry is matched as a whole word (not substring) to prevent false
// positives on valid types that share a prefix.
var knownBadResourceTypes = []string{
	"aws_api_gateway_rest_api_request_validator", // correct: aws_api_gateway_request_validator
	"aws_api_gateway_resource_validator",         // correct: aws_api_gateway_request_validator
	"aws_cloudwatch_logs_group",                  // correct: aws_cloudwatch_log_group
}

// containsWholeWord reports whether s contains word as a whole word
// (surrounded by non-alphanumeric, non-underscore characters or string boundaries).
func containsWholeWord(s, word string) bool {
	re := regexp.MustCompile(`(?:^|[^a-zA-Z0-9_])` + regexp.QuoteMeta(word) + `(?:[^a-zA-Z0-9_]|$)`)
	return re.MatchString(s)
}
