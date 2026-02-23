package scanner

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/rules"
)

// ===========================================================================
// Checkov parser tests
// ===========================================================================

func TestParseCheckovOutput_SingleReport(t *testing.T) {
	data := []byte(`{
		"results": {
			"failed_checks": [
				{
					"check_id": "CKV_AWS_24",
					"check_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
					"check_result": {"result": "FAILED"},
					"resource_address": "aws_security_group.allow_ssh",
					"severity": "HIGH",
					"guideline": "https://docs.checkov.io/CKV_AWS_24"
				}
			]
		}
	}`)

	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CKV_AWS_24" {
		t.Errorf("expected RuleID CKV_AWS_24, got %s", f.RuleID)
	}
	if f.Severity != rules.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", f.Severity)
	}
	if f.Resource != "aws_security_group.allow_ssh" {
		t.Errorf("expected resource aws_security_group.allow_ssh, got %s", f.Resource)
	}
	if f.Source != "scanner:checkov" {
		t.Errorf("expected source scanner:checkov, got %s", f.Source)
	}
}

func TestParseCheckovOutput_MultiReport(t *testing.T) {
	data := []byte(`[
		{
			"results": {
				"failed_checks": [
					{"check_id": "CKV_AWS_1", "check_name": "Check1", "resource_address": "r1", "severity": "LOW"}
				]
			}
		},
		{
			"results": {
				"failed_checks": [
					{"check_id": "CKV_AWS_2", "check_name": "Check2", "resource_address": "r2", "severity": "MEDIUM"}
				]
			}
		}
	]`)

	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestParseCheckovOutput_Empty(t *testing.T) {
	findings, err := parseCheckovOutput(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseCheckovOutput_NoFailedChecks(t *testing.T) {
	data := []byte(`{"results": {"failed_checks": []}}`)
	findings, err := parseCheckovOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestConvertCheckovFindings_FallbackResource(t *testing.T) {
	checks := []checkovCheck{
		{
			CheckID:      "CKV_AWS_1",
			CheckName:    "Test check",
			ResourceAddr: "",
			FilePath:     "main.tf",
			Severity:     "MEDIUM",
		},
	}
	findings := convertCheckovFindings(checks)
	if findings[0].Resource != "main.tf" {
		t.Errorf("expected fallback to FilePath, got %s", findings[0].Resource)
	}
}

func TestConvertCheckovFindings_FallbackDescription(t *testing.T) {
	checks := []checkovCheck{
		{
			CheckID:      "CKV_AWS_1",
			CheckName:    "",
			Description:  "A description",
			ResourceAddr: "r1",
			Severity:     "HIGH",
		},
	}
	findings := convertCheckovFindings(checks)
	if findings[0].Message != "[checkov] CKV_AWS_1: A description" {
		t.Errorf("expected description fallback, got %s", findings[0].Message)
	}
}

func TestMapCheckovSeverity(t *testing.T) {
	tests := []struct {
		severity string
		checkID  string
		want     string
	}{
		{"CRITICAL", "CKV_AWS_1", rules.SeverityCritical},
		{"HIGH", "CKV_AWS_1", rules.SeverityHigh},
		{"MEDIUM", "CKV_AWS_1", rules.SeverityMedium},
		{"LOW", "CKV_AWS_1", rules.SeverityLow},
		{"INFO", "CKV_AWS_1", rules.SeverityInfo},
		{"", "CKV_AWS_SECRET_1", rules.SeverityCritical}, // SECRET keyword
		{"", "CKV_AWS_CRED_1", rules.SeverityCritical},   // CRED keyword
		{"", "CKV_AWS_1", rules.SeverityHigh},            // default fallback
	}
	for _, tt := range tests {
		if got := mapCheckovSeverity(tt.severity, tt.checkID); got != tt.want {
			t.Errorf("mapCheckovSeverity(%q, %q) = %q, want %q", tt.severity, tt.checkID, got, tt.want)
		}
	}
}

func TestInferCheckovCategory(t *testing.T) {
	tests := []struct {
		checkID string
		want    string
	}{
		{"CKV_AWS_ENCRYPT_1", rules.CategorySecurity},
		{"CKV_AWS_SSL_1", rules.CategorySecurity},
		{"CKV_AWS_TLS_1", rules.CategorySecurity},
		{"CKV_AWS_LOG_1", rules.CategoryCompliance},
		{"CKV_AWS_MONITOR_1", rules.CategoryCompliance},
		{"CKV_AWS_BACKUP_1", rules.CategoryReliability},
		{"CKV_AWS_HA_1", rules.CategoryReliability},
		{"CKV_AWS_MULTI_AZ", rules.CategoryReliability},
		{"CKV_AWS_1", rules.CategorySecurity}, // default
	}
	for _, tt := range tests {
		if got := inferCheckovCategory(tt.checkID); got != tt.want {
			t.Errorf("inferCheckovCategory(%q) = %q, want %q", tt.checkID, got, tt.want)
		}
	}
}

// ===========================================================================
// TFSec parser tests
// ===========================================================================

func TestParseTfsecOutput_Valid(t *testing.T) {
	data := []byte(`{
		"results": [
			{
				"rule_id": "aws-iam-no-policy-wildcards",
				"long_id": "aws-iam-no-policy-wildcards",
				"rule_description": "IAM policy should avoid wildcards",
				"description": "IAM policy document uses wildcard",
				"severity": "HIGH",
				"resource": "aws_iam_policy.admin",
				"resolution": "Restrict IAM actions",
				"location": {"filename": "main.tf", "start_line": 10, "end_line": 15}
			}
		]
	}`)

	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != rules.SeverityHigh {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}
	if f.Source != "scanner:tfsec" {
		t.Errorf("expected source scanner:tfsec, got %s", f.Source)
	}
	if f.Remediation != "Restrict IAM actions" {
		t.Errorf("expected remediation, got %s", f.Remediation)
	}
}

func TestParseTfsecOutput_InvalidJSON(t *testing.T) {
	_, err := parseTfsecOutput([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseTfsecOutput_EmptyResults(t *testing.T) {
	data := []byte(`{"results": []}`)
	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTfsecOutput_FallbackFields(t *testing.T) {
	data := []byte(`{
		"results": [
			{
				"rule_id": "",
				"long_id": "aws-s3-long-id",
				"rule_description": "fallback desc",
				"description": "",
				"severity": "LOW",
				"resource": "",
				"location": {"filename": "s3.tf"}
			}
		]
	}`)

	findings, err := parseTfsecOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].RuleID != "aws-s3-long-id" {
		t.Errorf("expected long_id fallback, got %s", findings[0].RuleID)
	}
	if findings[0].Resource != "s3.tf" {
		t.Errorf("expected filename fallback, got %s", findings[0].Resource)
	}
}

// ===========================================================================
// Trivy parser tests
// ===========================================================================

func TestParseTrivyOutput_Valid(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "main.tf",
				"Misconfigurations": [
					{
						"Type": "Terraform Security Check",
						"ID": "AVD-AWS-0086",
						"AVDID": "AVD-AWS-0086",
						"Title": "S3 Access Block",
						"Description": "S3 bucket has no public access block",
						"Message": "Public access is not blocked",
						"Resolution": "Add public access block",
						"Severity": "HIGH",
						"Status": "FAIL",
						"CauseMetadata": {
							"Resource": "aws_s3_bucket.data",
							"StartLine": 1,
							"EndLine": 5
						}
					}
				]
			}
		]
	}`)

	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "AVD-AWS-0086" {
		t.Errorf("expected AVD-AWS-0086, got %s", f.RuleID)
	}
	if f.Resource != "aws_s3_bucket.data" {
		t.Errorf("expected aws_s3_bucket.data, got %s", f.Resource)
	}
	if f.Source != "scanner:trivy" {
		t.Errorf("expected scanner:trivy, got %s", f.Source)
	}
}

func TestParseTrivyOutput_SkipPass(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "main.tf",
				"Misconfigurations": [
					{
						"ID": "AVD-001",
						"AVDID": "AVD-001",
						"Severity": "LOW",
						"Status": "PASS",
						"Message": "Check passed"
					},
					{
						"ID": "AVD-002",
						"AVDID": "AVD-002",
						"Severity": "HIGH",
						"Status": "FAIL",
						"Message": "Check failed",
						"CauseMetadata": {"Resource": "r1"}
					}
				]
			}
		]
	}`)

	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (PASS skipped), got %d", len(findings))
	}
	if findings[0].RuleID != "AVD-002" {
		t.Errorf("expected AVD-002, got %s", findings[0].RuleID)
	}
}

func TestParseTrivyOutput_InvalidJSON(t *testing.T) {
	_, err := parseTrivyOutput([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseTrivyOutput_FallbackFields(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "vpc.tf",
				"Misconfigurations": [
					{
						"ID": "tfsec-id",
						"AVDID": "",
						"Severity": "MEDIUM",
						"Status": "FAIL",
						"Message": "",
						"Description": "fallback description",
						"CauseMetadata": {"Resource": ""}
					}
				]
			}
		]
	}`)

	findings, err := parseTrivyOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// AVDID empty → should fall back to ID
	if findings[0].RuleID != "tfsec-id" {
		t.Errorf("expected ID fallback, got %s", findings[0].RuleID)
	}
	// Resource empty → should fall back to Target
	if findings[0].Resource != "vpc.tf" {
		t.Errorf("expected Target fallback, got %s", findings[0].Resource)
	}
}

func TestMapTfsecSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"CRITICAL", rules.SeverityCritical},
		{"HIGH", rules.SeverityHigh},
		{"MEDIUM", rules.SeverityMedium},
		{"LOW", rules.SeverityLow},
		{"critical", rules.SeverityCritical}, // case insensitive
		{"UNKNOWN", rules.SeverityMedium},    // default
		{"", rules.SeverityMedium},
	}
	for _, tt := range tests {
		if got := mapTfsecSeverity(tt.severity); got != tt.want {
			t.Errorf("mapTfsecSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestInferTfsecCategory(t *testing.T) {
	tests := []struct {
		ruleID string
		want   string
	}{
		{"aws-iam-no-wildcards", rules.CategorySecurity},
		{"aws-auth-something", rules.CategorySecurity},
		{"aws-encrypt-at-rest", rules.CategorySecurity},
		{"aws-log-enabled", rules.CategoryCompliance},
		{"aws-monitor-check", rules.CategoryCompliance},
		{"aws-audit-trail", rules.CategoryCompliance},
		{"aws-backup-enabled", rules.CategoryReliability},
		{"aws-replica-check", rules.CategoryReliability},
		{"aws-some-other-check", rules.CategorySecurity}, // default
	}
	for _, tt := range tests {
		if got := inferTfsecCategory(tt.ruleID); got != tt.want {
			t.Errorf("inferTfsecCategory(%q) = %q, want %q", tt.ruleID, got, tt.want)
		}
	}
}

// ===========================================================================
// Terrascan parser tests
// ===========================================================================

func TestParseTerrascanOutput_Valid(t *testing.T) {
	data := []byte(`{
		"results": {
			"violations": [
				{
					"rule_name": "s3BucketEncryption",
					"description": "S3 bucket encryption not enabled",
					"rule_id": "AC_AWS_0207",
					"severity": "HIGH",
					"category": "Security Best Practices",
					"resource_name": "aws_s3_bucket.data",
					"resource_type": "aws_s3_bucket",
					"file": "main.tf",
					"line": 10
				}
			],
			"count": {"low": 0, "medium": 0, "high": 1, "total": 1}
		}
	}`)

	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "AC_AWS_0207" {
		t.Errorf("expected AC_AWS_0207, got %s", f.RuleID)
	}
	if f.Severity != rules.SeverityHigh {
		t.Errorf("expected HIGH, got %s", f.Severity)
	}
	if f.Source != "scanner:terrascan" {
		t.Errorf("expected scanner:terrascan, got %s", f.Source)
	}
}

func TestParseTerrascanOutput_InvalidJSON(t *testing.T) {
	_, err := parseTerrascanOutput([]byte("bad"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseTerrascanOutput_EmptyViolations(t *testing.T) {
	data := []byte(`{"results": {"violations": null, "count": {"total": 0}}}`)
	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseTerrascanOutput_FallbackResource(t *testing.T) {
	data := []byte(`{
		"results": {
			"violations": [
				{
					"rule_name": "testRule",
					"rule_id": "",
					"description": "test",
					"severity": "LOW",
					"category": "general",
					"resource_name": "",
					"file": "vpc.tf",
					"line": 42
				}
			],
			"count": {"total": 1}
		}
	}`)

	findings, err := parseTerrascanOutput(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// resource_name empty → file:line
	if findings[0].Resource != "vpc.tf:42" {
		t.Errorf("expected vpc.tf:42, got %s", findings[0].Resource)
	}
	// rule_id empty → rule_name fallback
	if findings[0].RuleID != "testRule" {
		t.Errorf("expected testRule, got %s", findings[0].RuleID)
	}
}

func TestMapTerrascanSeverity(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"HIGH", rules.SeverityHigh},
		{"MEDIUM", rules.SeverityMedium},
		{"LOW", rules.SeverityLow},
		{"high", rules.SeverityHigh}, // case insensitive
		{"UNKNOWN", rules.SeverityMedium},
		{"", rules.SeverityMedium},
	}
	for _, tt := range tests {
		if got := mapTerrascanSeverity(tt.severity); got != tt.want {
			t.Errorf("mapTerrascanSeverity(%q) = %q, want %q", tt.severity, got, tt.want)
		}
	}
}

func TestMapTerrascanCategory(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{"Security Best Practices", rules.CategorySecurity},
		{"IAM Policies", rules.CategorySecurity},
		{"Encryption at Rest", rules.CategorySecurity},
		{"Compliance Monitoring", rules.CategoryCompliance},
		{"Logging and Auditing", rules.CategoryCompliance},
		{"Monitor Resources", rules.CategoryCompliance},
		{"Resilience & HA", rules.CategoryReliability},
		{"Availability Zone", rules.CategoryReliability},
		{"Backup Strategy", rules.CategoryReliability},
		{"Best Practice", rules.CategoryBestPractice},
		{"General Practice", rules.CategoryBestPractice},
		{"Unknown Category", rules.CategorySecurity}, // default
	}
	for _, tt := range tests {
		if got := mapTerrascanCategory(tt.category); got != tt.want {
			t.Errorf("mapTerrascanCategory(%q) = %q, want %q", tt.category, got, tt.want)
		}
	}
}
