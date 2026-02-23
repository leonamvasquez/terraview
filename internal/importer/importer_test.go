package importer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFormat_Checkov(t *testing.T) {
	data := []byte(`{"results": {"failed_checks": [{"check_id": "CKV_AWS_1"}]}}`)
	if format := DetectFormat(data); format != "checkov" {
		t.Errorf("expected checkov, got %s", format)
	}
}

func TestDetectFormat_Tfsec(t *testing.T) {
	data := []byte(`{"results": [{"rule_id": "AWS001", "severity": "HIGH"}]}`)
	if format := DetectFormat(data); format != "tfsec" {
		t.Errorf("expected tfsec, got %s", format)
	}
}

func TestDetectFormat_SARIF(t *testing.T) {
	data := []byte(`{"$schema": "https://sarif.example.com/schema", "runs": []}`)
	if format := DetectFormat(data); format != "sarif" {
		t.Errorf("expected sarif, got %s", format)
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	data := []byte(`{"foo": "bar"}`)
	if format := DetectFormat(data); format != "unknown" {
		t.Errorf("expected unknown, got %s", format)
	}
}

func TestDetectFormat_InvalidJSON(t *testing.T) {
	data := []byte(`not json`)
	if format := DetectFormat(data); format != "unknown" {
		t.Errorf("expected unknown, got %s", format)
	}
}

func TestImport_NonexistentFile(t *testing.T) {
	_, err := Import("/nonexistent/file.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestMapCheckovSeverity(t *testing.T) {
	if got := mapCheckovSeverity("CKV_AWS_123"); got != "HIGH" {
		t.Errorf("expected HIGH, got %s", got)
	}
	if got := mapCheckovSeverity("CKV_OTHER"); got != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", got)
	}
}

func TestMapTfsecSeverity(t *testing.T) {
	if got := mapTfsecSeverity("CRITICAL"); got != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %s", got)
	}
	if got := mapTfsecSeverity("other"); got != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", got)
	}
}

func TestMapSARIFLevel(t *testing.T) {
	if got := mapSARIFLevel("error"); got != "HIGH" {
		t.Errorf("expected HIGH, got %s", got)
	}
	if got := mapSARIFLevel("warning"); got != "MEDIUM" {
		t.Errorf("expected MEDIUM, got %s", got)
	}
	if got := mapSARIFLevel("note"); got != "LOW" {
		t.Errorf("expected LOW, got %s", got)
	}
}

// ---------------------------------------------------------------------------
// importCheckov
// ---------------------------------------------------------------------------

func TestImportCheckov_Valid(t *testing.T) {
	data := []byte(`{
		"results": {
			"failed_checks": [
				{
					"check_id": "CKV_AWS_24",
					"check_result": {"result": "FAILED"},
					"resource_address": "aws_security_group.allow_ssh",
					"guideline": "https://docs.checkov.io"
				},
				{
					"check_id": "CKV_OTHER_1",
					"check_result": {"result": "FAILED"},
					"resource_address": "aws_s3_bucket.data",
					"guideline": "Check encryption"
				}
			]
		}
	}`)

	findings, err := importCheckov(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// CKV_AWS_ prefix → HIGH
	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH for CKV_AWS_, got %s", findings[0].Severity)
	}
	// CKV_OTHER_ → MEDIUM
	if findings[1].Severity != "MEDIUM" {
		t.Errorf("expected MEDIUM for CKV_OTHER_, got %s", findings[1].Severity)
	}
	if findings[0].Source != "external:checkov" {
		t.Errorf("expected external:checkov, got %s", findings[0].Source)
	}
}

func TestImportCheckov_InvalidJSON(t *testing.T) {
	_, err := importCheckov([]byte("bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestImportCheckov_Empty(t *testing.T) {
	data := []byte(`{"results": {"failed_checks": []}}`)
	findings, err := importCheckov(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// importTfsec
// ---------------------------------------------------------------------------

func TestImportTfsec_Valid(t *testing.T) {
	data := []byte(`{
		"results": [
			{
				"rule_id": "aws-iam-001",
				"description": "IAM wildcard",
				"severity": "HIGH",
				"resource": "aws_iam_policy.admin"
			}
		]
	}`)

	findings, err := importTfsec(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH, got %s", findings[0].Severity)
	}
	if findings[0].Source != "external:tfsec" {
		t.Errorf("expected external:tfsec, got %s", findings[0].Source)
	}
}

func TestImportTfsec_InvalidJSON(t *testing.T) {
	_, err := importTfsec([]byte("nope"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// importSARIF
// ---------------------------------------------------------------------------

func TestImportSARIF_Valid(t *testing.T) {
	data := []byte(`{
		"runs": [
			{
				"tool": {"driver": {"name": "checkov"}},
				"results": [
					{
						"ruleId": "CKV_AWS_1",
						"level": "error",
						"message": {"text": "S3 bucket not encrypted"},
						"locations": [
							{
								"physicalLocation": {
									"artifactLocation": {"uri": "main.tf"}
								}
							}
						]
					}
				]
			}
		]
	}`)

	findings, err := importSARIF(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Errorf("expected HIGH (error→HIGH), got %s", findings[0].Severity)
	}
	if findings[0].Resource != "main.tf" {
		t.Errorf("expected main.tf, got %s", findings[0].Resource)
	}
	if findings[0].Source != "external:checkov" {
		t.Errorf("expected external:checkov, got %s", findings[0].Source)
	}
}

func TestImportSARIF_NoLocations(t *testing.T) {
	data := []byte(`{
		"runs": [
			{
				"tool": {"driver": {"name": "tool1"}},
				"results": [
					{
						"ruleId": "R1",
						"level": "warning",
						"message": {"text": "test"}
					}
				]
			}
		]
	}`)

	findings, err := importSARIF(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Resource != "" {
		t.Errorf("expected empty resource, got %s", findings[0].Resource)
	}
}

func TestImportSARIF_NoToolName(t *testing.T) {
	data := []byte(`{
		"runs": [
			{
				"tool": {"driver": {"name": ""}},
				"results": [
					{
						"ruleId": "R1",
						"level": "note",
						"message": {"text": "info"}
					}
				]
			}
		]
	}`)

	findings, err := importSARIF(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if findings[0].Source != "external:sarif" {
		t.Errorf("expected external:sarif fallback, got %s", findings[0].Source)
	}
}

func TestImportSARIF_InvalidJSON(t *testing.T) {
	_, err := importSARIF([]byte("invalid"))
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// DetectFormat edge cases
// ---------------------------------------------------------------------------

func TestDetectFormat_SARIFByRunsKey(t *testing.T) {
	data := []byte(`{"runs": [{"tool": {"driver": {"name": "test"}}}]}`)
	if format := DetectFormat(data); format != "sarif" {
		t.Errorf("expected sarif (by runs key), got %s", format)
	}
}

// ---------------------------------------------------------------------------
// Import integration with temp files
// ---------------------------------------------------------------------------

func TestImport_CheckovFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkov.json")
	data := []byte(`{
		"results": {
			"failed_checks": [
				{"check_id": "CKV_AWS_1", "resource_address": "r1", "guideline": "fix it"}
			]
		}
	}`)
	os.WriteFile(path, data, 0644)

	findings, err := Import(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestImport_TfsecFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tfsec.json")
	data := []byte(`{
		"results": [
			{"rule_id": "AWS001", "description": "test", "severity": "MEDIUM", "resource": "r1"}
		]
	}`)
	os.WriteFile(path, data, 0644)

	findings, err := Import(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestImport_SARIFFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "results.sarif.json")
	data := []byte(`{
		"$schema": "https://sarif.example.com/schema",
		"runs": [
			{
				"tool": {"driver": {"name": "tool"}},
				"results": [
					{"ruleId": "R1", "level": "error", "message": {"text": "issue"}}
				]
			}
		]
	}`)
	os.WriteFile(path, data, 0644)

	findings, err := Import(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestImport_UnknownFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unknown.json")
	os.WriteFile(path, []byte(`{"random": true}`), 0644)

	_, err := Import(path)
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}
