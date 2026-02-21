package importer

import (
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
