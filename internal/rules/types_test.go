package rules

import (
	"encoding/json"
	"testing"
)

func TestSeverityConstants(t *testing.T) {
	expected := map[string]string{
		"CRITICAL": SeverityCritical,
		"HIGH":     SeverityHigh,
		"MEDIUM":   SeverityMedium,
		"LOW":      SeverityLow,
		"INFO":     SeverityInfo,
	}
	for want, got := range expected {
		if got != want {
			t.Errorf("severity %q = %q", want, got)
		}
	}
}

func TestCategoryConstants(t *testing.T) {
	expected := map[string]string{
		"security":        CategorySecurity,
		"compliance":      CategoryCompliance,
		"best-practice":   CategoryBestPractice,
		"maintainability": CategoryMaintainability,
		"reliability":     CategoryReliability,
	}
	for want, got := range expected {
		if got != want {
			t.Errorf("category %q = %q", want, got)
		}
	}
}

func TestFinding_JSONRoundTrip(t *testing.T) {
	f := Finding{
		RuleID:      "SEC001",
		Severity:    SeverityCritical,
		Category:    CategorySecurity,
		Resource:    "aws_security_group.open",
		Message:     "Security group allows all ingress",
		Remediation: "Restrict CIDR to specific IPs",
		Source:      "checkov",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.RuleID != f.RuleID {
		t.Errorf("RuleID: got %q, want %q", decoded.RuleID, f.RuleID)
	}
	if decoded.Severity != f.Severity {
		t.Errorf("Severity: got %q, want %q", decoded.Severity, f.Severity)
	}
	if decoded.Category != f.Category {
		t.Errorf("Category: got %q, want %q", decoded.Category, f.Category)
	}
	if decoded.Resource != f.Resource {
		t.Errorf("Resource: got %q, want %q", decoded.Resource, f.Resource)
	}
	if decoded.Message != f.Message {
		t.Errorf("Message: got %q, want %q", decoded.Message, f.Message)
	}
	if decoded.Remediation != f.Remediation {
		t.Errorf("Remediation: got %q, want %q", decoded.Remediation, f.Remediation)
	}
	if decoded.Source != f.Source {
		t.Errorf("Source: got %q, want %q", decoded.Source, f.Source)
	}
}

func TestFinding_JSONOmitEmpty(t *testing.T) {
	f := Finding{
		RuleID:   "SEC002",
		Severity: SeverityLow,
		Category: CategoryCompliance,
		Resource: "aws_s3_bucket.logs",
		Message:  "Missing versioning",
		Source:   "tfsec",
		// Remediation intentionally empty
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	s := string(data)
	if contains(s, "remediation") {
		t.Error("empty Remediation should be omitted from JSON")
	}
}

func TestFinding_JSONFields(t *testing.T) {
	f := Finding{
		RuleID:   "R1",
		Severity: SeverityInfo,
		Category: CategoryBestPractice,
		Resource: "r",
		Message:  "m",
		Source:   "s",
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)

	// Verify JSON field names match expected snake_case
	for _, expected := range []string{`"rule_id"`, `"severity"`, `"category"`, `"resource"`, `"message"`, `"source"`} {
		if !contains(s, expected) {
			t.Errorf("expected JSON field %s in output: %s", expected, s)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsSubstring(s, sub))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
