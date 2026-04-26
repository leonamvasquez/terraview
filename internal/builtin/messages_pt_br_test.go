package builtin

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/parser"
)

// TestBUG005_Finding_DefaultEnglish verifies that the finding() helper
// returns English messages by default (no --br).
func TestBUG005_Finding_DefaultEnglish(t *testing.T) {
	i18n.SetLang("en")
	r := parser.NormalizedResource{Address: "aws_s3_bucket.test", Type: "aws_s3_bucket", Action: "create"}
	f := finding(r, "CKV_AWS_19", "HIGH", "security",
		"S3 bucket does not have server-side encryption enabled", "add encryption")
	if f.Message != "S3 bucket does not have server-side encryption enabled" {
		t.Errorf("BUG-005: default message should be English, got: %q", f.Message)
	}
}

// TestBUG005_Finding_PTBRTranslated verifies that when pt-BR is active,
// a known rule ID returns the translated message.
func TestBUG005_Finding_PTBRTranslated(t *testing.T) {
	i18n.SetLang("pt-BR")
	t.Cleanup(func() { i18n.SetLang("en") })

	r := parser.NormalizedResource{Address: "aws_s3_bucket.test", Type: "aws_s3_bucket", Action: "create"}
	f := finding(r, "CKV_AWS_19", "HIGH", "security",
		"S3 bucket does not have server-side encryption enabled", "add encryption")

	want := messagesPTBR["CKV_AWS_19"]
	if f.Message != want {
		t.Errorf("BUG-005: pt-BR message = %q, want %q", f.Message, want)
	}
}

// TestBUG005_Finding_PTBRUnknownRule verifies that an unknown rule ID keeps
// the original English message even with pt-BR active.
func TestBUG005_Finding_PTBRUnknownRule(t *testing.T) {
	i18n.SetLang("pt-BR")
	t.Cleanup(func() { i18n.SetLang("en") })

	r := parser.NormalizedResource{Address: "custom.resource", Action: "create"}
	original := "some custom message"
	f := finding(r, "CUSTOM_999", "LOW", "security", original, "")
	if f.Message != original {
		t.Errorf("BUG-005: unknown rule should keep original message, got %q", f.Message)
	}
}

// TestBUG005_MessagesPTBR_Coverage verifies every rule in messagesPTBR has a
// non-empty translation and exists in allRules.
func TestBUG005_MessagesPTBR_Coverage(t *testing.T) {
	ruleIDs := make(map[string]bool, len(allRules))
	for _, rule := range allRules {
		ruleIDs[rule.ID] = true
	}

	for id, msg := range messagesPTBR {
		if msg == "" {
			t.Errorf("BUG-005: messagesPTBR[%q] is empty", id)
		}
		if !ruleIDs[id] {
			t.Errorf("BUG-005: messagesPTBR[%q] has no corresponding rule in allRules", id)
		}
	}
}
