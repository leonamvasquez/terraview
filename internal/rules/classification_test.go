package rules

import "testing"

func TestAdvisoryReason_KnownRules(t *testing.T) {
	cases := []string{"CKV_AWS_273", "CKV_AWS_157", "CKV_AWS_61"}
	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			reason, ok := AdvisoryReason(id)
			if !ok {
				t.Fatalf("expected %s to be advisory", id)
			}
			if reason == "" {
				t.Errorf("advisory %s must have a non-empty reason", id)
			}
		})
	}
}

func TestAdvisoryReason_UnknownRule(t *testing.T) {
	if reason, ok := AdvisoryReason("CKV_AWS_19"); ok {
		t.Errorf("CKV_AWS_19 (S3 SSE) should be auto-fixable, got advisory: %q", reason)
	}
	if reason, ok := AdvisoryReason("UNKNOWN_RULE"); ok {
		t.Errorf("unknown rule must default to auto-fixable, got: %q", reason)
	}
}

func TestAdvisoryReasonForFinding_Patterns(t *testing.T) {
	cases := []struct {
		name    string
		finding Finding
		want    bool
	}{
		{
			name:    "trivy wildcard policy by message",
			finding: Finding{RuleID: "AVD-AWS-0057", Message: "IAM policy uses wildcard action \"*\""},
			want:    true,
		},
		{
			name:    "terrascan rds publicly accessible",
			finding: Finding{RuleID: "AC_AWS_0044", Message: "RDS instance is publicly accessible"},
			want:    true,
		},
		{
			name:    "trivy lambda runtime deprecated",
			finding: Finding{RuleID: "AVD-AWS-0066", Message: "Lambda function uses a deprecated runtime"},
			want:    true,
		},
		{
			name:    "terrascan default security group",
			finding: Finding{RuleID: "AC_AWS_0229", Message: "Default security group is in use"},
			want:    true,
		},
		{
			name:    "hard-coded secret in env",
			finding: Finding{RuleID: "TF_GENERIC", Message: "API key in environment variable"},
			want:    true,
		},
		{
			name:    "deletion protection toggle",
			finding: Finding{RuleID: "AC_AWS_0501", Message: "Deletion protection is disabled"},
			want:    true,
		},
		{
			name:    "auto-fixable S3 SSE",
			finding: Finding{RuleID: "AVD-AWS-0088", Message: "S3 bucket missing server-side encryption"},
			want:    false,
		},
		{
			name:    "auto-fixable security group ingress",
			finding: Finding{RuleID: "AVD-AWS-0107", Message: "Security group rule allows ingress from 0.0.0.0/0"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := AdvisoryReasonForFinding(tc.finding)
			if ok != tc.want {
				t.Fatalf("AdvisoryReasonForFinding=%v want %v (reason=%q)", ok, tc.want, reason)
			}
			if ok && reason == "" {
				t.Error("matched advisory must have a non-empty reason")
			}
		})
	}
}

func TestIsArchitecturalFinding(t *testing.T) {
	if !IsArchitecturalFinding("llm", "architecture") {
		t.Error("AI architecture finding must be advisory")
	}
	if IsArchitecturalFinding("scanner:checkov", "security") {
		t.Error("checkov security finding must NOT be advisory by category")
	}
	if !IsArchitecturalFinding("scanner:checkov", "architecture") {
		t.Error("any architecture finding (including scanner) is advisory")
	}
}
