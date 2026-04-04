package fix

import (
	"fmt"
	"testing"
)

func TestRequiredResourceType(t *testing.T) {
	cases := []struct {
		ruleID string
		want   string
	}{
		{"CKV_AWS_158", "aws_kms_key"},
		{"CKV2_AWS_53", "aws_api_gateway_request_validator"},
		{"CKV2_AWS_51", "aws_api_gateway_client_certificate"},
		{"CKV_AWS_7", "aws_kms_key"},
		{"UNKNOWN_RULE", ""},
		{"", ""},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := RequiredResourceType(tc.ruleID)
			if got != tc.want {
				t.Errorf("RequiredResourceType(%q) = %q, want %q", tc.ruleID, got, tc.want)
			}
		})
	}
}

func TestCanonicalResourceName(t *testing.T) {
	cases := []struct {
		name       string
		sourceAddr string
		newType    string
		want       string
	}{
		{
			name:       "simple cloudwatch to kms",
			sourceAddr: "aws_cloudwatch_log_group.ecs",
			newType:    "aws_kms_key",
			want:       "aws_kms_key.ecs",
		},
		{
			name:       "api gateway method to request validator",
			sourceAddr: "aws_api_gateway_method.proxy",
			newType:    "aws_api_gateway_request_validator",
			want:       "aws_api_gateway_request_validator.proxy",
		},
		{
			name:       "module path stripped to last segment",
			sourceAddr: "module.vpc.aws_s3_bucket.logs",
			newType:    "aws_kms_key",
			want:       "aws_kms_key.logs",
		},
		{
			name:       "single segment address falls back to default",
			sourceAddr: "onlyone",
			newType:    "aws_kms_key",
			want:       "aws_kms_key.default",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := CanonicalResourceName(tc.sourceAddr, tc.newType)
			if got != tc.want {
				t.Errorf("CanonicalResourceName(%q, %q) = %q, want %q",
					tc.sourceAddr, tc.newType, got, tc.want)
			}
		})
	}
}

func TestRelevantAttributes(t *testing.T) {
	cases := []struct {
		ruleID        string
		wantNonNil    bool
		wantContains  string
	}{
		{"CKV_AWS_158", true, "kms_key_id"},
		{"CKV2_AWS_53", true, "rest_api_id"},
		{"CKV_AWS_225", true, "settings"},
		{"UNKNOWN_RULE", false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.ruleID, func(t *testing.T) {
			got := RelevantAttributes(tc.ruleID)
			if tc.wantNonNil && got == nil {
				t.Errorf("RelevantAttributes(%q) = nil, want non-nil slice", tc.ruleID)
				return
			}
			if !tc.wantNonNil && got != nil {
				t.Errorf("RelevantAttributes(%q) = %v, want nil", tc.ruleID, got)
				return
			}
			if tc.wantContains != "" {
				found := false
				for _, a := range got {
					if a == tc.wantContains {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("RelevantAttributes(%q) does not contain %q; got %v",
						tc.ruleID, tc.wantContains, got)
				}
			}
		})
	}
}

func TestTruncateConfig_KnownRuleKeepsRelevantAttrs(t *testing.T) {
	// CKV_AWS_158 relevant attrs: kms_key_id, name, retention_in_days
	config := map[string]interface{}{
		"kms_key_id":      "aws_kms_key.main.arn",
		"name":            "/ecs/service",
		"retention_in_days": 30,
		"tags":            map[string]interface{}{"env": "prod"},
		"irrelevant_attr": "should_be_removed",
	}

	got := TruncateConfig(config, "CKV_AWS_158")

	// Must keep relevant attrs.
	for _, attr := range []string{"kms_key_id", "name", "retention_in_days"} {
		if _, ok := got[attr]; !ok {
			t.Errorf("TruncateConfig kept no %q for CKV_AWS_158", attr)
		}
	}

	// Must discard irrelevant attrs.
	if _, ok := got["irrelevant_attr"]; ok {
		t.Error("TruncateConfig should have discarded irrelevant_attr for CKV_AWS_158")
	}
	if _, ok := got["tags"]; ok {
		t.Error("TruncateConfig should have discarded tags for CKV_AWS_158")
	}
}

func TestTruncateConfig_UnknownRuleCapAt20(t *testing.T) {
	// Build a config with 50 non-nil attributes.
	config := make(map[string]interface{}, 50)
	for i := 0; i < 50; i++ {
		config[fmt.Sprintf("attr_%02d", i)] = fmt.Sprintf("value_%d", i)
	}

	got := TruncateConfig(config, "UNKNOWN_RULE_XYZ")

	if len(got) > maxGenericAttrs {
		t.Errorf("TruncateConfig with unknown rule returned %d attrs, want <= %d",
			len(got), maxGenericAttrs)
	}
}

func TestTruncateConfig_NilConfigNoPanic(t *testing.T) {
	// Must not panic.
	got := TruncateConfig(nil, "CKV_AWS_158")
	if got != nil && len(got) != 0 {
		// Returning nil or empty map are both acceptable.
		t.Errorf("TruncateConfig(nil, ...) = %v, want nil or empty", got)
	}
}

func TestTruncateConfig_EmptyConfigNoPanic(t *testing.T) {
	got := TruncateConfig(map[string]interface{}{}, "CKV_AWS_158")
	if len(got) != 0 {
		t.Errorf("TruncateConfig({}, ...) = %v, want empty map", got)
	}
}

func TestTruncateConfig_AllNilAttrsWithKnownRuleFallsBackToGeneric(t *testing.T) {
	// CKV_AWS_158 relevant attrs are kms_key_id, name, retention_in_days.
	// If all are nil, keepAttrs falls back to generic truncation.
	config := map[string]interface{}{
		"kms_key_id":        nil,
		"name":              nil,
		"retention_in_days": nil,
		"some_other_attr":   "value",
	}

	got := TruncateConfig(config, "CKV_AWS_158")

	// Should fall back to generic; some_other_attr must be present.
	if _, ok := got["some_other_attr"]; !ok {
		t.Error("TruncateConfig should fall back to generic when all relevant attrs are nil")
	}
}
