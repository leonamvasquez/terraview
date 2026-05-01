package contextanalysis

import "testing"

func TestExtractRelevantAttributesForType_PerTypeKeys(t *testing.T) {
	values := map[string]interface{}{
		"instance_type":           "t3.micro",
		"ami":                     "ami-123",
		"backup_retention_period": 7, // belongs to RDS, not EC2
		"tags":                    map[string]interface{}{"env": "prod"},
		"random_field":            "ignored",
	}

	got := extractRelevantAttributesForType("aws_instance", values)

	if _, ok := got["instance_type"]; !ok {
		t.Error("aws_instance whitelist must include instance_type")
	}
	if _, ok := got["ami"]; !ok {
		t.Error("aws_instance whitelist must include ami")
	}
	if _, ok := got["tags"]; !ok {
		t.Error("fallback must always include tags")
	}
	if _, ok := got["backup_retention_period"]; ok {
		t.Error("aws_instance must NOT include backup_retention_period (belongs to RDS)")
	}
	if _, ok := got["random_field"]; ok {
		t.Error("random_field must not leak through whitelist")
	}
}

func TestExtractRelevantAttributesForType_FallbackForUnknownType(t *testing.T) {
	// Unknown type (e.g. aws_appsync_*) must still receive generic fallback
	// keys so it never reaches the AI without context.
	values := map[string]interface{}{
		"tags":         map[string]interface{}{"team": "data"},
		"kms_key_id":   "arn:aws:kms:...",
		"policy":       "...json...",
		"vpc_id":       "vpc-123",
		"weird_attr":   "ignored",
		"random_field": "ignored",
	}

	got := extractRelevantAttributesForType("aws_appsync_graphql_api", values)

	for _, k := range []string{"tags", "kms_key_id", "policy", "vpc_id"} {
		if _, ok := got[k]; !ok {
			t.Errorf("fallback must emit %q for unmapped types, got keys=%v", k, got)
		}
	}
	if _, ok := got["weird_attr"]; ok {
		t.Error("weird_attr should not leak through fallback")
	}
}

func TestExtractRelevantAttributesForType_NoDuplicateEmission(t *testing.T) {
	// "tags" appears in both per-type lists and fallback — must be emitted once.
	values := map[string]interface{}{
		"tags":          map[string]interface{}{"env": "prod"},
		"instance_type": "t3.large",
	}
	got := extractRelevantAttributesForType("aws_instance", values)

	if got["tags"] == nil {
		t.Fatal("tags must be present")
	}
	// Map cannot store duplicates by definition; sanity check on call path.
	if len(got) < 2 {
		t.Errorf("expected >=2 keys (tags + instance_type), got %d: %v", len(got), got)
	}
}

func TestExtractRelevantAttributesForType_EmptyValues(t *testing.T) {
	got := extractRelevantAttributesForType("aws_instance", nil)
	if len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestExtractRelevantAttributesForType_IAMRoleNoComputeNoise(t *testing.T) {
	// Regression: aws_iam_role must NOT pull RDS/EC2 keys even if values
	// happen to contain them (e.g. carried over from a wider parse step).
	values := map[string]interface{}{
		"assume_role_policy":      "...",
		"multi_az":                true, // EC2/RDS-only
		"backup_retention_period": 7,    // RDS-only
		"tags":                    map[string]interface{}{"x": "y"},
	}

	got := extractRelevantAttributesForType("aws_iam_role", values)

	if _, ok := got["assume_role_policy"]; !ok {
		t.Error("aws_iam_role must include assume_role_policy")
	}
	if _, ok := got["multi_az"]; ok {
		t.Error("aws_iam_role must NOT include multi_az (compute attribute leak)")
	}
	if _, ok := got["backup_retention_period"]; ok {
		t.Error("aws_iam_role must NOT include backup_retention_period (RDS attribute leak)")
	}
}
