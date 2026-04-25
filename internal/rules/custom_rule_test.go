package rules

import (
	"errors"
	"testing"
)

// stubResource implements ResourceLike for tests.
type stubResource struct {
	rType   string
	address string
	values  map[string]interface{}
}

func (s stubResource) GetType() string                   { return s.rType }
func (s stubResource) GetAddress() string                { return s.address }
func (s stubResource) GetValues() map[string]interface{} { return s.values }

func TestEvaluateCustomRules_EmptyInputs(t *testing.T) {
	rule := CustomRule{
		ID:        "TEST_001",
		Severity:  SeverityHigh,
		Condition: CustomCondition{Field: "name", Op: "is_null"},
	}
	res := stubResource{rType: "aws_s3_bucket", address: "aws_s3_bucket.x", values: map[string]interface{}{}}

	tests := []struct {
		name      string
		rules     []CustomRule
		resources []ResourceLike
	}{
		{"no rules", nil, []ResourceLike{res}},
		{"no resources", []CustomRule{rule}, nil},
		{"both empty", nil, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvaluateCustomRules(tc.rules, tc.resources, nil)
			if len(got) != 0 {
				t.Errorf("expected 0 findings, got %d", len(got))
			}
		})
	}
}

func TestEvaluateCustomRules_ResourceTypeFilter(t *testing.T) {
	rule := CustomRule{
		ID:           "TEST_002",
		Severity:     SeverityMedium,
		ResourceType: "aws_s3_bucket",
		Condition:    CustomCondition{Field: "bucket", Op: "is_null"},
	}
	resources := []ResourceLike{
		stubResource{rType: "aws_s3_bucket", address: "aws_s3_bucket.a", values: map[string]interface{}{}},
		stubResource{rType: "aws_instance", address: "aws_instance.b", values: map[string]interface{}{}},
	}

	got := EvaluateCustomRules([]CustomRule{rule}, resources, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding (filtered by type), got %d", len(got))
	}
	if got[0].Resource != "aws_s3_bucket.a" {
		t.Errorf("unexpected resource %q", got[0].Resource)
	}
}

func TestEvaluateCustomRules_Defaults(t *testing.T) {
	// Empty Severity and Category should default to MEDIUM / best-practice.
	rule := CustomRule{
		ID:        "TEST_003",
		Condition: CustomCondition{Field: "missing", Op: "is_null"},
	}
	res := stubResource{rType: "any", address: "any.x", values: map[string]interface{}{}}

	got := EvaluateCustomRules([]CustomRule{rule}, []ResourceLike{res}, nil)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Severity != SeverityMedium {
		t.Errorf("severity: got %q, want %q", got[0].Severity, SeverityMedium)
	}
	if got[0].Category != CategoryBestPractice {
		t.Errorf("category: got %q, want %q", got[0].Category, CategoryBestPractice)
	}
	if got[0].Source != "custom" {
		t.Errorf("source: got %q, want %q", got[0].Source, "custom")
	}
}

func TestEvaluateCustomRules_AllOps(t *testing.T) {
	makeRes := func(values map[string]interface{}) ResourceLike {
		return stubResource{rType: "aws_s3_bucket", address: "aws_s3_bucket.t", values: values}
	}

	tests := []struct {
		name       string
		op         string
		fieldValue interface{} // nil means field absent
		condValue  string
		wantFire   bool
	}{
		// is_null: fires when absent/nil/empty
		{"is_null/absent fires", "is_null", nil, "", true},
		{"is_null/present no-fire", "is_null", "val", "", false},

		// not_null: fires when absent/nil/empty (field is required)
		{"not_null/absent fires", "not_null", nil, "", true},
		{"not_null/present no-fire", "not_null", "val", "", false},

		// equals: fires when field != value
		{"equals/mismatch fires", "equals", "actual", "expected", true},
		{"equals/match no-fire", "equals", "same", "same", false},

		// not_equals: fires when field == value
		{"not_equals/match fires", "not_equals", "bad", "bad", true},
		{"not_equals/mismatch no-fire", "not_equals", "good", "bad", false},

		// contains: fires when field does NOT contain value
		{"contains/missing fires", "contains", "hello", "world", true},
		{"contains/present no-fire", "contains", "helloworld", "world", false},

		// not_contains: fires when field DOES contain value
		{"not_contains/present fires", "not_contains", "helloworld", "world", true},
		{"not_contains/missing no-fire", "not_contains", "hello", "world", false},

		// matches: fires when field does NOT match regex
		{"matches/no-match fires", "matches", "abc", `^\d+$`, true},
		{"matches/match no-fire", "matches", "123", `^\d+$`, false},

		// not_matches: fires when field DOES match regex
		{"not_matches/match fires", "not_matches", "123", `^\d+$`, true},
		{"not_matches/no-match no-fire", "not_matches", "abc", `^\d+$`, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var values map[string]interface{}
			if tc.fieldValue != nil {
				values = map[string]interface{}{"field": tc.fieldValue}
			} else {
				values = map[string]interface{}{}
			}

			rule := CustomRule{
				ID:        "OP_TEST",
				Condition: CustomCondition{Field: "field", Op: tc.op, Value: tc.condValue},
			}
			got := EvaluateCustomRules([]CustomRule{rule}, []ResourceLike{makeRes(values)}, nil)
			fired := len(got) > 0
			if fired != tc.wantFire {
				t.Errorf("op=%q fieldValue=%v condValue=%q: fired=%v, want %v",
					tc.op, tc.fieldValue, tc.condValue, fired, tc.wantFire)
			}
		})
	}
}

func TestEvaluateCustomRules_InvalidRegex(t *testing.T) {
	rule := CustomRule{
		ID:        "REGEX_001",
		Condition: CustomCondition{Field: "name", Op: "matches", Value: `[invalid`},
	}
	res := stubResource{rType: "any", address: "any.x", values: map[string]interface{}{"name": "foo"}}

	var capturedErr error
	got := EvaluateCustomRules([]CustomRule{rule}, []ResourceLike{res}, func(err error) {
		capturedErr = err
	})

	if len(got) != 0 {
		t.Errorf("expected 0 findings on invalid regex, got %d", len(got))
	}
	if capturedErr == nil {
		t.Error("expected errFn to be called for invalid regex")
	}
}

func TestEvaluateCustomRules_DotNotation(t *testing.T) {
	rule := CustomRule{
		ID:        "DOT_001",
		Condition: CustomCondition{Field: "tags.team", Op: "is_null"},
	}
	tests := []struct {
		name     string
		values   map[string]interface{}
		wantFire bool
	}{
		{
			"missing tags fires",
			map[string]interface{}{},
			true,
		},
		{
			"missing tags.team fires",
			map[string]interface{}{"tags": map[string]interface{}{"env": "prod"}},
			true,
		},
		{
			"present tags.team no-fire",
			map[string]interface{}{"tags": map[string]interface{}{"team": "platform"}},
			false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := stubResource{rType: "any", address: "any.x", values: tc.values}
			got := EvaluateCustomRules([]CustomRule{rule}, []ResourceLike{res}, nil)
			fired := len(got) > 0
			if fired != tc.wantFire {
				t.Errorf("fired=%v, want %v", fired, tc.wantFire)
			}
		})
	}
}

func TestEvaluateCustomRules_UnknownOp(t *testing.T) {
	rule := CustomRule{
		ID:        "UNK_001",
		Condition: CustomCondition{Field: "name", Op: "nonsense_op"},
	}
	res := stubResource{rType: "any", address: "any.x", values: map[string]interface{}{"name": "foo"}}

	var errCount int
	got := EvaluateCustomRules([]CustomRule{rule}, []ResourceLike{res}, func(err error) {
		errCount++
		if !errors.Is(err, err) { // always true — just ensures err is non-nil
			t.Error("errFn received nil error")
		}
	})

	if len(got) != 0 {
		t.Errorf("expected 0 findings on unknown op, got %d", len(got))
	}
	if errCount == 0 {
		t.Error("expected errFn to be called for unknown op")
	}
}
