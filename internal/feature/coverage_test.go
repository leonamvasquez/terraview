package feature

import (
	"testing"
)

// ---------------------------------------------------------------------------
// hasTruthyKey
// ---------------------------------------------------------------------------

func TestHasTruthyKey_Bool(t *testing.T) {
	vals := map[string]interface{}{"key": true}
	if !hasTruthyKey(vals, "key") {
		t.Error("expected true for bool true")
	}
}

func TestHasTruthyKey_BoolFalse(t *testing.T) {
	vals := map[string]interface{}{"key": false}
	if hasTruthyKey(vals, "key") {
		t.Error("expected false for bool false")
	}
}

func TestHasTruthyKey_StringTrue(t *testing.T) {
	for _, s := range []string{"true", "1", "yes"} {
		if !hasTruthyKey(map[string]interface{}{"k": s}, "k") {
			t.Errorf("expected true for string %q", s)
		}
	}
}

func TestHasTruthyKey_StringFalse(t *testing.T) {
	if hasTruthyKey(map[string]interface{}{"k": "no"}, "k") {
		t.Error("expected false for string 'no'")
	}
}

func TestHasTruthyKey_Float(t *testing.T) {
	if !hasTruthyKey(map[string]interface{}{"k": float64(1)}, "k") {
		t.Error("expected true for non-zero float")
	}
	if hasTruthyKey(map[string]interface{}{"k": float64(0)}, "k") {
		t.Error("expected false for zero float")
	}
}

func TestHasTruthyKey_Missing(t *testing.T) {
	if hasTruthyKey(map[string]interface{}{}, "missing") {
		t.Error("expected false for missing key")
	}
}

func TestHasTruthyKey_OtherType(t *testing.T) {
	if hasTruthyKey(map[string]interface{}{"k": []int{1, 2}}, "k") {
		t.Error("expected false for slice type")
	}
}

// ---------------------------------------------------------------------------
// hasFalsyKey
// ---------------------------------------------------------------------------

func TestHasFalsyKey_Bool(t *testing.T) {
	if !hasFalsyKey(map[string]interface{}{"k": false}, "k") {
		t.Error("expected true for bool false")
	}
	if hasFalsyKey(map[string]interface{}{"k": true}, "k") {
		t.Error("expected false for bool true")
	}
}

func TestHasFalsyKey_Strings(t *testing.T) {
	for _, s := range []string{"false", "0", "no"} {
		if !hasFalsyKey(map[string]interface{}{"k": s}, "k") {
			t.Errorf("expected true for string %q", s)
		}
	}
	if hasFalsyKey(map[string]interface{}{"k": "yes"}, "k") {
		t.Error("expected false for string 'yes'")
	}
}

func TestHasFalsyKey_Float(t *testing.T) {
	if !hasFalsyKey(map[string]interface{}{"k": float64(0)}, "k") {
		t.Error("expected true for zero float")
	}
	if hasFalsyKey(map[string]interface{}{"k": float64(1)}, "k") {
		t.Error("expected false for non-zero float")
	}
}

func TestHasFalsyKey_Missing(t *testing.T) {
	if hasFalsyKey(map[string]interface{}{}, "missing") {
		t.Error("expected false for missing key")
	}
}

func TestHasFalsyKey_OtherType(t *testing.T) {
	if hasFalsyKey(map[string]interface{}{"k": []string{"a"}}, "k") {
		t.Error("expected false for slice type")
	}
}

// ---------------------------------------------------------------------------
// hasNonEmptyKey
// ---------------------------------------------------------------------------

func TestHasNonEmptyKey_String(t *testing.T) {
	if !hasNonEmptyKey(map[string]interface{}{"k": "hello"}, "k") {
		t.Error("expected true for non-empty string")
	}
	if hasNonEmptyKey(map[string]interface{}{"k": ""}, "k") {
		t.Error("expected false for empty string")
	}
}

func TestHasNonEmptyKey_Map(t *testing.T) {
	if !hasNonEmptyKey(map[string]interface{}{"k": map[string]interface{}{"a": 1}}, "k") {
		t.Error("expected true for non-empty map")
	}
	if hasNonEmptyKey(map[string]interface{}{"k": map[string]interface{}{}}, "k") {
		t.Error("expected false for empty map")
	}
}

func TestHasNonEmptyKey_Slice(t *testing.T) {
	if !hasNonEmptyKey(map[string]interface{}{"k": []interface{}{1}}, "k") {
		t.Error("expected true for non-empty slice")
	}
	if hasNonEmptyKey(map[string]interface{}{"k": []interface{}{}}, "k") {
		t.Error("expected false for empty slice")
	}
}

func TestHasNonEmptyKey_Nil(t *testing.T) {
	if hasNonEmptyKey(map[string]interface{}{"k": nil}, "k") {
		t.Error("expected false for nil value")
	}
}

func TestHasNonEmptyKey_Missing(t *testing.T) {
	if hasNonEmptyKey(map[string]interface{}{}, "missing") {
		t.Error("expected false for missing key")
	}
}

func TestHasNonEmptyKey_OtherType(t *testing.T) {
	// For other types (int, float, etc.), returns true by default
	if !hasNonEmptyKey(map[string]interface{}{"k": 42}, "k") {
		t.Error("expected true for int type (default case)")
	}
}

// ---------------------------------------------------------------------------
// hasPositiveIntKey
// ---------------------------------------------------------------------------

func TestHasPositiveIntKey_Float(t *testing.T) {
	if !hasPositiveIntKey(map[string]interface{}{"k": float64(5)}, "k") {
		t.Error("expected true for positive float")
	}
	if hasPositiveIntKey(map[string]interface{}{"k": float64(0)}, "k") {
		t.Error("expected false for zero float")
	}
	if hasPositiveIntKey(map[string]interface{}{"k": float64(-1)}, "k") {
		t.Error("expected false for negative float")
	}
}

func TestHasPositiveIntKey_Int(t *testing.T) {
	if !hasPositiveIntKey(map[string]interface{}{"k": 5}, "k") {
		t.Error("expected true for positive int")
	}
	if hasPositiveIntKey(map[string]interface{}{"k": 0}, "k") {
		t.Error("expected false for zero int")
	}
}

func TestHasPositiveIntKey_Missing(t *testing.T) {
	if hasPositiveIntKey(map[string]interface{}{}, "missing") {
		t.Error("expected false for missing key")
	}
}

func TestHasPositiveIntKey_OtherType(t *testing.T) {
	if hasPositiveIntKey(map[string]interface{}{"k": "not-a-number"}, "k") {
		t.Error("expected false for string type")
	}
}

// ---------------------------------------------------------------------------
// hasWildcardPolicy
// ---------------------------------------------------------------------------

func TestHasWildcardPolicy_ActionStar(t *testing.T) {
	vals := map[string]interface{}{
		"policy": `{"Statement":[{"Action":"*","Effect":"Allow"}]}`,
	}
	if !hasWildcardPolicy(vals) {
		t.Error("expected true for wildcard Action")
	}
}

func TestHasWildcardPolicy_NoWildcard(t *testing.T) {
	vals := map[string]interface{}{
		"policy": `{"Statement":[{"Action":"s3:GetObject","Effect":"Allow"}]}`,
	}
	if hasWildcardPolicy(vals) {
		t.Error("expected false for non-wildcard policy")
	}
}

func TestHasWildcardPolicy_EmptyMap(t *testing.T) {
	if hasWildcardPolicy(map[string]interface{}{}) {
		t.Error("expected false for empty map")
	}
}

func TestHasWildcardPolicy_DirectActionStar(t *testing.T) {
	vals := map[string]interface{}{
		"inline_policy": `"Action":"*"`,
	}
	if !hasWildcardPolicy(vals) {
		t.Error("expected true for directly embedded Action:*")
	}
}
