package rules

import (
	"fmt"
	"regexp"
	"strings"
)

// CustomRule mirrors config.CustomRuleConfig but lives in the rules package to
// avoid an import cycle (config must not import rules). The caller is responsible
// for converting between the two types.
type CustomRule struct {
	ID           string
	Severity     string
	Category     string
	Message      string
	Remediation  string
	ResourceType string
	Condition    CustomCondition
}

// CustomCondition specifies the field path, operator, and comparison value.
type CustomCondition struct {
	Field string
	Op    string
	Value string
}

// ResourceLike is a minimal view of a resource that custom rules operate on.
// parser.NormalizedResource satisfies this interface.
type ResourceLike interface {
	GetType() string
	GetAddress() string
	GetValues() map[string]interface{}
}

// EvaluateCustomRules applies each CustomRule to every resource and returns
// findings for every (rule, resource) pair where the condition fires.
//
// errFn is called with non-fatal errors (invalid regex, unknown op) so the
// caller can log them; evaluation continues after each error.
func EvaluateCustomRules(customRules []CustomRule, resources []ResourceLike, errFn func(error)) []Finding {
	if len(customRules) == 0 || len(resources) == 0 {
		return nil
	}
	if errFn == nil {
		errFn = func(error) {}
	}

	var findings []Finding
	for _, rule := range customRules {
		sev := rule.Severity
		if sev == "" {
			sev = SeverityMedium
		}
		cat := rule.Category
		if cat == "" {
			cat = CategoryBestPractice
		}

		for _, res := range resources {
			if rule.ResourceType != "" && res.GetType() != rule.ResourceType {
				continue
			}

			fired, err := conditionFires(rule.Condition, res.GetValues())
			if err != nil {
				errFn(fmt.Errorf("custom rule %s [%s]: %w", rule.ID, res.GetAddress(), err))
				continue
			}
			if !fired {
				continue
			}

			findings = append(findings, Finding{
				RuleID:      rule.ID,
				Severity:    sev,
				Category:    cat,
				Resource:    res.GetAddress(),
				Message:     rule.Message,
				Remediation: rule.Remediation,
				Source:      "custom",
			})
		}
	}
	return findings
}

// conditionFires returns true when the condition triggers a finding for the
// given resource values. The semantics per op are:
//
//	is_null     → fires when field is absent / nil / empty string
//	not_null    → fires when field is absent / nil / empty string  (alias: field is required)
//	equals      → fires when field != value
//	not_equals  → fires when field == value
//	contains    → fires when field does NOT contain value
//	not_contains→ fires when field DOES contain value
//	matches     → fires when field does NOT match regex value
//	not_matches → fires when field DOES match regex value
func conditionFires(cond CustomCondition, values map[string]interface{}) (bool, error) {
	raw, exists := getNestedField(values, cond.Field)

	isAbsent := !exists || raw == nil
	strVal := ""
	if !isAbsent {
		strVal = fmt.Sprintf("%v", raw)
	}

	switch cond.Op {
	case "is_null":
		return isAbsent || strVal == "", nil

	case "not_null":
		// fires when the field is absent/nil/empty — i.e. the required field is missing
		return isAbsent || strVal == "", nil

	case "equals":
		return strVal != cond.Value, nil

	case "not_equals":
		return strVal == cond.Value, nil

	case "contains":
		return !strings.Contains(strVal, cond.Value), nil

	case "not_contains":
		return strings.Contains(strVal, cond.Value), nil

	case "matches":
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", cond.Value, err)
		}
		return !re.MatchString(strVal), nil

	case "not_matches":
		re, err := regexp.Compile(cond.Value)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", cond.Value, err)
		}
		return re.MatchString(strVal), nil

	default:
		return false, fmt.Errorf("unknown op %q", cond.Op)
	}
}

// getNestedField resolves dot-notation paths (e.g. "tags.team") against a
// nested map structure. Returns the value and whether it was found.
func getNestedField(values map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.SplitN(path, ".", 2)
	if values == nil {
		return nil, false
	}

	v, ok := values[parts[0]]
	if !ok {
		return nil, false
	}

	if len(parts) == 1 {
		return v, true
	}

	// Recurse into nested map
	nested, ok := v.(map[string]interface{})
	if !ok {
		return nil, false
	}
	return getNestedField(nested, parts[1])
}
