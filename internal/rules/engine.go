package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
	"gopkg.in/yaml.v3"
)

// Engine loads rule definitions and evaluates resources against them.
type Engine struct {
	config    RulesConfig
	evaluators []Rule
}

// NewEngine creates a new rules engine from a YAML rules file.
func NewEngine(rulesPath string) (*Engine, error) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file %s: %w", rulesPath, err)
	}

	var config RulesConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules YAML: %w", err)
	}

	engine := &Engine{config: config}
	engine.evaluators = engine.buildEvaluators()

	return engine, nil
}

// NewEngineFromConfig creates an engine directly from a RulesConfig.
func NewEngineFromConfig(config RulesConfig) *Engine {
	engine := &Engine{config: config}
	engine.evaluators = engine.buildEvaluators()
	return engine
}

// NewEngineFromPaths creates an engine by merging multiple rule files.
// Returns an error if two files define a rule with the same ID.
func NewEngineFromPaths(paths []string) (*Engine, error) {
	merged := RulesConfig{Version: "1.0"}
	seenIDs := make(map[string]string) // ruleID -> source file

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("failed to read rules file %s: %w", p, err)
		}

		var cfg RulesConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse rules YAML %s: %w", p, err)
		}

		// Check for duplicate rule IDs
		for _, rd := range cfg.Rules {
			if existing, ok := seenIDs[rd.ID]; ok {
				return nil, fmt.Errorf("duplicate rule ID %q: defined in both %s and %s", rd.ID, existing, p)
			}
			seenIDs[rd.ID] = p
		}

		merged.Rules = append(merged.Rules, cfg.Rules...)

		// Merge required tags (deduplicate)
		merged.RequiredTags = mergeStringSlices(merged.RequiredTags, cfg.RequiredTags)

		// Merge critical resource types (deduplicate)
		merged.CriticalResourceTypes = mergeStringSlices(merged.CriticalResourceTypes, cfg.CriticalResourceTypes)

		// Merge taggable resource types (deduplicate)
		merged.TaggableResourceTypes = mergeStringSlices(merged.TaggableResourceTypes, cfg.TaggableResourceTypes)
	}

	engine := &Engine{config: merged}
	engine.evaluators = engine.buildEvaluators()
	return engine, nil
}

// ResolveRulePacks expands pack names into file paths.
// It looks in the given packsDir for files named <pack>.yaml.
// If a pack name is a direct file path that exists, it is used as-is.
func ResolveRulePacks(packs []string, packsDir string) ([]string, error) {
	var paths []string

	for _, pack := range packs {
		// If it's a direct path that exists, use it
		if _, err := os.Stat(pack); err == nil {
			paths = append(paths, pack)
			continue
		}

		// Look in packs directory
		candidate := filepath.Join(packsDir, pack+".yaml")
		if _, err := os.Stat(candidate); err == nil {
			paths = append(paths, candidate)
			continue
		}

		// Look in packs subdirectory
		candidate = filepath.Join(packsDir, "packs", pack+".yaml")
		if _, err := os.Stat(candidate); err == nil {
			paths = append(paths, candidate)
			continue
		}

		return nil, fmt.Errorf("rule pack %q not found (searched %s)", pack, packsDir)
	}

	return paths, nil
}

func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	result := make([]string, len(a))
	copy(result, a)
	for _, s := range b {
		if !seen[s] {
			result = append(result, s)
			seen[s] = true
		}
	}
	return result
}

// CriticalResourceTypes returns the list of critical resource types from the loaded config.
func (e *Engine) CriticalResourceTypes() []string {
	return e.config.CriticalResourceTypes
}

// SetRequiredTags overrides the required tags and rebuilds evaluators.
func (e *Engine) SetRequiredTags(tags []string) {
	e.config.RequiredTags = tags
	e.evaluators = e.buildEvaluators()
}

// buildEvaluators creates Rule implementations from the loaded definitions.
func (e *Engine) buildEvaluators() []Rule {
	var evaluators []Rule

	for _, rd := range e.config.Rules {
		if !rd.Enabled {
			continue
		}
		evaluators = append(evaluators, &GenericRule{definition: rd})
	}

	if len(e.config.RequiredTags) > 0 {
		taggableMap := make(map[string]bool, len(e.config.TaggableResourceTypes))
		for _, t := range e.config.TaggableResourceTypes {
			taggableMap[t] = true
		}
		evaluators = append(evaluators, &TagRule{
			requiredTags:  e.config.RequiredTags,
			taggableTypes: taggableMap,
		})
	}

	if len(e.config.CriticalResourceTypes) > 0 {
		evaluators = append(evaluators, &CriticalDeletionRule{
			criticalTypes: e.config.CriticalResourceTypes,
		})
	}

	return evaluators
}

// Evaluate runs all enabled rules against a set of normalized resources.
func (e *Engine) Evaluate(resources []parser.NormalizedResource) []Finding {
	var findings []Finding

	for _, resource := range resources {
		for _, rule := range e.evaluators {
			results := rule.Evaluate(resource, resources)
			findings = append(findings, results...)
		}
	}

	return findings
}

// GenericRule evaluates a resource against a YAML-defined rule with conditions.
type GenericRule struct {
	definition RuleDefinition
}

func (r *GenericRule) ID() string {
	return r.definition.ID
}

func (r *GenericRule) Evaluate(resource parser.NormalizedResource, allResources []parser.NormalizedResource) []Finding {
	if !r.matchesTarget(resource.Type) {
		return nil
	}

	if r.allConditionsMet(resource) {
		// Check companion excludes — suppress finding if a companion resource exists
		if r.hasCompanionResource(resource, allResources) {
			return nil
		}

		return []Finding{{
			RuleID:      r.definition.ID,
			Severity:    r.definition.Severity,
			Category:    r.definition.Category,
			Resource:    resource.Address,
			Message:     r.definition.Description,
			Remediation: r.definition.Remediation,
			Source:      "hard-rule",
		}}
	}

	return nil
}

// hasCompanionResource checks if any companion resource exists in the plan
// that would suppress this finding (e.g., aws_s3_bucket_versioning for an S3 bucket).
func (r *GenericRule) hasCompanionResource(resource parser.NormalizedResource, allResources []parser.NormalizedResource) bool {
	if len(r.definition.CompanionExcludes) == 0 {
		return false
	}

	// Extract the resource name (last part of the address, e.g., "my_bucket" from "aws_s3_bucket.my_bucket")
	resourceName := resource.Name

	for _, ce := range r.definition.CompanionExcludes {
		for _, other := range allResources {
			if other.Type != ce.ResourceType {
				continue
			}
			if other.Action == "delete" {
				continue
			}
			// Check if companion references this resource by name field (when value is known at plan time)
			if ce.NameField != "" {
				if refVal, ok := other.Values[ce.NameField]; ok && refVal != nil {
					ref := fmt.Sprintf("%v", refVal)
					// Match by resource name, bucket name, or full address
					if ref == resourceName || ref == resource.Address || matchesBucketRef(ref, resource) {
						return true
					}
				}
				// When name_field value is unknown/computed at plan time (common for bucket references),
				// fall back to matching by resource logical name — Terraform convention is to name
				// companion resources the same as the primary resource (e.g., aws_s3_bucket.logs
				// and aws_s3_bucket_versioning.logs).
				if other.Name == resourceName {
					return true
				}
				continue
			}
			// Fallback: match by resource name pattern
			if strings.Contains(other.Address, resourceName) {
				return true
			}
		}
	}
	return false
}

// matchesBucketRef checks if a reference value matches the resource's bucket/name attribute.
func matchesBucketRef(ref string, resource parser.NormalizedResource) bool {
	if bucket, ok := resource.Values["bucket"]; ok {
		return ref == fmt.Sprintf("%v", bucket)
	}
	return false
}

func (r *GenericRule) matchesTarget(resourceType string) bool {
	if len(r.definition.Targets) == 0 {
		return true
	}
	for _, t := range r.definition.Targets {
		if t == resourceType || t == "*" {
			return true
		}
	}
	return false
}

func (r *GenericRule) allConditionsMet(resource parser.NormalizedResource) bool {
	for _, cond := range r.definition.Conditions {
		if !evaluateCondition(cond, resource) {
			return false
		}
	}
	return true
}

// evaluateCondition checks a single condition against resource values.
func evaluateCondition(cond Condition, resource parser.NormalizedResource) bool {
	val := getNestedValue(resource.Values, cond.Field)

	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", val) == fmt.Sprintf("%v", cond.Value)
	case "not_equals":
		return fmt.Sprintf("%v", val) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return stringContains(val, fmt.Sprintf("%v", cond.Value))
	case "not_contains":
		return !stringContains(val, fmt.Sprintf("%v", cond.Value))
	case "exists":
		return val != nil
	case "not_exists":
		return val == nil
	case "matches":
		return fmt.Sprintf("%v", val) == fmt.Sprintf("%v", cond.Value)
	case "is_action":
		return resource.Action == fmt.Sprintf("%v", cond.Value)
	case "contains_in_list":
		return listContainsValue(val, fmt.Sprintf("%v", cond.Value))
	case "is_true":
		return isTruthy(val)
	case "is_false":
		return !isTruthy(val)
	default:
		return false
	}
}

// getNestedValue traverses a nested map using dot-separated keys.
func getNestedValue(values map[string]interface{}, path string) interface{} {
	parts := strings.Split(path, ".")
	var current interface{} = values

	for _, part := range parts {
		switch v := current.(type) {
		case map[string]interface{}:
			current = v[part]
		case map[interface{}]interface{}:
			current = v[part]
		default:
			return nil
		}
	}

	return current
}

// stringContains checks if a value contains a substring.
func stringContains(val interface{}, substr string) bool {
	switch v := val.(type) {
	case string:
		return strings.Contains(v, substr)
	case []interface{}:
		for _, item := range v {
			if strings.Contains(fmt.Sprintf("%v", item), substr) {
				return true
			}
		}
	}
	return false
}

// listContainsValue checks if a list value contains a specific item.
// It recursively searches nested maps and sub-arrays, so it can find
// "0.0.0.0/0" inside structures like ingress[].cidr_blocks[].
func listContainsValue(val interface{}, target string) bool {
	switch v := val.(type) {
	case []interface{}:
		for _, item := range v {
			switch nested := item.(type) {
			case string:
				if nested == target {
					return true
				}
			case map[string]interface{}:
				if deepContainsValue(nested, target) {
					return true
				}
			default:
				if fmt.Sprintf("%v", item) == target {
					return true
				}
			}
		}
	case string:
		return v == target
	}
	return false
}

// deepContainsValue recursively searches all values in a map for the target string.
func deepContainsValue(m map[string]interface{}, target string) bool {
	for _, v := range m {
		switch val := v.(type) {
		case string:
			if val == target {
				return true
			}
		case []interface{}:
			if listContainsValue(val, target) {
				return true
			}
		case map[string]interface{}:
			if deepContainsValue(val, target) {
				return true
			}
		default:
			if fmt.Sprintf("%v", v) == target {
				return true
			}
		}
	}
	return false
}

// isTruthy checks if a value is truthy.
func isTruthy(val interface{}) bool {
	if val == nil {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	case float64:
		return v != 0
	case int:
		return v != 0
	}
	return false
}

// TagRule checks that all resources have required tags.
type TagRule struct {
	requiredTags  []string
	taggableTypes map[string]bool
}

func (r *TagRule) ID() string {
	return "TAG001"
}

func (r *TagRule) Evaluate(resource parser.NormalizedResource, allResources []parser.NormalizedResource) []Finding {
	if resource.Action == "delete" || resource.Action == "read" || resource.Action == "no-op" {
		return nil
	}

	tags := extractTags(resource.Values)

	// If tags is nil, check whether this resource type is known to be taggable
	if tags == nil {
		if r.isTaggable(resource.Type) {
			// Resource is taggable but has no tags field — flag all required tags
			var findings []Finding
			for _, required := range r.requiredTags {
				findings = append(findings, Finding{
					RuleID:      "TAG001",
					Severity:    SeverityMedium,
					Category:    CategoryCompliance,
					Resource:    resource.Address,
					Message:     fmt.Sprintf("Resource is missing required tag: %s", required),
					Remediation: fmt.Sprintf("Add the tag '%s' to the resource to comply with tagging policy.", required),
					Source:      "hard-rule",
				})
			}
			return findings
		}
		return nil // resource type doesn't support tags
	}

	var findings []Finding
	for _, required := range r.requiredTags {
		if _, exists := tags[required]; !exists {
			findings = append(findings, Finding{
				RuleID:      "TAG001",
				Severity:    SeverityMedium,
				Category:    CategoryCompliance,
				Resource:    resource.Address,
				Message:     fmt.Sprintf("Resource is missing required tag: %s", required),
				Remediation: fmt.Sprintf("Add the tag '%s' to the resource to comply with tagging policy.", required),
				Source:      "hard-rule",
			})
		}
	}

	return findings
}

// isTaggable returns true if the resource type is known to support tags.
// If no taggable types are configured, it falls back to prefix heuristic for AWS resources.
func (r *TagRule) isTaggable(resourceType string) bool {
	if len(r.taggableTypes) > 0 {
		return r.taggableTypes[resourceType]
	}
	// Fallback: most AWS resources support tags
	return strings.HasPrefix(resourceType, "aws_")
}

// extractTags extracts tags from resource values, handling both "tags" and "tags_all" fields.
func extractTags(values map[string]interface{}) map[string]interface{} {
	if tags, ok := values["tags"]; ok {
		if tagMap, ok := tags.(map[string]interface{}); ok {
			return tagMap
		}
	}
	if tags, ok := values["tags_all"]; ok {
		if tagMap, ok := tags.(map[string]interface{}); ok {
			return tagMap
		}
	}
	return nil
}

// CriticalDeletionRule detects deletion of critical resource types.
type CriticalDeletionRule struct {
	criticalTypes []string
}

func (r *CriticalDeletionRule) ID() string {
	return "DEL001"
}

func (r *CriticalDeletionRule) Evaluate(resource parser.NormalizedResource, allResources []parser.NormalizedResource) []Finding {
	if resource.Action != "delete" && resource.Action != "replace" {
		return nil
	}

	for _, ct := range r.criticalTypes {
		if resource.Type == ct {
			return []Finding{{
				RuleID:      "DEL001",
				Severity:    SeverityHigh,
				Category:    CategoryReliability,
				Resource:    resource.Address,
				Message:     fmt.Sprintf("Critical resource %s is being %sd. This may cause data loss or service disruption.", resource.Address, resource.Action),
				Remediation: "Review this change carefully. Ensure backups exist and the deletion is intentional. Consider using lifecycle prevent_destroy.",
				Source:      "hard-rule",
			}}
		}
	}

	return nil
}
