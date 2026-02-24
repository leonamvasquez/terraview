package parser

import (
	"testing"
)

// FuzzParse feeds random bytes into the plan JSON parser.
// Goal: ensure the parser never panics on arbitrary input.
func FuzzParse(f *testing.F) {
	// ── Seed corpus ──────────────────────────────────────────────────
	// Valid minimal plan
	f.Add([]byte(`{
		"format_version": "1.2",
		"resource_changes": [{
			"address": "aws_instance.web",
			"type": "aws_instance",
			"name": "web",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {"actions": ["create"], "after": {}}
		}]
	}`))

	// Multiple resources with different actions
	f.Add([]byte(`{
		"format_version": "1.2",
		"resource_changes": [
			{"address": "a.b", "type": "a", "name": "b", "provider_name": "p",
			 "change": {"actions": ["create"], "after": {"key": "val"}}},
			{"address": "c.d", "type": "c", "name": "d", "provider_name": "p",
			 "change": {"actions": ["delete", "create"], "before": {"x": 1}, "after": {"x": 2}}}
		]
	}`))

	// Empty resource_changes (should return error)
	f.Add([]byte(`{"format_version": "1.2", "resource_changes": []}`))

	// Invalid JSON
	f.Add([]byte(`{invalid json`))

	// Null
	f.Add([]byte(`null`))

	// Empty object
	f.Add([]byte(`{}`))

	// Top-level array
	f.Add([]byte(`[{"format_version": "1.0"}]`))

	// Deeply nested values
	f.Add([]byte(`{
		"format_version": "1.2",
		"resource_changes": [{
			"address": "aws_s3_bucket.data",
			"type": "aws_s3_bucket",
			"name": "data",
			"provider_name": "registry.terraform.io/hashicorp/aws",
			"change": {
				"actions": ["create"],
				"after": {
					"tags": {"env": "prod", "team": "infra"},
					"nested": {"deep": {"value": 42}}
				}
			}
		}]
	}`))

	p := NewParser()

	f.Fuzz(func(t *testing.T, data []byte) {
		// The parser must never panic, only return errors.
		result, err := p.Parse(data)
		if err != nil {
			return
		}

		// If parsing succeeded, normalization must also be safe.
		if result != nil {
			resources := p.NormalizeResources(result)
			p.ExtractResourceSummary(resources)
		}
	})
}

// FuzzNormalizeAction tests the action normalization logic with random strings.
// Goal: ensure normalizeAction never panics on arbitrary input.
func FuzzNormalizeAction(f *testing.F) {
	// ── Seed corpus ──────────────────────────────────────────────────
	f.Add("create")
	f.Add("delete")
	f.Add("update")
	f.Add("read")
	f.Add("no-op")
	f.Add("")
	f.Add("unknown-action")
	f.Add("create,delete")
	f.Add("a]b[c{d}e")

	f.Fuzz(func(t *testing.T, action string) {
		// Single action — must never panic.
		_ = normalizeAction([]string{action})

		// Dual actions — must never panic.
		_ = normalizeAction([]string{action, "create"})
		_ = normalizeAction([]string{"delete", action})

		// Empty slice — must never panic.
		_ = normalizeAction([]string{})
	})
}
