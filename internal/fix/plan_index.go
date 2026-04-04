package fix

import (
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// PlanIndex provides fast lookup of all Terraform resources by type and resolves
// attribute-level references from the plan's Configuration section.
// This allows fix suggestions to reference real resource addresses instead of
// inventing placeholder names.
type PlanIndex struct {
	// ByType maps resource type → list of addresses present in the plan.
	// e.g. "aws_kms_key" → ["aws_kms_key.main", "aws_kms_key.logs"]
	ByType map[string][]string

	// refs maps resource address → attribute name → resolved Terraform reference.
	// e.g. "aws_api_gateway_method.proxy" → "rest_api_id" → "aws_api_gateway_rest_api.main.id"
	refs map[string]map[string]string
}

// BuildIndex constructs a PlanIndex from a parsed TerraformPlan and its
// normalized resource list. Both arguments may be nil — the index degrades
// gracefully, returning empty results for all lookups.
func BuildIndex(plan *parser.TerraformPlan, resources []parser.NormalizedResource) *PlanIndex {
	idx := &PlanIndex{
		ByType: make(map[string][]string),
		refs:   make(map[string]map[string]string),
	}

	// Index all resources by type (create + update actions — not deletes).
	for _, r := range resources {
		if r.Action == "delete" {
			continue
		}
		idx.ByType[r.Type] = append(idx.ByType[r.Type], r.Address)
	}

	if plan == nil {
		return idx
	}

	// Extract Terraform attribute references from plan Configuration section.
	for _, cr := range plan.Configuration.RootModule.Resources {
		deps := extractConfigRefs(cr)
		if len(deps) > 0 {
			idx.refs[cr.Address] = deps
		}
	}

	return idx
}

// ResourcesOfType returns all resource addresses of the given provider type.
// Returns nil if none exist in the plan.
func (p *PlanIndex) ResourcesOfType(resourceType string) []string {
	return p.ByType[resourceType]
}

// ResolvedRefs returns the map of attribute → Terraform reference for the
// given resource address. For example, for "aws_api_gateway_method.proxy":
//
//	{"rest_api_id": "aws_api_gateway_rest_api.main.id"}
func (p *PlanIndex) ResolvedRefs(resourceAddr string) map[string]string {
	return p.refs[resourceAddr]
}

// extractConfigRefs parses a ConfigResource's Expressions map and returns
// a map of attribute name → resolved Terraform reference string.
//
// Terraform plan JSON expressions look like:
//
//	"rest_api_id": { "references": ["aws_api_gateway_rest_api.main.id", "aws_api_gateway_rest_api.main"] }
//
// We pick the most-specific reference (longest, e.g. with .id/.arn suffix)
// and skip meta-references (var., local., path., module., data.).
func extractConfigRefs(cr parser.ConfigResource) map[string]string {
	result := make(map[string]string)

	for attr, exprRaw := range cr.Expressions {
		expr, ok := exprRaw.(map[string]interface{})
		if !ok {
			continue
		}
		refsRaw, ok := expr["references"].([]interface{})
		if !ok || len(refsRaw) == 0 {
			continue
		}

		best := pickBestRef(refsRaw)
		if best != "" {
			result[attr] = best
		}
	}

	return result
}

// metaPrefixes are Terraform reference prefixes that don't map to a resource address.
var metaPrefixes = []string{"var.", "local.", "path.", "module.", "data.", "each.", "count."}

// pickBestRef selects the most specific resource reference from a Terraform
// references array. The "best" is the longest string that isn't a meta-reference.
// Terraform always lists the specific attribute first (e.g. "aws_kms_key.main.arn")
// before the resource address ("aws_kms_key.main"), so we take the first valid entry.
func pickBestRef(refsRaw []interface{}) string {
	var best string
	for _, r := range refsRaw {
		ref, ok := r.(string)
		if !ok || ref == "" {
			continue
		}
		if isMeta(ref) {
			continue
		}
		// Prefer the longer form (e.g. ".arn" or ".id" suffix) over bare address.
		if len(ref) > len(best) {
			best = ref
		}
	}
	return best
}

func isMeta(ref string) bool {
	for _, pfx := range metaPrefixes {
		if strings.HasPrefix(ref, pfx) {
			return true
		}
	}
	return false
}
