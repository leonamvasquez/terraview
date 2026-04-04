package fix

import (
	"testing"

	"github.com/leonamvasquez/terraview/internal/parser"
)

// syntheticPlan builds a TerraformPlan with 3 resources and configuration
// expressions for aws_api_gateway_method.proxy, as required by the Sprint 6
// test specification.
func syntheticPlan() *parser.TerraformPlan {
	return &parser.TerraformPlan{
		Configuration: parser.Configuration{
			RootModule: parser.ConfigModule{
				Resources: []parser.ConfigResource{
					{
						Address: "aws_api_gateway_method.proxy",
						Type:    "aws_api_gateway_method",
						Name:    "proxy",
						Expressions: map[string]interface{}{
							"rest_api_id": map[string]interface{}{
								"references": []interface{}{
									"aws_api_gateway_rest_api.main.id",
									"aws_api_gateway_rest_api.main",
								},
							},
							// var.resource_id should be ignored (meta-prefix).
							"resource_id": map[string]interface{}{
								"references": []interface{}{
									"var.resource_id",
								},
							},
						},
					},
				},
			},
		},
	}
}

// syntheticResources returns the three normalized resources used across plan_index tests.
func syntheticResources() []parser.NormalizedResource {
	return []parser.NormalizedResource{
		{Address: "aws_kms_key.main", Type: "aws_kms_key", Name: "main", Action: "create"},
		{Address: "aws_api_gateway_rest_api.main", Type: "aws_api_gateway_rest_api", Name: "main", Action: "create"},
		{Address: "aws_api_gateway_method.proxy", Type: "aws_api_gateway_method", Name: "proxy", Action: "create"},
	}
}

func TestBuildIndex_IndexesTypesByResource(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	if idx == nil {
		t.Fatal("BuildIndex returned nil")
	}

	cases := []struct {
		resourceType string
		wantLen      int
		wantAddr     string
	}{
		{"aws_kms_key", 1, "aws_kms_key.main"},
		{"aws_api_gateway_rest_api", 1, "aws_api_gateway_rest_api.main"},
		{"aws_api_gateway_method", 1, "aws_api_gateway_method.proxy"},
	}

	for _, tc := range cases {
		got := idx.ResourcesOfType(tc.resourceType)
		if len(got) != tc.wantLen {
			t.Errorf("ResourcesOfType(%q): got %d entries, want %d", tc.resourceType, len(got), tc.wantLen)
			continue
		}
		if got[0] != tc.wantAddr {
			t.Errorf("ResourcesOfType(%q)[0] = %q, want %q", tc.resourceType, got[0], tc.wantAddr)
		}
	}
}

func TestBuildIndex_DeletedResourcesExcluded(t *testing.T) {
	resources := []parser.NormalizedResource{
		{Address: "aws_kms_key.old", Type: "aws_kms_key", Name: "old", Action: "delete"},
		{Address: "aws_kms_key.main", Type: "aws_kms_key", Name: "main", Action: "create"},
	}

	idx := BuildIndex(nil, resources)

	got := idx.ResourcesOfType("aws_kms_key")
	if len(got) != 1 || got[0] != "aws_kms_key.main" {
		t.Errorf("expected only aws_kms_key.main (non-deleted), got %v", got)
	}
}

func TestResourcesOfType_KnownType(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	got := idx.ResourcesOfType("aws_kms_key")
	if len(got) != 1 || got[0] != "aws_kms_key.main" {
		t.Errorf("ResourcesOfType(\"aws_kms_key\") = %v, want [\"aws_kms_key.main\"]", got)
	}
}

func TestResourcesOfType_UnknownTypeReturnsNil(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	got := idx.ResourcesOfType("aws_ec2_instance")
	if got != nil {
		t.Errorf("ResourcesOfType(\"aws_ec2_instance\") = %v, want nil", got)
	}
}

func TestResolvedRefs_PicksMostSpecificRef(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	refs := idx.ResolvedRefs("aws_api_gateway_method.proxy")
	if refs == nil {
		t.Fatal("ResolvedRefs returned nil for aws_api_gateway_method.proxy")
	}

	got, ok := refs["rest_api_id"]
	if !ok {
		t.Fatal("rest_api_id not found in resolved refs")
	}
	// Should pick the longer/more specific form ".id".
	want := "aws_api_gateway_rest_api.main.id"
	if got != want {
		t.Errorf("refs[\"rest_api_id\"] = %q, want %q", got, want)
	}
}

func TestResolvedRefs_MetaRefIgnored(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	refs := idx.ResolvedRefs("aws_api_gateway_method.proxy")

	if _, ok := refs["resource_id"]; ok {
		t.Error("resource_id with only var.resource_id should not appear in resolved refs")
	}
}

func TestResolvedRefs_UnknownResourceReturnsNil(t *testing.T) {
	idx := BuildIndex(syntheticPlan(), syntheticResources())

	got := idx.ResolvedRefs("aws_lambda_function.unknown")
	if got != nil {
		t.Errorf("ResolvedRefs for unknown resource = %v, want nil", got)
	}
}

func TestBuildIndex_NilPlanDegraceGracefully(t *testing.T) {
	// Must not panic.
	idx := BuildIndex(nil, syntheticResources())

	if idx == nil {
		t.Fatal("BuildIndex(nil, resources) returned nil")
	}

	// ByType still populated from resources.
	if got := idx.ResourcesOfType("aws_kms_key"); len(got) == 0 {
		t.Error("expected aws_kms_key to be indexed even with nil plan")
	}

	// refs section should be empty — no panic on lookup.
	if refs := idx.ResolvedRefs("aws_api_gateway_method.proxy"); refs != nil {
		t.Errorf("expected nil refs when plan is nil, got %v", refs)
	}
}

func TestBuildIndex_NilResourcesDegraceGracefully(t *testing.T) {
	// Must not panic.
	idx := BuildIndex(syntheticPlan(), nil)

	if idx == nil {
		t.Fatal("BuildIndex(plan, nil) returned nil")
	}

	// No resources indexed.
	if got := idx.ResourcesOfType("aws_kms_key"); got != nil {
		t.Errorf("expected nil for empty resources, got %v", got)
	}
}

func TestPickBestRef_PrefersLongerRef(t *testing.T) {
	cases := []struct {
		name string
		refs []interface{}
		want string
	}{
		{
			name: "specific before bare",
			refs: []interface{}{"aws_kms_key.main.arn", "aws_kms_key.main"},
			want: "aws_kms_key.main.arn",
		},
		{
			name: "id suffix",
			refs: []interface{}{"aws_api_gateway_rest_api.main.id", "aws_api_gateway_rest_api.main"},
			want: "aws_api_gateway_rest_api.main.id",
		},
		{
			name: "all meta refs returns empty",
			refs: []interface{}{"var.kms_key_id", "local.kms_arn"},
			want: "",
		},
		{
			name: "mixed meta and real",
			refs: []interface{}{"var.key", "aws_kms_key.main"},
			want: "aws_kms_key.main",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pickBestRef(tc.refs)
			if got != tc.want {
				t.Errorf("pickBestRef(%v) = %q, want %q", tc.refs, got, tc.want)
			}
		})
	}
}

func TestIsMeta(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"var.something", true},
		{"local.name", true},
		{"path.module", true},
		{"module.vpc", true},
		{"data.aws_region.current", true},
		{"each.key", true},
		{"count.index", true},
		{"aws_kms_key.main", false},
		{"aws_api_gateway_rest_api.main.id", false},
		{"", false},
	}

	for _, tc := range cases {
		got := isMeta(tc.ref)
		if got != tc.want {
			t.Errorf("isMeta(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}
