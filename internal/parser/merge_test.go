package parser

import (
	"testing"
)

func TestMergeTerraformPlans_TwoPlans(t *testing.T) {
	plans := map[string]*TerraformPlan{
		"vpc": {
			FormatVersion:    "1.2",
			TerraformVersion: "1.9.0",
			ResourceChanges: []ResourceChange{
				{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main", Change: Change{Actions: []string{"create"}}},
				{Address: "aws_subnet.pub", Type: "aws_subnet", Name: "pub", Change: Change{Actions: []string{"create"}}},
			},
			PlannedValues: PlannedValues{
				RootModule: Module{
					Resources: []PlannedResource{
						{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main"},
					},
				},
			},
			Configuration: Configuration{
				ProviderConfig: map[string]ProviderConfig{
					"aws": {Name: "aws"},
				},
				RootModule: ConfigModule{},
			},
			Variables: map[string]Variable{
				"region": {Default: "us-east-1"},
			},
		},
		"eks": {
			FormatVersion:    "1.2",
			TerraformVersion: "1.9.0",
			ResourceChanges: []ResourceChange{
				{Address: "aws_eks_cluster.main", Type: "aws_eks_cluster", Name: "main", Change: Change{Actions: []string{"create"}}},
			},
			PlannedValues: PlannedValues{
				RootModule: Module{
					Resources: []PlannedResource{
						{Address: "aws_eks_cluster.main", Type: "aws_eks_cluster", Name: "main"},
					},
				},
			},
			Configuration: Configuration{
				ProviderConfig: map[string]ProviderConfig{
					"aws": {Name: "aws"},
				},
				RootModule: ConfigModule{},
			},
			Variables: map[string]Variable{
				"cluster_name": {Default: "prod"},
			},
		},
	}

	merged, err := MergeTerraformPlans(plans)
	if err != nil {
		t.Fatalf("MergeTerraformPlans failed: %v", err)
	}

	// Version from first plan (alphabetical: eks)
	if merged.FormatVersion != "1.2" {
		t.Errorf("FormatVersion = %q, want %q", merged.FormatVersion, "1.2")
	}

	// ResourceChanges: 2 from vpc + 1 from eks = 3
	if len(merged.ResourceChanges) != 3 {
		t.Fatalf("ResourceChanges count = %d, want 3", len(merged.ResourceChanges))
	}

	// Check address prefixing (sorted: eks first, then vpc)
	rc0 := merged.ResourceChanges[0]
	if rc0.Address != "module.eks.aws_eks_cluster.main" {
		t.Errorf("RC[0].Address = %q, want %q", rc0.Address, "module.eks.aws_eks_cluster.main")
	}
	if rc0.ModuleAddress != "module.eks" {
		t.Errorf("RC[0].ModuleAddress = %q, want %q", rc0.ModuleAddress, "module.eks")
	}

	rc1 := merged.ResourceChanges[1]
	if rc1.Address != "module.vpc.aws_vpc.main" {
		t.Errorf("RC[1].Address = %q, want %q", rc1.Address, "module.vpc.aws_vpc.main")
	}

	// PlannedValues: 2 child modules
	if len(merged.PlannedValues.RootModule.ChildModules) != 2 {
		t.Fatalf("ChildModules count = %d, want 2", len(merged.PlannedValues.RootModule.ChildModules))
	}
	if merged.PlannedValues.RootModule.ChildModules[0].Address != "module.eks" {
		t.Errorf("ChildModules[0].Address = %q, want %q",
			merged.PlannedValues.RootModule.ChildModules[0].Address, "module.eks")
	}

	// Configuration: 2 module calls
	if len(merged.Configuration.RootModule.ModuleCalls) != 2 {
		t.Errorf("ModuleCalls count = %d, want 2", len(merged.Configuration.RootModule.ModuleCalls))
	}
	if _, ok := merged.Configuration.RootModule.ModuleCalls["vpc"]; !ok {
		t.Error("Missing ModuleCall for 'vpc'")
	}

	// Variables: merged (both keys present)
	if _, ok := merged.Variables["region"]; !ok {
		t.Error("Missing variable 'region'")
	}
	if _, ok := merged.Variables["cluster_name"]; !ok {
		t.Error("Missing variable 'cluster_name'")
	}
}

func TestMergeTerraformPlans_SinglePlan(t *testing.T) {
	plans := map[string]*TerraformPlan{
		"vpc": {
			FormatVersion: "1.2",
			ResourceChanges: []ResourceChange{
				{Address: "aws_vpc.main", Type: "aws_vpc", Name: "main"},
			},
			PlannedValues: PlannedValues{RootModule: Module{}},
			Configuration: Configuration{
				ProviderConfig: make(map[string]ProviderConfig),
				RootModule:     ConfigModule{},
			},
		},
	}

	merged, err := MergeTerraformPlans(plans)
	if err != nil {
		t.Fatalf("MergeTerraformPlans failed: %v", err)
	}

	if len(merged.ResourceChanges) != 1 {
		t.Fatalf("ResourceChanges count = %d, want 1", len(merged.ResourceChanges))
	}
	if merged.ResourceChanges[0].Address != "module.vpc.aws_vpc.main" {
		t.Errorf("Address = %q, want %q", merged.ResourceChanges[0].Address, "module.vpc.aws_vpc.main")
	}
}

func TestMergeTerraformPlans_EmptyMap(t *testing.T) {
	_, err := MergeTerraformPlans(map[string]*TerraformPlan{})
	if err == nil {
		t.Error("expected error for empty map, got nil")
	}
}

func TestMergeTerraformPlans_ModuleAddressPrefixing(t *testing.T) {
	plans := map[string]*TerraformPlan{
		"network": {
			FormatVersion: "1.2",
			ResourceChanges: []ResourceChange{
				{
					Address:       "module.subnets.aws_subnet.pub",
					ModuleAddress: "module.subnets",
					Type:          "aws_subnet",
					Name:          "pub",
				},
			},
			PlannedValues: PlannedValues{RootModule: Module{}},
			Configuration: Configuration{
				ProviderConfig: make(map[string]ProviderConfig),
				RootModule:     ConfigModule{},
			},
		},
	}

	merged, err := MergeTerraformPlans(plans)
	if err != nil {
		t.Fatalf("MergeTerraformPlans failed: %v", err)
	}

	rc := merged.ResourceChanges[0]
	if rc.Address != "module.network.module.subnets.aws_subnet.pub" {
		t.Errorf("Address = %q, want %q", rc.Address, "module.network.module.subnets.aws_subnet.pub")
	}
	if rc.ModuleAddress != "module.network.module.subnets" {
		t.Errorf("ModuleAddress = %q, want %q", rc.ModuleAddress, "module.network.module.subnets")
	}
}
