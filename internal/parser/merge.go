package parser

import (
	"fmt"
	"log"
	"sort"
)

// MergeTerraformPlans combines multiple TerraformPlan structs (one per Terragrunt module)
// into a single plan. Each module's resources are prefixed with "module.<modName>." so that
// the downstream pipeline (scanner, AI, diagram, scoring) sees a unified plan.
//
// The merged plan has:
//   - FormatVersion/TerraformVersion from the first plan
//   - ResourceChanges concatenated with prefixed addresses
//   - PlannedValues.RootModule.ChildModules: one Module per input plan
//   - Configuration merged (provider configs union, one ModuleCall per plan)
//   - Variables merged (union, last wins on conflict)
func MergeTerraformPlans(plans map[string]*TerraformPlan) (*TerraformPlan, error) {
	if len(plans) == 0 {
		return nil, fmt.Errorf("no plans to merge")
	}

	// Sort module names for deterministic output
	modNames := make([]string, 0, len(plans))
	for name := range plans {
		modNames = append(modNames, name)
	}
	sort.Strings(modNames)

	merged := &TerraformPlan{
		PlannedValues: PlannedValues{
			RootModule: Module{},
		},
		Configuration: Configuration{
			ProviderConfig: make(map[string]ProviderConfig),
			RootModule: ConfigModule{
				ModuleCalls: make(map[string]ModuleCall),
			},
		},
		Variables: make(map[string]Variable),
	}

	versionSet := false
	for _, modName := range modNames {
		plan := plans[modName]

		// Skip modules with no resource changes
		if len(plan.ResourceChanges) == 0 {
			log.Printf("[merge] aviso: módulo %q sem resource_changes, ignorado", modName)
			continue
		}

		prefix := "module." + modName

		// Version info from first non-empty plan; warn on mismatch
		if !versionSet {
			merged.FormatVersion = plan.FormatVersion
			merged.TerraformVersion = plan.TerraformVersion
			versionSet = true
		} else {
			if plan.FormatVersion != merged.FormatVersion {
				log.Printf("[merge] aviso: módulo %q usa format_version %q (esperado %q)", modName, plan.FormatVersion, merged.FormatVersion)
			}
			if plan.TerraformVersion != merged.TerraformVersion {
				log.Printf("[merge] aviso: módulo %q usa terraform %q (esperado %q)", modName, plan.TerraformVersion, merged.TerraformVersion)
			}
		}

		// Merge ResourceChanges with address prefixing
		for _, rc := range plan.ResourceChanges {
			rc.Address = prefix + "." + rc.Address
			if rc.ModuleAddress == "" {
				rc.ModuleAddress = prefix
			} else {
				rc.ModuleAddress = prefix + "." + rc.ModuleAddress
			}
			merged.ResourceChanges = append(merged.ResourceChanges, rc)
		}

		// Merge PlannedValues as child modules
		childModule := Module{
			Address:   prefix,
			Resources: plan.PlannedValues.RootModule.Resources,
		}
		// Prefix resource addresses in planned values
		for j := range childModule.Resources {
			childModule.Resources[j].Address = prefix + "." + childModule.Resources[j].Address
		}
		// Carry over any existing child modules
		childModule.ChildModules = plan.PlannedValues.RootModule.ChildModules
		merged.PlannedValues.RootModule.ChildModules = append(
			merged.PlannedValues.RootModule.ChildModules, childModule,
		)

		// Merge Configuration.ProviderConfig (union; first wins, warn on duplicate)
		for k, v := range plan.Configuration.ProviderConfig {
			if _, exists := merged.Configuration.ProviderConfig[k]; !exists {
				merged.Configuration.ProviderConfig[k] = v
			} else {
				log.Printf("[merge] aviso: provider %q duplicado no módulo %q (usando config do primeiro módulo)", k, modName)
			}
		}

		// Add ModuleCall for this module
		merged.Configuration.RootModule.ModuleCalls[modName] = ModuleCall{
			Source: modName,
			Module: &plan.Configuration.RootModule,
		}

		// Merge Variables (union, last wins on conflict)
		for k, v := range plan.Variables {
			if _, exists := merged.Variables[k]; exists {
				log.Printf("[merge] aviso: variável %q sobrescrita pelo módulo %q", k, modName)
			}
			merged.Variables[k] = v
		}
	}

	return merged, nil
}
