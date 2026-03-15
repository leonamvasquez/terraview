package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/modules"
	"github.com/leonamvasquez/terraview/internal/parser"
)

var (
	modulesCheckRegistry bool
)

var modulesCmd = &cobra.Command{
	Use:   "modules",
	Short: "Analyze Terraform module usage and health",
	Long: `Analyzes module calls in a Terraform plan for version pinning, source
hygiene, and nesting depth.

This command is deterministic and does not require AI.
If --plan is not specified, terraview will auto-generate the plan.

Rules checked:
  MOD_001  Registry module without version constraint
  MOD_002  Git source pinned to branch instead of tag
  MOD_003  Git source without any ref
  MOD_004  Module nesting exceeds recommended depth
  MOD_005  Module source uses HTTP instead of HTTPS
  MOD_006  Registry module has newer version available (--check-registry)

Examples:
  terraview modules
  terraview modules --plan plan.json
  terraview modules --check-registry
  terraview modules --format json

Terragrunt:
  terraview modules --terragrunt
  terraview modules --terragrunt -d modules/vpc`,
	RunE: runModules,
}

func init() {
	modulesCmd.Flags().BoolVar(&modulesCheckRegistry, "check-registry", false,
		"Check Terraform Registry for latest module versions (requires network)")
}

func runModules(cmd *cobra.Command, args []string) error {
	resolvedPlan := planFile

	if resolvedPlan == "" {
		generated, _, err := generatePlan()
		if err != nil {
			return err
		}
		resolvedPlan = generated
	}

	p := parser.NewParser()
	plan, err := p.ParseFile(resolvedPlan)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	logVerbose("Analyzing module calls...")

	var registry modules.RegistryChecker
	if modulesCheckRegistry {
		registry = modules.NewTerraformRegistry()
		logVerbose("Registry version checks enabled")
	}

	analyzer := modules.NewAnalyzer(registry)
	result := analyzer.Analyze(plan)

	logVerbose("Found %d modules, %d findings", result.Summary.TotalModules, len(result.Findings))

	// Output
	switch outputFormat {
	case "json":
		out, err := modules.FormatJSON(result)
		if err != nil {
			return err
		}
		fmt.Println(out)
	default:
		fmt.Print(modules.FormatPretty(result))
	}

	// Write to file if output dir specified
	resolvedOutput := outputDir
	if resolvedOutput == "" {
		resolvedOutput = workDir
	}

	modulesPath := filepath.Join(resolvedOutput, "modules.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal modules result: %w", err)
	}
	if err := os.WriteFile(modulesPath, data, 0644); err != nil { //nolint:gosec // report file, not secret
		return fmt.Errorf("failed to write %s: %w", modulesPath, err)
	}
	logVerbose("Written: %s", modulesPath)

	// Exit code: 1 if HIGH findings, 2 if CRITICAL
	for _, f := range result.Findings {
		if f.Severity == "CRITICAL" {
			return &ExitError{Code: 2}
		}
	}
	for _, f := range result.Findings {
		if f.Severity == "HIGH" {
			return &ExitError{Code: 1}
		}
	}

	return nil
}
