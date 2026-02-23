package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/leonamvasquez/terraview/internal/diagram"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/topology"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var diagramCmd = &cobra.Command{
	Use:   "diagram",
	Short: "Generate ASCII infrastructure diagram",
	Long: `Generates an ASCII infrastructure diagram from a Terraform plan.

This command is deterministic and does not require AI.
If --plan is not specified, terraview will auto-generate the plan.

Examples:
  terraview diagram
  terraview diagram --plan plan.json
  terraview diagram --output ./reports`,
	RunE: runDiagram,
}

func runDiagram(cmd *cobra.Command, args []string) error {
	resolvedPlan := planFile

	// Auto-generate plan if not provided
	if resolvedPlan == "" {
		if err := workspace.Validate(workDir); err != nil {
			return err
		}

		executor, err := terraformexec.NewExecutor(workDir)
		if err != nil {
			return err
		}

		if executor.NeedsInit() {
			if err := executor.Init(); err != nil {
				return err
			}
		}

		generated, err := executor.Plan()
		if err != nil {
			return err
		}
		resolvedPlan = generated
	}

	// Parse plan
	p := parser.NewParser()
	plan, err := p.ParseFile(resolvedPlan)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	logVerbose("Found %d resources", len(resources))

	if len(resources) == 0 {
		fmt.Println("No resources found in plan. Nothing to diagram.")
		return nil
	}

	// Build topology and generate diagram
	topoGraph := topology.BuildGraph(resources)
	gen := diagram.NewGenerator()
	result := gen.GenerateWithGraph(resources, topoGraph)

	// Output
	fmt.Println(result)

	// Write to file if output dir specified
	resolvedOutput := outputDir
	if resolvedOutput == "" {
		resolvedOutput = workDir
	}

	diagramPath := filepath.Join(resolvedOutput, "diagram.txt")
	if err := os.WriteFile(diagramPath, []byte(result), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", diagramPath, err)
	}
	logVerbose("Written: %s", diagramPath)

	return nil
}
