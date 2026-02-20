package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/leonam/terraview/internal/drift"
	"github.com/leonam/terraview/internal/parser"
	"github.com/leonam/terraview/internal/rules"
	"github.com/leonam/terraview/internal/terraformexec"
	"github.com/leonam/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect and classify infrastructure drift",
	Long: `Runs terraform plan to detect drift between state and infrastructure.

Classifies each change by risk level and generates a drift report.
Does NOT require LLM — uses deterministic analysis only.

Exit codes:
  0 — no drift or low-risk changes only
  1 — HIGH risk drift detected
  2 — CRITICAL risk drift detected

Examples:
  terraview drift
  terraview drift --plan plan.json
  terraview drift --format compact
  terraview drift --format json`,
	RunE: runDrift,
}

func init() {
	driftCmd.Flags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	driftCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for drift report")
	driftCmd.Flags().StringVar(&outputFormat, "format", "", "Output format: pretty, compact, json (default pretty)")
}

func runDrift(cmd *cobra.Command, args []string) error {
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
	logVerbose("Parsing plan for drift analysis: %s", resolvedPlan)
	p := parser.NewParser()
	plan, err := p.ParseFile(resolvedPlan)
	if err != nil {
		return fmt.Errorf("parse error: %w", err)
	}

	resources := p.NormalizeResources(plan)
	logVerbose("Found %d resources in plan", len(resources))

	// Load critical resource types from rules if available
	var criticalTypes []string
	resolvedRules := rulesFile
	if resolvedRules == "" {
		resolvedRules = findBundledFile("rules", "default-rules.yaml")
	}
	if resolvedRules != "" {
		engine, err := rules.NewEngine(resolvedRules)
		if err == nil {
			criticalTypes = engine.CriticalResourceTypes()
		}
	}

	// Analyze drift
	analyzer := drift.NewAnalyzer(criticalTypes)
	result := analyzer.Analyze(resources)

	// Output
	resolvedOutput := outputDir
	if resolvedOutput == "" {
		resolvedOutput = workDir
	}

	// Write JSON
	driftJSON, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal drift result: %w", err)
	}

	jsonPath := filepath.Join(resolvedOutput, "drift.json")
	if err := os.WriteFile(jsonPath, driftJSON, 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", jsonPath, err)
	}
	logVerbose("Written: %s", jsonPath)

	// Resolve format
	driftFormat := "pretty"
	if outputFormat != "" {
		driftFormat = outputFormat
	}

	// Print summary
	if driftFormat != "json" {
		printDriftSummary(result, driftFormat)
	}

	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}

	return nil
}

func printDriftSummary(result drift.DriftResult, format string) {
	if format == "compact" {
		if result.TotalChanges == 0 {
			fmt.Println("terraview drift: no changes detected | exit=0")
			return
		}
		fmt.Printf("terraview drift: %d changes | findings=%d | max=%s | exit=%d\n",
			result.TotalChanges, len(result.Findings), result.MaxSeverity, result.ExitCode)
		return
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Drift Analysis")
	fmt.Println("═══════════════════════════════════════════════")

	if result.TotalChanges == 0 {
		fmt.Println("  No infrastructure drift detected.")
		fmt.Println("  State is in sync with the real infrastructure.")
		fmt.Println("═══════════════════════════════════════════════")
		return
	}

	fmt.Printf("  Total changes:  %d\n", result.TotalChanges)

	if result.Creates > 0 {
		fmt.Printf("    Creates:      %d\n", result.Creates)
	}
	if result.Updates > 0 {
		fmt.Printf("    Updates:      %d\n", result.Updates)
	}
	if result.Deletes > 0 {
		fmt.Printf("    Deletes:      %d\n", result.Deletes)
	}
	if result.Replaces > 0 {
		fmt.Printf("    Replaces:     %d\n", result.Replaces)
	}
	fmt.Println()

	if len(result.Findings) > 0 {
		fmt.Printf("  Drift findings: %d\n", len(result.Findings))
		fmt.Println()
		for _, f := range result.Findings {
			fmt.Printf("    [%s] %s\n", f.Severity, f.Message)
		}
		fmt.Println()
	}

	fmt.Printf("  Max severity:   %s\n", result.MaxSeverity)
	fmt.Printf("  Exit code:      %d\n", result.ExitCode)
	fmt.Println()
	fmt.Printf("  %s\n", result.Summary)
	fmt.Println("═══════════════════════════════════════════════")
}
