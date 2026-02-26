package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/leonamvasquez/terraview/internal/drift"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/spf13/cobra"
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect and classify infrastructure drift",
	Long: `Runs terraform plan to detect drift between state and infrastructure.

Classifies each change by risk level and generates a drift report.
Use --intelligence for advanced classification (intentional vs suspicious).

Exit codes:
  0 — no drift or low-risk changes only
  1 — HIGH risk drift detected
  2 — CRITICAL risk drift detected

Examples:
  terraview drift
  terraview drift --plan plan.json
  terraview drift --intelligence          # classify + risk score
  terraview drift --format compact
  terraview drift --format json

Terragrunt:
  terraview drift --terragrunt
  terraview drift --terragrunt -d modules/vpc`,
	RunE: runDrift,
}

var driftIntelligenceFlag bool

func init() {
	// Only local flag — global flags (--plan, --output, --format) are inherited from root
	driftCmd.Flags().BoolVar(&driftIntelligenceFlag, "intelligence", false, "Advanced drift classification and risk scoring")
}

func runDrift(cmd *cobra.Command, args []string) error {
	resolvedPlan := planFile

	// Auto-generate plan if not provided
	if resolvedPlan == "" {
		generated, _, err := generatePlan()
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

	// Analyze drift (uses built-in critical resource types)
	analyzer := drift.NewAnalyzer(nil)
	result := analyzer.Analyze(resources)

	// Intelligence analysis if requested
	var intelResult *drift.IntelligenceResult
	if driftIntelligenceFlag {
		intelResult = drift.ClassifyDrift(resources, nil)
		logVerbose("Drift intelligence: %d items, risk=%s (%.1f)", len(intelResult.Items), intelResult.RiskLevel, intelResult.OverallRisk)
	}

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

	// Write intelligence JSON if available
	if intelResult != nil {
		intelJSON, err := json.MarshalIndent(intelResult, "", "  ")
		if err == nil {
			intelPath := filepath.Join(resolvedOutput, "drift-intelligence.json")
			if err := os.WriteFile(intelPath, intelJSON, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "%s WARNING: failed to write %s: %v\n", output.Prefix(), intelPath, err)
			} else {
				logVerbose("Written: %s", intelPath)
			}
		}
	}

	// Resolve format
	driftFormat := "pretty"
	if outputFormat != "" {
		driftFormat = outputFormat
	}

	// Print summary
	if driftFormat != "json" {
		printDriftSummary(result, driftFormat)
		if intelResult != nil && driftFormat != "compact" {
			fmt.Println()
			fmt.Println(drift.FormatNarrative(intelResult))
		}
	}

	if result.ExitCode != 0 {
		return &ExitError{Code: result.ExitCode}
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
