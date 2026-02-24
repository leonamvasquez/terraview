package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var (
	nonInteractive bool
)

var applyCmd = &cobra.Command{
	Use:   "apply [scanner]",
	Short: "Scan and conditionally apply the Terraform plan",
	Long: `Runs a full scan of the Terraform plan, then conditionally applies it.

The scanner is specified as a positional argument (same pattern as scan).

Behavior:
  - Blocks if any CRITICAL findings are detected
  - Shows scan summary and asks for confirmation (interactive mode)
  - Use --non-interactive for CI pipelines (blocks on CRITICAL, auto-approves otherwise)

Examples:
  terraview apply checkov                     # scan + interactive apply
  terraview apply checkov --ai                # scan + AI + interactive apply
  terraview apply checkov --non-interactive   # CI mode
  terraview apply checkov --all               # everything enabled + apply`,
	Args: cobra.MaximumNArgs(1),
	RunE: runApply,
}

func init() {
	applyCmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Skip confirmation prompt (for CI)")
	applyCmd.Flags().BoolVar(&aiEnabled, "ai", false, "Enable AI-powered semantic review")
	applyCmd.Flags().BoolVar(&strict, "strict", false, "Strict mode: HIGH findings also return exit code 2")
	applyCmd.Flags().BoolVar(&explainFlag, "explain", false, "Generate AI-powered natural language explanation (implies --ai)")
	applyCmd.Flags().BoolVar(&diagramFlag, "diagram", false, "Show ASCII infrastructure diagram")
	applyCmd.Flags().BoolVar(&impactFlag, "impact", false, "Analyze dependency impact of changes")
	applyCmd.Flags().StringVar(&findingsFile, "findings", "", "Import external findings from Checkov/tfsec/Trivy JSON")
	applyCmd.Flags().BoolVar(&allFlag, "all", false, "Enable all features: explain + diagram + impact")
}

func runApply(cmd *cobra.Command, args []string) error {
	// Resolve scanner from positional arg
	scannerName := ""
	if len(args) > 0 {
		scannerName = args[0]
	}

	// --all enables all features
	if allFlag {
		explainFlag = true
		diagramFlag = true
		impactFlag = true
		aiEnabled = true
	}

	// If no scanner specified, try auto-select (same as scan command)
	if scannerName == "" {
		cfg, _ := config.Load(workDir)
		resolved, _ := scanner.ResolveDefault(cfg.Scanner.Default)
		if resolved != nil {
			scannerName = resolved.Name()
			logVerbose("Auto-selected scanner: %s", scannerName)
		}
	}

	// Validate: must specify a scanner or --ai (or both)
	if scannerName == "" && !aiEnabled && !explainFlag && !diagramFlag && findingsFile == "" {
		return fmt.Errorf("specify a scanner or --ai\n\nUsage:\n  terraview apply checkov          # scan + apply\n  terraview apply checkov --ai     # scan + AI + apply\n\nAvailable scanners: checkov, tfsec, terrascan")
	}

	// 1. Run scan
	_, exitCode, err := executeReview(scannerName)
	if err != nil {
		return err
	}

	// 2. Block on CRITICAL
	if exitCode == 2 {
		fmt.Println()
		fmt.Println("BLOCKED: CRITICAL findings detected. Fix them before applying.")
		fmt.Println("Review the findings in review.md for details.")
		return &ExitError{Code: 2}
	}

	// 3. Warn on HIGH
	if exitCode == 1 {
		fmt.Println()
		fmt.Println("WARNING: HIGH severity findings detected.")
		fmt.Println("Review the findings in review.md before proceeding.")
		fmt.Println()
	}

	// 4. Confirm
	if !nonInteractive {
		if !confirmApply() {
			fmt.Println("Apply cancelled.")
			return nil
		}
	} else {
		logVerbose("Non-interactive mode: auto-approving apply")
	}

	// 5. Apply
	if err := workspace.Validate(workDir); err != nil {
		return err
	}

	executor, err := terraformexec.NewExecutor(workDir)
	if err != nil {
		return err
	}

	if err := executor.Apply(); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("Apply completed successfully.")

	return nil
}

func confirmApply() bool {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Do you want to apply this plan? (yes/no): ")
	input, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	input = strings.TrimSpace(strings.ToLower(input))
	return input == "yes" || input == "y"
}
