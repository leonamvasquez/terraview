package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:     "validate",
	Aliases: []string{"test"},
	Short:   "Validate Terraform config and run security scanners (no AI)",
	Long: `Runs a scanner-based validation suite — no LLM dependency:

  1. terraform fmt -check  — formatting verification
  2. terraform validate    — syntax and configuration checks
  3. terraform test        — native tests (Terraform 1.6+, if available)
  4. Security scanners     — external scanner evaluation (checkov, tfsec, etc.)

Exit codes:
  0 — all checks passed
  1 — execution error (fmt, validate, plan generation)
  2 — scanner violations (CRITICAL or HIGH findings)

Examples:
  terraview validate
  terraview validate -v`,
	RunE: runValidate,
}

func runValidate(cmd *cobra.Command, args []string) error {
	if err := workspace.Validate(workDir); err != nil {
		return err
	}

	executor, err := terraformexec.NewExecutor(workDir)
	if err != nil {
		return err
	}

	stepErrors := 0
	ruleViolations := false

	// --- Step 1: terraform fmt -check ---
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Step 1: terraform fmt -check")
	fmt.Println("═══════════════════════════════════════════════")

	fmtOut, err := executor.FmtCheck()
	if err != nil {
		unformatted := strings.TrimSpace(fmtOut)
		if unformatted != "" {
			fmt.Printf("\n  Unformatted files:\n")
			for _, f := range strings.Split(unformatted, "\n") {
				if f = strings.TrimSpace(f); f != "" {
					fmt.Printf("    - %s\n", f)
				}
			}
		}
		fmt.Print("\n  Result: FAILED (run 'terraform fmt' to fix)\n\n")
		stepErrors++
	} else {
		fmt.Print("\n  Result: PASSED\n\n")
	}

	// --- Step 2: terraform validate ---
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Step 2: terraform validate")
	fmt.Println("═══════════════════════════════════════════════")

	if executor.NeedsInit() {
		if err := executor.Init(); err != nil {
			return err
		}
	}

	_, err = executor.Validate()
	if err != nil {
		fmt.Printf("\n  Result: FAILED (%v)\n\n", err)
		stepErrors++
	} else {
		fmt.Print("\n  Result: PASSED\n\n")
	}

	// --- Step 3: terraform test ---
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Step 3: terraform test")
	fmt.Println("═══════════════════════════════════════════════")

	_, available, err := executor.Test()
	if !available {
		fmt.Print("\n  Result: SKIPPED (terraform test not available in this version)\n\n")
	} else if err != nil {
		fmt.Printf("\n  Result: FAILED (%v)\n\n", err)
		stepErrors++
	} else {
		fmt.Print("\n  Result: PASSED\n\n")
	}

	// --- Step 4: Security Scanners ---
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Step 4: Security Scanners")
	fmt.Println("═══════════════════════════════════════════════")

	ruleViolations = !runScannerTest(executor)

	// --- Summary ---
	fmt.Println("═══════════════════════════════════════════════")
	if stepErrors == 0 && !ruleViolations {
		fmt.Println("  All tests PASSED")
		fmt.Println("═══════════════════════════════════════════════")
		return nil
	}

	if ruleViolations {
		fmt.Println("  FAILED — scanner violations detected")
		fmt.Println("═══════════════════════════════════════════════")
		return &ExitError{Code: 2}
	}

	fmt.Println("  FAILED — execution errors")
	fmt.Println("═══════════════════════════════════════════════")
	return &ExitError{Code: 1}
}

func runScannerTest(executor *terraformexec.Executor) bool {
	// Resolve available scanners
	scanners, err := scanner.Resolve("auto")
	if err != nil {
		fmt.Printf("\n  Failed to resolve scanners: %v\n\n", err)
		return false
	}

	if len(scanners) == 0 {
		fmt.Printf("\n  %s No scanners available. Install checkov, tfsec, or terrascan.\n", output.Prefix())
		fmt.Print("\n  Result: SKIPPED\n\n")
		return true
	}

	names := make([]string, len(scanners))
	for i, s := range scanners {
		names[i] = s.Name()
	}
	fmt.Printf("\n  Scanners: %s\n", strings.Join(names, ", "))

	// Ensure plan.json exists
	planPath := executor.WorkDir()
	planJSON := planPath
	if fi, err := os.Stat(planPath); err == nil && fi.IsDir() {
		planJSON = planPath + "/plan.json"
	}

	if _, err := os.Stat(planJSON); err != nil {
		generated, err := executor.Plan()
		if err != nil {
			fmt.Printf("\n  Failed to generate plan: %v\n\n", err)
			return false
		}
		planJSON = generated
	}

	scanCtx := scanner.ScanContext{
		PlanPath:  planJSON,
		SourceDir: executor.WorkDir(),
		WorkDir:   executor.WorkDir(),
	}

	rawResults := scanner.RunAll(scanners, scanCtx)
	aggResult := scanner.Aggregate(rawResults)

	criticalCount := 0
	highCount := 0
	for _, f := range aggResult.Findings {
		switch f.Severity {
		case rules.SeverityCritical:
			criticalCount++
		case rules.SeverityHigh:
			highCount++
		}
	}

	fmt.Printf("  Findings: %d (CRITICAL: %d, HIGH: %d)\n\n",
		len(aggResult.Findings), criticalCount, highCount)

	if criticalCount > 0 {
		for _, f := range aggResult.Findings {
			if f.Severity == rules.SeverityCritical {
				fmt.Printf("  [CRITICAL] %s: %s\n", f.Resource, f.Message)
			}
		}
		fmt.Println()
	}

	if criticalCount > 0 || highCount > 0 {
		fmt.Print("  Result: FAILED\n\n")
		return false
	}

	fmt.Print("  Result: PASSED\n\n")
	return true
}
