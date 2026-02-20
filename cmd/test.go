package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/leonamvasquez/terraview/internal/parser"
	"github.com/leonamvasquez/terraview/internal/rules"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Validate Terraform config and run hard rules (no AI)",
	Long: `Runs a deterministic test suite — no LLM dependency:

  1. terraform fmt -check  — formatting verification
  2. terraform validate    — syntax and configuration checks
  3. terraform test        — native tests (Terraform 1.6+, if available)
  4. Hard rules            — deterministic rule evaluation against the plan

Exit codes:
  0 — all checks passed
  1 — execution error (fmt, validate, plan generation)
  2 — rule violations (CRITICAL or HIGH findings)

Examples:
  terraview test
  terraview test --rules custom-rules.yaml
  terraview test -v`,
	RunE: runTest,
}

func init() {
	testCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "Path to rules YAML file")
}

func runTest(cmd *cobra.Command, args []string) error {
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

	// --- Step 4: Hard rules ---
	fmt.Println("═══════════════════════════════════════════════")
	fmt.Println("  Step 4: Hard Rules")
	fmt.Println("═══════════════════════════════════════════════")

	ruleViolations = !runHardRulesTest(executor)

	// --- Summary ---
	fmt.Println("═══════════════════════════════════════════════")
	if stepErrors == 0 && !ruleViolations {
		fmt.Println("  All tests PASSED")
		fmt.Println("═══════════════════════════════════════════════")
		return nil
	}

	if ruleViolations {
		fmt.Println("  FAILED — rule violations detected")
		fmt.Println("═══════════════════════════════════════════════")
		os.Exit(2)
	}

	fmt.Println("  FAILED — execution errors")
	fmt.Println("═══════════════════════════════════════════════")
	os.Exit(1)

	return nil
}

func runHardRulesTest(executor *terraformexec.Executor) bool {
	resolvedRules := rulesFile
	if resolvedRules == "" {
		resolvedRules = findBundledFile("rules", "default-rules.yaml")
	}

	// Check if plan.json already exists
	planPath := filepath.Join(executor.WorkDir(), "plan.json")
	if _, err := os.Stat(planPath); err != nil {
		// Generate plan
		generated, err := executor.Plan()
		if err != nil {
			fmt.Printf("\n  Failed to generate plan: %v\n\n", err)
			return false
		}
		planPath = generated
	}

	p := parser.NewParser()
	plan, err := p.ParseFile(planPath)
	if err != nil {
		fmt.Printf("\n  Failed to parse plan: %v\n\n", err)
		return false
	}

	resources := p.NormalizeResources(plan)

	engine, err := rules.NewEngine(resolvedRules)
	if err != nil {
		fmt.Printf("\n  Failed to load rules: %v\n\n", err)
		return false
	}

	findings := engine.Evaluate(resources)

	criticalCount := 0
	highCount := 0
	for _, f := range findings {
		switch f.Severity {
		case rules.SeverityCritical:
			criticalCount++
		case rules.SeverityHigh:
			highCount++
		}
	}

	fmt.Printf("\n  Resources: %d | Findings: %d (CRITICAL: %d, HIGH: %d)\n\n",
		len(resources), len(findings), criticalCount, highCount)

	if criticalCount > 0 {
		for _, f := range findings {
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
