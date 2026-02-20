package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/leonam/terraview/internal/terraformexec"
	"github.com/leonam/terraview/internal/workspace"
	"github.com/spf13/cobra"
)

var (
	nonInteractive bool
)

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Review the plan and apply if safe",
	Long: `Runs a full review of the Terraform plan, then conditionally applies it.

Behavior:
  - Blocks if any CRITICAL findings are detected
  - Shows review summary and asks for confirmation (interactive mode)
  - Use --non-interactive for CI pipelines (blocks on CRITICAL, auto-approves otherwise)

Examples:
  terraview apply                     # interactive mode
  terraview apply --non-interactive   # CI mode
  terraview apply --skip-llm          # skip LLM, interactive`,
	RunE: runApply,
}

func init() {
	applyCmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "Skip confirmation prompt (for CI)")
	applyCmd.Flags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	applyCmd.Flags().StringVarP(&rulesFile, "rules", "r", "", "Path to rules YAML file")
	applyCmd.Flags().StringVar(&promptDir, "prompts", "", "Path to prompts directory")
	applyCmd.Flags().StringVarP(&outputDir, "output", "o", "", "Output directory for review files")
	applyCmd.Flags().StringVar(&ollamaURL, "ollama-url", "", "Ollama server URL (legacy, prefer --provider)")
	applyCmd.Flags().StringVar(&ollamaModel, "model", "", "AI model to use")
	applyCmd.Flags().StringVar(&aiProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek)")
	applyCmd.Flags().IntVar(&timeout, "timeout", 0, "AI request timeout in seconds")
	applyCmd.Flags().Float64Var(&temperature, "temperature", -1, "AI temperature (0.0-1.0)")
	applyCmd.Flags().BoolVar(&skipLLM, "skip-llm", false, "Skip AI analysis (hard rules only)")
	applyCmd.Flags().StringVar(&outputFormat, "format", "", "Output format: pretty, compact, json (default pretty)")
	applyCmd.Flags().BoolVar(&safeMode, "safe", false, "Safe mode: light model, reduced resources")
}

func runApply(cmd *cobra.Command, args []string) error {
	// 1. Run review
	_, exitCode, err := executeReview()
	if err != nil {
		return err
	}

	// 2. Block on CRITICAL
	if exitCode == 2 {
		fmt.Println()
		fmt.Println("BLOCKED: CRITICAL findings detected. Fix them before applying.")
		fmt.Println("Review the findings in review.md for details.")
		os.Exit(2)
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
