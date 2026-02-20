package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	verbose bool
	workDir string
)

// Version is set at build time via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "terraview",
	Short: "Semantic reviewer for Terraform plans",
	Long: `terraview — Semantic reviewer for Terraform plans

Analyzes infrastructure-as-code using deterministic rules and optional AI review.

Core Commands:
  review      Review a Terraform plan (rules + AI)
  apply       Review and conditionally apply the plan
  test        Run deterministic checks (no AI)
  drift       Detect and classify infrastructure drift

AI Management:
  ai          Manage AI providers (list, test, current)
  install     Install LLM runtime (Ollama)
  uninstall   Remove LLM runtime

Utilities:
  version     Show version information
  update      Check for updates

Get started:
  cd my-terraform-project
  terraview review                  # full review (rules + AI)
  terraview review --skip-llm       # hard rules only
  terraview test                    # deterministic checks
  terraview drift                   # detect drift`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&workDir, "dir", "d", ".", "Terraform workspace directory")

	// Core commands
	rootCmd.AddCommand(reviewCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(driftCmd)

	// AI management
	rootCmd.AddCommand(aiCmd)
	rootCmd.AddCommand(installCmd)
	rootCmd.AddCommand(uninstallCmd)

	// Utilities
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
}

// Execute runs the root command.
func Execute(version string) {
	Version = version

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "[terraview] "+format+"\n", args...)
	}
}
