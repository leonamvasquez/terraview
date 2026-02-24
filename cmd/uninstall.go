package cmd

import (
	"fmt"
	"os"

	"github.com/leonamvasquez/terraview/internal/installer"
	"github.com/spf13/cobra"
)

var uninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall dependencies managed by terraview",
	Long:  `Remove external dependencies that were installed by terraview.`,
}

var uninstallLLMCmd = &cobra.Command{
	Use:   "llm",
	Short: "Uninstall Ollama and remove all models",
	Long: `Removes the Ollama binary, stops any running service,
and deletes downloaded model data.

This command is idempotent: running it when Ollama is not
installed will simply confirm there is nothing to remove.

Examples:
  terraview uninstall llm`,
	RunE: runUninstallLLM,
}

func init() {
	uninstallCmd.AddCommand(uninstallLLMCmd)
}

func runUninstallLLM(cmd *cobra.Command, args []string) error {
	// Show what will be removed
	if installer.OllamaInstalled() {
		version := installer.OllamaVersion()
		fmt.Printf("Ollama %s is installed.\n", version)

		models, err := installer.ListModels()
		if err == nil && len(models) > 0 {
			fmt.Printf("Models installed: %v\n", models)
		}

		fmt.Println("\nThis will:")
		fmt.Println("  - Stop Ollama service (if running)")
		fmt.Println("  - Remove Ollama binary")
		fmt.Println("  - Remove all downloaded models and data")
		fmt.Println()

		// Confirm with user
		fmt.Print("Continue? [y/N] ")
		var confirm string
		fmt.Scanln(&confirm)
		if confirm != "y" && confirm != "Y" {
			fmt.Println("Canceled.")
			return nil
		}
		fmt.Println()
	}

	u := installer.NewUninstaller(os.Stdout)
	result, err := u.Uninstall()
	if err != nil {
		return fmt.Errorf("uninstall failed: %w", err)
	}

	fmt.Println()
	if !result.WasInstalled {
		fmt.Println("Nothing to uninstall.")
		return nil
	}

	if result.BinaryRemoved {
		fmt.Println("✔ Ollama binary removed.")
	}
	if result.DataRemoved {
		fmt.Println("✔ Ollama data removed.")
	}
	if result.ServiceStopped {
		fmt.Println("✔ Ollama service stopped.")
	}

	fmt.Println("\nOllama has been uninstalled.")
	return nil
}
