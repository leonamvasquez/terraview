package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/installer"
	"github.com/spf13/cobra"
)

var installModel string

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install dependencies for terraview",
	Long:  `Install and configure external dependencies required by terraview.`,
}

var installLLMCmd = &cobra.Command{
	Use:   "llm",
	Short: "Install Ollama and pull the default LLM model",
	Long: `Automatically installs the Ollama runtime for local LLM inference,
pulls the configured model, and validates the setup.

This command is idempotent: running it multiple times will not
reinstall — it will only validate the existing installation.

Examples:
  terraview install llm
  terraview install llm --model codellama:13b`,
	RunE: runInstallLLM,
}

func init() {
	installLLMCmd.Flags().StringVar(&installModel, "model", "", "Model to pull (defaults to config or llama3.1:8b)")
	installCmd.AddCommand(installLLMCmd)
}

func runInstallLLM(cmd *cobra.Command, args []string) error {
	// Resolve model: CLI flag > config > default
	model := installModel
	if model == "" {
		cfg, err := config.Load(workDir)
		if err == nil && cfg.LLM.Model != "" {
			model = cfg.LLM.Model
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, signalsToNotify...)
	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nInstallation interrupted.")
		cancel()
	}()

	inst := installer.NewInstaller(model, os.Stdout)
	result, err := inst.Install(ctx)
	if err != nil {
		return fmt.Errorf("install failed: %w", err)
	}

	fmt.Println()
	if result.Validated {
		fmt.Println("✔ LLM successfully installed and ready.")
	}

	if result.AlreadyInstalled {
		fmt.Printf("  Version: %s\n", result.Version)
		fmt.Println("  Status:  already installed, validated")
	}

	return nil
}
