package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/leonam/terraview/internal/ai"
	_ "github.com/leonam/terraview/internal/ai/providers" // register all providers
	"github.com/leonam/terraview/internal/config"
	"github.com/spf13/cobra"
)

var aiCmd = &cobra.Command{
	Use:   "ai",
	Short: "Manage AI providers for Terraform plan review",
	Long: `Manage AI providers used by terraview for intelligent plan analysis.

Subcommands:
  list      List all available AI providers
  current   Show the currently configured provider
  test      Test connectivity to the configured provider`,
}

var aiListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all available AI providers",
	RunE:  runAIList,
}

var aiCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the currently configured AI provider",
	RunE:  runAICurrent,
}

var aiTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test connectivity to the configured AI provider",
	RunE:  runAITest,
}

func init() {
	aiCmd.AddCommand(aiListCmd)
	aiCmd.AddCommand(aiCurrentCmd)
	aiCmd.AddCommand(aiTestCmd)
}

func runAIList(cmd *cobra.Command, args []string) error {
	providers := ai.List()

	fmt.Println("Available AI Providers:")
	fmt.Println()

	for _, p := range providers {
		keyStatus := "no key required"
		if p.RequiresKey {
			envVal := os.Getenv(p.EnvVarKey)
			if envVal != "" {
				keyStatus = fmt.Sprintf("%s = ****%s", p.EnvVarKey, lastN(envVal, 4))
			} else {
				keyStatus = fmt.Sprintf("%s = (not set)", p.EnvVarKey)
			}
		}

		fmt.Printf("  %-12s  %s  [%s]\n", p.Name, p.DisplayName, keyStatus)
	}

	fmt.Println()
	fmt.Println("Configure via .terraview.yaml:")
	fmt.Println("  llm:")
	fmt.Println("    provider: <name>")
	fmt.Println("    model: <model-id>")

	return nil
}

func runAICurrent(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	fmt.Printf("Provider:    %s\n", cfg.LLM.Provider)
	fmt.Printf("Model:       %s\n", cfg.LLM.Model)
	fmt.Printf("URL:         %s\n", cfg.LLM.URL)
	fmt.Printf("Timeout:     %ds\n", cfg.LLM.TimeoutSeconds)
	fmt.Printf("Temperature: %.2f\n", cfg.LLM.Temperature)
	fmt.Printf("Enabled:     %v\n", cfg.LLM.Enabled)

	if !ai.Has(cfg.LLM.Provider) {
		fmt.Fprintf(os.Stderr, "\nWARNING: provider %q is not registered. Available: %v\n", cfg.LLM.Provider, ai.Names())
	}

	return nil
}

func runAITest(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}

	providerName := cfg.LLM.Provider
	fmt.Printf("Testing provider: %s (model: %s)\n", providerName, cfg.LLM.Model)

	providerCfg := ai.ProviderConfig{
		Model:       cfg.LLM.Model,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     cfg.LLM.URL,
		Temperature: cfg.LLM.Temperature,
		TimeoutSecs: cfg.LLM.TimeoutSeconds,
		MaxTokens:   4096,
		MaxRetries:  1,
	}

	provider, err := ai.Create(providerName, providerCfg)
	if err != nil {
		return fmt.Errorf("failed to create provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Print("Validating... ")
	if err := provider.Validate(ctx); err != nil {
		fmt.Println("FAILED")
		return fmt.Errorf("validation failed: %w", err)
	}

	fmt.Println("OK")
	fmt.Printf("\nProvider %q is reachable and ready.\n", providerName)

	return nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
