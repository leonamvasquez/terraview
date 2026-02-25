package cmd

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/leonamvasquez/terraview/internal/ai"
	_ "github.com/leonamvasquez/terraview/internal/ai/providers" // register all providers
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/spf13/cobra"
)

var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage AI providers and LLM runtimes",
	Long: `Manage the AI providers and runtimes used by terraview.

Subcommands:
  list        List available providers and choose the default interactively
  use         Set default provider non-interactively (for scripts)
  current     Show the currently configured provider
  test        Test connectivity with the configured provider
  install     Install LLM runtime (ollama)
  uninstall   Remove LLM runtime`,
}

var aiListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available providers and choose the default interactively",
	RunE:  runAIList,
}

var aiUseCmd = &cobra.Command{
	Use:   "use <provider> [model]",
	Short: "Set default provider non-interactively (useful in scripts)",
	Long: `Set the default provider globally without interactive mode.

Examples:
  terraview provider use gemini
  terraview provider use openrouter google/gemini-2.0-flash-001
  terraview provider use ollama llama3.1:8b`,
	Args: cobra.RangeArgs(1, 2),
	RunE: runAIUse,
}

var aiCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Show the currently configured AI provider",
	RunE:  runAICurrent,
}

var aiTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test connectivity with the configured AI provider",
	RunE:  runAITest,
}

func init() {
	providerCmd.AddCommand(aiListCmd)
	providerCmd.AddCommand(aiUseCmd)
	providerCmd.AddCommand(aiCurrentCmd)
	providerCmd.AddCommand(aiTestCmd)
	providerCmd.AddCommand(installCmd)
	providerCmd.AddCommand(uninstallCmd)
}

// runAIList shows an interactive provider picker, then a model picker, and saves the choice.
func runAIList(cmd *cobra.Command, args []string) error {
	providers := ai.List()

	// Load current config to mark the active provider
	cfg, _ := config.Load(workDir)
	currentProvider := cfg.LLM.Provider
	currentModel := cfg.LLM.Model

	// ── Step 1: Pick provider ──────────────────────────────────────────────
	providerItems := make([]selectItem, len(providers))
	defaultProviderIdx := 0
	for i, p := range providers {
		keyStatus := "sem chave necessária"
		if p.RequiresKey {
			if val := os.Getenv(p.EnvVarKey); val != "" {
				keyStatus = p.EnvVarKey + "=****" + lastN(val, 4)
			} else {
				keyStatus = p.EnvVarKey + " não configurada"
			}
		}
		providerItems[i] = selectItem{
			Label:    p.Name,
			Detail:   p.DisplayName + "  " + keyStatus,
			Value:    p.Name,
			IsActive: p.Name == currentProvider,
		}
		if p.Name == currentProvider {
			defaultProviderIdx = i
		}
	}

	chosenProvider, ok := runSelector("Escolha o provider de IA padrão:", providerItems, defaultProviderIdx)
	if !ok {
		fmt.Println("Cancelado.")
		return nil
	}

	// ── Step 2: Pick model for chosen provider ─────────────────────────────
	var providerInfo ai.ProviderInfo
	for _, p := range providers {
		if p.Name == chosenProvider {
			providerInfo = p
			break
		}
	}

	chosenModel, ok := runModelSelector(providerInfo, currentProvider, currentModel)
	if !ok {
		fmt.Println("Cancelado.")
		return nil
	}

	// ── Step 3: Save to global config ──────────────────────────────────────
	if err := config.SaveGlobalLLMProvider(chosenProvider, chosenModel); err != nil {
		return fmt.Errorf("falha ao salvar configuração: %w", err)
	}

	fmt.Printf("\n%s✓%s  Provider padrão definido: %s%s%s  modelo: %s%s%s\n",
		ansiGreen, ansiReset,
		ansiBold, chosenProvider, ansiReset,
		ansiBold, chosenModel, ansiReset,
	)
	fmt.Printf("   Salvo em: %s\n", config.GlobalConfigPath())

	// Tip: show if API key is needed but not set
	if providerInfo.RequiresKey && os.Getenv(providerInfo.EnvVarKey) == "" {
		fmt.Printf("\n%s⚠  %s não está configurada.%s\n", ansiYellow, providerInfo.EnvVarKey, ansiReset)
		if runtime.GOOS == "windows" {
			fmt.Printf("   Configure via variável de ambiente:\n")
			fmt.Printf("   %ssetx %s sua_chave_aqui%s\n\n", ansiDim, providerInfo.EnvVarKey, ansiReset)
		} else {
			fmt.Printf("   Adicione ao seu shell profile (~/.zshrc ou ~/.bashrc):\n")
			fmt.Printf("   %sexport %s=sua_chave_aqui%s\n\n", ansiDim, providerInfo.EnvVarKey, ansiReset)
		}
	} else {
		fmt.Printf("\n   Pronto! Execute: %sterraview review%s\n", ansiBold, ansiReset)
	}

	return nil
}

// runModelSelector shows a live-filter model picker for the given provider.
// The user can navigate and filter the suggested list. If the typed text
// does not match any suggestion, Enter confirms the raw text as a custom model.
func runModelSelector(p ai.ProviderInfo, currentProvider, currentModel string) (string, bool) {
	defaultModel := p.DefaultModel
	if p.Name == currentProvider && currentModel != "" {
		defaultModel = currentModel
	}

	if len(p.SuggestedModels) == 0 {
		return defaultModel, true
	}

	modelItems := make([]selectItem, 0, len(p.SuggestedModels))
	defaultIdx := 0
	for i, m := range p.SuggestedModels {
		if m == defaultModel {
			defaultIdx = i
		}
		modelItems = append(modelItems, selectItem{
			Label:    m,
			Value:    m,
			IsActive: m == defaultModel,
		})
	}

	return runFilterSelector(
		fmt.Sprintf("Escolha o modelo para %s:", p.Name),
		modelItems,
		defaultIdx,
	)
}

// runAIUse sets the provider (and optionally model) non-interactively.
func runAIUse(cmd *cobra.Command, args []string) error {
	provider := args[0]
	model := ""
	if len(args) > 1 {
		model = args[1]
	}

	if !ai.Has(provider) {
		return fmt.Errorf("provider %q não encontrado. Disponíveis: %v", provider, ai.Names())
	}

	// Use provider's default model if none given
	if model == "" {
		for _, p := range ai.List() {
			if p.Name == provider {
				model = p.DefaultModel
				break
			}
		}
	}

	if err := config.SaveGlobalLLMProvider(provider, model); err != nil {
		return fmt.Errorf("falha ao salvar configuração: %w", err)
	}

	fmt.Printf("%s✓%s  Provider: %s%s%s  modelo: %s\n",
		ansiGreen, ansiReset, ansiBold, provider, ansiReset, model)
	fmt.Printf("   Salvo em: %s\n", config.GlobalConfigPath())
	return nil
}

func runAICurrent(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("erro ao ler config: %w", err)
	}

	globalPath := config.GlobalConfigPath()
	_, globalErr := os.Stat(globalPath)

	fmt.Println()
	fmt.Printf("  Provider:    %s%s%s\n", ansiBold, cfg.LLM.Provider, ansiReset)
	fmt.Printf("  Modelo:      %s\n", cfg.LLM.Model)
	fmt.Printf("  URL:         %s\n", cfg.LLM.URL)
	fmt.Printf("  Timeout:     %ds\n", cfg.LLM.TimeoutSeconds)
	fmt.Printf("  Temperature: %.2f\n", cfg.LLM.Temperature)
	fmt.Printf("  Ativado:     %v\n", cfg.LLM.Enabled)
	fmt.Println()

	if globalErr == nil {
		fmt.Printf("  %sConfig global:%s %s\n", ansiDim, ansiReset, globalPath)
	}
	localPath := workDir + "/.terraview.yaml"
	if _, statErr := os.Stat(localPath); statErr == nil {
		fmt.Printf("  %sConfig local:%s  %s\n", ansiDim, ansiReset, localPath)
	}
	fmt.Println()

	if !ai.Has(cfg.LLM.Provider) {
		fmt.Fprintf(os.Stderr, "%s⚠ provider %q não registrado. Disponíveis: %v%s\n",
			ansiYellow, cfg.LLM.Provider, ai.Names(), ansiReset)
	}

	return nil
}

func runAITest(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("erro ao ler config: %w", err)
	}

	providerName := cfg.LLM.Provider
	fmt.Printf("Testando provider: %s%s%s  (modelo: %s)\n", ansiBold, providerName, ansiReset, cfg.LLM.Model)

	// When the provider is not ollama and no explicit URL was set, clear the
	// default Ollama URL so each provider falls back to its own base URL.
	effectiveURL := cfg.LLM.URL
	if providerName != "ollama" && effectiveURL == "http://localhost:11434" {
		effectiveURL = ""
	}

	providerCfg := ai.ProviderConfig{
		Model:       cfg.LLM.Model,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     effectiveURL,
		Temperature: cfg.LLM.Temperature,
		TimeoutSecs: cfg.LLM.TimeoutSeconds,
		MaxTokens:   4096,
		MaxRetries:  1,
	}

	provider, err := ai.Create(providerName, providerCfg)
	if err != nil {
		return fmt.Errorf("falha ao criar provider: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	fmt.Print("Validando... ")
	if err := provider.Validate(ctx); err != nil {
		fmt.Printf("%sFALHOU%s\n", ansiRed, ansiReset)
		return fmt.Errorf("validação falhou: %w", err)
	}

	fmt.Printf("%sOK%s\n", ansiGreen, ansiReset)
	fmt.Printf("\nProvider %q está acessível e pronto.\n", providerName)

	return nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
