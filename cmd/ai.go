package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/leonamvasquez/terraview/internal/ai"
	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/util"
	"github.com/spf13/cobra"
)

// pick returns the English string by default, or the Brazilian Portuguese
// string when the --br flag is active.
func pick(en, br string) string {
	if i18n.IsBR() {
		return br
	}
	return en
}

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

// runAIList shows an interactive provider picker, then a model picker, tests
// connectivity, and saves the choice. Loops back with an error message if the
// provider cannot be reached.
func runAIList(cmd *cobra.Command, args []string) error {
	providers := ai.List()

	// Load current config to mark the active provider
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	currentProvider := cfg.LLM.Provider
	currentModel := cfg.LLM.Model

	// ── Build provider items ───────────────────────────────────────────────
	providerItems := make([]selectItem, len(providers))
	defaultProviderIdx := 0
	for i, p := range providers {
		keyStatus := pick("no key required", "sem chave necessária")
		if p.RequiresKey {
			if val := os.Getenv(p.EnvVarKey); val != "" {
				keyStatus = p.EnvVarKey + "=****" + lastN(val, 4)
			} else {
				keyStatus = p.EnvVarKey + pick(" not set", " não configurada")
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

	var connectErrMsg string

	for {
		// Show connection error from the previous attempt, if any.
		if connectErrMsg != "" {
			fmt.Printf("\n%s✗ %s%s\n\n", ansiRed, connectErrMsg, ansiReset)
		}

		// ── Step 1: Pick provider ──────────────────────────────────────────
		chosenProvider, ok := runSelector(pick("Choose default AI provider:", "Escolha o provider de IA padrão:"), providerItems, defaultProviderIdx)
		if !ok {
			fmt.Println(pick("Cancelled.", "Cancelado."))
			return nil
		}

		// ── Step 2: Pick model ─────────────────────────────────────────────
		var providerInfo ai.ProviderInfo
		for _, p := range providers {
			if p.Name == chosenProvider {
				providerInfo = p
				break
			}
		}

		chosenModel, ok := runModelSelector(providerInfo, currentProvider, currentModel)
		if !ok {
			fmt.Println(pick("Cancelled.", "Cancelado."))
			return nil
		}

		// ── Step 3: Test connectivity ──────────────────────────────────────
		effectiveURL := cfg.LLM.URL
		if chosenProvider != "ollama" && effectiveURL == util.DefaultOllamaURL {
			effectiveURL = ""
		}

		providerCfg := ai.ProviderConfig{
			Model:       chosenModel,
			APIKey:      cfg.LLM.APIKey,
			BaseURL:     effectiveURL,
			Temperature: cfg.LLM.Temperature,
			TimeoutSecs: int(util.ValidationTimeout.Seconds()),
			MaxTokens:   64,
			MaxRetries:  0,
		}

		spinMsg := pick(
			fmt.Sprintf("Testing connectivity with %s (%s)...", chosenProvider, chosenModel),
			fmt.Sprintf("Testando conectividade com %s (%s)...", chosenProvider, chosenModel),
		)

		validateErr := output.SpinWhileE(spinMsg, func() error {
			testProvider, err := ai.Create(chosenProvider, providerCfg)
			if err != nil {
				return err
			}
			testCtx, testCancel := context.WithTimeout(context.Background(), util.ValidationTimeout)
			defer testCancel()
			return testProvider.Validate(testCtx)
		})

		if validateErr != nil {
			connectErrMsg = buildConnectError(providerInfo, chosenProvider, validateErr)
			for i, item := range providerItems {
				if item.Value == chosenProvider {
					defaultProviderIdx = i
					break
				}
			}
			continue
		}

		// ── Step 4: Save to global config ─────────────────────────────────
		if err := config.SaveGlobalLLMProvider(chosenProvider, chosenModel); err != nil {
			return fmt.Errorf("failed to save config: %w", err)
		}

		// Show integration test result
		if providerInfo.CLIBinary != "" {
			fmt.Printf("\n%s✓%s  "+pick(
				"Integration test passed — %q CLI is installed and ready.",
				"Teste de integração OK — CLI %q está instalado e pronto.",
			)+"\n", ansiGreen, ansiReset, providerInfo.CLIBinary)
		} else if providerInfo.RequiresKey {
			fmt.Printf("\n%s✓%s  "+pick(
				"Integration test passed — API key is valid and %s API is reachable.",
				"Teste de integração OK — chave de API válida e API %s acessível.",
			)+"\n", ansiGreen, ansiReset, chosenProvider)
		} else {
			fmt.Printf("\n%s✓%s  "+pick(
				"Integration test passed — %s is reachable.",
				"Teste de integração OK — %s está acessível.",
			)+"\n", ansiGreen, ansiReset, chosenProvider)
		}

		fmt.Printf("%s✓%s  "+pick("Default provider: %s%s%s  model: %s%s%s", "Provider padrão definido: %s%s%s  modelo: %s%s%s")+"\n",
			ansiGreen, ansiReset,
			ansiBold, chosenProvider, ansiReset,
			ansiBold, chosenModel, ansiReset,
		)
		fmt.Printf("   "+pick("Saved to: %s", "Salvo em: %s")+"\n", config.GlobalConfigPath())

		if providerInfo.RequiresKey && os.Getenv(providerInfo.EnvVarKey) == "" {
			fmt.Printf("\n%s⚠  %s "+pick("is not set.", "não está configurada.")+"%s\n", ansiYellow, providerInfo.EnvVarKey, ansiReset)
			if runtime.GOOS == "windows" {
				fmt.Println("   " + pick("Set it as environment variable:", "Configure via variável de ambiente:"))
				fmt.Printf("   %ssetx %s %s%s\n\n", ansiDim, providerInfo.EnvVarKey, pick("your_key_here", "sua_chave_aqui"), ansiReset)
			} else {
				fmt.Println("   " + pick("Add to your shell profile (~/.zshrc or ~/.bashrc):", "Adicione ao seu shell profile (~/.zshrc ou ~/.bashrc):"))
				fmt.Printf("   %sexport %s=%s%s\n\n", ansiDim, providerInfo.EnvVarKey, pick("your_key_here", "sua_chave_aqui"), ansiReset)
			}
		} else {
			fmt.Printf("\n   "+pick("Ready! Run: %sterraview scan%s", "Pronto! Execute: %sterraview scan%s")+"\n", ansiBold, ansiReset)
		}

		break
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
		fmt.Sprintf(pick("Choose model for %s:", "Escolha o modelo para %s:"), p.Name),
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
		return fmt.Errorf(pick("provider %q not found. Available: %v", "provider %q não encontrado. Disponíveis: %v"), provider, ai.Names())
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
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("%s✓%s  Provider: %s%s%s  "+pick("model", "modelo")+": %s\n",
		ansiGreen, ansiReset, ansiBold, provider, ansiReset, model)
	fmt.Printf("   "+pick("Saved to: %s", "Salvo em: %s")+"\n", config.GlobalConfigPath())
	return nil
}

func runAICurrent(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf(pick("error reading config: %w", "erro ao ler config: %w"), err)
	}

	globalPath := config.GlobalConfigPath()
	_, globalErr := os.Stat(globalPath)

	fmt.Println()
	fmt.Printf("  Provider:    %s%s%s\n", ansiBold, cfg.LLM.Provider, ansiReset)
	fmt.Printf("  "+pick("Model", "Modelo")+":       %s\n", cfg.LLM.Model)
	fmt.Printf("  URL:         %s\n", cfg.LLM.URL)
	fmt.Printf("  Timeout:     %ds\n", cfg.LLM.TimeoutSeconds)
	fmt.Printf("  Temperature: %.2f\n", cfg.LLM.Temperature)
	fmt.Printf("  "+pick("Enabled", "Ativado")+":      %v\n", cfg.LLM.Enabled)
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
		fmt.Fprintf(os.Stderr, "%s⚠ provider %q "+pick("not registered. Available: %v", "não registrado. Disponíveis: %v")+"%s\n",
			ansiYellow, cfg.LLM.Provider, ai.Names(), ansiReset)
	}

	return nil
}

func runAITest(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf(pick("failed to read config: %w", "erro ao ler config: %w"), err)
	}

	providerName := cfg.LLM.Provider
	modelName := cfg.LLM.Model

	// Resolve provider info for diagnostic messages
	var providerInfo ai.ProviderInfo
	for _, p := range ai.List() {
		if p.Name == providerName {
			providerInfo = p
			break
		}
	}

	effectiveURL := cfg.LLM.URL
	if providerName != "ollama" && effectiveURL == util.DefaultOllamaURL {
		effectiveURL = ""
	}

	providerCfg := ai.ProviderConfig{
		Model:       modelName,
		APIKey:      cfg.LLM.APIKey,
		BaseURL:     effectiveURL,
		Temperature: cfg.LLM.Temperature,
		TimeoutSecs: cfg.LLM.TimeoutSeconds,
		MaxTokens:   util.DefaultAnalyzeMaxTokens,
		MaxRetries:  1,
	}

	spinMsg := pick(
		fmt.Sprintf("Testing provider %s (%s)...", providerName, modelName),
		fmt.Sprintf("Testando provider %s (%s)...", providerName, modelName),
	)

	validateErr := output.SpinWhileE(spinMsg, func() error {
		testProvider, createErr := ai.Create(providerName, providerCfg)
		if createErr != nil {
			return createErr
		}
		testCtx, testCancel := context.WithTimeout(context.Background(), util.ValidationTimeout)
		defer testCancel()
		return testProvider.Validate(testCtx)
	})

	if validateErr != nil {
		errMsg := buildConnectError(providerInfo, providerName, validateErr)
		fmt.Printf("\n%s✗ %s%s\n", ansiRed, errMsg, ansiReset)
		return errors.New(pick("provider test failed", "teste do provider falhou"))
	}

	if providerInfo.CLIBinary != "" {
		fmt.Printf("\n%s✓%s  "+pick(
			"Integration test passed — %q CLI is installed and ready.",
			"Teste de integração OK — CLI %q está instalado e pronto.",
		)+"\n", ansiGreen, ansiReset, providerInfo.CLIBinary)
	} else if providerInfo.RequiresKey {
		fmt.Printf("\n%s✓%s  "+pick(
			"Integration test passed — API key is valid and %s API is reachable.",
			"Teste de integração OK — chave de API válida e API %s acessível.",
		)+"\n", ansiGreen, ansiReset, providerName)
	} else {
		fmt.Printf("\n%s✓%s  "+pick(
			"Integration test passed — %s is reachable.",
			"Teste de integração OK — %s está acessível.",
		)+"\n", ansiGreen, ansiReset, providerName)
	}

	fmt.Printf("   Provider: %s%s%s  "+pick("model", "modelo")+": %s\n",
		ansiBold, providerName, ansiReset, modelName)

	return nil
}

func lastN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// buildConnectError produces a user-friendly error message based on the
// provider type (CLI-based subscription, API-key based, or local).
func buildConnectError(info ai.ProviderInfo, chosenProvider string, err error) string {
	// ── CLI-based subscription providers (gemini-cli, claude-code) ──────
	if info.CLIBinary != "" {
		if _, lookErr := exec.LookPath(info.CLIBinary); lookErr != nil {
			return pick(
				fmt.Sprintf(
					"The %q CLI is not installed on this machine.\n"+
						"  This is a subscription-based provider that requires the CLI tool locally.\n"+
						"  Install it with:  %s\n"+
						"  Then run '%s' once to authenticate.",
					info.CLIBinary, info.InstallHint, info.CLIBinary,
				),
				fmt.Sprintf(
					"O CLI %q não está instalado nesta máquina.\n"+
						"  Este provider é baseado em assinatura e requer o CLI instalado localmente.\n"+
						"  Instale com:  %s\n"+
						"  Depois execute '%s' uma vez para autenticar.",
					info.CLIBinary, info.InstallHint, info.CLIBinary,
				),
			)
		}
		// Binary found but something else failed
		return pick(
			fmt.Sprintf(
				"The %q CLI is installed but the connection test failed: %v\n"+
					"  Try running '%s' interactively to check authentication.",
				info.CLIBinary, err, info.CLIBinary,
			),
			fmt.Sprintf(
				"O CLI %q está instalado mas o teste de conexão falhou: %v\n"+
					"  Tente executar '%s' interativamente para verificar a autenticação.",
				info.CLIBinary, err, info.CLIBinary,
			),
		)
	}

	// ── API-key based providers (gemini, claude, deepseek, openrouter) ──
	if info.RequiresKey && info.EnvVarKey != "" {
		if os.Getenv(info.EnvVarKey) == "" {
			return pick(
				fmt.Sprintf(
					"The API key for %q is not configured.\n"+
						"  Set the environment variable %s with your API key.\n"+
						"  Example:  export %s=your_key_here",
					chosenProvider, info.EnvVarKey, info.EnvVarKey,
				),
				fmt.Sprintf(
					"A chave de API para %q não está configurada.\n"+
						"  Defina a variável de ambiente %s com sua chave de API.\n"+
						"  Exemplo:  export %s=sua_chave_aqui",
					chosenProvider, info.EnvVarKey, info.EnvVarKey,
				),
			)
		}
		// Key is set but validation still failed (invalid key, network, etc.)
		return pick(
			fmt.Sprintf(
				"The API key for %q is set but the connection failed: %v\n"+
					"  Check that your %s is valid and that you have internet access.",
				chosenProvider, err, info.EnvVarKey,
			),
			fmt.Sprintf(
				"A chave de API para %q está configurada mas a conexão falhou: %v\n"+
					"  Verifique se sua %s é válida e se você tem acesso à internet.",
				chosenProvider, err, info.EnvVarKey,
			),
		)
	}

	// ── Local providers (ollama) ───────────────────────────────────────
	return pick(
		fmt.Sprintf(
			"Could not connect to %q: %v\n"+
				"  Make sure the service is running and accessible.",
			chosenProvider, err,
		),
		fmt.Sprintf(
			"Não foi possível conectar ao %q: %v\n"+
				"  Verifique se o serviço está em execução e acessível.",
			chosenProvider, err,
		),
	)
}
