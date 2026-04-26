package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/scanner"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive environment setup",
	Long: `Detects installed security scanners and AI providers, shows their status,
default scanner configuration, and available providers.

This command is informational and non-destructive — it only checks what
is available. To install scanners, use 'terraview scanners install'.

Examples:
  terraview setup`,
	RunE: runSetup,
}

func init() {
	// registered in root.go init()
}

func runSetup(cmd *cobra.Command, args []string) error {
	fmt.Println()
	fmt.Println(ansiBold + "  terraview setup" + ansiReset)
	fmt.Println(ansiBold + "  ═══════════════" + ansiReset)
	fmt.Println()

	// ── Section 1: Security Scanners ──────────────────────────────
	fmt.Println(ansiBold + "  " + pick("Security Scanners", "Scanners de Segurança") + ansiReset)
	fmt.Println()

	allScanners := scanner.DefaultManager.All()
	available := scanner.DefaultManager.Available()
	missing := scanner.DefaultManager.Missing()

	type entry struct {
		name     string
		version  string
		priority int
		ok       bool
		hint     scanner.InstallHint
	}
	entries := make([]entry, 0, len(available)+len(missing))
	for _, s := range available {
		entries = append(entries, entry{
			name: s.Name(), version: s.Version(),
			priority: s.Priority(), ok: true,
		})
	}
	for _, m := range missing {
		s := allScanners[m.Name]
		pri := 99
		if s != nil {
			pri = s.Priority()
		}
		entries = append(entries, entry{
			name: m.Name, priority: pri,
			ok: false, hint: m.Hint,
		})
	}
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].priority < entries[i].priority {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	for _, e := range entries {
		if e.ok {
			fmt.Printf("  %s[✓]%s %-12s %s%s%s\n",
				ansiGreen, ansiReset, e.name, ansiDim, e.version, ansiReset)
		} else {
			hint := e.hint.Default
			if hint == "" {
				hint = pick("not installed", "não instalado")
			}
			fmt.Printf("  %s[✗]%s %-12s %s%s%s\n",
				ansiRed, ansiReset, e.name, ansiDim, hint, ansiReset)
		}
	}

	fmt.Println()
	fmt.Printf("  %s %d/%d scanners\n",
		pick("Available:", "Disponíveis:"), len(available), len(allScanners))

	cfg, err := config.Load(workDir)
	if err != nil {
		return fmt.Errorf("config error: %w", err)
	}
	if cfg.Scanner.Default != "" {
		fmt.Printf("  %s %s%s%s\n",
			pick("Default:  ", "Padrão:    "), ansiBold, cfg.Scanner.Default, ansiReset)
	} else if len(available) > 0 {
		fmt.Printf("  %s %s%s%s\n",
			pick("Default:  ", "Padrão:    "), ansiDim,
			pick("(auto — highest priority installed)", "(automático — maior prioridade instalado)"), ansiReset)
	}

	if len(missing) > 0 {
		fmt.Println()
		fmt.Printf("  %s%s%s\n", ansiDim,
			pick("Install missing: terraview scanners install --all",
				"Instalar faltantes: terraview scanners install --all"), ansiReset)
	}

	// ── Section 2: AI Provider ────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  " + pick("AI Provider", "Provider de IA") + ansiReset)
	fmt.Println()

	// configuredProvider is the provider set in .terraview.yaml (may be empty).
	configuredProvider := cfg.LLM.Provider

	type providerSpec struct {
		// name is the display name shown to the user.
		name string
		// configKey is the key used in .terraview.yaml llm.provider.
		configKey string
		// envVar is the environment variable required for HTTP providers (empty for CLI/local).
		envVar string
		// cliBinary is the executable to look up for CLI-based providers (empty for HTTP).
		cliBinary string
	}

	providerSpecs := []providerSpec{
		{name: "ollama", configKey: "ollama", cliBinary: "ollama"},
		{name: "gemini-cli", configKey: "gemini-cli", cliBinary: "gemini"},
		{name: "claude-code", configKey: "claude-code", cliBinary: "claude"},
		{name: "gemini", configKey: "gemini", envVar: "GEMINI_API_KEY"},
		{name: "claude", configKey: "claude", envVar: "ANTHROPIC_API_KEY"},
		{name: "openai", configKey: "openai", envVar: "OPENAI_API_KEY"},
		{name: "deepseek", configKey: "deepseek", envVar: "DEEPSEEK_API_KEY"},
		{name: "openrouter", configKey: "openrouter", envVar: "OPENROUTER_API_KEY"},
	}

	aiAvail := 0
	for _, p := range providerSpecs {
		isConfigured := p.configKey == configuredProvider
		defaultTag := ""
		if isConfigured {
			defaultTag = " " + ansiCyan + pick("(default)", "(padrão)") + ansiReset
		}

		if p.cliBinary != "" {
			if commandAvailable(p.cliBinary) {
				fmt.Printf("  %s[✓]%s %-12s %s%s%s%s\n",
					ansiGreen, ansiReset, p.name, ansiDim,
					pick("local CLI", "CLI local"), ansiReset, defaultTag)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %-12s %s%s%s%s\n",
					ansiRed, ansiReset, p.name, ansiDim,
					pick("not installed", "não instalado"), ansiReset, defaultTag)
			}
		} else if p.envVar != "" {
			if os.Getenv(p.envVar) != "" {
				fmt.Printf("  %s[✓]%s %-12s %s%s %s%s%s\n",
					ansiGreen, ansiReset, p.name, ansiDim, p.envVar,
					pick("set", "configurado"), ansiReset, defaultTag)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %-12s %s%s %s%s%s\n",
					ansiYellow, ansiReset, p.name, ansiDim, p.envVar,
					pick("not set", "não configurado"), ansiReset, defaultTag)
			}
		}
	}

	fmt.Println()
	if aiAvail > 0 {
		fmt.Printf("  %s✔%s %s (%d provider%s %s)\n",
			ansiGreen, ansiReset,
			pick("AI ready", "IA pronta"),
			aiAvail, pluralS(aiAvail),
			pick("available", "disponível"+pluralS(aiAvail)))
	} else {
		fmt.Printf("  %s!%s %s\n", ansiYellow, ansiReset,
			pick("No AI provider configured", "Nenhum provider de IA configurado"))
		fmt.Printf("  %s%s%s\n", ansiDim,
			pick("Run: terraview provider list", "Execute: terraview provider list"), ansiReset)
	}

	// ── Quick Start ───────────────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  " + pick("Quick Start", "Início Rápido") + ansiReset)
	fmt.Println()
	fmt.Printf("  %sterraview scan checkov%s                   # %s\n",
		ansiCyan, ansiReset, pick("scanners only", "apenas scanners"))
	fmt.Printf("  %sterraview scan checkov --provider gemini%s # %s\n",
		ansiCyan, ansiReset, pick("scanners + AI", "scanners + IA"))
	fmt.Println()

	return nil
}

func commandAvailable(name string) bool {
	_, err := execLookPath(name)
	return err == nil
}

var execLookPath = defaultLookPath

func defaultLookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func pluralS(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
