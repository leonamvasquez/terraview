package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/leonamvasquez/terraview/internal/config"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/spf13/cobra"
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
	if brFlag {
		return runSetupBR()
	}
	return runSetupEN()
}

func runSetupEN() error {
	fmt.Println()
	fmt.Println(ansiBold + "  terraview setup" + ansiReset)
	fmt.Println(ansiBold + "  ═══════════════" + ansiReset)
	fmt.Println()

	// ── Section 1: Security Scanners ──────────────────────────────
	fmt.Println(ansiBold + "  Security Scanners" + ansiReset)
	fmt.Println()

	allScanners := scanner.DefaultManager.All()
	available := scanner.DefaultManager.Available()
	missing := scanner.DefaultManager.Missing()

	// Show each scanner status, sorted by priority
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
		s, _ := allScanners[m.Name]
		pri := 99
		if s != nil {
			pri = s.Priority()
		}
		entries = append(entries, entry{
			name: m.Name, priority: pri,
			ok: false, hint: m.Hint,
		})
	}
	// Sort by priority
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
				hint = "not installed"
			}
			fmt.Printf("  %s[✗]%s %-12s %s%s%s\n",
				ansiRed, ansiReset, e.name, ansiDim, hint, ansiReset)
		}
	}

	fmt.Println()
	fmt.Printf("  Available: %d/%d scanners\n", len(available), len(allScanners))

	// Show default scanner
	cfg, _ := config.Load(workDir)
	if cfg.Scanner.Default != "" {
		fmt.Printf("  Default:   %s%s%s\n", ansiBold, cfg.Scanner.Default, ansiReset)
	} else if len(available) > 0 {
		fmt.Printf("  Default:   %s(auto — highest priority installed)%s\n", ansiDim, ansiReset)
	}

	if len(missing) > 0 {
		fmt.Println()
		fmt.Printf("  %sInstall missing: terraview scanners install --all%s\n", ansiDim, ansiReset)
	}

	// ── Section 2: AI Provider ────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  AI Provider" + ansiReset)
	fmt.Println()

	// Check for common AI-related env vars
	providers := []struct {
		name   string
		envVar string
		cmd    string
	}{
		{"Ollama", "", "ollama"},
		{"Gemini", "GEMINI_API_KEY", ""},
		{"Claude", "ANTHROPIC_API_KEY", ""},
		{"OpenAI", "OPENAI_API_KEY", ""},
		{"DeepSeek", "DEEPSEEK_API_KEY", ""},
		{"OpenRouter", "OPENROUTER_API_KEY", ""},
	}

	aiAvail := 0
	for _, p := range providers {
		if p.cmd != "" {
			// Binary check (Ollama)
			if commandAvailable(p.cmd) {
				fmt.Printf("  %s[✓]%s %s %s(local)%s\n",
					ansiGreen, ansiReset, p.name, ansiDim, ansiReset)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %s %s(not installed)%s\n",
					ansiRed, ansiReset, p.name, ansiDim, ansiReset)
			}
		} else if p.envVar != "" {
			// API key check
			if os.Getenv(p.envVar) != "" {
				fmt.Printf("  %s[✓]%s %s %s(%s set)%s\n",
					ansiGreen, ansiReset, p.name, ansiDim, p.envVar, ansiReset)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %s %s(%s not set)%s\n",
					ansiYellow, ansiReset, p.name, ansiDim, p.envVar, ansiReset)
			}
		}
	}

	fmt.Println()
	if aiAvail > 0 {
		fmt.Printf("  %s✔%s AI ready (%d provider%s available)\n",
			ansiGreen, ansiReset, aiAvail, pluralS(aiAvail))
	} else {
		fmt.Printf("  %s!%s No AI provider configured\n", ansiYellow, ansiReset)
		fmt.Printf("  %sRun: terraview provider list%s\n", ansiDim, ansiReset)
	}

	// ── Summary ───────────────────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  Quick Start" + ansiReset)
	fmt.Println()
	fmt.Printf("  %sterraview scan checkov%s          # scanners only\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview scan checkov --ai%s     # scanners + AI\n", ansiCyan, ansiReset)
	fmt.Println()

	return nil
}

func runSetupBR() error {
	fmt.Println()
	fmt.Println(ansiBold + "  terraview setup" + ansiReset)
	fmt.Println(ansiBold + "  ═══════════════" + ansiReset)
	fmt.Println()

	// ── Seção 1: Scanners de Segurança ──────────────────────────
	fmt.Println(ansiBold + "  Scanners de Segurança" + ansiReset)
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
		s, _ := allScanners[m.Name]
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
				hint = "não instalado"
			}
			fmt.Printf("  %s[✗]%s %-12s %s%s%s\n",
				ansiRed, ansiReset, e.name, ansiDim, hint, ansiReset)
		}
	}

	fmt.Println()
	fmt.Printf("  Disponíveis: %d/%d scanners\n", len(available), len(allScanners))

	// Mostrar scanner padrão
	cfg, _ := config.Load(workDir)
	if cfg.Scanner.Default != "" {
		fmt.Printf("  Padrão:     %s%s%s\n", ansiBold, cfg.Scanner.Default, ansiReset)
	} else if len(available) > 0 {
		fmt.Printf("  Padrão:     %s(automático — maior prioridade instalado)%s\n", ansiDim, ansiReset)
	}

	if len(missing) > 0 {
		fmt.Println()
		fmt.Printf("  %sInstalar faltantes: terraview scanners install --all%s\n", ansiDim, ansiReset)
	}

	// ── Seção 2: Provider de IA ──────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  Provider de IA" + ansiReset)
	fmt.Println()

	providers := []struct {
		name   string
		envVar string
		cmd    string
	}{
		{"Ollama", "", "ollama"},
		{"Gemini", "GEMINI_API_KEY", ""},
		{"Claude", "ANTHROPIC_API_KEY", ""},
		{"OpenAI", "OPENAI_API_KEY", ""},
		{"DeepSeek", "DEEPSEEK_API_KEY", ""},
		{"OpenRouter", "OPENROUTER_API_KEY", ""},
	}

	aiAvail := 0
	for _, p := range providers {
		if p.cmd != "" {
			if commandAvailable(p.cmd) {
				fmt.Printf("  %s[✓]%s %s %s(local)%s\n",
					ansiGreen, ansiReset, p.name, ansiDim, ansiReset)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %s %s(não instalado)%s\n",
					ansiRed, ansiReset, p.name, ansiDim, ansiReset)
			}
		} else if p.envVar != "" {
			if os.Getenv(p.envVar) != "" {
				fmt.Printf("  %s[✓]%s %s %s(%s configurado)%s\n",
					ansiGreen, ansiReset, p.name, ansiDim, p.envVar, ansiReset)
				aiAvail++
			} else {
				fmt.Printf("  %s[✗]%s %s %s(%s não configurado)%s\n",
					ansiYellow, ansiReset, p.name, ansiDim, p.envVar, ansiReset)
			}
		}
	}

	fmt.Println()
	if aiAvail > 0 {
		fmt.Printf("  %s✔%s IA pronta (%d provider%s disponível%s)\n",
			ansiGreen, ansiReset, aiAvail, pluralS(aiAvail), pluralS(aiAvail))
	} else {
		fmt.Printf("  %s!%s Nenhum provider de IA configurado\n", ansiYellow, ansiReset)
		fmt.Printf("  %sExecute: terraview provider list%s\n", ansiDim, ansiReset)
	}

	// ── Início rápido ─────────────────────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  Início Rápido" + ansiReset)
	fmt.Println()
	fmt.Printf("  %sterraview scan checkov%s          # apenas scanners\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview scan checkov --ai%s     # scanners + IA\n", ansiCyan, ansiReset)
	fmt.Println()

	return nil
}

func commandAvailable(name string) bool {
	_, err := execLookPath(name)
	return err == nil
}

// execLookPath wraps exec.LookPath for testability
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
