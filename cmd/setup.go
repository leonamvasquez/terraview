package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/spf13/cobra"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive environment setup",
	Long: `Detects installed security scanners and AI providers, shows their status,
and guides you through installing missing tools.

This command is informational and non-destructive — it only checks what
is available and offers install hints for anything missing.

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
	var entries []entry
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

	if len(missing) > 0 {
		fmt.Println()
		fmt.Println(ansiBold + "  Install Commands:" + ansiReset)
		for _, m := range missing {
			if m.Hint.Brew != "" {
				fmt.Printf("    %s$ %s%s\n", ansiDim, m.Hint.Brew, ansiReset)
			} else if m.Hint.Pip != "" {
				fmt.Printf("    %s$ %s%s\n", ansiDim, m.Hint.Pip, ansiReset)
			} else if m.Hint.Default != "" {
				fmt.Printf("    %s%s%s\n", ansiDim, m.Hint.Default, ansiReset)
			}
		}
	}

	// ── Section 2: Scanner Precedence ─────────────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  Tool Precedence" + ansiReset)
	fmt.Println(ansiDim + "  (lower number = higher priority)" + ansiReset)
	fmt.Println()
	precedence := []struct {
		pri  int
		name string
	}{
		{1, "Checkov"},
		{2, "tfsec/Trivy"},
		{3, "Terrascan"},
		{4, "KICS"},
		{5, "Deterministic rules"},
		{6, "AI analysis"},
	}
	for _, p := range precedence {
		marker := ansiDim + "○" + ansiReset
		// Check if it's an installed scanner
		for _, a := range available {
			if strings.EqualFold(a.Name(), strings.Split(p.name, "/")[0]) {
				marker = ansiGreen + "●" + ansiReset
				break
			}
		}
		if p.pri >= 5 {
			marker = ansiGreen + "●" + ansiReset // always available
		}
		fmt.Printf("  %s %d. %s\n", marker, p.pri, p.name)
	}

	// ── Section 3: AI Provider ────────────────────────────────────
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
	fmt.Printf("  %sterraview plan%s                 # scanners only\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview plan --ai%s             # scanners + AI\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview validate%s              # fast deterministic checks\n", ansiCyan, ansiReset)
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
	var entries []entry
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

	if len(missing) > 0 {
		fmt.Println()
		fmt.Println(ansiBold + "  Comandos de Instalação:" + ansiReset)
		for _, m := range missing {
			if m.Hint.Brew != "" {
				fmt.Printf("    %s$ %s%s\n", ansiDim, m.Hint.Brew, ansiReset)
			} else if m.Hint.Pip != "" {
				fmt.Printf("    %s$ %s%s\n", ansiDim, m.Hint.Pip, ansiReset)
			} else if m.Hint.Default != "" {
				fmt.Printf("    %s%s%s\n", ansiDim, m.Hint.Default, ansiReset)
			}
		}
	}

	// ── Seção 2: Precedência de Ferramentas ──────────────────────
	fmt.Println()
	fmt.Println(ansiBold + "  Precedência de Ferramentas" + ansiReset)
	fmt.Println(ansiDim + "  (número menor = maior prioridade)" + ansiReset)
	fmt.Println()
	precedence := []struct {
		pri  int
		name string
	}{
		{1, "Checkov"},
		{2, "tfsec/Trivy"},
		{3, "Terrascan"},
		{4, "KICS"},
		{5, "Regras determinísticas"},
		{6, "Análise por IA"},
	}
	for _, p := range precedence {
		marker := ansiDim + "○" + ansiReset
		for _, a := range available {
			if strings.EqualFold(a.Name(), strings.Split(p.name, "/")[0]) {
				marker = ansiGreen + "●" + ansiReset
				break
			}
		}
		if p.pri >= 5 {
			marker = ansiGreen + "●" + ansiReset
		}
		fmt.Printf("  %s %d. %s\n", marker, p.pri, p.name)
	}

	// ── Seção 3: Provider de IA ──────────────────────────────────
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
	fmt.Printf("  %sterraview plan%s                 # apenas scanners\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview plan --ai%s             # scanners + IA\n", ansiCyan, ansiReset)
	fmt.Printf("  %sterraview validate%s              # verificações determinísticas\n", ansiCyan, ansiReset)
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
