package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/spf13/cobra"
)

var (
	// Global flags (persistent, inherited by all subcommands)
	verbose      bool
	workDir      string
	brFlag       bool
	noColor      bool
	planFile     string
	outputDir    string
	outputFormat string
	aiProvider   string
	ollamaModel  string
)

// Version is set at build time via ldflags.
var Version = "v0.4.1"

var rootCmd = &cobra.Command{
	Use:   "terraview",
	Short: "Semantic reviewer for Terraform plans",
	Long: `terraview — Semantic reviewer for Terraform plans

Security scanning and AI review for Terraform plans.

Core Commands:
  scan        Security scan + optional AI analysis
  apply       Scan and conditionally apply the plan
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation
  drift       Detect and classify infrastructure drift

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test
              provider install | uninstall

Scanner Management:
  scanners    Manage security scanners
              scanners list | install

Utilities:
  version     Show version information
  upgrade     Upgrade to the latest version
  setup       Interactive environment setup

Get started:
  cd my-terraform-project
  terraview scan checkov                    # security scanner
  terraview scan checkov --ai               # scanner + AI analysis
  terraview scan --ai                       # AI-only analysis
  terraview scan checkov --all              # everything enabled
  terraview diagram                         # infrastructure diagram
  terraview explain                         # AI explanation
  terraview drift                           # detect drift
  terraview provider list                   # manage AI providers`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&workDir, "dir", "d", ".", "Terraform workspace directory")
	rootCmd.PersistentFlags().BoolVar(&brFlag, "br", false, "Output in Brazilian Portuguese (pt-BR)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().StringVarP(&planFile, "plan", "p", "", "Path to terraform plan JSON (auto-generates if omitted)")
	rootCmd.PersistentFlags().StringVarP(&outputDir, "output", "o", "", "Output directory for generated files")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "", "Output format: pretty, compact, json, sarif (default pretty)")
	rootCmd.PersistentFlags().StringVar(&aiProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek, openrouter)")
	rootCmd.PersistentFlags().StringVar(&ollamaModel, "model", "", "AI model to use")

	// Core commands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(diagramCmd)
	rootCmd.AddCommand(explainCmd)
	rootCmd.AddCommand(driftCmd)

	// Provider management (includes install/uninstall as subcommands)
	rootCmd.AddCommand(providerCmd)

	// Utilities
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scannersCmd)

	// Hide the completion command from help output
	rootCmd.InitDefaultCompletionCmd()
	for _, c := range rootCmd.Commands() {
		if c.Name() == "completion" {
			c.Hidden = true
		}
	}

	// Apply pt-BR translations early so --help can use them.
	// Cobra doesn't call PersistentPreRun on --help, so we check os.Args directly.
	for _, arg := range os.Args {
		if arg == "--br" {
			brFlag = true
			i18n.SetLang("pt-BR")
			applyBRTranslations()
		}
		if arg == "--no-color" {
			noColor = true
			output.DisableColor()
		}
	}
}

// applyBRTranslations replaces all command descriptions with Portuguese translations.
func applyBRTranslations() {
	// Root
	rootCmd.Short = "Revisor semântico para planos Terraform"
	rootCmd.Long = `terraview — Revisor semântico para planos Terraform

Escaneamento de segurança e revisão com IA para planos Terraform.

Comandos Principais:
  scan        Escaneamento de segurança + análise IA opcional
  apply       Escanear e aplicar condicionalmente o plano
  diagram     Gerar diagrama ASCII de infraestrutura
  explain     Explicação de infraestrutura com IA
  drift       Detectar e classificar drift de infraestrutura

Gerenciamento de Providers:
  provider    Gerenciar providers de IA e runtimes LLM
              provider list | use | current | test
              provider install | uninstall

Gerenciamento de Scanners:
  scanners    Gerenciar scanners de segurança
              scanners list | install

Utilitários:
  version     Exibir informações de versão
  upgrade     Atualizar para a versão mais recente
  setup       Configuração interativa do ambiente

Primeiros passos:
  cd meu-projeto-terraform
  terraview scan checkov                    # scanner de segurança
  terraview scan checkov --ai               # scanner + análise IA
  terraview scan --ai                       # apenas análise IA
  terraview scan checkov --all              # tudo habilitado
  terraview diagram                         # diagrama de infraestrutura
  terraview explain                         # explicação com IA
  terraview drift                           # detectar drift
  terraview provider list                   # gerenciar providers de IA`

	// scan
	scanCmd.Short = "Escaneamento de segurança e análise IA opcional de um plano Terraform"
	scanCmd.Long = `Analisa um plano Terraform usando um scanner de segurança e/ou revisão com IA.

O scanner é especificado como argumento posicional.
Se --plan não for especificado, o terraview executará automaticamente:
  terraform init   (se necessário)
  terraform plan   (gera o plano)
  terraform show   (exporta JSON)

Exemplos:
  terraview scan checkov                       # apenas scanner de segurança
  terraview scan checkov --ai                  # scanner + análise IA
  terraview scan --ai                          # apenas análise IA (sem scanner)
  terraview scan checkov --all                 # tudo habilitado
  terraview scan checkov --ai --provider gemini  # Gemini AI
  terraview scan checkov --explain             # scanner + explicação IA
  terraview scan checkov --diagram             # scanner + diagrama
  terraview scan checkov --impact             # análise de impacto
  terraview scan checkov --format compact      # saída mínima
  terraview scan checkov --format sarif        # SARIF para CI
  terraview scan checkov --strict              # HIGH retorna código de saída 2
  terraview scan checkov --findings ext.json   # importar achados externos`

	// apply
	applyCmd.Short = "Escanear e aplicar condicionalmente o plano Terraform"
	applyCmd.Long = `Executa um escaneamento completo do plano Terraform e aplica condicionalmente.

O scanner é especificado como argumento posicional (mesmo padrão do scan).

Comportamento:
  - Bloqueia se achados CRÍTICOS forem detectados
  - Exibe resumo do escaneamento e pede confirmação (modo interativo)
  - Use --non-interactive para pipelines CI (bloqueia em CRÍTICO, aprova automaticamente caso contrário)

Exemplos:
  terraview apply checkov                     # escanear + aplicar interativo
  terraview apply checkov --ai                # escanear + IA + aplicar
  terraview apply checkov --non-interactive   # modo CI
  terraview apply checkov --all               # tudo habilitado + aplicar`

	// diagram
	diagramCmd.Short = "Gerar diagrama ASCII de infraestrutura"
	diagramCmd.Long = `Gera um diagrama ASCII de infraestrutura a partir de um plano Terraform.

Este comando é determinístico e não requer IA.
Se --plan não for especificado, o terraview gera o plano automaticamente.

Exemplos:
  terraview diagram
  terraview diagram --plan plan.json
  terraview diagram --output ./relatorios`

	// drift
	driftCmd.Short = "Detectar e classificar drift de infraestrutura"
	driftCmd.Long = `Executa terraform plan para detectar drift entre estado e infraestrutura.

Classifica cada mudança por nível de risco e gera um relatório de drift.
Use --intelligence para classificação avançada (intencional vs suspeito).

Códigos de saída:
  0 — sem drift ou apenas mudanças de baixo risco
  1 — drift de risco ALTO detectado
  2 — drift de risco CRÍTICO detectado

Exemplos:
  terraview drift
  terraview drift --plan plan.json
  terraview drift --intelligence          # classificar + score de risco
  terraview drift --format compact
  terraview drift --format json`

	// explain
	explainCmd.Short = "Explicação em linguagem natural da infraestrutura com IA"
	explainCmd.Long = `Gera uma explicação abrangente em linguagem natural da sua infraestrutura
Terraform usando IA. Explica o que cada recurso faz, como se conectam
e o padrão de arquitetura geral.

Requer um provider de IA (--provider ou configurado em .terraview.yaml).

Exemplos:
  terraview explain
  terraview explain --plan plan.json
  terraview explain --provider gemini
  terraview explain --format json`

	// provider
	providerCmd.Short = "Gerenciar providers de IA e runtimes LLM"
	providerCmd.Long = `Gerencia os providers de IA e runtimes usados pelo terraview.

Subcomandos:
  list        Listar providers disponíveis e escolher o padrão interativamente
  use         Definir provider padrão sem interação (para scripts)
  current     Exibir o provider atualmente configurado
  test        Testar conectividade com o provider configurado
  install     Instalar runtime LLM (Ollama)
  uninstall   Remover runtime LLM`

	// provider subcommands (already partially in PT)
	aiListCmd.Short = "Listar providers disponíveis e escolher o padrão interativamente"
	aiUseCmd.Short = "Definir provider padrão (sem interação, útil em scripts)"
	aiUseCmd.Long = `Define o provider padrão globalmente sem modo interativo.

Exemplos:
  terraview ai use gemini
  terraview ai use openrouter google/gemini-2.0-flash-001
  terraview ai use ollama llama3.1:8b`
	aiCurrentCmd.Short = "Exibir o provider de IA atualmente configurado"
	aiTestCmd.Short = "Testar conectividade com o provider de IA configurado"

	// install / uninstall
	installCmd.Short = "Instalar dependências do terraview"
	installCmd.Long = "Instala e configura dependências externas necessárias pelo terraview."
	installLLMCmd.Short = "Instalar Ollama e baixar o modelo LLM padrão"
	installLLMCmd.Long = `Instala automaticamente o runtime Ollama para inferência LLM local,
baixa o modelo configurado e valida a instalação.

Este comando é idempotente: executá-lo várias vezes não
reinstalará — apenas validará a instalação existente.

Exemplos:
  terraview install llm
  terraview install llm --model codellama:13b`

	uninstallCmd.Short = "Desinstalar dependências gerenciadas pelo terraview"
	uninstallCmd.Long = "Remove dependências externas que foram instaladas pelo terraview."
	uninstallLLMCmd.Short = "Desinstalar Ollama e remover todos os modelos"
	uninstallLLMCmd.Long = `Remove o binário do Ollama, para qualquer serviço em execução
e deleta dados de modelos baixados.

Este comando é idempotente: executá-lo quando o Ollama não está
instalado simplesmente confirmará que não há nada a remover.

Exemplos:
  terraview uninstall llm`

	// version / upgrade / setup
	versionCmd.Short = "Exibir a versão do terraview"
	upgradeCmd.Short = "Atualizar terraview para a versão mais recente"
	setupCmd.Short = "Configuração interativa do ambiente"
	setupCmd.Long = `Detecta scanners de segurança e providers de IA instalados, exibe status
e sugere comandos de instalação para ferramentas ausentes.

Este comando é informacional e não-destrutivo — apenas verifica o que
está disponível e oferece dicas de instalação.

Exemplos:
  terraview setup`
	upgradeCmd.Long = `Baixa e instala a versão mais recente do terraview via GitHub Releases.

Detecta seu SO e arquitetura automaticamente.
Também atualiza assets inclusos (prompts e regras).

Exemplos:
  terraview upgrade              # atualizar se versão mais nova disponível
  terraview upgrade --force      # forçar reinstalação mesmo se atualizado`

	// Translate persistent flag descriptions
	rootCmd.PersistentFlags().Lookup("verbose").Usage = "Habilitar saída detalhada"
	rootCmd.PersistentFlags().Lookup("dir").Usage = "Diretório do workspace Terraform"
	rootCmd.PersistentFlags().Lookup("br").Usage = "Saída em Português Brasileiro (pt-BR)"
	rootCmd.PersistentFlags().Lookup("no-color").Usage = "Desabilitar saída colorida"
	rootCmd.PersistentFlags().Lookup("plan").Usage = "Caminho para JSON do plano Terraform (gera automaticamente se omitido)"
	rootCmd.PersistentFlags().Lookup("output").Usage = "Diretório de saída para arquivos gerados"
	rootCmd.PersistentFlags().Lookup("format").Usage = "Formato de saída: pretty, compact, json, sarif (padrão pretty)"
	rootCmd.PersistentFlags().Lookup("provider").Usage = "Provider de IA (ollama, gemini, claude, deepseek, openrouter)"
	rootCmd.PersistentFlags().Lookup("model").Usage = "Modelo de IA a ser usado"

	// Translate local flags for each command
	translateFlags(scanCmd, map[string]string{
		"ai":       "Habilitar revisão semântica com IA",
		"strict":   "Modo estrito: achados HIGH também retornam código de saída 2",
		"explain":  "Gerar explicação em linguagem natural com IA (implica --ai)",
		"diagram":  "Exibir diagrama ASCII de infraestrutura",
		"impact":   "Analisar impacto de dependências das mudanças",
		"findings": "Importar achados externos de Checkov/tfsec/Trivy JSON",
		"all":      "Habilitar tudo: explain + diagram + impact",
	})
	translateFlags(applyCmd, map[string]string{
		"non-interactive": "Pular prompt de confirmação (para CI)",
		"ai":              "Habilitar revisão semântica com IA",
		"strict":          "Modo estrito: achados HIGH também retornam código de saída 2",
		"explain":         "Gerar explicação em linguagem natural com IA (implica --ai)",
		"diagram":         "Exibir diagrama ASCII de infraestrutura",
		"impact":          "Analisar impacto de dependências das mudanças",
		"findings":        "Importar achados externos de Checkov/tfsec/Trivy JSON",
		"all":             "Habilitar tudo: explain + diagram + impact",
	})
	translateFlags(driftCmd, map[string]string{
		"intelligence": "Classificação avançada de drift e scoring de risco",
	})
	translateFlags(installLLMCmd, map[string]string{
		"model": "Modelo a baixar (padrão da config ou llama3.1:8b)",
	})
	translateFlags(upgradeCmd, map[string]string{
		"force": "Forçar atualização mesmo se já estiver na versão mais recente",
	})

	// Translate Cobra built-in template labels
	brUsageTemplate := `Uso:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [comando]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Exemplos:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Comandos Disponíveis:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

Flags:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Flags Globais:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Tópicos de ajuda adicionais:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [comando] --help" para mais informações sobre um comando.{{end}}
`
	rootCmd.SetUsageTemplate(brUsageTemplate)
	// Translate the root --help flag (Cobra adds it lazily, so we must init flags first)
	rootCmd.InitDefaultHelpFlag()
	if h := rootCmd.Flags().Lookup("help"); h != nil {
		h.Usage = "ajuda para terraview"
	}
	// Translate Cobra built-in commands (must init them first)
	rootCmd.InitDefaultHelpCmd()
	rootCmd.InitDefaultCompletionCmd()
	for _, c := range rootCmd.Commands() {
		switch c.Name() {
		case "help":
			c.Short = "Ajuda sobre qualquer comando"
			c.Long = "Ajuda sobre qualquer comando da aplicação."
		case "completion":
			c.Hidden = true
		}
	}
	// Apply to all subcommands recursively
	applyTemplateToCmds(rootCmd, brUsageTemplate)
}

// ExitError signals a non-zero exit code without being a "real" error.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// Execute runs the root command.
func Execute(version string) {
	Version = version

	// Ensure ~/.terraview/bin is in PATH so scanner binaries are discoverable
	scanner.EnsureBinDirInPath()

	if err := rootCmd.Execute(); err != nil {
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Fprintf(os.Stderr, "%s "+format+"\n", append([]interface{}{output.Prefix()}, args...)...)
	}
}

// applyTemplateToCmds recursively sets the usage template on all subcommands.
func applyTemplateToCmds(cmd *cobra.Command, tmpl string) {
	for _, c := range cmd.Commands() {
		c.SetUsageTemplate(tmpl)
		// Translate the auto-generated --help flag
		if h := c.Flags().Lookup("help"); h != nil {
			h.Usage = "ajuda para " + c.Name()
		}
		applyTemplateToCmds(c, tmpl)
	}
}

// translateFlags translates flag usage descriptions for a command.
func translateFlags(cmd *cobra.Command, translations map[string]string) {
	for name, usage := range translations {
		if f := cmd.Flags().Lookup(name); f != nil {
			f.Usage = usage
		}
	}
}
