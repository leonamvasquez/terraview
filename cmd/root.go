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
	// Global flags
	verbose bool
	workDir string
	brFlag  bool
	noColor bool
)

// Version is set at build time via ldflags.
var Version = "v0.3.2"

var rootCmd = &cobra.Command{
	Use:   "terraview",
	Short: "Semantic reviewer for Terraform plans",
	Long: `terraview — Semantic reviewer for Terraform plans

Security scanning and AI review for Terraform plans.

Core Commands:
  plan        Analyze a Terraform plan (scanner + AI)
  apply       Review and conditionally apply the plan
  validate    Run scanner checks (no AI)
  drift       Detect and classify infrastructure drift
  explain     Explain infrastructure in natural language

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test
              provider install | uninstall

Utilities:
  version     Show version information
  upgrade     Upgrade to the latest version
  setup       Interactive environment setup

Get started:
  cd my-terraform-project
  terraview plan --scanner checkov          # run security scanner
  terraview plan --scanner checkov --ai     # review with AI analysis
  terraview plan --scanner checkov --diagram # show infrastructure diagram
  terraview validate                # scanner checks
  terraview drift                   # detect drift
  terraview provider list           # manage AI providers`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVarP(&workDir, "dir", "d", ".", "Terraform workspace directory")
	rootCmd.PersistentFlags().BoolVar(&brFlag, "br", false, "Output in Brazilian Portuguese (pt-BR)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Core commands
	rootCmd.AddCommand(planCmd)
	rootCmd.AddCommand(applyCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(driftCmd)
	rootCmd.AddCommand(explainCmd)

	// Provider management (includes install/uninstall as subcommands)
	rootCmd.AddCommand(providerCmd)

	// Utilities
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scannersCmd)

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
  plan        Analisar um plano Terraform (regras + IA)
  apply       Revisar e aplicar condicionalmente o plano
  validate    Executar verificações de scanner (sem IA)
  drift       Detectar e classificar drift de infraestrutura
  explain     Explicar infraestrutura em linguagem natural

Gerenciamento de Providers:
  provider    Gerenciar providers de IA e runtimes LLM
              provider list | use | current | test
              provider install | uninstall

Utilitários:
  version     Exibir informações de versão
  upgrade     Atualizar para a versão mais recente
  setup       Configuração interativa do ambiente

Primeiros passos:
  cd meu-projeto-terraform
  terraview plan --scanner checkov          # executar scanner de segurança
  terraview plan --scanner checkov --ai     # revisão com análise de IA
  terraview plan --scanner checkov --diagram # diagrama de infraestrutura
  terraview validate                # verificações de scanner
  terraview drift                   # detectar drift
  terraview provider list           # gerenciar providers de IA`

	// plan
	planCmd.Short = "Analisar um plano Terraform para segurança, arquitetura e boas práticas"
	planCmd.Long = `Analisa um plano Terraform usando um scanner de segurança e revisão opcional com IA.

O scanner deve ser especificado explicitamente via --scanner.
Se --plan não for especificado, o terraview executará automaticamente:
  terraform init   (se necessário)
  terraform plan   (gera o plano)
  terraform show   (exporta JSON)

Exemplos:
  terraview plan --scanner checkov            # usar checkov
  terraview plan --scanner tfsec              # usar tfsec
  terraview plan --scanner checkov --ai       # scanner + análise com IA
  terraview plan --scanner checkov --ai --provider gemini  # Gemini AI
  terraview plan --scanner checkov --ai --explain  # IA + explicação
  terraview plan --scanner checkov --diagram  # diagrama de infraestrutura
  terraview plan --scanner checkov --blast-radius  # raio de impacto
  terraview plan --scanner checkov --format compact  # saída mínima
  terraview plan --scanner checkov --format sarif    # SARIF para CI
  terraview plan --scanner checkov --strict   # HIGH retorna código de saída 2
  terraview plan --scanner checkov --safe     # modo seguro
  terraview plan --findings checkov.json      # importar achados externos`

	// apply
	applyCmd.Short = "Revisar o plano e aplicar se seguro"
	applyCmd.Long = `Executa uma revisão completa do plano Terraform e aplica condicionalmente.

Comportamento:
  - Bloqueia se achados CRÍTICOS forem detectados
  - Exibe resumo da revisão e pede confirmação (modo interativo)
  - Use --non-interactive para pipelines CI (bloqueia em CRÍTICO, aprova automaticamente caso contrário)

Exemplos:
  terraview apply                     # modo interativo
  terraview apply --non-interactive   # modo CI
  terraview apply --ai                # revisão com IA, interativo`

	// validate
	validateCmd.Short = "Validar configuração Terraform e executar scanners de segurança (sem IA)"
	validateCmd.Long = `Executa uma suíte de validação com scanners — sem dependência de LLM:

  1. terraform fmt -check  — verificação de formatação
  2. terraform validate    — verificações de sintaxe e configuração
  3. terraform test        — testes nativos (Terraform 1.6+, se disponível)
  4. Scanners de segurança — avaliação via scanners externos (checkov, tfsec, etc.)

Códigos de saída:
  0 — todas as verificações passaram
  1 — erro de execução (fmt, validate, geração do plano)
  2 — violações de scanner (achados CRÍTICOS ou ALTOS)

Exemplos:
  terraview validate
  terraview validate -v`

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

	// Translate local flags for each command
	translateFlags(planCmd, map[string]string{
		"plan":           "Caminho para JSON do plano Terraform (gera automaticamente se omitido)",
		"prompts":        "Caminho para diretório de prompts",
		"output":         "Diretório de saída para arquivos de revisão",
		"ollama-url":     "URL do servidor Ollama (legado, prefira --provider)",
		"model":          "Modelo de IA a ser usado",
		"provider":       "Provider de IA (ollama, gemini, claude, deepseek)",
		"timeout":        "Timeout da requisição de IA em segundos",
		"temperature":    "Temperatura da IA (0.0-1.0)",
		"ai":             "Habilitar revisão semântica com IA",
		"format":         "Formato de saída: pretty, compact, json, sarif (padrão pretty)",
		"strict":         "Modo estrito: achados HIGH também retornam código de saída 2",
		"safe":           "Modo seguro: modelo leve, threads reduzidos, limites mais rígidos",
		"explain":        "Gerar explicação em linguagem natural com IA (implica --ai)",
		"diagram":        "Exibir diagrama ASCII de infraestrutura",
		"blast-radius":   "Analisar raio de impacto das mudanças",
		"findings":       "Importar achados externos de Checkov/tfsec/Trivy JSON",
		"second-opinion": "IA valida achados dos scanners (implica --ai)",
		"trend":          "Rastrear e exibir tendências de score ao longo do tempo",
		"smell":          "Detectar design smells de infraestrutura",
		"scanner":        "Scanner a usar: checkov, tfsec ou terrascan (obrigatório)",
	})
	translateFlags(applyCmd, map[string]string{
		"non-interactive": "Pular prompt de confirmação (para CI)",
		"plan":            "Caminho para JSON do plano Terraform (gera automaticamente se omitido)",
		"prompts":         "Caminho para diretório de prompts",
		"output":          "Diretório de saída para arquivos de revisão",
		"ollama-url":      "URL do servidor Ollama (legado, prefira --provider)",
		"model":           "Modelo de IA a ser usado",
		"provider":        "Provider de IA (ollama, gemini, claude, deepseek)",
		"timeout":         "Timeout da requisição de IA em segundos",
		"temperature":     "Temperatura da IA (0.0-1.0)",
		"ai":              "Habilitar revisão semântica com IA",
		"format":          "Formato de saída: pretty, compact, json, sarif (padrão pretty)",
		"safe":            "Modo seguro: modelo leve, recursos reduzidos",
		"explain":         "Gerar explicação em linguagem natural com IA (implica --ai)",
		"diagram":         "Exibir diagrama ASCII de infraestrutura",
		"blast-radius":    "Analisar raio de impacto das mudanças",
		"findings":        "Importar achados externos de Checkov/tfsec/Trivy JSON",
	})
	translateFlags(validateCmd, map[string]string{})
	translateFlags(driftCmd, map[string]string{
		"plan":         "Caminho para JSON do plano Terraform (gera automaticamente se omitido)",
		"output":       "Diretório de saída para relatório de drift",
		"format":       "Formato de saída: pretty, compact, json (padrão pretty)",
		"intelligence": "Classificação avançada de drift e scoring de risco",
	})
	translateFlags(explainCmd, map[string]string{
		"plan":     "Caminho para JSON do plano Terraform (gera automaticamente se omitido)",
		"provider": "Provider de IA (ollama, gemini, claude, deepseek)",
		"model":    "Modelo de IA a ser usado",
		"timeout":  "Timeout da requisição de IA em segundos",
		"output":   "Diretório de saída",
		"format":   "Formato de saída: pretty, json (padrão pretty)",
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
			c.Short = "Gerar script de autocompletar para o shell especificado"
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
