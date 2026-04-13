package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/leonamvasquez/terraview/internal/i18n"
	"github.com/leonamvasquez/terraview/internal/output"
	"github.com/leonamvasquez/terraview/internal/scanner"
	"github.com/leonamvasquez/terraview/internal/terraformexec"
	"github.com/leonamvasquez/terraview/internal/workspace"
)

var (
	// Global flags (persistent, inherited by all subcommands)
	verbose        bool
	workDir        string
	brFlag         bool
	noColor        bool
	planFile       string
	outputDir      string
	outputFormat   string
	activeProvider string
	activeModel    string
	terragruntFlag string // --terragrunt [config]: use terragrunt; optionally specify config file
)

// Version is set at build time via ldflags.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "terraview",
	Short: "Security scanner + AI contextual analysis for Terraform plans",
	Long: `terraview — Security scanner + AI contextual analysis for Terraform plans

Combines static security scanners (Checkov, tfsec, Terrascan) with AI-powered
contextual analysis that detects cross-resource risks scanners cannot find.
Scanner and AI run in parallel by default.

Core Commands:
  scan        Security scan + AI contextual analysis (parallel)
  status      Show open findings from the last scan
  fix         AI-generated fixes for open findings (interactive)
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation

History & Cache:
  history     View scan history, trends, and comparisons
  cache       Manage the AI response cache

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test

Scanner Management:
  scanners    Manage security scanners
              scanners list | install | default

Integration:
  mcp         Model Context Protocol server for AI agents

Utilities:
  version     Show version information
  setup       Interactive environment setup

Get started:
  cd my-terraform-project
  terraview scan checkov                    # scanner + AI (default)
  terraview scan checkov --static           # scanner only, no AI
  terraview status                          # show open findings
  terraview fix                             # apply AI fixes interactively
  terraview diagram                         # infrastructure diagram
  terraview explain                         # AI explanation
  terraview history                         # scan history
  terraview provider list                   # manage AI providers

Terragrunt:
  terraview scan checkov --terragrunt                    # auto-detect config
  terraview scan checkov --terragrunt dev.hcl            # specific config file`,
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
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "format", "f", "", "Output format: pretty, compact, json, sarif, html (default pretty)")
	rootCmd.PersistentFlags().StringVar(&activeProvider, "provider", "", "AI provider (ollama, gemini, claude, deepseek, openrouter)")
	rootCmd.PersistentFlags().StringVar(&activeModel, "model", "", "AI model to use")
	rootCmd.PersistentFlags().StringVar(&terragruntFlag, "terragrunt", "", "Use Terragrunt for plan generation (optionally specify config file path)")
	rootCmd.PersistentFlags().Lookup("terragrunt").NoOptDefVal = "auto"

	// Core commands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(fixCmd)
	rootCmd.AddCommand(diagramCmd)
	rootCmd.AddCommand(explainCmd)

	// Provider management (includes install/uninstall as subcommands)
	rootCmd.AddCommand(providerCmd)

	// Utilities
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(scannersCmd)
	rootCmd.AddCommand(cacheCmd)

	// Shell completions (bash, zsh, fish, powershell)
	// Install: terraview completion bash | sudo tee /etc/bash_completion.d/terraview
	//          terraview completion zsh  | sudo tee "${fpath[1]}/_terraview"
	//          terraview completion fish | source (terraview completion fish | psub)
	rootCmd.InitDefaultCompletionCmd()

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
			disableCmdColors()
		}
	}

}

func applyBRTranslations() {
	// Root
	rootCmd.Short = "Scanner de segurança + análise contextual IA para planos Terraform"
	rootCmd.Long = `terraview — Scanner de segurança + análise contextual IA para planos Terraform

Combina scanners de segurança estáticos (Checkov, tfsec, Terrascan) com análise
contextual por IA que detecta riscos entre recursos que scanners não encontram.
Scanner e IA rodam em paralelo por padrão.

Comandos Principais:
  scan        Escaneamento de segurança + análise IA (paralelo)
  status      Exibir findings abertos do último scan
  fix         Correções geradas por IA para findings abertos (interativo)
  diagram     Gerar diagrama ASCII de infraestrutura
  explain     Explicação de infraestrutura com IA

Histórico & Cache:
  history     Visualizar histórico de scans, tendências e comparações
  cache       Gerenciar cache de respostas IA

Gerenciamento de Providers:
  provider    Gerenciar providers de IA e runtimes LLM
              provider list | use | current | test

Gerenciamento de Scanners:
  scanners    Gerenciar scanners de segurança
              scanners list | install | default

Integração:
  mcp         Servidor Model Context Protocol para agentes IA

Utilitários:
  version     Exibir informações de versão
  setup       Configuração interativa do ambiente

Primeiros passos:
  cd meu-projeto-terraform
  terraview scan checkov                    # scanner + IA (padrão)
  terraview scan checkov --static           # apenas scanner, sem IA
  terraview status                          # exibir findings abertos
  terraview fix                             # aplicar fixes IA interativamente
  terraview diagram                         # diagrama de infraestrutura
  terraview explain                         # explicação com IA
  terraview history                         # histórico de scans
  terraview provider list                   # gerenciar providers de IA

Terragrunt:
  terraview scan checkov --terragrunt                    # auto-detectar config
  terraview scan checkov --terragrunt dev.hcl            # arquivo de config específico`

	// scan
	scanCmd.Short = "Escaneamento de segurança + análise contextual IA de um plano Terraform"
	scanCmd.Long = `Analisa um plano Terraform usando scanners de segurança e análise contextual IA.

Por padrão, o terraview executa TANTO o scanner de segurança QUANTO a análise
contextual IA em paralelo. O scanner verifica recursos individuais contra regras;
a IA analisa relações entre recursos, padrões de arquitetura e riscos de
dependência que scanners estáticos não detectam.

A IA roda automaticamente quando um provider está configurado (via .terraview.yaml,
flag --provider, ou 'terraview provider use'). Use --static para desabilitar a IA.

O scanner é especificado como argumento posicional.
Se --plan não for especificado, o terraview executará automaticamente:
  terraform init   (se necessário)
  terraform plan   (gera o plano)
  terraform show   (exporta JSON)

Exemplos:
  terraview scan checkov                       # scanner + IA (padrão)
  terraview scan checkov --static              # apenas scanner, sem IA
  terraview scan checkov --provider gemini     # usar provider IA específico
  terraview scan checkov --format compact      # saída mínima
  terraview scan checkov --format sarif        # SARIF para CI
  terraview scan checkov --strict              # HIGH retorna código de saída 2
  terraview scan checkov --findings ext.json   # importar achados externos

Comandos relacionados:
  terraview explain                            # explicação de infra com IA
  terraview diagram                            # diagrama ASCII da infra
  terraview fix                                # gerar/aplicar fixes por IA

Terragrunt:
  terraview scan checkov --terragrunt                    # auto-detectar config terragrunt
  terraview scan checkov --terragrunt dev.hcl            # usar arquivo de config específico
  terraview scan checkov --terragrunt terragrunt/prd.hcl # caminho para arquivo de config`

	// status
	statusCmd.Short = "Exibir findings abertos do último scan"
	statusCmd.Long = `Exibe os findings de segurança do scan mais recente para este projeto.
Mostra um delta contra o scan anterior e lista todos os findings CRITICAL/HIGH abertos.

Execute 'terraview fix' para corrigir estes findings interativamente.`
	translateFlags(statusCmd, map[string]string{
		"all": "Exibir todas as severidades, não apenas CRITICAL/HIGH",
	})

	// fix
	fixCmd.Short = "Revisar e aplicar interativamente correções geradas por IA"
	fixCmd.Long = `Lê os findings do último scan e gera correções HCL com IA.
Cada correção é apresentada para aprovação antes de ser aplicada ao arquivo .tf.

Requer um 'terraview scan' anterior neste diretório do projeto.`
	fixCmd.Example = `  terraview fix
  terraview fix --max-fix 10
  terraview fix --all
  terraview fix --provider claude --model claude-haiku-4-5`
	translateFlags(fixCmd, map[string]string{
		"max-fix":  "Número máximo de findings para gerar correções",
		"all":      "Corrigir todos os findings CRITICAL/HIGH sem prompts interativos",
		"provider": "Override do provider de IA (padrão: do último scan ou config)",
		"model":    "Override do modelo de IA",
	})

	// diagram
	diagramCmd.Short = "Gerar diagrama ASCII de infraestrutura"
	diagramCmd.Long = `Gera um diagrama ASCII de infraestrutura a partir de um plano Terraform.

Este comando é determinístico e não requer IA.
Se --plan não for especificado, o terraview gera o plano automaticamente.

Modos de diagrama:
  topo   Visão topológica com conexões, nesting VPC e agregação de recursos (padrão)
  flat   Visão flat original baseada em camadas

Exemplos:
  terraview diagram
  terraview diagram --diagram-mode topo
  terraview diagram --diagram-mode flat
  terraview diagram --plan plan.json
  terraview diagram --output ./relatorios

Terragrunt:
  terraview diagram --terragrunt
  terraview diagram --terragrunt -d modules/vpc`
	translateFlags(diagramCmd, map[string]string{
		"diagram-mode": "Modo de diagrama: topo (topológico) ou flat (camadas)",
	})

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

	// history
	historyCmd.Short = "Visualizar histórico de scans e tendências"
	historyCmd.Long = `Visualizar histórico de scans armazenado localmente em SQLite.

Todo scan do terraview registra resultados automaticamente. Use history para
consultar, comparar e acompanhar a postura de segurança ao longo do tempo.

Uso:
  terraview history                           # últimos 20 scans, projeto atual
  terraview history --all                     # todos os projetos
  terraview history --limit 50
  terraview history --since 7d
  terraview history --since 2025-01-01
  terraview history --format json|csv
  terraview history trend                     # tendências com sparkline
  terraview history compare                   # último vs anterior
  terraview history clear                     # limpar projeto atual
  terraview history export --format csv -o scans.csv`
	translateFlags(historyCmd, map[string]string{
		"all":     "Exibir todos os projetos",
		"limit":   "Número máximo de scans a exibir",
		"project": "Filtrar por diretório do projeto",
		"since":   "Exibir scans desde (ex: 7d, 30d, 2025-01-01)",
		"format":  "Formato de saída: pretty, json, csv",
	})

	historyTrendCmd.Short = "Exibir tendências de score com sparklines"
	historyTrendCmd.Long = `Exibe como scores de segurança e contagens de findings evoluem ao longo do tempo.
Mostra gráficos sparkline e percentuais de variação.

Uso:
  terraview history trend
  terraview history trend --limit 30`
	translateFlags(historyTrendCmd, map[string]string{
		"limit": "Número de scans para tendência",
		"since": "Tendência desde (ex: 7d, 30d)",
	})

	historyCompareCmd.Short = "Comparar último scan com um anterior"
	historyCompareCmd.Long = `Compara o último scan contra um scan anterior ou ponto no tempo.

Uso:
  terraview history compare                   # último vs anterior
  terraview history compare --with 5          # último vs scan #5
  terraview history compare --since 7d        # último vs scan mais antigo em 7 dias`
	translateFlags(historyCompareCmd, map[string]string{
		"with":  "Comparar com scan #ID",
		"since": "Comparar com scan mais antigo desde (ex: 7d)",
	})

	historyClearCmd.Short = "Limpar histórico de scans"
	historyClearCmd.Long = `Remove registros do histórico de scans.

Uso:
  terraview history clear                     # apenas projeto atual
  terraview history clear --all               # todos os projetos
  terraview history clear --before 30d        # mais antigos que 30 dias`
	translateFlags(historyClearCmd, map[string]string{
		"all":    "Limpar todos os projetos",
		"before": "Limpar scans mais antigos que (ex: 30d, 0d)",
	})

	historyExportCmd.Short = "Exportar histórico de scans para arquivo"
	historyExportCmd.Long = `Exporta histórico de scans para arquivo CSV ou JSON.

Uso:
  terraview history export --format csv -o scans.csv
  terraview history export --format json -o scans.json`
	translateFlags(historyExportCmd, map[string]string{
		"format": "Formato de exportação: json, csv",
		"output": "Caminho do arquivo de saída (obrigatório)",
	})

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

	// provider subcommands
	aiListCmd.Short = "Listar providers disponíveis e escolher o padrão interativamente"
	aiUseCmd.Short = "Definir provider padrão (sem interação, útil em scripts)"
	aiUseCmd.Long = `Define o provider padrão globalmente sem modo interativo.

Exemplos:
  terraview provider use gemini
  terraview provider use openrouter google/gemini-2.0-flash-001
  terraview provider use ollama llama3.1:8b`
	aiCurrentCmd.Short = "Exibir o provider de IA atualmente configurado"
	aiTestCmd.Short = "Testar conectividade com o provider de IA configurado"

	// mcp
	mcpCmd.Short = "Servidor Model Context Protocol (MCP)"
	mcpCmd.Long = `Servidor MCP para integração com agentes IA.

Expõe funcionalidades do terraview via Model Context Protocol,
permitindo que agentes IA (Claude Code, Cursor, Windsurf) chamem
ferramentas do terraview programaticamente via stdio.

Uso:
  terraview mcp server`

	mcpServeCmd.Short = "Iniciar o servidor MCP via stdio"
	mcpServeCmd.Long = `Inicia um servidor Model Context Protocol que lê mensagens JSON-RPC 2.0
do stdin e escreve respostas no stdout.

Logs vão para stderr. Apenas JSON-RPC válido aparece no stdout.

Registrar no Claude Code:
  claude mcp add terraview -- terraview mcp server

Registrar no Cursor (.cursor/mcp.json):
  {
    "mcpServers": {
      "terraview": {
        "command": "terraview",
        "args": ["mcp", "server"]
      }
    }
  }

Ferramentas expostas:
  terraview_scan             Scan de segurança com scorecard
  terraview_explain          Explicação de infraestrutura com IA
  terraview_diagram          Diagrama ASCII de infraestrutura
  terraview_history          Consultar histórico de scans
  terraview_history_trend    Tendências de score ao longo do tempo
  terraview_history_compare  Comparar dois scans lado a lado
  terraview_impact           Blast radius / impacto de dependências
  terraview_cache            Status e gerenciamento do cache IA
  terraview_scanners         Listar scanners de segurança disponíveis
  terraview_version          Informações de versão e ambiente`

	// cache (pick() evaluates at package init before --br is set, so override here)
	cacheCmd.Short = "Gerenciar o cache de respostas IA"
	cacheCmd.Long = "Gerencia o cache persistente de respostas IA armazenado em ~/.terraview/cache/"
	cacheClearCmd.Short = "Limpar o cache de respostas IA"
	cacheStatusCmd.Short = "Exibir estatísticas do cache"

	// version / setup
	versionCmd.Short = "Exibir a versão do terraview"
	setupCmd.Short = "Configuração interativa do ambiente"
	setupCmd.Long = `Detecta scanners de segurança e providers de IA instalados, exibe o status
do ambiente, scanner padrão configurado e providers disponíveis.

Este comando é informacional e não-destrutivo — apenas verifica o que
está disponível. Para instalar scanners, use 'terraview scanners install'.

Exemplos:
  terraview setup`

	// scanners
	scannersCmd.Short = "Gerenciar scanners de segurança"
	scannersCmd.Long = "Listar, instalar e gerenciar binários de scanners de segurança."
	scannersListCmd.Short = "Listar todos os scanners com status de instalação"
	scannersInstallCmd.Short = "Instalar um ou mais binários de scanner"
	scannersInstallCmd.Long = `Instala binários de scanners de segurança no diretório gerenciado pelo terraview.

Exemplos:
  terraview scanners install checkov
  terraview scanners install tfsec terrascan
  terraview scanners install --all
  terraview scanners install checkov --force`
	scannersDefaultCmd.Short = "Definir ou exibir o scanner padrão"
	scannersDefaultCmd.Long = `Define ou exibe o scanner padrão usado pelo 'terraview scan'.

Exemplos:
  terraview scanners default              # exibir scanner padrão
  terraview scanners default checkov      # definir checkov como padrão`
	// Translate persistent flag descriptions (defined in root.go init, always available)
	rootCmd.PersistentFlags().Lookup("verbose").Usage = "Habilitar saída detalhada"
	rootCmd.PersistentFlags().Lookup("dir").Usage = "Diretório do workspace Terraform"
	rootCmd.PersistentFlags().Lookup("br").Usage = "Saída em Português Brasileiro (pt-BR)"
	rootCmd.PersistentFlags().Lookup("no-color").Usage = "Desabilitar saída colorida"
	rootCmd.PersistentFlags().Lookup("plan").Usage = "Caminho para JSON do plano Terraform (gera automaticamente se omitido)"
	rootCmd.PersistentFlags().Lookup("output").Usage = "Diretório de saída para arquivos gerados"
	rootCmd.PersistentFlags().Lookup("format").Usage = "Formato de saída: pretty, compact, json, sarif (padrão pretty)"
	rootCmd.PersistentFlags().Lookup("provider").Usage = "Provider de IA (ollama, gemini, claude, deepseek, openrouter)"
	rootCmd.PersistentFlags().Lookup("model").Usage = "Modelo de IA a ser usado"
	rootCmd.PersistentFlags().Lookup("terragrunt").Usage = "Usar Terragrunt para gerar plano (opcionalmente especificar arquivo de config)"

	// Translate local flags for commands whose init() runs BEFORE root.go
	// (alphabetical: ai.go → mcp.go). Commands after root.go (scan.go, scanners.go,
	// status.go) translate their own flags in their init() functions.
	translateFlags(fixCmd, map[string]string{
		"max-fix":  "Número máximo de findings para gerar correções",
		"all":      "Corrigir todos os findings CRITICAL/HIGH sem prompts interativos",
		"provider": "Override do provider de IA (padrão: do último scan ou config)",
		"model":    "Override do modelo de IA",
	})
	translateFlags(diagramCmd, map[string]string{
		"diagram-mode": "Modo de diagrama: topo (topológico) ou flat (camadas)",
	})
	translateFlags(historyCmd, map[string]string{
		"all":     "Exibir todos os projetos",
		"limit":   "Número máximo de scans a exibir",
		"project": "Filtrar por diretório do projeto",
		"since":   "Exibir scans desde (ex: 7d, 30d, 2025-01-01)",
		"format":  "Formato de saída: pretty, json, csv",
	})
	translateFlags(historyTrendCmd, map[string]string{
		"limit": "Número de scans para tendência",
		"since": "Tendência desde (ex: 7d, 30d)",
	})
	translateFlags(historyCompareCmd, map[string]string{
		"with":  "Comparar com scan #ID",
		"since": "Comparar com scan mais antigo desde (ex: 7d)",
	})
	translateFlags(historyClearCmd, map[string]string{
		"all":    "Limpar todos os projetos",
		"before": "Limpar scans mais antigos que (ex: 30d, 0d)",
	})
	translateFlags(historyExportCmd, map[string]string{
		"format": "Formato de exportação: json, csv",
		"output": "Caminho do arquivo de saída (obrigatório)",
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

func translateFlags(cmd *cobra.Command, translations map[string]string) {
	for name, usage := range translations {
		if f := cmd.Flags().Lookup(name); f != nil {
			f.Usage = usage
		}
	}
}

// generatePlan creates the appropriate executor (terraform or terragrunt) and generates
// the plan JSON. This extracts the common pattern used by scan, explain, diagram, and drift.
// If terragruntFlag is set, it uses Terragrunt; otherwise, it uses Terraform.
func generatePlan() (string, terraformexec.PlanExecutor, error) { //nolint:unparam // PlanExecutor intentionally kept for future use by callers that may need it
	var executor terraformexec.PlanExecutor
	var err error

	// Resolve terragrunt config from --terragrunt flag
	useTerragrunt := terragruntFlag != ""
	configFile := ""

	// --terragrunt dev.hcl → use that file as config
	if terragruntFlag != "" && terragruntFlag != "auto" {
		configFile = terragruntFlag
	}

	// Auto-detect terragrunt project when not explicitly set
	if !useTerragrunt && terraformexec.IsTerragruntProject(workDir) {
		useTerragrunt = true
		fmt.Fprintf(os.Stderr, "%s Auto-detected Terragrunt project at %s\n", output.Prefix(), workDir)
	}

	if useTerragrunt {
		if configFile != "" {
			fmt.Fprintf(os.Stderr, "%s Terragrunt mode: config=%s\n", output.Prefix(), configFile)
		} else {
			fmt.Fprintf(os.Stderr, "%s Terragrunt mode: auto-detect\n", output.Prefix())
		}

		if configFile == "" {
			// Multi-module root: discover child modules, plan each, merge
			if terraformexec.IsTerragruntRootWithModules(workDir) {
				executor, err = terraformexec.NewTerragruntMultiExecutor(workDir, "")
			} else {
				// Single module: validate workspace and plan directly
				if err := terraformexec.ValidateTerragruntWorkspace(workDir); err != nil {
					return "", nil, err
				}
				executor, err = terraformexec.NewTerragruntExecutor(workDir, "")
			}
		} else {
			// Config file provided: skip workspace validation
			executor, err = terraformexec.NewTerragruntExecutor(workDir, configFile)
		}
	} else {
		if err := workspace.Validate(workDir); err != nil {
			return "", nil, err
		}
		executor, err = terraformexec.NewExecutor(workDir)
	}
	if err != nil {
		return "", nil, err
	}

	if executor.NeedsInit() {
		if err := executor.Init(); err != nil {
			return "", nil, err
		}
	}

	planPath, err := executor.Plan()
	if err != nil {
		return "", nil, err
	}

	return planPath, executor, nil
}
