# Comandos

## Visão geral

```
$ terraview

Core Commands:
  scan        Security scan + AI contextual analysis (parallel)
  status      Show findings from last scan with delta vs previous
  fix         Generate (plan) and apply AI-suggested HCL fixes
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation
  history     View scan history and trends

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test

Scanner Management:
  scanners    Manage security scanners
              scanners list | install | default

Integration:
  mcp         Model Context Protocol server for AI agents
              mcp server

Utilities:
  cache       Manage the AI response cache
              cache status | clear
  version     Show version information
  setup       Interactive environment setup

Flags:
  -d, --dir string        Terraform workspace directory (default ".")
  -p, --plan string       Path to terraform plan JSON (auto-generates if omitted)
  -f, --format string     Output format: pretty, compact, json, sarif
  -o, --output string     Output directory for generated files
      --provider string   AI provider (ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code)
      --model string      AI model to use
      --br                Output in Brazilian Portuguese (pt-BR)
      --no-color          Disable colored output
  -v, --verbose           Enable verbose output
```

---

## Scan

Por padrão, o terraview roda **ambos** o scanner de segurança e a análise contextual por IA **em paralelo**. A IA ativa automaticamente quando um provider está configurado (via `.terraview.yaml`, flag `--provider`, ou `terraview provider use`). Se nenhum provider estiver configurado, apenas o scanner roda.

```bash
terraview scan                              # auto-selecionar scanner padrão
terraview scan checkov                      # scan com Checkov (+ IA se provider configurado)
terraview scan tfsec                        # scan com tfsec
terraview scan terrascan                    # scan com Terrascan
terraview scan checkov --static             # apenas scanner, desabilitar IA
terraview scan checkov --plan plan.json     # usar plan JSON existente
terraview scan checkov -f sarif             # saída SARIF para CI
terraview scan checkov --strict             # HIGH também retorna exit code 2
terraview scan checkov --findings ext.json  # importar findings externos Checkov/tfsec/Trivy
```

### Configurando diretório ou arquivo de entrada

Escanear o diretório atual (detecta Terraform automaticamente):

```bash
terraview scan checkov
```

Ou um diretório específico:

```bash
terraview scan checkov -d /caminho/para/meu-projeto
```

Ou gerar o plan manualmente:

```bash
terraform init
terraform plan -out tf.plan
terraform show -json tf.plan > tf.json
terraview scan checkov --plan tf.json
```

Usar providers CLI (subscription — sem API key):

```bash
terraview scan checkov --provider gemini-cli --model gemini-3
terraview scan checkov --provider claude-code --model claude-sonnet-4-5
```

---

## Status

Exibe os findings de segurança do scan mais recente para o projeto atual. Mostra delta contra o scan anterior e lista todos os findings CRITICAL/HIGH abertos.

```bash
terraview status                            # findings CRITICAL/HIGH do último scan
terraview status --all                      # incluir também MEDIUM/LOW/INFO
terraview status --explain-scores           # decomposição detalhada dos scores
```

---

## Fix

Gera correções HCL via IA para os findings do último scan. Subcomando pai — use `fix plan` (dry-run) ou `fix apply` (interativo/automático).

```bash
terraview fix plan                                  # dry-run: mostra diff colorido, não escreve
terraview fix apply                                 # interativo (y/n por fix)
terraview fix apply --auto-approve                  # aplica tudo sem prompt (CI/scripts)
terraview fix apply CKV_AWS_18                      # apenas findings deste rule ID
terraview fix apply --severity CRITICAL             # apenas CRITICAL
terraview fix apply --file vpc.tf                   # apenas fixes que alteram este arquivo
terraview fix apply --severity HIGH --max 5         # combinar filtros
```

Requer um `terraview scan` anterior no mesmo diretório do projeto.

---

## Diagram

Gera um diagrama ASCII determinístico da infraestrutura a partir de um plano Terraform. Não requer IA. Atualmente suporta apenas **AWS**.

Dois modos de renderização estão disponíveis:

- **topo** (padrão) — visão topológica com aninhamento VPC, tiers de subnet, setas de conexão, referências cruzadas de security groups, arestas bidirecionais, nós visuais NAT/TGW/VPN e agregação de recursos
- **flat** — visão simples baseada em camadas

```bash
terraview diagram                           # diagrama do diretório atual (modo topo)
terraview diagram --plan plan.json          # diagrama de plan existente
terraview diagram --diagram-mode flat       # visão flat baseada em camadas
terraview diagram --output ./reports        # salvar diagram.txt no diretório
```

---

## Explain

Gera uma explicação em linguagem natural da sua infraestrutura Terraform usando IA. Requer um provider configurado.

```bash
terraview explain                           # explicar projeto atual
terraview explain --plan plan.json          # explicar de plan existente
terraview explain --provider gemini         # usar provider específico
terraview explain --format json             # saída JSON estruturada
```

---

## Gerenciamento de providers

```bash
terraview provider list                     # seletor interativo (provider + modelo + teste de conectividade)
terraview provider use gemini gemini-2.5-pro  # definir provider via CLI (não-interativo)
terraview provider use ollama llama3.1:8b   # definir provider local
terraview provider current                  # exibir configuração atual
terraview provider test                     # testar conectividade do provider configurado
```

O comando `provider list` executa um **teste de integração automático**. Se o teste falhar, uma mensagem de diagnóstico é exibida:

- **CLI não instalado** → mostra comando de instalação (`npm install -g ...`)
- **API key ausente** → mostra variável de ambiente a configurar
- **API key inválida / rede** → sugere verificar credenciais e conectividade
- **Serviço local inacessível** → sugere verificar se o serviço está rodando

```
  [terraview] Testing connectivity with gemini-cli (gemini-3)... ✓

  ✓  Integration test passed — "gemini" CLI is installed and ready.
  ✓  Default provider: gemini-cli  model: gemini-3
     Saved to: ~/.terraview/.terraview.yaml
```

---

## Gerenciamento de scanners

```bash
terraview scanners list                     # listar scanners com status de instalação
terraview scanners install checkov          # instalar scanner específico
terraview scanners install tfsec terrascan  # instalar múltiplos scanners
terraview scanners install --all            # instalar todos os scanners faltantes
terraview scanners install --all --force    # forçar reinstalação de todos
terraview scanners default checkov          # definir scanner padrão
terraview scanners default                  # exibir scanner padrão atual
```

---

## History

Visualiza o histórico de scans armazenado localmente em SQLite. Todo scan do terraview registra resultados automaticamente quando o history está habilitado.

```bash
terraview history                           # últimos 20 scans, projeto atual
terraview history --all                     # todos os projetos
terraview history --limit 50                # limitar quantidade
terraview history --since 7d                # scans dos últimos 7 dias
terraview history --since 2025-01-01        # scans desde uma data
terraview history --format json             # saída JSON
terraview history --format csv              # saída CSV
```

### Subcomandos

```bash
terraview history trend                     # tendências com sparklines
terraview history trend --limit 30          # últimos 30 scans

terraview history compare                   # último vs anterior
terraview history compare --with 5          # último vs scan #5
terraview history compare --since 7d        # último vs mais antigo em 7 dias

terraview history clear                     # limpar projeto atual
terraview history clear --all               # limpar todos os projetos
terraview history clear --before 30d        # limpar mais antigos que 30 dias

terraview history export --format csv -o scans.csv   # exportar para CSV
terraview history export --format json -o scans.json # exportar para JSON
```

### Configuração

Habilite no `.terraview.yaml`:

```yaml
history:
  enabled: true
  retention_days: 90      # auto-limpeza de registros antigos
  max_size_mb: 50         # tamanho máximo do banco SQLite
```

---

## MCP (Model Context Protocol)

Servidor MCP para integração com agentes AI. Expõe funcionalidades do terraview via JSON-RPC 2.0 sobre stdio, permitindo que Claude Code, Cursor e Windsurf chamem tools programaticamente.

```bash
terraview mcp server                        # iniciar servidor MCP
```

O alias `terraview mcp serve` continua funcionando para compatibilidade.

### Registro com agentes

**Claude Code:**

```bash
claude mcp add terraview -- terraview mcp server
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "terraview": {
      "command": "terraview",
      "args": ["mcp", "server"]
    }
  }
}
```

### Tools expostas

| Tool | Descrição |
|------|-----------|
| `terraview_scan` | Security scan com scorecard |
| `terraview_explain` | Explicação da infraestrutura por IA |
| `terraview_diagram` | Diagrama ASCII da infraestrutura |
| `terraview_history` | Consultar histórico de scans |
| `terraview_history_trend` | Tendências de scores ao longo do tempo |
| `terraview_history_compare` | Comparar dois scans lado a lado |
| `terraview_impact` | Blast radius / análise de impacto |
| `terraview_cache` | Status e gerenciamento do cache de IA |
| `terraview_scanners` | Listar scanners disponíveis |
| `terraview_fix_suggest` | Sugestões de correção geradas por IA |
| `terraview_version` | Versão e informações do ambiente |

---

## Outros comandos

```bash
terraview setup                             # diagnóstico do ambiente
terraview version                           # versão, Go runtime, OS/arch
```

---

## Saída e formatos

```bash
terraview scan checkov                      # saída pretty (padrão)
terraview scan checkov -f compact           # resumo em uma linha
terraview scan checkov -f json              # JSON (review.json)
terraview scan checkov -f sarif             # SARIF (review.sarif.json) para GitHub Security tab
terraview scan checkov -o ./reports         # gravar review.json + review.md em ./reports
```

Todos os scans geram `review.json` e `review.md`. A saída SARIF é gerada quando `-f sarif` é usado.

---

## Exit Codes

| Código | Significado |
|--------|-------------|
| `0`    | Sem issues ou apenas MEDIUM/LOW/INFO |
| `1`    | Findings de severidade HIGH |
| `2`    | Findings CRITICAL |

Modo estrito (`--strict`): promove findings HIGH para exit code 2.
