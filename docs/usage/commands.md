# Comandos

## Visão geral

```
$ terraview

Core Commands:
  scan        Security scan + AI contextual analysis (parallel)
  apply       Scan and conditionally apply the plan
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation
  drift       Detect and classify infrastructure drift
  modules     Analyze Terraform module usage and health
  history     View scan history and trends

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test
              provider install | uninstall

Scanner Management:
  scanners    Manage security scanners
              scanners list | install | default

Integration:
  mcp         Model Context Protocol server for AI agents
              mcp serve

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
terraview scan checkov --all                # habilitar explain + diagram + impact
terraview scan checkov --explain            # scanner + IA + explicação em linguagem natural
terraview scan checkov --diagram            # scanner + IA + diagrama ASCII da infraestrutura
terraview scan checkov --impact             # scanner + IA + análise de raio de impacto
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

## Apply

Roda scan + aplica o plano condicionalmente. Bloqueia se houver findings CRITICAL. Exibe o resumo do scan e pede confirmação no modo interativo.

```bash
terraview apply checkov                     # interativo
terraview apply checkov --non-interactive   # modo CI (bloqueia CRITICAL, auto-aprova caso contrário)
terraview apply checkov --static            # apenas scanner + apply
terraview apply checkov --all               # tudo habilitado + apply
```

---

## Diagram

Gera um diagrama ASCII determinístico da infraestrutura. Não requer IA.

```bash
terraview diagram                           # diagrama do diretório atual
terraview diagram --plan plan.json          # diagrama de plan existente
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

## Drift

Detecta e classifica drift de infraestrutura rodando `terraform plan` e analisando mudanças.

```bash
terraview drift                             # detecção básica de drift
terraview drift --plan plan.json            # de plan existente
terraview drift --intelligence              # avançado: classifica intencional vs suspeito
terraview drift --format compact            # resumo em uma linha
terraview drift --format json               # saída JSON
```

Exit codes: `0` = sem drift ou apenas baixo risco, `1` = risco HIGH, `2` = risco CRITICAL.

---

## Gerenciamento de providers

```bash
terraview provider list                     # seletor interativo (provider + modelo + teste de conectividade)
terraview provider use gemini gemini-2.5-pro  # definir provider via CLI (não-interativo)
terraview provider use ollama llama3.1:8b   # definir provider local
terraview provider current                  # exibir configuração atual
terraview provider test                     # testar conectividade do provider configurado
terraview provider install ollama           # instalar runtime Ollama + pull do modelo
terraview provider install ollama --model codellama:13b  # instalar com modelo específico
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

## Modules

Analisa módulos Terraform no plan para versionamento, higiene de source e profundidade de nesting. Determinístico, não requer IA.

```bash
terraview modules                           # analisar módulos do diretório atual
terraview modules --plan plan.json          # analisar de plan existente
terraview modules --check-registry          # verificar versões no Terraform Registry (requer rede)
terraview modules --format json             # saída JSON
terraview modules --terragrunt              # suporte a Terragrunt
terraview modules --terragrunt -d modules/vpc
```

### Regras verificadas

| Regra | Descrição |
|-------|-----------|
| `MOD_001` | Módulo do Registry sem constraint de versão |
| `MOD_002` | Source Git fixado em branch em vez de tag |
| `MOD_003` | Source Git sem nenhum ref |
| `MOD_004` | Nesting de módulo excede profundidade recomendada |
| `MOD_005` | Source de módulo usa HTTP em vez de HTTPS |
| `MOD_006` | Módulo do Registry tem versão mais nova disponível (requer `--check-registry`) |

Exit codes: `0` = sem issues, `1` = findings HIGH, `2` = findings CRITICAL.

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
terraview mcp serve                         # iniciar servidor MCP
```

### Registro com agentes

**Claude Code:**

```bash
claude mcp add terraview -- terraview mcp serve
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "terraview": {
      "command": "terraview",
      "args": ["mcp", "serve"]
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
| `terraview_drift` | Detecção e classificação de drift |
| `terraview_history` | Consultar histórico de scans |
| `terraview_history_trend` | Tendências de scores ao longo do tempo |
| `terraview_history_compare` | Comparar dois scans lado a lado |
| `terraview_impact` | Blast radius / análise de impacto |
| `terraview_cache` | Status e gerenciamento do cache de IA |
| `terraview_scanners` | Listar scanners disponíveis |
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
| `2`    | Findings CRITICAL (bloqueia apply) |

Modo estrito (`--strict`): promove findings HIGH para exit code 2.
