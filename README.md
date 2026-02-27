<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/terraview-logo-dark-theme.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/terraview-logo-white-theme.png">
  <img alt="terraview" src=".github/assets/terraview-logo-white-theme.png">
</picture>

**Escolha seu idioma:** [Português](README.md) | [English](README.en.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://golang.org)
[![GitHub release](https://img.shields.io/github/v/release/leonamvasquez/terraview)](https://github.com/leonamvasquez/terraview/releases/latest)
[![CI](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml/badge.svg)](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/leonamvasquez/terraview/branch/main/graph/badge.svg)](https://codecov.io/gh/leonamvasquez/terraview)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)

O Terraview é uma ferramenta de análise de segurança para planos Terraform que combina scanners estáticos (Checkov, tfsec, Terrascan) com análise contextual por IA rodando **em paralelo**.

Ele escaneia infraestrutura cloud provisionada com Terraform, detecta misconfigurações de segurança e compliance utilizando scanners open-source de análise estática, e enriquece automaticamente os resultados com análise contextual por IA multi-provider (Ollama, Gemini, Claude, OpenAI, DeepSeek, OpenRouter, Gemini CLI, Claude Code) quando um provider está configurado.

O terraview roda como binário único sem dependências externas. Quando um provider de IA está configurado, scanner e IA rodam em paralelo automaticamente. Use `--static` para rodar apenas o scanner, sem IA.

## Sumário

- [Features](#features)
- [Exemplos](#exemplos)
- [Primeiros Passos](#primeiros-passos)
- [Instalação](#instalação)
- [Atualização](#atualização)
- [Autocompletar no shell](#autocompletar-no-shell)
- [Uso](#uso)
- [Scan](#scan)
- [Apply](#apply)
- [Diagram](#diagram)
- [Explain](#explain)
- [Drift](#drift)
- [Gerenciamento de providers](#gerenciamento-de-providers)
- [Gerenciamento de scanners](#gerenciamento-de-scanners)
- [Saída e formatos](#saída-e-formatos)
- [Configuração via arquivo](#configuração-via-arquivo)
- [Security Scanners](#security-scanners)
- [AI Providers](#ai-providers)
- [Integração com IAs por Assinatura](#integração-com-ias-por-assinatura)
- [Integração CI/CD](#integração-cicd)
- [Docker](#docker)
- [Arquitetura](#arquitetura)
- [Desenvolvimento](#desenvolvimento)
- [Contribuindo](#contribuindo)
- [Aviso](#aviso)
- [Suporte](#suporte)
- [Licença](#licença)

## Features

- **Security Scanners** — integração automática com Checkov, tfsec e Terrascan; detecta o que está instalado e roda automaticamente
- **Análise contextual IA (padrão)** — quando um provider de IA está configurado, a IA roda **em paralelo** com o scanner, analisando relações entre recursos, cadeias de dependência e anti-patterns arquiteturais que scanners não detectam.
- **IA Multi-Provider** — duas categorias:
  - **API**: Ollama (local), Google Gemini, Anthropic Claude, OpenAI, DeepSeek e OpenRouter
  - **CLI (subscription)**: Gemini CLI e Claude Code — usam assinatura pessoal, sem API key
- **Teste de integração automático** — ao selecionar um provider via `provider list`, o terraview testa a conectividade e retorna feedback específico por tipo de provider (CLI instalado, API key válida, serviço acessível)
- **Resolução de conflitos** scanner × IA: scanner prevalece em divergência (confiança 0.80); concordância eleva confiança a 1.00
- **Scorecard unificado** com scores de Segurança, Compliance, Manutenibilidade e Overall (0–10)
- **Vetores de risco** — extração de risco por recurso em 5 eixos: exposição de rede, criptografia, identidade, governança, observabilidade
- **Diagrama ASCII** da infraestrutura gerado direto no terminal via `--diagram`
- **Análise de impacto** — raio de dependências das mudanças via `--impact`
- **Explicação IA** — explicação em linguagem natural da sua infraestrutura via `explain`
- **Zero configuração** — detecta projetos Terraform e roda `init + plan + show` automaticamente
- **Drift detection** — detecta e classifica drift de infraestrutura com `--intelligence` opcional para scoring avançado
- **CI/CD nativo** — exit codes semânticos (0/1/2) + saída SARIF, JSON, Markdown para GitHub Actions, GitLab CI e Azure DevOps
- **Supply chain hardening** — SBOM (CycloneDX), assinatura cosign, SLSA Build Provenance Level 3 em cada release
- **Bilíngue (en/pt-BR)** — flag `--br` disponível em todos os comandos
- **Auto-atualização** via `terraview upgrade`
- **Alias `tv`** — symlink criado na instalação; `tv scan` = `terraview scan`
- **Instalação cross-platform** dos scanners via `terraview scanners install --all` (Linux, macOS, Windows)

## Exemplos

Resultado do scan no CLI

```
  terraview scan checkov
  ══════════════════════

  ┌──────────────────────────────────────────────────────┐
  │  Scorecard                                           │
  │  Security:       7.2 / 10                            │
  │  Compliance:     8.5 / 10                            │
  │  Maintainability: 9.0 / 10                           │
  │  Overall:        8.2 / 10                            │
  └──────────────────────────────────────────────────────┘

  Findings: 3 CRITICAL, 5 HIGH, 12 MEDIUM, 4 LOW

  [CRITICAL] aws_s3_bucket.data — Encryption not enabled
  [HIGH]     aws_security_group.web — Ingress open to 0.0.0.0/0
  [MEDIUM]   aws_instance.app — IMDSv2 not enforced
  ...
```

Resultado do setup

```
  terraview setup
  ═══════════════

  Security Scanners

  [✓] checkov      3.2.504
  [✗] tfsec        Install with: terraview scanners install tfsec
  [✗] terrascan    Install with: terraview scanners install terrascan

  AI Providers

  [✓] ollama           running (llama3.1:8b)
  [✓] gemini-cli       gemini CLI installed
  [✓] claude-code      claude CLI installed
  [✗] gemini           GEMINI_API_KEY not set
  [✗] claude           ANTHROPIC_API_KEY not set

  AI ready (2 providers available)

  Quick Start

  terraview scan checkov              # scanner + IA (padrão)
  terraview scan checkov --static     # apenas scanner

  Install missing: terraview scanners install --all
```

## Primeiros Passos

### Requisitos

- Terraform >= 0.12
- Um ou mais scanners instalados (Checkov, tfsec, Terrascan) — o terraview pode instalá-los por você

### Instalação rápida

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Configurar IA

```bash
terraview provider list                     # seletor interativo + teste de conectividade
```

### Primeiro scan

```bash
cd meu-projeto-terraform
terraview scan checkov                      # scanner + IA (padrão quando provider configurado)
terraview scan checkov --static             # apenas scanner, sem IA
terraview scan checkov --all                # tudo: explain + diagram + impact
```

## Instalação

### Script de instalação (Linux, macOS, Windows WSL)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

O script detecta automaticamente OS e arquitetura, baixa o binário correto do GitHub Releases e cria o alias `tv`.

### Homebrew (macOS / Linux)

```bash
brew install leonamvasquez/terraview/terraview
```

### Scoop (Windows)

```powershell
scoop bucket add terraview https://github.com/leonamvasquez/scoop-terraview.git
scoop install terraview
```

### APT — Debian / Ubuntu

```bash
# Adicionar repositório 
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.deb.sh' | sudo bash

# Instalar
sudo apt update
sudo apt install terraview
```

### DNF / YUM — Fedora / RHEL / Amazon Linux

```bash
# Adicionar repositório 
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.rpm.sh' | sudo bash

# Instalar
sudo dnf install terraview
```

### Docker

```bash
docker pull leonamvasquez/terraview:latest

# Uso
docker run --rm -v $(pwd):/workspace leonamvasquez/terraview scan checkov
```

### Windows — PowerShell (script direto)

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

### Download manual

```bash
# Substitua <VERSION>, <OS> e <ARCH> conforme seu sistema
# OS: linux, darwin, windows | ARCH: amd64, arm64
curl -Lo terraview.tar.gz https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-<OS>-<ARCH>.tar.gz
tar -xzf terraview.tar.gz
sudo mv terraview /usr/local/bin/terraview
```

### Compilar do código-fonte

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

Compila o binário, instala em `~/.local/bin/terraview`, cria o symlink `tv` e copia os prompts para `~/.terraview/prompts/`.

## Atualização

Se instalou via script ou download manual:

```bash
terraview upgrade
terraview upgrade --force                   # forçar reinstalação mesmo se atualizado
```

Via Homebrew:

```bash
brew upgrade leonamvasquez/terraview/terraview
```

Via Scoop:

```powershell
scoop update terraview
```

Via APT:

```bash
sudo apt update && sudo apt upgrade terraview
```

Via DNF:

```bash
sudo dnf upgrade terraview
```

## Autocompletar no shell

```bash
# Bash
terraview completion bash | sudo tee /etc/bash_completion.d/terraview > /dev/null
source /etc/bash_completion.d/terraview

# Zsh (adicione ao ~/.zshrc)
terraview completion zsh | sudo tee "${fpath[1]}/_terraview" > /dev/null

# Fish
terraview completion fish | source

# PowerShell (adicione ao seu $PROFILE)
terraview completion powershell | Out-File $PROFILE -Append
```

Após configurar, reabra o terminal e use `terraview <Tab>` para autocompletar comandos, flags e argumentos.

## Uso

```
$ terraview

Core Commands:
  scan        Security scan + AI contextual analysis (parallel)
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
              scanners list | install | default

Utilities:
  version     Show version information
  upgrade     Upgrade to the latest version
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

### Scan

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

#### Configurando diretório ou arquivo de entrada

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

### Apply

Roda scan + aplica o plano condicionalmente. Bloqueia se houver findings CRITICAL. Exibe o resumo do scan e pede confirmação no modo interativo.

```bash
terraview apply checkov                     # interativo
terraview apply checkov --non-interactive   # modo CI (bloqueia CRITICAL, auto-aprova caso contrário)
terraview apply checkov --static            # apenas scanner + apply
terraview apply checkov --all               # tudo habilitado + apply
```

### Diagram

Gera um diagrama ASCII determinístico da infraestrutura. Não requer IA.

```bash
terraview diagram                           # diagrama do diretório atual
terraview diagram --plan plan.json          # diagrama de plan existente
terraview diagram --output ./reports        # salvar diagram.txt no diretório
```

### Explain

Gera uma explicação em linguagem natural da sua infraestrutura Terraform usando IA. Requer um provider configurado.

```bash
terraview explain                           # explicar projeto atual
terraview explain --plan plan.json          # explicar de plan existente
terraview explain --provider gemini         # usar provider específico
terraview explain --format json             # saída JSON estruturada
```

### Drift

Detecta e classifica drift de infraestrutura rodando `terraform plan` e analisando mudanças.

```bash
terraview drift                             # detecção básica de drift
terraview drift --plan plan.json            # de plan existente
terraview drift --intelligence              # avançado: classifica intencional vs suspeito
terraview drift --format compact            # resumo em uma linha
terraview drift --format json               # saída JSON
```

Exit codes: `0` = sem drift ou apenas baixo risco, `1` = risco HIGH, `2` = risco CRITICAL.

### Gerenciamento de providers

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

### Gerenciamento de scanners

```bash
terraview scanners list                     # listar scanners com status de instalação
terraview scanners install checkov          # instalar scanner específico
terraview scanners install tfsec terrascan  # instalar múltiplos scanners
terraview scanners install --all            # instalar todos os scanners faltantes
terraview scanners install --all --force    # forçar reinstalação de todos
terraview scanners default checkov          # definir scanner padrão
terraview scanners default                  # exibir scanner padrão atual
```

### Outros comandos

```bash
terraview setup                             # diagnóstico do ambiente
terraview version                           # versão, Go runtime, OS/arch
terraview upgrade                           # auto-atualização via GitHub Releases
```

### Exit Codes

| Código | Significado |
|--------|-------------|
| `0`    | Sem issues ou apenas MEDIUM/LOW/INFO |
| `1`    | Findings de severidade HIGH |
| `2`    | Findings CRITICAL (bloqueia apply) |

## Saída e formatos

```bash
terraview scan checkov                      # saída pretty (padrão)
terraview scan checkov -f compact           # resumo em uma linha
terraview scan checkov -f json              # JSON (review.json)
terraview scan checkov -f sarif             # SARIF (review.sarif.json) para GitHub Security tab
terraview scan checkov -o ./reports         # gravar review.json + review.md em ./reports
```

Todos os scans geram `review.json` e `review.md`. A saída SARIF é gerada quando `-f sarif` é usado.

## Configuração via arquivo

O terraview pode ser configurado com um arquivo YAML. Por padrão, procura `.terraview.yaml` nos seguintes locais (em ordem de precedência):

1. Diretório do projeto (passado via `--dir`)
2. Diretório de trabalho atual
3. Home do usuário (`~/.terraview/.terraview.yaml`)

Exemplo de configuração:

```yaml
llm:
  enabled: true
  provider: ollama              # ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code
  model: llama3.1:8b            # modelo específico do provider
  url: http://localhost:11434   # URL customizada (relevante apenas para ollama)
  api_key: ""                   # para providers API (não necessário para ollama ou CLI providers)
  timeout_seconds: 120          # timeout para chamadas LLM
  temperature: 0.2              # 0.0 a 1.0 (menor = mais determinístico)
  ollama:
    max_threads: 0              # 0 = usar todos os CPUs
    max_memory_mb: 0            # 0 = sem limite
    min_free_memory_mb: 1024    # memória livre mínima para iniciar Ollama

scanner:
  default: checkov              # scanner padrão para "terraview scan"

scoring:
  severity_weights:
    critical: 5.0
    high: 3.0
    medium: 1.0
    low: 0.5

rules:
  required_tags:                # tags obrigatórias em todos os recursos
    - Environment
    - Owner
    - CostCenter
  disabled_rules:               # silenciar rule IDs específicos
    - CKV_AWS_79
  # enabled_rules: []           # se definido, apenas estas rules são avaliadas

output:
  format: pretty                # pretty, compact, json
```

### Variáveis de ambiente

| Variável             | Provider    | Descrição                     |
|----------------------|-------------|-------------------------------|
| `GEMINI_API_KEY`     | Gemini      | API key do Google Gemini      |
| `ANTHROPIC_API_KEY`  | Claude      | API key da Anthropic          |
| `OPENAI_API_KEY`     | OpenAI      | API key da OpenAI             |
| `DEEPSEEK_API_KEY`   | DeepSeek    | API key do DeepSeek           |
| `OPENROUTER_API_KEY` | OpenRouter  | API key do OpenRouter         |
| `NO_COLOR`           | (global)    | Desabilita saída colorida     |

O Ollama não requer API key. Os providers `gemini-cli` e `claude-code` autenticam via suas respectivas assinaturas CLI.

## Security Scanners

| Scanner | Descrição | Instalação |
|---------|-----------|------------|
| [Checkov](https://www.checkov.io/) | Scanner de segurança e compliance para IaC | `terraview scanners install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Análise estática de segurança para Terraform | `terraview scanners install tfsec` |
| [Terrascan](https://runterrascan.io/) | Detector de violations e compliance | `terraview scanners install terrascan` |

Os findings de todos os scanners são normalizados, deduplicados e exibidos em um scorecard unificado.

```bash
terraview scanners install --all            # instalar todos
terraview scanners install checkov          # instalar um específico
terraview scanners default checkov          # definir como padrão
terraview scanners list                     # ver status
```

## AI Providers

O terraview suporta **8 providers de IA** organizados em três categorias:

### Providers via API (requer API key)

| Provider | Variável de ambiente | Modelo padrão | Exemplos de modelos |
|----------|---------------------|---------------|---------------------|
| **gemini** | `GEMINI_API_KEY` | gemini-2.5-pro | gemini-2.5-pro, gemini-2.5-flash, gemini-2.0-flash |
| **claude** | `ANTHROPIC_API_KEY` | claude-sonnet-4-5 | claude-sonnet-4-5, claude-opus-4-5, claude-haiku-4-5 |
| **openai** | `OPENAI_API_KEY` | gpt-4o | gpt-4o, gpt-4o-mini, o3-mini |
| **deepseek** | `DEEPSEEK_API_KEY` | deepseek-v3.2 | deepseek-chat, deepseek-reasoner |
| **openrouter** | `OPENROUTER_API_KEY` | anthropic/claude-opus-4.6 | Qualquer modelo disponível no OpenRouter |

### Providers via CLI (subscription — sem API key)

| Provider | CLI necessário | Instalação | Modelo padrão |
|----------|---------------|------------|---------------|
| **gemini-cli** | `gemini` | `npm install -g @google/gemini-cli` | gemini-2.5-pro |
| **claude-code** | `claude` | `npm install -g @anthropic-ai/claude-code` | claude-sonnet-4-5 |

Estes providers usam sua **assinatura pessoal** (Google/Anthropic) para billing. Não é necessário API key — basta ter o CLI instalado e autenticado.

### Provider local (sem internet)

| Provider | Requisito | Modelo padrão |
|----------|-----------|---------------|
| **ollama** | Ollama rodando localmente | llama3.1:8b |

```bash
terraview provider install ollama           # instalar Ollama + pull do modelo padrão
terraview provider install ollama --model codellama:13b  # modelo personalizado
```

## Integração com IAs por Assinatura

O terraview oferece integração nativa com **IAs por assinatura** — providers que utilizam o CLI oficial do Google (Gemini CLI) ou da Anthropic (Claude Code) para análise, cobrando na assinatura pessoal do desenvolvedor em vez de exigir API keys ou créditos pré-pagos.

### Como funciona

Em vez de fazer requisições HTTP diretas para APIs, o terraview invoca os binários CLI instalados localmente (`gemini` ou `claude`) como subprocessos. Isso significa que:

1. **Sem API key** — autenticação é feita pela sessão do CLI já logada na sua conta Google ou Anthropic
2. **Billing pela assinatura** — o custo é absorvido pelo plano que você já paga (Google One AI Premium, Anthropic Max, etc.)
3. **Sem configuração extra** — se o CLI funciona no seu terminal, funciona no terraview
4. **Mesmos modelos da API** — acesso a modelos como `gemini-3`, `gemini-2.5-pro`, `claude-sonnet-4-5`, `claude-opus-4-6`

### Configuração

```bash
# Gemini CLI (requer Google One AI Premium ou Google AI Studio login)
npm install -g @google/gemini-cli
gemini                                      # autenticar na primeira execução
terraview provider use gemini-cli           # definir como provider padrão

# Claude Code (requer Anthropic Max, Pro ou Team)
npm install -g @anthropic-ai/claude-code
claude                                      # autenticar na primeira execução
terraview provider use claude-code          # definir como provider padrão
```

### Uso

```bash
# Scan com Gemini CLI
terraview scan checkov --provider gemini-cli
terraview scan checkov --provider gemini-cli --model gemini-3

# Scan com Claude Code
terraview scan checkov --provider claude-code
terraview scan checkov --provider claude-code --model claude-opus-4-6

# Explicação de infraestrutura com provider CLI
terraview explain --provider claude-code

# Drift analysis com IA por assinatura
terraview drift --intelligence --provider gemini-cli
```

### API vs CLI (subscription) — quando usar cada um

| Aspecto | API (key) | CLI (subscription) |
|---------|-----------|-------------------|
| **Configuração** | Criar conta + gerar API key | Instalar CLI + fazer login |
| **Billing** | Pay-per-token (créditos) | Plano mensal fixo |
| **Ideal para** | CI/CD, pipelines automatizadas | Desenvolvimento local, uso pessoal |
| **Rate limits** | Limites da API (varia por tier) | Limites da assinatura |
| **Offline** | Não | Não (mas Ollama sim) |
| **Providers** | gemini, claude, openai, deepseek, openrouter | gemini-cli, claude-code |

> **Dica:** Para uso local no dia a dia, providers por assinatura são a escolha mais prática — zero configuração de keys, billing simples. Para CI/CD, prefira providers via API (ou Ollama para ambientes air-gapped).

## Integração CI/CD

### GitHub Actions

```yaml
name: Terraform Security Scan
on:
  pull_request:
    paths: ['**.tf']

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Security scan
        run: terraview scan checkov -f sarif -o ./reports

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/review.sarif.json

      - name: Comment on PR
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: reports/review.md
```

### GitLab CI

```yaml
terraform-scan:
  stage: validate
  script:
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview scan checkov -f json -o ./reports
  artifacts:
    paths: [reports/review.json, reports/review.md]
    when: always
```

## Docker

```bash
docker pull ghcr.io/leonamvasquez/terraview:latest
docker run --rm -v $(pwd):/workspace -w /workspace ghcr.io/leonamvasquez/terraview scan checkov
```

Para saída SARIF com arquivo salvo no diretório montado:

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ghcr.io/leonamvasquez/terraview scan checkov -f sarif -o /workspace/reports
```

## Arquitetura

```
┌─────────────────────────────────────────────────────────────────────────┐
│                             terraview CLI                               │
│  scan | apply | diagram | explain | drift | provider | scanners | ...  │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                        ┌────────┴────────┐
                        ▼                 ▼
               Terraform Executor    Plan JSON (--plan)
                   init + plan           │
                   show -json            │
                        │                │
                        └───────┬────────┘
                                ▼
                   ┌─────────────────────────┐
                   │   Parser + Normalizer    │
                   │   NormalizedResource[]   │
                   └────────────┬────────────┘
                                │
                   ┌────────────┴────────────┐
                   ▼                         ▼
          Topology Graph            Feature Extractor
          (30+ ref fields)        (5 risk axes per resource)
                   │                         │
          ┌────────┴────────┐    ┌───────────┴──────────┐
          ▼                 ▼    ▼                       ▼
  ┌──────────────┐  ┌──────────────────┐  ┌──────────────────┐
  │   Scanner    │  │  AI Context      │  │  Compress +      │
  │  Checkov     │  │  Analysis        │  │  Cache           │
  │  tfsec       │  │  (cross-resource │  │  (risk vectors   │
  │  Terrascan   │  │   relationships) │  │   → LLM)         │
  └──────┬───────┘  └────────┬─────────┘  └──────────────────┘
         │                   │
         └──────────┬────────┘
                    ▼
         ┌─────────────────────┐
         │  Normalizer         │ deduplicar scanner + AI
         │  Resolver           │ resolver conflitos com confiança
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │  Scorer             │ scores 0-10 (segurança, compliance, manutenib.)
         │  Aggregator         │ veredito + exit code
         │  Meta-analysis      │ correlação cross-tool
         └──────────┬──────────┘
                    ▼
         ┌─────────────────────┐
         │  Output             │
         │  pretty | compact   │
         │  json | sarif | md  │
         └─────────────────────┘
```

## Desenvolvimento

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make build        # build para plataforma atual
make test         # testes com race detection + coverage
make test-short   # testes rápidos (sem race detector)
make coverage     # relatório de cobertura HTML
make lint         # golangci-lint (ou go vet como fallback)
make clean        # remover artefatos de build
make dist         # build para todas as plataformas (linux/darwin/windows, amd64/arm64)
make docker-build # build da imagem Docker
make docker-run   # rodar no Docker com plan de exemplo
make install      # instalar localmente em ~/.local/bin + assets em ~/.terraview
make uninstall    # remover instalação local
make release      # criar draft de release no GitHub (requer gh CLI)
```

## Contribuir

Contribuição é bem-vinda! Veja [CONTRIBUTING.md](CONTRIBUTING.md) para instruções completas.

Resumo:

- Branch a partir de `main` com prefixo `feat/`, `fix/`, `docs/`, `refactor/`, etc.
- Commits em formato [Conventional Commits](https://www.conventionalcommits.org/): `feat(scanner): add trivy support`
- Testes obrigatórios: `make test` deve passar. Novos módulos devem incluir `_test.go`
- Lint: `make lint` sem erros
- PRs devem descrever o problema e a solução

Para reportar vulnerabilidades de segurança, consulte o [SECURITY.md](SECURITY.md).

## Aviso

- O terraview **não salva, publica ou compartilha** nenhuma informação identificável do usuário.
- Quando a IA está ativa (comportamento padrão quando um provider está configurado), o conteúdo do plan Terraform é enviado ao provider selecionado (Ollama roda localmente; APIs cloud como Gemini/Claude enviam dados externamente). Revise a política de privacidade do provider antes de usar com dados sensíveis.
- Para uso 100% local e offline, utilize o Ollama como provider de IA.

## Suporte

O terraview é mantido como projeto open source sob licença MIT.

- Documentação: este README e [CONTRIBUTING.md](CONTRIBUTING.md)
- Problemas: [GitHub Issues](https://github.com/leonamvasquez/terraview/issues)
- Discussões: [GitHub Discussions](https://github.com/leonamvasquez/terraview/discussions)
- Segurança: [SECURITY.md](SECURITY.md)

### Versão de Go suportada

Seguimos o ciclo oficial de suporte do Go com testes automatizados. Atualmente suportamos **Go 1.26+**. Se encontrar problemas com qualquer versão não-EOL, abra uma [Issue](https://github.com/leonamvasquez/terraview/issues).

## Licença

Distribuído sob a licença [MIT](LICENSE).
