![terraview](terraview.png)

**Escolha seu idioma:** [Português](README.md) | [English](README.en.md)

# terraview

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![GitHub release](https://img.shields.io/github/v/release/leonamvasquez/terraview)](https://github.com/leonamvasquez/terraview/releases/latest)

Análise de segurança de planos Terraform combinando scanners estáticos (Checkov, tfsec, Terrascan) com revisão inteligente por IA. Scanners rodam por padrão. IA é opt-in. Binário único sem dependências.

## Sumário

- [Features](#features)
- [Exemplo de Saída](#exemplo-de-saída)
- [Quick Start](#quick-start)
- [Instalação](#instalação)
- [Uso](#uso)
- [Configuração](#configuração)
- [Integração CI/CD](#integração-cicd)
- [Arquitetura](#arquitetura)
- [Desenvolvimento](#desenvolvimento)
- [Licença](#licença)

## Features

- **Security Scanners** — integração automática com Checkov, tfsec e Terrascan; detecta o que está instalado e roda automaticamente
- **IA Multi-Provider** — Ollama (local), Gemini, Claude, DeepSeek e OpenRouter com seleção interativa
- **Resolução de Conflitos** — quando scanner e IA divergem, scanner prevalece; concordâncias elevam confiança a 100%
- **Scorecard** — scores de Segurança, Compliance, Manutenibilidade e Overall em escala 0-10
- **Risk Clusters** — agrupamento de findings por recurso com score de risco ponderado
- **Diagrama ASCII** — visualização da infraestrutura direto no terminal
- **Análise de Impacto** — raio de dependências das mudanças via `--impact`
- **Zero Configuração** — detecta projetos Terraform e roda `init + plan + show` automaticamente
- **Drift Detection** — detecta e classifica drift de infraestrutura
- **CI/CD Nativo** — exit codes semânticos + saída SARIF/JSON para GitHub Actions e GitLab CI
- **Auto-Atualização** — `terraview upgrade` busca a versão mais recente do GitHub
- **Alias `tv`** — symlink criado na instalação; `tv scan` = `terraview scan`

## Exemplo de Saída

```
  terraview setup
  ═══════════════

  Security Scanners

  [✓] checkov      3.2.504
  [✗] tfsec        Install with: brew install tfsec
  [✗] terrascan    Install with: brew install terrascan
```

## Quick Start

### 1. Instalar

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### 2. Escanear

```bash
cd meu-projeto-terraform
terraview scan checkov
```

### 3. Revisar

Os resultados são exibidos em um scorecard com findings agrupados e scores. Adicione `--ai` para revisão inteligente ou `--all` para habilitar tudo: `--explain --diagram --impact`.

```bash
terraview scan checkov --ai                 # scanner + IA
terraview scan checkov --all                # tudo habilitado
```

## Instalação

### Script de instalação (Linux, macOS, Windows WSL)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

O script detecta automaticamente OS e arquitetura, baixa o binário correto e cria o alias `tv`.

<details>
<summary>Windows — PowerShell</summary>

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

</details>

<details>
<summary>Download manual</summary>

```bash
# Substitua <VERSION>, <OS> e <ARCH> conforme seu sistema
# OS: linux, darwin, windows | ARCH: amd64, arm64
curl -Lo terraview.tar.gz https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-<OS>-<ARCH>.tar.gz
tar -xzf terraview.tar.gz
sudo mv terraview-<OS>-<ARCH> /usr/local/bin/terraview
```

</details>

### Compilar do código-fonte

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Instalar runtime de IA local (Ollama)

```bash
terraview provider install llm
```

## Uso

```
$ terraview

Usage:
  terraview [command]

Available Commands:
  scan        Security scan + optional AI analysis
  apply       Scan and conditionally apply the plan
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation
  drift       Detect and classify infrastructure drift
  provider    Manage AI providers & LLM runtimes
  scanners    Manage security scanners
  setup       Interactive environment setup
  version     Show version information
  upgrade     Upgrade to the latest version

Flags:
  -d, --dir string        Terraform workspace directory (default ".")
  -p, --plan string       Path to terraform plan JSON (auto-generates if omitted)
  -f, --format string     Output format: pretty, compact, json, sarif
  -o, --output string     Output directory for generated files
      --provider string   AI provider (ollama, gemini, claude, deepseek, openrouter)
      --model string      AI model to use
      --br                Output in Brazilian Portuguese (pt-BR)
      --no-color          Disable colored output
  -v, --verbose           Enable verbose output
```

### Scan

```bash
terraview scan checkov                      # scan com Checkov
terraview scan tfsec                        # scan com tfsec
terraview scan                              # usa scanner padrão (ou auto-seleciona)
terraview scan checkov --ai                 # scanner + IA
terraview scan --ai                         # apenas IA (sem scanner)
terraview scan checkov --all                # explain + diagram + impact
terraview scan checkov --plan plan.json     # usar plan.json existente
terraview scan checkov -f sarif             # saída SARIF para CI
terraview scan checkov --strict             # HIGH retorna exit code 2
```

### Apply

Roda scan + aplica o plano condicionalmente. Bloqueia se houver findings CRITICAL.

```bash
terraview apply checkov                     # interativo
terraview apply checkov --non-interactive   # modo CI
terraview apply checkov --ai                # com IA
```

### Outros comandos

```bash
terraview diagram                           # diagrama ASCII da infraestrutura
terraview explain                           # explicação IA da infraestrutura
terraview drift                             # detectar drift
terraview provider list                     # seletor interativo de provider/modelo
terraview scanners install checkov          # instalar checkov
terraview scanners install --all            # instalar todos os scanners
terraview scanners default checkov          # definir scanner padrão
terraview scanners list                     # listar scanners com status
terraview setup                             # diagnóstico do ambiente
terraview upgrade                           # auto-atualização
```

### Exit Codes

| Código | Significado |
|--------|-------------|
| 0 | Sem issues ou apenas MEDIUM/LOW/INFO |
| 1 | Findings de severidade HIGH |
| 2 | Findings CRITICAL (bloqueia apply) |

## Configuração

Arquivo local no projeto (override) ou global em `~/.terraview/.terraview.yaml`:

```yaml
llm:
  enabled: true
  provider: ollama              # ollama, gemini, claude, deepseek, openrouter
  model: llama3.1:8b
  url: http://localhost:11434
  api_key: ""                   # para providers cloud
  timeout_seconds: 120
  temperature: 0.2

scanner:
  default: checkov              # checkov, tfsec, terrascan

scoring:
  severity_weights:
    critical: 5
    high: 3
    medium: 1
    low: 0.5

output:
  format: pretty                # pretty, compact, json, sarif
```

## Security Scanners

| Scanner | Descrição | Instalação |
|---------|-----------|------------|
| [Checkov](https://www.checkov.io/) | Scanner de segurança e compliance para IaC | `terraview scanners install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Análise estática de segurança para Terraform | `terraview scanners install tfsec` |
| [Terrascan](https://runterrascan.io/) | Detector de violations e compliance | `terraview scanners install terrascan` |

Os findings de todos os scanners são normalizados, agregados e exibidos em um scorecard unificado.

```bash
terraview scanners install --all            # instalar todos
terraview scanners install checkov          # instalar um específico
terraview scanners default checkov          # definir como padrão
terraview scanners list                     # ver status
```

### Resolução de Conflitos (Scanner × IA)

| Cenário | Ação | Confiança |
|---------|------|-----------|
| Scanner e IA concordam (±1 nível) | **Confirmado** — boost de confiança | 1.00 |
| Scanner e IA divergem | **Scanner prevalece** | 0.80 |
| Apenas scanner detectou | **Scanner-only** | 0.80 |
| Apenas IA detectou | **AI-only** | 0.50 |

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

      - name: Install Checkov
        run: pip install checkov

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Security scan
        run: terraview scan checkov -f sarif -o ./reports

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
    - pip install checkov
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview scan checkov -f json -o ./reports
  artifacts:
    paths: [reports/review.json, reports/review.md]
    when: always
```

## Arquitetura

```
┌───────────────────────────────────────────────────────────────────────┐
│                            terraview CLI                              │
│  scan │ apply │ diagram │ explain │ drift │ provider │ ...            │
└──────────────────────────────┬────────────────────────────────────────┘
                               │
                  ┌────────────┴─────────────┐
                  ▼                          ▼
        ┌──────────────────────┐   ┌──────────────────────┐
        │  Security Scanners   │   │    AI Providers       │
        │  Checkov │ tfsec     │   │  Ollama │ Gemini      │
        │  Terrascan           │   │  Claude │ DeepSeek    │
        └──────────┬───────────┘   │  OpenRouter           │
                   │               └──────────┬────────────┘
                   ▼                          ▼
        ┌──────────────────────────────────────────────┐
        │       Conflict Resolver (scanner × AI)        │
        │  confirmed │ scanner-priority │ ai-only        │
        └──────────────────────┬───────────────────────┘
                               ▼
        ┌──────────────────────────────────────────────┐
        │          Aggregator + Scorer + Meta           │
        │           review.json / .md / .sarif          │
        └──────────────────────────────────────────────┘
```

## Desenvolvimento

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make build        # compilar para a plataforma atual
make test         # executar testes com race detection
make coverage     # relatório de cobertura
make dist         # build para todas as plataformas
make install      # instalar localmente (~/.local/bin)
```

Contribuições são bem-vindas! Abra uma [issue](https://github.com/leonamvasquez/terraview/issues) ou envie um pull request.

## Licença

Distribuído sob a licença [MIT](LICENSE).
