<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/terraview-logo-dark-theme.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/terraview-logo-white-theme.png">
  <img alt="terraview" src=".github/assets/terraview-logo-white-theme.png">
</picture>

**Choose your language:** [Português](README.md) | [English](README.en.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://golang.org)
[![GitHub release](https://img.shields.io/github/v/release/leonamvasquez/terraview)](https://github.com/leonamvasquez/terraview/releases/latest)
[![CI](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml/badge.svg)](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/leonamvasquez/terraview)](https://goreportcard.com/report/github.com/leonamvasquez/terraview)
[![codecov](https://codecov.io/gh/leonamvasquez/terraview/branch/main/graph/badge.svg)](https://codecov.io/gh/leonamvasquez/terraview)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/leonamvasquez/terraview/badge)](https://scorecard.dev/viewer/?uri=github.com/leonamvasquez/terraview)

Terraview is a security analysis tool for Terraform plans that combines static scanners (Checkov, tfsec, Terrascan) with AI contextual analysis running **in parallel**.

It scans cloud infrastructure provisioned with Terraform, detects security and compliance misconfigurations using open-source static analysis scanners, and automatically enriches the results with multi-provider AI contextual analysis (Ollama, Gemini, Claude, OpenAI, DeepSeek, OpenRouter, Gemini CLI, Claude Code) when a provider is configured.

Terraview runs as a single binary with no external dependencies. When an AI provider is configured, scanner and AI run in parallel automatically. Use `--static` to run scanner only, without AI.

## Table of Contents

- [Features](#features)
- [Examples](#examples)
- [Getting Started](#getting-started)
- [Installation](#installation)
- [Upgrade](#upgrade)
- [Shell Completions](#shell-completions)
- [Usage](#usage)
- [Scan](#scan)
- [Apply](#apply)
- [Diagram](#diagram)
- [Explain](#explain)
- [Drift](#drift)
- [Provider Management](#provider-management)
- [Scanner Management](#scanner-management)
- [AI Cache](#ai-cache)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Security Scanners](#security-scanners)
- [AI Providers](#ai-providers)
- [Subscription-Based AI Integration](#subscription-based-ai-integration)
- [CI/CD Integration](#cicd-integration)
- [Docker](#docker)
- [Architecture](#architecture)
- [Development](#development)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [Support](#support)
- [License](#license)

## Features

- **Security Scanners** — automatic integration with Checkov, tfsec and Terrascan; detects what's installed and runs automatically
- **AI contextual analysis (default)** — when an AI provider is configured, AI runs **in parallel** with the scanner, analyzing cross-resource relationships, dependency chains and architectural anti-patterns that scanners cannot detect.
- **Multi-Provider AI** — two categories:
  - **API**: Ollama (local), Google Gemini, Anthropic Claude, OpenAI, DeepSeek and OpenRouter
  - **CLI (subscription)**: Gemini CLI and Claude Code — use your personal subscription, no API key required
- **Automatic integration test** — when selecting a provider via `provider list`, terraview tests connectivity and returns type-specific feedback (CLI installed, API key valid, service reachable)
- **Conflict Resolution** — scanner × AI: scanner wins on disagreement (confidence 0.80); agreement boosts confidence to 1.00
- **Unified Scorecard** with Security, Compliance, Maintainability and Overall scores (0–10)
- **Risk vectors** — per-resource risk extraction across 5 axes: network exposure, encryption, identity, governance, observability
- **ASCII Diagram** — infrastructure visualization right in the terminal via `--diagram`
- **Impact Analysis** — dependency blast radius of changes via `--impact`
- **AI Explanation** — natural language explanation of your infrastructure via `explain`
- **Zero Configuration** — detects Terraform projects and runs `init + plan + show` automatically
- **Drift Detection** — detects and classifies infrastructure drift with optional `--intelligence` for advanced risk scoring
- **Native CI/CD** — semantic exit codes (0/1/2) + SARIF, JSON, Markdown output for GitHub Actions, GitLab CI and Azure DevOps
- **Supply chain hardening** — SBOM (CycloneDX), cosign signatures, SLSA Build Provenance Level 3 on every release
- **Bilingual (en/pt-BR)** — `--br` flag available on all commands
- **Update** via your package manager (`brew upgrade terraview`, `scoop update terraview`, `apt upgrade terraview`, etc.)
- **`tv` alias** — symlink created on install; `tv scan` = `terraview scan`
- **Persistent AI cache** on disk — reruns with the same plan skip redundant API calls (`cache status | clear`)
- **Cross-platform scanner install** via `terraview scanners install --all` (Linux, macOS, Windows)

## Examples

Scan output in the CLI

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

Setup output

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

  terraview scan checkov              # scanner + AI (default)
  terraview scan checkov --static     # scanner only

  Install missing: terraview scanners install --all
```

## Getting Started

### Requirements

- Terraform >= 0.12
- One or more scanners installed (Checkov, tfsec, Terrascan) — terraview can install them for you

### Quick install

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Configure AI

```bash
terraview provider list                     # interactive picker + connectivity test
```

### First scan

```bash
cd my-terraform-project
terraview scan checkov                      # scanner + AI (default when provider configured)
terraview scan checkov --static             # scanner only, no AI
terraview scan checkov --all                # everything: explain + diagram + impact
```

## Installation

### Install script (Linux, macOS, Windows WSL)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

The script automatically detects your OS and architecture, downloads the correct binary from GitHub Releases and creates the `tv` alias.

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
# Add repository
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.deb.sh' | sudo bash

# Install
sudo apt update
sudo apt install terraview
```

### DNF / YUM — Fedora / RHEL / Amazon Linux

```bash
# Add repository
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.rpm.sh' | sudo bash

# Install
sudo dnf install terraview
```

### Docker

```bash
docker pull leonamvasquez/terraview:latest

# Usage
docker run --rm -v $(pwd):/workspace leonamvasquez/terraview scan checkov
```

### Windows — PowerShell (direct script)

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

### Manual download

```bash
# Replace <VERSION>, <OS> and <ARCH> for your system
# OS: linux, darwin, windows | ARCH: amd64, arm64
curl -Lo terraview.tar.gz https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-<OS>-<ARCH>.tar.gz
tar -xzf terraview.tar.gz
sudo mv terraview /usr/local/bin/terraview
```

### Build from source

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

Compiles the binary, installs it to `~/.local/bin/terraview`, creates the `tv` symlink and copies prompts to `~/.terraview/prompts/`.

## Upgrade

Update Terraview using your package manager:

```bash
# Homebrew
brew upgrade leonamvasquez/terraview/terraview

# Scoop
scoop update terraview

# APT
sudo apt update && sudo apt upgrade terraview

# DNF
sudo dnf upgrade terraview
```

## Shell Completions

```bash
# Bash
terraview completion bash | sudo tee /etc/bash_completion.d/terraview > /dev/null
source /etc/bash_completion.d/terraview

# Zsh (add to ~/.zshrc)
terraview completion zsh | sudo tee "${fpath[1]}/_terraview" > /dev/null

# Fish
terraview completion fish | source

# PowerShell (add to your $PROFILE)
terraview completion powershell | Out-File $PROFILE -Append
```

After configuring, reopen the terminal and use `terraview <Tab>` to autocomplete commands, flags and arguments.

## Usage

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

### Scan

By default, terraview runs **both** the security scanner and AI contextual analysis **in parallel**. AI activates automatically when a provider is configured (via `.terraview.yaml`, `--provider` flag, or `terraview provider use`). If no provider is configured, only the scanner runs.

```bash
terraview scan                              # auto-select default scanner
terraview scan checkov                      # scan with Checkov (+ AI if provider configured)
terraview scan tfsec                        # scan with tfsec
terraview scan terrascan                    # scan with Terrascan
terraview scan checkov --static             # scanner only, disable AI
terraview scan checkov --all                # enable explain + diagram + impact
terraview scan checkov --explain            # scanner + AI + natural language explanation
terraview scan checkov --diagram            # scanner + AI + ASCII infrastructure diagram
terraview scan checkov --impact             # scanner + AI + blast radius analysis
terraview scan checkov --plan plan.json     # use existing plan JSON
terraview scan checkov -f sarif             # SARIF output for CI
terraview scan checkov --strict             # HIGH findings also return exit code 2
terraview scan checkov --findings ext.json  # import external Checkov/tfsec/Trivy findings
```

#### Setting directory or input file

Scan the current directory (auto-detects Terraform):

```bash
terraview scan checkov
```

Or a specific directory:

```bash
terraview scan checkov -d /path/to/my-project
```

Or generate the plan manually:

```bash
terraform init
terraform plan -out tf.plan
terraform show -json tf.plan > tf.json
terraview scan checkov --plan tf.json
```

Use CLI providers (subscription — no API key):

```bash
terraview scan checkov --provider gemini-cli --model gemini-3
terraview scan checkov --provider claude-code --model claude-sonnet-4-5
```

### Apply

Runs scan + conditionally applies the plan. Blocks if any CRITICAL findings are detected. Shows the scan summary and asks for confirmation in interactive mode.

```bash
terraview apply checkov                     # interactive
terraview apply checkov --non-interactive   # CI mode (blocks on CRITICAL, auto-approves otherwise)
terraview apply checkov --static            # scanner only + apply
terraview apply checkov --all               # everything enabled + apply
```

### Diagram

Generates a deterministic ASCII infrastructure diagram. Does not require AI.

```bash
terraview diagram                           # diagram from current directory
terraview diagram --plan plan.json          # diagram from existing plan
terraview diagram --output ./reports        # write diagram.txt to directory
```

### Explain

Generates a natural-language explanation of your Terraform infrastructure using AI. Requires a configured provider.

```bash
terraview explain                           # explain current project
terraview explain --plan plan.json          # explain from existing plan
terraview explain --provider gemini         # use a specific provider
terraview explain --format json             # structured JSON output
```

### Drift

Detects and classifies infrastructure drift by running `terraform plan` and analyzing changes.

```bash
terraview drift                             # basic drift detection
terraview drift --plan plan.json            # from existing plan
terraview drift --intelligence              # advanced: classify intentional vs suspicious
terraview drift --format compact            # one-line summary
terraview drift --format json               # JSON output
```

Exit codes: `0` = no drift or low-risk only, `1` = HIGH risk, `2` = CRITICAL risk.

### Provider Management

```bash
terraview provider list                     # interactive picker (provider + model + connectivity test)
terraview provider use gemini gemini-2.5-pro  # set provider via CLI (non-interactive)
terraview provider use ollama llama3.1:8b   # set local provider
terraview provider current                  # show current configuration
terraview provider test                     # test configured provider connectivity
terraview provider install ollama           # install Ollama runtime + pull model
terraview provider install ollama --model codellama:13b  # install with specific model
```

The `provider list` command runs an **automatic integration test**. If the test fails, a diagnostic message is shown:

- **CLI not installed** → shows install command (`npm install -g ...`)
- **API key missing** → shows environment variable to set
- **API key invalid / network error** → suggests checking credentials and connectivity
- **Local service unreachable** → suggests checking if the service is running

```
  [terraview] Testing connectivity with gemini-cli (gemini-3)... ✓

  ✓  Integration test passed — "gemini" CLI is installed and ready.
  ✓  Default provider: gemini-cli  model: gemini-3
     Saved to: ~/.terraview/.terraview.yaml
```

### Scanner Management

```bash
terraview scanners list                     # list scanners with installation status
terraview scanners install checkov          # install a specific scanner
terraview scanners install tfsec terrascan  # install multiple scanners
terraview scanners install --all            # install all missing scanners
terraview scanners install --all --force    # force reinstall all
terraview scanners default checkov          # set default scanner
terraview scanners default                  # show current default
```

### AI Cache

Terraview features a persistent AI response cache on disk (`~/.terraview/cache/`). When enabled, reruns with the same plan reuse the previous response without additional API calls.

```bash
terraview cache status                      # show cache statistics (entries, size, dates)
terraview cache clear                       # clear all cached AI responses
```

Enable in `.terraview.yaml`:

```yaml
llm:
  cache: true            # enable persistent cache
  cache_ttl_hours: 24    # TTL in hours (default: 24)
```

### Other commands

```bash
terraview setup                             # environment diagnostic
terraview version                           # version, Go runtime, OS/arch
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | No issues or MEDIUM/LOW/INFO only |
| `1`  | HIGH severity findings |
| `2`  | CRITICAL findings (blocks apply) |

## Output Formats

```bash
terraview scan checkov                      # pretty output (default)
terraview scan checkov -f compact           # one-line summary
terraview scan checkov -f json              # JSON (review.json)
terraview scan checkov -f sarif             # SARIF (review.sarif.json) for GitHub Security tab
terraview scan checkov -o ./reports         # write review.json + review.md to ./reports
```

All scan runs generate `review.json` and `review.md`. SARIF output is generated when `-f sarif` is used.

## Configuration

Terraview can be configured with a YAML file. By default, it looks for `.terraview.yaml` in the following locations (in order of precedence):

1. Project directory (passed via `--dir`)
2. Current working directory
3. User home (`~/.terraview/.terraview.yaml`)

Configuration example (see [`examples/.terraview.yaml`](examples/.terraview.yaml) for full reference with all documented fields):

> **WARNING:** Never commit `api_key` directly in `.terraview.yaml`. Prefer environment variables (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.) or add `.terraview.yaml` to your `.gitignore`. Terraview emits a warning to stderr when it detects `api_key` in the config file.

```yaml
llm:
  enabled: true
  provider: ollama              # ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code
  model: llama3.1:8b            # provider-specific model
  url: http://localhost:11434   # custom URL (only relevant for ollama)
  # api_key: ""                 # prefer environment variables (see warning above)
  timeout_seconds: 120          # timeout for LLM calls
  temperature: 0.2              # 0.0 to 1.0 (lower = more deterministic)
  max_resources: 30             # max resources in AI prompt (default: 30)
  cache: false                  # enable persistent AI response cache
  cache_ttl_hours: 24           # cache TTL in hours (default: 24)
  ollama:
    num_ctx: 4096               # model context window (default: 4096)
    max_threads: 0              # 0 = use all CPUs
    max_memory_mb: 0            # 0 = no limit
    min_free_memory_mb: 1024    # minimum free memory to start Ollama

scanner:
  default: checkov              # default scanner for "terraview scan"

scoring:
  severity_weights:
    critical: 5.0
    high: 3.0
    medium: 1.0
    low: 0.5

rules:
  required_tags:                # mandatory tags on all resources
    - Environment
    - Owner
    - CostCenter
  disabled_rules:               # silence specific rule IDs
    - CKV_AWS_79
  # enabled_rules: []           # if set, only these rules are evaluated

output:
  format: pretty                # pretty, compact, json
```

### Environment variables

| Variable             | Provider    | Description                 |
|----------------------|-------------|-----------------------------|
| `GEMINI_API_KEY`     | Gemini      | Google Gemini API key       |
| `ANTHROPIC_API_KEY`  | Claude      | Anthropic API key           |
| `OPENAI_API_KEY`     | OpenAI      | OpenAI API key              |
| `DEEPSEEK_API_KEY`   | DeepSeek    | DeepSeek API key            |
| `OPENROUTER_API_KEY` | OpenRouter  | OpenRouter API key          |
| `NO_COLOR`           | (global)    | Disables colored output     |

Ollama requires no API key. The `gemini-cli` and `claude-code` providers authenticate via their respective CLI subscriptions.

## Security Scanners

| Scanner | Description | Install |
|---------|-------------|---------|
| [Checkov](https://www.checkov.io/) | Security and compliance scanner for IaC | `terraview scanners install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Static security analysis for Terraform | `terraview scanners install tfsec` |
| [Terrascan](https://runterrascan.io/) | Compliance violation detector | `terraview scanners install terrascan` |

Findings from all scanners are normalized, deduplicated, and presented in a unified scorecard.

```bash
terraview scanners install --all            # install all
terraview scanners install checkov          # install specific
terraview scanners default checkov          # set as default
terraview scanners list                     # check status
```

## AI Providers

Terraview supports **8 AI providers** organized in three categories:

### API providers (requires API key)

| Provider | Environment variable | Default model | Example models |
|----------|---------------------|---------------|----------------|
| **gemini** | `GEMINI_API_KEY` | gemini-2.5-flash | gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash |
| **claude** | `ANTHROPIC_API_KEY` | claude-haiku-4-5 | claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-6 |
| **openai** | `OPENAI_API_KEY` | gpt-4o-mini | gpt-4o-mini, gpt-4o, o3-mini |
| **deepseek** | `DEEPSEEK_API_KEY` | deepseek-v3.2 | deepseek-chat, deepseek-reasoner |
| **openrouter** | `OPENROUTER_API_KEY` | google/gemini-2.5-flash | Any model available on OpenRouter |

### CLI providers (subscription — no API key)

| Provider | Required CLI | Installation | Default model |
|----------|-------------|-------------|---------------|
| **gemini-cli** | `gemini` | `npm install -g @google/gemini-cli` | gemini-2.5-flash |
| **claude-code** | `claude` | `npm install -g @anthropic-ai/claude-code` | claude-haiku-4-5 |

These providers use your **personal subscription** (Google/Anthropic) for billing. No API key needed — just install the CLI and authenticate once.

### Local provider (offline)

| Provider | Requirement | Default model |
|----------|-------------|---------------|
| **ollama** | Ollama running locally | llama3.1:8b |

```bash
terraview provider install ollama           # install Ollama + pull default model
terraview provider install ollama --model codellama:13b  # custom model
```

## Subscription-Based AI Integration

Terraview stands out from similar tools by offering native integration with **subscription-based AIs** — providers that use Google's (Gemini CLI) or Anthropic's (Claude Code) official CLI for analysis, billing through the developer's personal subscription instead of requiring API keys or prepaid credits.

### How it works

Instead of making direct HTTP requests to APIs, terraview invokes locally installed CLI binaries (`gemini` or `claude`) as subprocesses. This means:

1. **No API key** — authentication is handled by the CLI session already logged into your Google or Anthropic account
2. **Subscription billing** — cost is absorbed by the plan you already pay for (Google One AI Premium, Anthropic Max, etc.)
3. **No extra configuration** — if the CLI works in your terminal, it works in terraview
4. **Same models as the API** — access models like `gemini-3`, `gemini-2.5-pro`, `claude-sonnet-4-5`, `claude-opus-4-6`

### Setup

```bash
# Gemini CLI (requires Google One AI Premium or Google AI Studio login)
npm install -g @google/gemini-cli
gemini                                      # authenticate on first run
terraview provider use gemini-cli           # set as default provider

# Claude Code (requires Anthropic Max, Pro or Team)
npm install -g @anthropic-ai/claude-code
claude                                      # authenticate on first run
terraview provider use claude-code          # set as default provider
```

### Usage

```bash
# Scan with Gemini CLI
terraview scan checkov --provider gemini-cli
terraview scan checkov --provider gemini-cli --model gemini-3

# Scan with Claude Code
terraview scan checkov --provider claude-code
terraview scan checkov --provider claude-code --model claude-opus-4-6

# Infrastructure explanation with CLI provider
terraview explain --provider claude-code

# Drift analysis with subscription AI
terraview drift --intelligence --provider gemini-cli
```

### API vs CLI (subscription) — when to use each

| Aspect | API (key) | CLI (subscription) |
|--------|-----------|-------------------|
| **Setup** | Create account + generate API key | Install CLI + log in |
| **Billing** | Pay-per-token (credits) | Fixed monthly plan |
| **Best for** | CI/CD, automated pipelines | Local development, personal use |
| **Rate limits** | API limits (varies by tier) | Subscription limits |
| **Offline** | No | No (but Ollama yes) |
| **Providers** | gemini, claude, openai, deepseek, openrouter | gemini-cli, claude-code |

> **Tip:** For daily local use, subscription providers are the most practical choice — zero key configuration, simple billing. For CI/CD, prefer API providers (or Ollama for air-gapped environments).

## CI/CD Integration

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

For SARIF output with files saved to the mounted directory:

```bash
docker run --rm -v $(pwd):/workspace -w /workspace \
  ghcr.io/leonamvasquez/terraview scan checkov -f sarif -o /workspace/reports
```

## Architecture

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              terraview CLI                                │
│  scan | apply | diagram | explain | drift | provider | scanners | cache  │
└────────────────────────────────┬──────────────────────────────────────────┘
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
                                ▼
                       Topology Graph
                       (30+ ref fields)
                                │
               ┌────────────────┼────────────────┐
               │           PARALLEL              │
               ▼                                 ▼
      ┌──────────────┐              ┌──────────────────┐
      │   Scanner    │              │  AI Context      │
      │  Checkov     │              │  Analysis        │
      │  tfsec       │              │  (cross-resource │
      │  Terrascan   │              │   relationships, │
      │              │              │   risk vectors)  │
      └──────┬───────┘              └────────┬─────────┘
             │                               │
             │                      ┌────────┴─────────┐
             │                      │  AI Cache        │
             │                      │  (disk, TTL 24h) │
             │                      └────────┬─────────┘
             │                               │
             └──────────┬────────────────────┘
                        ▼
             ┌─────────────────────┐
             │  Normalizer         │ deduplicate scanner + AI
             │  Resolver           │ same resource+category → scanner wins
             └──────────┬──────────┘
                        ▼
             ┌─────────────────────┐
             │  Aggregator         │ scores 0-10 (security, compliance, maint.)
             │  Scorer             │ verdict + exit code
             │  Meta-analysis      │ cross-tool correlation
             └──────────┬──────────┘
                        ▼
             ┌─────────────────────┐
             │  Output             │
             │  pretty | compact   │
             │  json | sarif | md  │
             └─────────────────────┘
```

## Development

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make build        # build for current platform
make test         # run tests with race detection + coverage
make test-short   # fast tests (no race detector)
make coverage     # HTML coverage report
make lint         # golangci-lint (or go vet fallback)
make clean        # remove build artifacts
make dist         # build for all platforms (linux/darwin/windows, amd64/arm64)
make docker-build # build Docker image
make docker-run   # run in Docker with example plan
make install      # install locally to ~/.local/bin + assets to ~/.terraview
make uninstall    # remove local installation
make release      # create draft GitHub release (requires gh CLI)
```

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for full instructions.

Summary:

- Branch from `main` with prefix `feat/`, `fix/`, `docs/`, `refactor/`, etc.
- Commits in [Conventional Commits](https://www.conventionalcommits.org/) format: `feat(scanner): add trivy support`
- Tests required: `make test` must pass. New modules must include `_test.go`
- Lint: `make lint` with no errors
- PRs should describe the problem and the solution

To report security vulnerabilities, see [SECURITY.md](SECURITY.md).

## Disclaimer

- Terraview **does not save, publish or share** any identifiable user information.
- When AI is active (default behavior when a provider is configured), the Terraform plan content is sent to the selected provider (Ollama runs locally; cloud APIs like Gemini/Claude send data externally). Review the provider's data policy before using with sensitive data.
- For 100% local and offline analysis, use Ollama as the AI provider.

## Support

Terraview is maintained as an open source project under the MIT license.

- Documentation: this README and [CONTRIBUTING.md](CONTRIBUTING.md)
- Issues: [GitHub Issues](https://github.com/leonamvasquez/terraview/issues)
- Discussions: [GitHub Discussions](https://github.com/leonamvasquez/terraview/discussions)
- Security: [SECURITY.md](SECURITY.md)

### Supported Go version

We follow the official Go support cycle with automated tests. Currently supporting **Go 1.26+**. If you encounter issues with any non-EOL version, open an [Issue](https://github.com/leonamvasquez/terraview/issues).

## License

Distributed under the [MIT](LICENSE) License.
