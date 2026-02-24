<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/assets/terraview-logo-dark-theme.png">
  <source media="(prefers-color-scheme: light)" srcset=".github/assets/terraview-logo-white-theme.png">
  <img alt="terraview" src=".github/assets/terraview-logo-white-theme.png">
</picture>

**Choose your language:** [Português](README.md) | [English](README.en.md)

# terraview

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)
[![GitHub release](https://img.shields.io/github/v/release/leonamvasquez/terraview)](https://github.com/leonamvasquez/terraview/releases/latest)

Security analysis for Terraform plans combining static scanners (Checkov, tfsec, Terrascan) with intelligent AI review. Scanners run by default. AI is opt-in. Single binary, no dependencies.

## Table of Contents

- [Features](#features)
- [Example Output](#example-output)
- [Quick Start](#quick-start)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [CI/CD Integration](#cicd-integration)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

## Features

- 🔒 **Security Scanners** — automatic integration with Checkov, tfsec and Terrascan; detects what's installed and runs automatically
- 🤖 **Multi-Provider AI** — Ollama (local), Gemini, Claude, DeepSeek and OpenRouter with interactive selection
- ⚖️ **Conflict Resolution** — when scanner and AI disagree, scanner wins; agreements boost confidence to 100%
- 📊 **Scorecard** — Security, Compliance, Maintainability and Overall scores on a 0-10 scale
- 🎯 **Risk Clusters** — findings grouped by resource with weighted risk scores
- 📐 **ASCII Diagram** — infrastructure visualization right in the terminal
- 💥 **Impact Analysis** — dependency blast radius of changes via `--impact`
- ⚡ **Zero Configuration** — detects Terraform projects and runs `init + plan + show` automatically
- 🔄 **Drift Detection** — detects and classifies infrastructure drift
- 🚀 **Native CI/CD** — semantic exit codes + SARIF/JSON output for GitHub Actions and GitLab CI
- 📦 **Auto-Update** — `terraview upgrade` fetches the latest release from GitHub
- 🔗 **`tv` alias** — symlink created on install; `tv scan` = `terraview scan`

## Example Output

```
  terraview setup
  ═══════════════

  Security Scanners

  [✓] checkov      3.2.504
  [✗] tfsec        not installed
  [✗] terrascan    not installed

  Default: checkov

  Install missing: terraview scanners install --all
```

## Quick Start

### 1. Install

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### 2. Scan

```bash
cd my-terraform-project
terraview scan checkov
```

### 3. Review

Results are displayed in a scorecard with grouped findings and scores. Add `--ai` for intelligent review or `--all` to enable everything: `--explain --diagram --impact`.

```bash
terraview scan checkov --ai                 # scanner + AI
terraview scan checkov --all                # everything enabled
```

## Installation

### Install script (Linux, macOS, Windows WSL)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

The script automatically detects your OS and architecture, downloads the correct binary, and creates the `tv` alias.

<details>
<summary>Windows — PowerShell</summary>

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

</details>

<details>
<summary>Manual download</summary>

```bash
# Replace <VERSION>, <OS> and <ARCH> for your system
# OS: linux, darwin, windows | ARCH: amd64, arm64
curl -Lo terraview.tar.gz https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-<OS>-<ARCH>.tar.gz
tar -xzf terraview.tar.gz
sudo mv terraview-<OS>-<ARCH> /usr/local/bin/terraview
```

</details>

### Build from source

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Install the local AI runtime (Ollama)

```bash
terraview provider install llm
```

## Usage

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
terraview scan                              # auto-select (default or priority)
terraview scan checkov                      # scan with Checkov
terraview scan tfsec                        # scan with tfsec
terraview scan checkov --ai                 # scanner + AI review
terraview scan --ai                         # AI-only (no scanner)
terraview scan checkov --all                # explain + diagram + impact
terraview scan checkov --plan plan.json     # use existing plan.json
terraview scan checkov -f sarif             # SARIF output for CI
terraview scan checkov --strict             # HIGH returns exit code 2
```

### Apply

Runs scan + conditionally applies the plan. Blocks if any CRITICAL findings are detected.

```bash
terraview apply checkov                     # interactive
terraview apply checkov --non-interactive   # CI mode
terraview apply checkov --ai                # with AI review
```

### Other commands

```bash
terraview diagram                           # ASCII infrastructure diagram
terraview explain                           # AI explanation of infrastructure
terraview drift                             # detect drift
terraview provider list                     # interactive provider/model picker
terraview scanners install checkov          # install specific scanner
terraview scanners install --all            # install all scanners
terraview scanners default checkov          # set default scanner
terraview scanners list                     # show scanner status
terraview setup                             # environment diagnostic
terraview upgrade                           # self-update
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues or MEDIUM/LOW/INFO only |
| 1 | HIGH severity findings |
| 2 | CRITICAL findings (blocks apply) |

## Configuration

Local file in the project directory (overrides global) or global at `~/.terraview/.terraview.yaml`:

```yaml
llm:
  enabled: true
  provider: ollama              # ollama, gemini, claude, deepseek, openrouter
  model: llama3.1:8b
  url: http://localhost:11434
  api_key: ""                   # for cloud providers
  timeout_seconds: 120
  temperature: 0.2

scoring:
  severity_weights:
    critical: 5
    high: 3
    medium: 1
    low: 0.5

scanner:
  default: checkov              # default scanner for "terraview scan"

output:
  format: pretty                # pretty, compact, json, sarif
```

## Security Scanners

| Scanner | Description | Install |
|---------|-------------|---------|
| [Checkov](https://www.checkov.io/) | Security and compliance scanner for IaC | `terraview scanners install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Static security analysis for Terraform | `terraview scanners install tfsec` |
| [Terrascan](https://runterrascan.io/) | Compliance violation detector | `terraview scanners install terrascan` |

Findings from all scanners are normalized, aggregated, and presented in a unified scorecard.

```bash
terraview scanners install --all            # install all
terraview scanners install checkov          # install specific
terraview scanners default checkov          # set as default
terraview scanners list                     # check status
```

### Conflict Resolution (Scanner × AI)

| Scenario | Action | Confidence |
|----------|--------|------------|
| Scanner and AI agree (±1 level) | **Confirmed** — confidence boost | 1.00 |
| Scanner and AI disagree | **Scanner wins** | 0.80 |
| Only scanner detected | **Scanner-only** | 0.80 |
| Only AI detected | **AI-only** | 0.50 |

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

## Architecture

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

## Development

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make build        # build for current platform
make test         # run tests with race detection
make coverage     # coverage report
make dist         # build for all platforms
make install      # install locally (~/.local/bin)
```

Contributions are welcome! Open an [issue](https://github.com/leonamvasquez/terraview/issues) or submit a pull request.

## License

Distributed under the [MIT](LICENSE) License.
