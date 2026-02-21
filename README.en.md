![terraview](terraview.png)

**Choose your language:** [Português](README.md) | [English](README.en.md)

# terraview: Security Scanning and AI Review for Terraform Plans

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)

## Overview

**terraview** is an open-source command-line tool that performs **security analysis of Terraform plans**, combining external scanners (Checkov, tfsec, Terrascan, KICS) with intelligent AI review via multiple providers (Ollama, Gemini, Claude, DeepSeek, OpenRouter).

Scanners run by default. AI is opt-in. Single binary, no dependencies.

Built for DevOps, SRE and Platform Engineering teams who want to ensure security and compliance before any `terraform apply`.

## Key Features

- **Security Scanners**: Automatic integration with Checkov, tfsec, Terrascan and KICS — detects what's installed and runs automatically
- **Multi-Provider AI**: Supports Ollama (local), Gemini, Claude, DeepSeek and OpenRouter with interactive selection
- **Zero Configuration**: Auto-detects Terraform projects and runs `init + plan + show` automatically
- **Interactive Provider Selector**: `terraview provider list` opens an arrow-key picker to choose provider and model
- **Detailed Scorecard**: Security, Compliance, Maintainability and Overall scores on a 0-10 scale
- **Infrastructure Diagram**: `--diagram` generates an ASCII diagram of the planned infrastructure
- **Blast Radius**: `--blast-radius` analyzes the impact radius of changes
- **Code Smells**: `--smell` detects infrastructure design anti-patterns
- **Score Trends**: `--trend` tracks and displays score trends over time
- **Native CI/CD**: Ready-to-use integration with GitHub Actions and GitLab CI via semantic exit codes
- **Auto-Update**: `terraview upgrade` fetches and installs the latest release from GitHub
- **Native `tv` alias**: `tv` symlink installed automatically — `tv plan` works exactly like `terraview plan`

## Installation

### Linux / macOS

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

> If PowerShell complains about execution policy, run first:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

The installer downloads `terraview.exe`, creates a `tv.exe` alias, and automatically adds both to the user `PATH`.

### Build from source

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Install the local AI runtime (Ollama)

```bash
terraview provider install
```

After installation:

```bash
terraview version   # or: tv version
terraview --help
```

## Getting Started

```bash
# Navigate to any Terraform project
cd my-terraform-project

# Analyze the plan (runs terraform init + plan + scanners automatically)
terraview plan

# Use the short alias
tv plan

# Analyze an existing plan.json
terraview plan --plan plan.json

# Scanners + AI review
terraview plan --ai

# Choose an AI provider
terraview plan --ai --provider gemini
terraview plan --ai --provider claude
terraview plan --ai --provider openrouter

# Run specific scanners
terraview plan --scanners checkov,tfsec

# Infrastructure diagram
terraview plan --diagram

# Blast radius analysis
terraview plan --blast-radius

# Strict mode (HIGH findings also return exit code 2)
terraview plan --strict

# Review and apply
terraview apply
```

## Commands

### `terraview plan`

Analyzes a Terraform plan with security scanners and optional AI review.

If `--plan` is not provided, terraview automatically:
1. Detects `.tf` files in the current directory
2. Runs `terraform init` (if needed)
3. Runs `terraform plan -out=tfplan`
4. Exports `terraform show -json tfplan > plan.json`
5. Runs scanners and the review pipeline

```bash
terraview plan                                # auto-detection + scanners
terraview plan --plan plan.json               # use existing plan.json
terraview plan --ai                           # scanners + AI review
terraview plan --ai --provider gemini         # use Gemini
terraview plan --ai --model mistral:7b        # specific model
terraview plan --scanners checkov,tfsec       # specific scanners
terraview plan --diagram                      # infrastructure diagram
terraview plan --blast-radius                 # impact radius
terraview plan --smell                        # detect code smells
terraview plan --trend                        # score trends
terraview plan --format compact               # minimal output
terraview plan --format json                  # JSON output only
terraview plan --format sarif                 # SARIF output for CI
terraview plan --strict                       # HIGH returns exit code 2
terraview plan --safe                         # safe mode (light model)
terraview plan --profile prod                 # production review profile
terraview plan --findings checkov.json        # import external findings
```

> **Alias:** `terraview review` works as an alias for `terraview plan`.

### `terraview apply`

Runs a full review then conditionally applies the plan.

- **Blocks** if any CRITICAL findings are detected
- Displays a summary and asks for confirmation
- Use `--non-interactive` in CI/CD pipelines

```bash
terraview apply                           # interactive
terraview apply --non-interactive         # CI mode
terraview apply --ai                      # AI review + apply
```

### `terraview validate`

Runs a deterministic validation suite (no AI dependency):

1. `terraform fmt -check` — formatting check
2. `terraform validate` — syntax validation
3. `terraform test` — native tests (Terraform 1.6+)
4. Security Scanners — external scanner evaluation

```bash
terraview validate
terraview validate -v                     # verbose mode
```

> **Alias:** `terraview test` works as an alias for `terraview validate`.

### `terraview drift`

Detects and classifies infrastructure drift.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --intelligence            # advanced classification + risk score
terraview drift --format compact
terraview drift --format json
```

### `terraview explain`

Generates a comprehensive natural-language explanation of your infrastructure using AI.

```bash
terraview explain
terraview explain --plan plan.json
terraview explain --provider gemini
terraview explain --format json
```

### Provider Management

#### `terraview provider list`

Opens an **interactive picker** with arrow keys to choose the default provider and model. The choice is saved globally to `~/.terraview/.terraview.yaml`.

```bash
terraview provider list                            # interactive selection
terraview provider use gemini gemini-2.0-flash     # non-interactive (scripts/CI)
terraview provider current                         # show active config
terraview provider test                            # validate connectivity
```

> **Alias:** `terraview ai` works as an alias for `terraview provider`.

#### `terraview provider install` / `terraview provider uninstall`

```bash
terraview provider install      # install Ollama + pull default model
terraview provider uninstall    # remove Ollama and its data
```

### Utilities

```bash
terraview version          # version info
terraview upgrade          # self-update from GitHub
```

## Configuration (.terraview.yaml)

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

output:
  format: pretty                # pretty, compact, json, sarif
```

## Security Scanners

terraview automatically integrates with the following external scanners. Just have them installed — terraview detects and runs them automatically (`--scanners auto`).

| Scanner | Description | Install |
|---------|-------------|---------|
| [Checkov](https://www.checkov.io/) | Security and compliance scanner for IaC | `pip install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Static security analysis for Terraform | `brew install tfsec` |
| [Terrascan](https://runterrascan.io/) | Compliance violation detector | `brew install terrascan` |
| [KICS](https://kics.io/) | Keeping Infrastructure as Code Secure | `brew install kics` |

Findings from all scanners are normalized, aggregated, and presented in a unified scorecard.

```bash
terraview plan                              # runs all available scanners
terraview plan --scanners checkov,tfsec     # run only specific scanners
terraview plan --findings checkov.json      # import findings from external run
```

## Scores and Exit Codes

Scores are calculated on a 0-10 scale with weighted penalties per severity.

**Severity weights:** CRITICAL=5.0, HIGH=3.0, MEDIUM=1.0, LOW=0.5, INFO=0.0

**Categories:** Security (weight 3×), Compliance (2×), Maintainability (1.5×), Reliability (1×)

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues or MEDIUM/LOW/INFO only |
| 1 | HIGH severity findings |
| 2 | CRITICAL severity findings (blocks apply) |

## CI/CD Integration

### GitHub Actions

```yaml
name: Terraform Review
on:
  pull_request:
    paths: ['**.tf']

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Install Checkov
        run: pip install checkov

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Review plan
        run: terraview plan

      - name: Comment on PR
        if: always()
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: review.md
```

### GitLab CI

```yaml
terraform-review:
  stage: validate
  script:
    - pip install checkov
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview plan
  artifacts:
    paths: [review.json, review.md]
    when: always
```

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                       terraview CLI                       │
│  plan │ apply │ validate │ drift │ explain │ provider     │
└──────────────────────┬───────────────────────────────────┘
                       │
          ┌────────────┴─────────────┐
          ▼                          ▼
┌──────────────────────┐   ┌──────────────────────┐
│  Security Scanners   │   │    AI Providers       │
│  Checkov │ tfsec     │   │  Ollama │ Gemini      │
│  Terrascan │ KICS    │   │  Claude │ DeepSeek    │
└──────────┬───────────┘   │  OpenRouter           │
           │               └──────────┬────────────┘
           │                          │
           └────────────┬─────────────┘
                        ▼
           ┌───────────────────────┐
           │  Aggregator + Scorer  │
           │  review.json / .md    │
           └───────────────────────┘
```

## Development

```bash
make build        # build for current platform
make test         # run tests with race detection
make test-short   # fast tests
make coverage     # coverage report
make dist         # build for all platforms
make install      # install locally (~/.local/bin)
make help         # list all targets
```

## Roadmap

- [x] SARIF output format
- [x] Score history and trend tracking
- [x] Customizable scoring profiles
- [x] External scanner integration (Checkov, tfsec, Terrascan, KICS)
- [x] ASCII infrastructure diagram
- [x] Blast radius analysis
- [x] Code smell detection
- [ ] Azure and GCP support
- [ ] Terraform module-aware analysis
- [ ] OPA/Rego policy integration

## Support and Contact

- **GitHub Issues**: [github.com/leonamvasquez/terraview/issues](https://github.com/leonamvasquez/terraview/issues)
- **GitHub Discussions**: [github.com/leonamvasquez/terraview/discussions](https://github.com/leonamvasquez/terraview/discussions)

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## FAQ

**Q: Does terraview work offline?**
A: Yes. Scanners run locally, and when using Ollama as the AI provider, all analysis is done without sending data externally.

**Q: Do I need Terraform installed?**
A: Yes, if you want automatic plan generation (`terraview plan` without `--plan`). If you already have a `plan.json`, Terraform is not required.

**Q: Do I need any scanner installed?**
A: Recommended but not required. terraview automatically detects which scanners are available (`--scanners auto`). Without any scanner, only the AI pipeline can be used with `--ai`.

**Q: How do I configure a cloud provider (Gemini, Claude, etc.)?**
A: Run `terraview provider list`, select the provider with arrow keys and confirm. terraview will show which environment variable to set (e.g., `GEMINI_API_KEY`).

**Q: Can I use terraview in monorepos with multiple workspaces?**
A: Yes. Use `--dir` to specify the workspace or `--plan` with a previously generated `plan.json`.

**Q: How do I update to the latest version?**
A: Run `terraview upgrade`. It checks, downloads and installs automatically.

**Q: What is the `tv` alias?**
A: During installation, a `tv -> terraview` symlink is created. You can use `tv plan`, `tv provider list`, etc. as a shorthand.

**Q: What's the difference between `terraview plan` and `terraview validate`?**
A: `plan` runs scanners and optionally AI for a full analysis. `validate` runs quick deterministic checks (fmt, validate, test, scanners) without AI support — ideal for pre-commit or fast CI.
