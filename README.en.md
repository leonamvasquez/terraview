![terraview](terraview.png)

**Choose your language:** [Português](README.md) | [English](README.en.md)

# terraview: Semantic Review of Terraform Plans with AI

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)

## Overview

**terraview** is an open-source command-line tool that performs **semantic analysis of Terraform plans**, combining deterministic hard rules with intelligent AI review via multiple providers (Ollama, Gemini, Claude, DeepSeek, OpenRouter).

100% local by default. Multi-provider AI. Single binary, no dependencies.

Built for DevOps, SRE and Platform Engineering teams who want to ensure quality, security and compliance before any `terraform apply`.

## Key Features

- **Deterministic Analysis**: Versioned YAML rules that detect known anti-patterns (open SGs, missing encryption, permissive IAM)
- **Multi-Provider AI**: Supports Ollama (local), Gemini, Claude, DeepSeek and OpenRouter with interactive selection
- **100% Local by Default**: No infrastructure data leaves your machine when using Ollama
- **Zero Configuration**: Auto-detects Terraform projects and runs `init + plan + show` automatically
- **Interactive AI Selector**: `terraview ai list` opens an arrow-key picker to choose provider and model
- **Detailed Scorecard**: Security, Compliance, Maintainability and Overall scores on a 0-10 scale
- **Native CI/CD**: Ready-to-use integration with GitHub Actions and GitLab CI via semantic exit codes
- **Auto-Update**: `terraview update` fetches and installs the latest release from GitHub
- **Native `tv` alias**: `tv` symlink installed automatically — `tv review` works exactly like `terraview review`

## Installation

### Install script (recommended)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Build from source

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Install the local AI runtime (Ollama)

```bash
terraview install llm
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

# Review the plan (runs terraform init + plan automatically)
terraview review

# Use the short alias
tv review

# Review an existing plan.json
terraview review --plan plan.json

# Deterministic rules only (no AI)
terraview review --skip-llm

# Choose an AI provider
terraview review --provider gemini
terraview review --provider claude
terraview review --provider openrouter

# Strict mode (HIGH findings also return exit code 2)
terraview review --strict

# Review and apply
terraview apply
```

## Commands

### `terraview review`

Analyzes a Terraform plan with deterministic rules and optional AI review.

If `--plan` is not provided, terraview automatically:
1. Detects `.tf` files in the current directory
2. Runs `terraform init` (if needed)
3. Runs `terraform plan -out=tfplan`
4. Exports `terraform show -json tfplan > plan.json`
5. Runs the full review pipeline

```bash
terraview review                          # auto-detection
terraview review --plan plan.json         # use existing plan.json
terraview review --skip-llm               # deterministic rules only
terraview review --provider gemini        # use Gemini
terraview review --model mistral:7b       # specific model
terraview review --format compact         # minimal output
terraview review --format json            # JSON output only
```

### `terraview apply`

Runs a full review then conditionally applies the plan.

- **Blocks** if any CRITICAL findings are detected
- Displays a summary and asks for confirmation
- Use `--non-interactive` in CI/CD pipelines

```bash
terraview apply                           # interactive
terraview apply --non-interactive         # CI mode
```

### `terraview test`

Runs a deterministic test suite (no AI dependency):

1. `terraform fmt -check` — formatting check
2. `terraform validate` — syntax validation
3. `terraform test` — native tests (Terraform 1.6+)
4. Hard rules — deterministic evaluation

```bash
terraview test
terraview test --rules custom-rules.yaml
```

### `terraview drift`

Detects and classifies infrastructure drift.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --format compact
```

### AI Management

#### `terraview ai list`

Opens an **interactive picker** with arrow keys to choose the default provider and model. The choice is saved globally to `~/.terraview/.terraview.yaml`.

```bash
terraview ai list                            # interactive selection
terraview ai use gemini gemini-2.0-flash     # non-interactive (scripts/CI)
terraview ai current                         # show active config
terraview ai test                            # validate connectivity
```

#### `terraview install llm` / `terraview uninstall llm`

```bash
terraview install llm      # install Ollama + pull default model
terraview uninstall llm    # remove Ollama and its data
```

### Utilities

```bash
terraview version          # version info
terraview update           # self-update from GitHub
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

rules:
  required_tags:
    - environment
    - owner

output:
  format: pretty                # pretty, compact, json
```

## Available Rules

Rules are defined in YAML and support the following operators:

`equals` · `not_equals` · `contains` · `not_contains` · `exists` · `not_exists` · `is_true` · `is_false` · `is_action` · `contains_in_list`

### Default Rules

| ID | Name | Severity |
|----|------|----------|
| SEC001 | SSH Open to Internet | HIGH |
| SEC002 | S3 Bucket Without Encryption | HIGH |
| SEC003 | IAM Policy with Wildcard Actions | CRITICAL |
| SEC004 | IAM Policy with Wildcard Resources | HIGH |
| SEC005 | RDS Publicly Accessible | HIGH |
| SEC006 | S3 Bucket Public ACL | HIGH |
| SEC007 | Security Group Allows All Traffic | CRITICAL |
| REL001 | RDS Without Multi-AZ | MEDIUM |
| REL002 | RDS Without Backup | HIGH |
| BP001 | S3 Bucket Without Versioning | MEDIUM |
| BP002 | EBS Volume Without Encryption | MEDIUM |
| COMP001 | CloudWatch Logs Without Retention | LOW |
| TAG001 | Missing Required Tags | MEDIUM |
| DEL001 | Critical Resource Deletion | HIGH |

### Custom Rules

```yaml
version: "1.0"
required_tags:
  - Environment
  - CostCenter
rules:
  - id: CUSTOM001
    name: My Custom Rule
    description: "Describes what this rule checks"
    severity: HIGH
    category: security
    remediation: "How to fix"
    enabled: true
    targets:
      - aws_s3_bucket
    conditions:
      - field: some_field
        operator: equals
        value: "bad_value"
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

      - name: Install terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Review plan
        run: terraview review --skip-llm

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
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview review --skip-llm
  artifacts:
    paths: [review.json, review.md]
    when: always
```

## Architecture

```
┌────────────────────────────────────────────────────────┐
│                      terraview CLI                      │
│   review │ apply │ test │ drift │ ai │ update │ install  │
└─────────────────────┬──────────────────────────────────┘
                      │
          ┌───────────┴────────────┐
          ▼                        ▼
┌─────────────────────┐   ┌──────────────────────┐
│  Rules Engine       │   │    AI Providers      │
│  (YAML rules)       │   │  Ollama │ Gemini      │
│  Deterministic      │   │  Claude │ DeepSeek    │
└─────────┬───────────┘   │  OpenRouter           │
          │               └──────────┬────────────┘
          │                          │
          └─────────────┬────────────┘
                        ▼
          ┌─────────────────────────┐
          │  Aggregator + Scorer    │
          │  review.json / .md      │
          └─────────────────────────┘
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

- [ ] Azure and GCP support
- [ ] Customizable scoring profiles
- [ ] SARIF output format
- [ ] Terraform module-aware analysis
- [ ] Plugin system for rules
- [ ] Score history and trend tracking
- [ ] OPA/Rego policy integration

## Support and Contact

- **GitHub Issues**: [github.com/leonamvasquez/terraview/issues](https://github.com/leonamvasquez/terraview/issues)
- **GitHub Discussions**: [github.com/leonamvasquez/terraview/discussions](https://github.com/leonamvasquez/terraview/discussions)

## License

This project is distributed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## FAQ

**Q: Does terraview work offline?**
A: Yes. When using Ollama as the provider, all analysis is done locally. No infrastructure data leaves your machine.

**Q: Do I need Terraform installed?**
A: Yes, if you want automatic plan generation (`terraview review` without `--plan`). If you already have a `plan.json`, Terraform is not required.

**Q: How do I configure a cloud provider (Gemini, Claude, etc.)?**
A: Run `terraview ai list`, select the provider with arrow keys and confirm. terraview will show which environment variable to set (e.g., `GEMINI_API_KEY`).

**Q: Can I use terraview in monorepos with multiple workspaces?**
A: Yes. Use `--dir` to specify the workspace or `--plan` with a previously generated `plan.json`.

**Q: How do I update to the latest version?**
A: Run `terraview update`. It checks, downloads and installs automatically.

**Q: What is the `tv` alias?**
A: During installation, a `tv -> terraview` symlink is created. You can use `tv review`, `tv ai list`, etc. as a shorthand.
