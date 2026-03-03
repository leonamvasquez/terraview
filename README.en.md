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

Security analysis for Terraform plans combining static scanners (Checkov, tfsec, Terrascan) with AI contextual analysis running **in parallel**. Single binary, zero dependencies, 8 AI providers supported.

## Quick Start

```bash
# Install
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# First scan
cd my-terraform-project
terraview scan checkov
```

Other methods: `brew install leonamvasquez/terraview/terraview` · `scoop install terraview` · `apt install terraview` · [Docker](https://leonamvasquez.github.io/terraview/integration/docker/)

## Features

- **Security Scanners** — Checkov, tfsec, Terrascan automatically integrated
- **Parallel AI analysis** — Ollama, Gemini, Claude, OpenAI, DeepSeek, OpenRouter, Gemini CLI, Claude Code
- **Unified Scorecard** — Security, Compliance, Maintainability (0–10)
- **Risk vectors** — 5 axes per resource (network, encryption, identity, governance, observability)
- **ASCII Diagram** — `--diagram` for terminal visualization
- **Impact Analysis** — `--impact` for blast radius
- **Drift Detection** — detection and classification with `--intelligence`
- **Native CI/CD** — semantic exit codes + SARIF, JSON, Markdown
- **Persistent Cache** — reruns skip redundant API calls
- **Supply Chain** — SBOM, cosign, SLSA Level 3

## Example

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
```

## Documentation

**[leonamvasquez.github.io/terraview](https://leonamvasquez.github.io/terraview/)** — full documentation including:

- [Installation](https://leonamvasquez.github.io/terraview/getting-started/installation/) — all methods
- [Quick Start](https://leonamvasquez.github.io/terraview/getting-started/quickstart/) — first scan walkthrough
- [Commands](https://leonamvasquez.github.io/terraview/usage/commands/) — scan, apply, diagram, explain, drift
- [AI Providers](https://leonamvasquez.github.io/terraview/usage/ai-providers/) — 8 providers, API vs CLI
- [Configuration](https://leonamvasquez.github.io/terraview/usage/configuration/) — `.terraview.yaml`
- [CI/CD](https://leonamvasquez.github.io/terraview/integration/cicd/) — GitHub Actions, GitLab CI, Azure DevOps
- [Scoring Methodology](https://leonamvasquez.github.io/terraview/reference/scoring/) — formulas and examples
- [Architecture](https://leonamvasquez.github.io/terraview/reference/architecture/) — pipeline and components

## Disclaimer

Terraview **does not save, publish or share** any user information. When AI is active, plan content is sent to the configured provider. For 100% local analysis, use Ollama.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions. Vulnerabilities: [SECURITY.md](SECURITY.md).

## Support

- [GitHub Issues](https://github.com/leonamvasquez/terraview/issues)
- [GitHub Discussions](https://github.com/leonamvasquez/terraview/discussions)

## License

Distributed under the [MIT](LICENSE) License.
