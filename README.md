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
[![Go Report Card](https://goreportcard.com/badge/github.com/leonamvasquez/terraview)](https://goreportcard.com/report/github.com/leonamvasquez/terraview)
[![codecov](https://codecov.io/gh/leonamvasquez/terraview/branch/main/graph/badge.svg)](https://codecov.io/gh/leonamvasquez/terraview)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/leonamvasquez/terraview/badge)](https://scorecard.dev/viewer/?uri=github.com/leonamvasquez/terraview)

Análise de segurança para planos Terraform que combina scanners estáticos (Checkov, tfsec, Terrascan) com análise contextual por IA rodando **em paralelo**. Binário único, zero dependências, múltiplos providers de IA suportados.

## Início Rápido

```bash
# Instalar
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# Primeiro scan
cd meu-projeto-terraform
terraview scan checkov
```

Outros métodos: `brew install leonamvasquez/terraview/terraview` · `scoop install terraview` · `apt install terraview` · [Docker](https://leonamvasquez.github.io/terraview/integration/docker/)

## Features

- **Scanners de segurança** — Checkov, tfsec, Terrascan integrados automaticamente
- **IA contextual em paralelo** — Ollama, Gemini, Claude, OpenAI, DeepSeek, OpenRouter, Gemini CLI, Claude Code + qualquer API OpenAI-compatible via Custom
- **Supressão de findings** — arquivo `.terraview-ignore` para suprimir falsos positivos e riscos aceitos, com escopo por regra, recurso ou fonte (`--ignore-file`)
- **Correção automática (AI Fix)** — `--fix` gera sugestões de HCL corrigido para findings CRITICAL/HIGH com validação e diff
- **Scorecard unificado** — Segurança, Compliance, Manutenibilidade (0–10)
- **Vetores de risco** — 5 eixos por recurso (rede, criptografia, identidade, governança, observabilidade)
- **Diagrama ASCII (AWS)** — visualização topológica da infraestrutura no terminal.
- **Análise de impacto** — `--impact` para blast radius
- **Drift detection** — detecção e classificação com `--intelligence`
- **Histórico de scans** — tracking em SQLite com trends, comparação e exportação
- **MCP Server** — integração com agentes AI (Claude Code, Cursor, Windsurf)
- **CI/CD nativo** — exit codes semânticos + SARIF, JSON, Markdown
- **Cache persistente** — re-execuções evitam chamadas repetidas à API
- **Supply chain** — SBOM, cosign, SLSA Level 3

## Exemplo

```
  terraview scan checkov
  ══════════════════════

  ┌──────────────────────────────────────────────────────┐
  │  Scorecard                                           │
  │  Security:       7.2 / 10                            │
  │  Compliance:     8.5 / 10                            │
  │  Maintainability: 9.0 / 10                           │
  └──────────────────────────────────────────────────────┘

  Findings: 3 CRITICAL, 5 HIGH, 12 MEDIUM, 4 LOW
```

## Documentação

**[leonamvasquez.github.io/terraview](https://leonamvasquez.github.io/terraview/)** — documentação completa incluindo:

- [Instalação](https://leonamvasquez.github.io/terraview/getting-started/installation/) — todos os métodos
- [Configuração Rápida](https://leonamvasquez.github.io/terraview/getting-started/quickstart/) — primeiro scan passo a passo
- [Comandos](https://leonamvasquez.github.io/terraview/usage/commands/) — scan, apply, diagram, explain, drift
- [AI Providers](https://leonamvasquez.github.io/terraview/usage/ai-providers/) — API, CLI, Custom e local
- [Configuração](https://leonamvasquez.github.io/terraview/usage/configuration/) — `.terraview.yaml`
- [CI/CD](https://leonamvasquez.github.io/terraview/integration/cicd/) — GitHub Actions, GitLab CI, Azure DevOps
- [Metodologia de Scoring](https://leonamvasquez.github.io/terraview/reference/scoring/) — fórmulas e exemplos
- [Arquitetura](https://leonamvasquez.github.io/terraview/reference/architecture/) — pipeline e componentes

## Aviso

O terraview **não salva, publica ou compartilha** informações do usuário. Quando a IA está ativa, o conteúdo do plan é enviado ao provider configurado. Para uso 100% local, utilize o Ollama.

## Contribuir

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para instruções. Vulnerabilidades: [SECURITY.md](SECURITY.md).

## Suporte

- [GitHub Issues](https://github.com/leonamvasquez/terraview/issues)
- [GitHub Discussions](https://github.com/leonamvasquez/terraview/discussions)

## Licença

Distribuído sob a licença [MIT](LICENSE).
