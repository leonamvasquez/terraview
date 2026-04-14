# TerraView

**Análise de segurança para Terraform com scanners estáticos e IA contextual em paralelo.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/leonamvasquez/terraview/blob/main/LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://golang.org)
[![GitHub release](https://img.shields.io/github/v/release/leonamvasquez/terraview)](https://github.com/leonamvasquez/terraview/releases/latest)
[![CI](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml/badge.svg)](https://github.com/leonamvasquez/terraview/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/leonamvasquez/terraview/branch/main/graph/badge.svg)](https://codecov.io/gh/leonamvasquez/terraview)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/leonamvasquez/terraview/badge)](https://scorecard.dev/viewer/?uri=github.com/leonamvasquez/terraview)

---

O TerraView escaneia infraestrutura cloud provisionada com Terraform, detecta misconfigurações de segurança e compliance utilizando scanners open-source (Checkov, tfsec, Terrascan), e enriquece automaticamente os resultados com análise contextual por IA multi-provider quando um provider está configurado.

## Início Rápido

```bash
# Instalar
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# Primeiro scan
cd meu-projeto-terraform
terraview scan checkov
```

## Features Principais

- **Scanners de segurança** — Checkov, tfsec e Terrascan integrados automaticamente
- **IA contextual em paralelo** — Ollama, Gemini, Claude, OpenAI, DeepSeek, OpenRouter, Gemini CLI, Claude Code + qualquer API OpenAI-compatible via Custom
- **Scorecard unificado** — scores de Segurança, Compliance, Manutenibilidade e Overall (0–10)
- **Vetores de risco** — análise em 5 eixos por recurso: rede, criptografia, identidade, governança, observabilidade
- **Diagrama ASCII (AWS)** — visualização topológica da infraestrutura no terminal com aninhamento VPC, tiers de subnet e setas de conexão
- **Blast radius via MCP** — análise de raio de dependências exposta a agentes IA pela tool `terraview_impact`
- **Histórico de scans** — tracking em SQLite com trends (sparklines), comparação e exportação
- **MCP Server** — integração com agentes AI (Claude Code, Cursor, Windsurf) via Model Context Protocol
- **CI/CD nativo** — exit codes semânticos + saída SARIF, JSON, Markdown
- **Zero configuração** — detecta projetos Terraform e roda automaticamente
- **Cache persistente** — re-execuções com o mesmo plan evitam chamadas à API
- **Supply chain hardening** — SBOM, cosign, SLSA Build Provenance Level 3

## Exemplo

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

## Próximos Passos

- [Instalação](getting-started/installation.md) — todos os métodos de instalação
- [Configuração Rápida](getting-started/quickstart.md) — primeiro scan passo a passo
- [Comandos](usage/commands.md) — referência completa dos comandos
- [AI Providers](usage/ai-providers.md) — todos os providers suportados
- [Histórico](usage/history.md) — tracking de scans com trends e comparação
- [MCP Server](usage/mcp.md) — integração com agentes AI
- [Integração CI/CD](integration/cicd.md) — GitHub Actions, GitLab CI, Azure DevOps
