# Changelog

Todas as mudanças notáveis deste projeto são documentadas aqui.

Formato baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
com versionamento semântico [SemVer](https://semver.org/lang/pt-BR/).

> O changelog a partir da v0.6.0 é gerado automaticamente pelo GoReleaser
> a partir de [Conventional Commits](https://www.conventionalcommits.org/).

---

## [Unreleased]

## [0.5.3] — 2026-01-xx

### Adicionado
- Suporte a providers via assinatura: `gemini-cli` e `claude-code` (subprocess + JSON)
- Opção de modelo personalizado no seletor interativo de modelos
- Shell completions expostas via `terraview completion bash|zsh|fish|powershell`
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates e PR template
- Homebrew tap: `brew install leonamvasquez/terraview/terraview`

### Alterado
- `provider install llm` renomeado para `provider install ollama` (consistência)
- Modelos sugeridos atualizados para versões mais recentes de cada provider
- Lista de modelos sugeridos reduzida por provider para evitar overflow visual no seletor
- README: exemplos de instalação agora usam comandos Linux nativos (apt, snap, pip)

### Corrigido
- Seletor interativo de modelos bugava visualmente ao digitar texto longo
- Contagem de linhas no `eraseLines` estava incorreta com itens de detalhes longos

## [0.5.2] — 2025-12-xx

### Adicionado
- Pipeline CI/CD com supply chain hardening: SBOM, cosign, SLSA provenance
- Fuzz testing contínuo (`FuzzParse`, `FuzzNormalizeAction`)
- SAST com Semgrep, secret scanning com Gitleaks
- OSV Scanner + govulncheck para CVEs em dependências
- Docker Scout no pipeline de release

### Alterado
- Atualizado Go 1.24 → 1.26
- Cobra v1.8.0 → v1.10.2, pflag v1.0.5 → v1.0.10

## [0.5.1] — 2025-11-xx

### Adicionado
- Logo dark/light theme no README
- Animações de spinner durante operações longas
- Reorganização de assets para `.github/assets/`

## [0.5.0] — 2025-10-xx

### Adicionado
- Audit completo de segurança e qualidade de código
- Providers: DeepSeek, OpenRouter
- Risk clusters com score de risco ponderado
- Análise de impacto `--impact`

## [0.1.0] — 2025-01-xx

### Adicionado
- MVP: scan com Checkov, tfsec, Terrascan
- Revisão com IA via Ollama (local), Gemini, Claude
- Scorecard com scores de Segurança, Compliance, Manutenibilidade
- Diagrama ASCII de infraestrutura
- Drift detection
- Exit codes semânticos (0/1/2) para CI/CD
- Saída SARIF para GitHub Actions
- Auto-update via `terraview upgrade`
- Alias `tv`

[Unreleased]: https://github.com/leonamvasquez/terraview/compare/v0.5.3...HEAD
[0.5.3]: https://github.com/leonamvasquez/terraview/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/leonamvasquez/terraview/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/leonamvasquez/terraview/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/leonamvasquez/terraview/compare/v0.1.0...v0.5.0
[0.1.0]: https://github.com/leonamvasquez/terraview/releases/tag/v0.1.0
