# Changelog

All notable changes to this project are documented here.

Based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
with [SemVer](https://semver.org/) versioning.

---

## [0.6.0] — 2026-03-27

### Added
- **Topological diagram mode** (`terraview diagram --diagram-mode topo`): novo modo de diagrama ASCII que renderiza a infraestrutura Terraform com aninhamento real de VPCs, subnets e camadas de serviços AWS, agregação de recursos por grupo de serviço e layout topológico baseado em DAG

### Fixed
- **EventBridge invisível no diagrama**: recursos `aws_cloudwatch_event_*` remapeados para o grupo correto `EventBridge`; adicionado `aws_eventbridge_*` e `aws_scheduler_*` à categoria `Messaging`
- **Providers auxiliares poluindo Global Services**: recursos `random_*`, `tls_*`, `null_*` e `time_*` removidos do diagrama por não representarem infraestrutura real
- Lint: formatação `gofmt` em 8 arquivos; remoção de funções, constantes e parâmetros não utilizados (`dblCorner*`, `writeVPCLine`, `groupsToLines`, `truncateLabel`, `wrapText`, `isVPCType`, `isSubnetType`, `isClusterType`, parâmetro `compounds` em `layoutVPCWithSubnets`)

### Changed
- Bumps de CI/CD: `codecov/codecov-action` v5.5.3, `github/codeql-action` v4.34.1, `anchore/sbom-action` v0.24.0, `docker/scout-action` v1.20.3, `sigstore/cosign-installer` v4.1.0
- Bump de dependência: `modernc.org/sqlite` v1.47.0, `golang.org/x/term` v0.41.0

---

## [0.5.0] — 2026-03-15

### Added
- **Module analysis subsystem** (`terraview modules`): análise de saúde, versões e profundidade de módulos Terraform com verificação opcional de registry (`--check-registry`)
- **History tracking with SQLite** (`terraview history`): armazenamento persistente de resultados de scan com trends (sparkline), comparação lado-a-lado e política de retenção configurável
- **MCP Server** (`terraview mcp`): servidor Model Context Protocol sobre stdio (JSON-RPC 2.0) para integração com agentes AI (Claude Code, Cursor, Windsurf) — 10 tools expostas
- **Custom AI provider**: suporte a endpoints HTTP customizados compatíveis com a API OpenAI
- **Volume penalty no scoring**: penalidade logarítmica por volume absoluto de findings para evitar diluição em infraestruturas grandes

### Changed
- Go atualizado para 1.26.1
- Bumps de CI/CD: actions/setup-go v6.3.0, actions/setup-python v6.2.0, docker/setup-buildx-action v4.0.0, docker/login-action v4.0.0, docker/metadata-action v6.0.0, docker/scout-action v1.20.1, github/codeql-action v4.32.6, actions/upload-pages-artifact v4.0.0
- Bump golang.org/x/sys v0.41.0 → v0.42.0
- Docker base image golang atualizada
- Diagram generator refatorado e expandido
- README.en.md expandido com documentação completa em inglês e diagrama de arquitetura

### Fixed
- `gofmt` aplicado ao custom provider
- Lint errors corrigidos em múltiplos pacotes
- SARIF: `remediation` movida de `fixes` para `rule.Help` (corrige `artifactChanges` obrigatório)
- Logo terraview atualizado (dark/light theme)
- Testes unitários expandidos cobrindo 19 pacotes (69% → 79.5% cobertura)

---

## [0.4.1] — 2026-03-06

### Added
- Testes unitários cobrindo 19 pacotes adicionais (cobertura: 69% → 79.5%)

### Fixed
- Testes incompatíveis com ambiente CI corrigidos

---

## [0.4.0] — 2026-03-03

### Added
- **AI Findings Validator**: validação automática de findings IA contra grafo de topologia com 5 regras (existência de recurso, tipo, severidade, duplicatas, campos vazios)
- **Graceful degradation & retry**: pipeline continua com resultados parciais quando IA ou scanners falham; retry inteligente com backoff exponencial para erros transientes
- **SHA-256 plan hash cache**: cache de respostas IA usa hash do plano como chave primária para invalidação precisa
- **MkDocs Material documentation site**: documentação completa migrada para site estático com tema Material, toggle dark/light, navegação em pt-BR
- **Scoring methodology docs**: `SCORING.md` com metodologia detalhada e flag `--explain-scores` para decomposição de scores
- **Integration test fixtures**: 20 fixtures de saída de scanners (checkov, tfsec, terrascan) com 29 testes de integração
- **Sensitive data sanitizer**: redação automática de dados sensíveis (API keys, tokens, passwords) antes do envio para análise IA

### Changed
- `gemini-cli` default model: `gemini-2.5-flash` → `gemini-2.5-pro` (mais confiável)
- `gemini-cli` suggested models: removidos `gemini-2.5-flash` e `gemini-3.1-pro-preview` (instáveis/timeout)
- `openrouter` default model: `google/gemini-2.5-flash` → `google/gemini-2.5-pro`

### Fixed
- Gemini CLI model resolution errors (`ModelNotFoundError`) resolved by updating default model
- `gemini-3.1-pro-preview` removed due to persistent context deadline timeouts

---

## [0.3.0] — 2026-03-01

### Added
- Persistent AI response cache on disk (`~/.terraview/cache/`) with configurable TTL
- `cache status` and `cache clear` commands to manage the AI cache
- Configurable resource limit for AI prompts (`max_resources`, default: 30)
- API key validation without token consumption (preflight check)
- Full configuration example in `examples/.terraview.yaml` with all documented fields
- OpenSSF Scorecard workflow for continuous repository security assessment
- OpenSSF Scorecard and Go Report Card badges in READMEs
- GolangCI-lint integration with 18 enabled linters (gosec, gocritic, unparam, noctx, bodyclose, etc.)
- `internal/i18n` module for centralized bilingual strings
- `internal/util` module for shared constants and utilities

### Changed
- Default models updated to cost-effective alternatives across all providers:
  - `claude`: claude-sonnet-4-5 → claude-haiku-4-5
  - `openai`: gpt-4o → gpt-4o-mini
  - `gemini`: gemini-2.5-pro → gemini-2.5-flash
  - `openrouter`: anthropic/claude-opus-4.6 → google/gemini-2.5-flash
  - `gemini-cli`: gemini-2.5-pro → gemini-2.5-flash
  - `claude-code`: claude-sonnet-4-5 → claude-haiku-4-5
- `executeReview` refactored into modular functions: `resolveReviewConfig`, `parsePlan`, `runScanners`, `mergeAndScore`, `renderOutput`
- Prompt compression pipeline optimized with adaptive token budget
- Security and code quality audit with all linter issues resolved
- `setup` command simplified and refactored

### Removed
- `terraview upgrade` command removed — updates are now handled by package managers (Homebrew, Scoop, APT, DNF)
- `--ai` flag removed (deprecated). AI is enabled by default when a provider is configured; use `--static` to disable
- `internal/compress` module removed (replaced by integrated pipeline)

### Fixed
- Version fallback to `dev` when git tags are unavailable
- SARIF: correct `semanticVersion` field and schema validation
- HTTP read limit to prevent OOM on large responses
- Config file parsing error handling
- gofmt/goimports formatting fixes across ~15 files
- `noctx` in downloader: `client.Get()` replaced with `http.NewRequestWithContext()`

## [0.2.5] — 2026-02-27

### Added
- Subscription-based AI providers: `gemini-cli` and `claude-code` (subprocess + JSON)
- CI/CD pipeline with supply chain hardening: SBOM, cosign, SLSA Build Provenance Level 3
- Continuous fuzz testing (`FuzzParse`, `FuzzNormalizeAction`)
- SAST with Semgrep, secret scanning with Gitleaks
- OSV Scanner + govulncheck for dependency CVEs
- Docker Scout in the release pipeline
- Shell completions via `terraview completion bash|zsh|fish|powershell`
- `CONTRIBUTING.md`, `SECURITY.md`, issue templates and PR template
- Homebrew tap: `brew install leonamvasquez/terraview/terraview`
- .deb and .rpm package publishing on Cloudsmith
- Dark/light theme logo in README

### Changed
- Updated Go 1.24 → 1.26
- Cobra v1.8.0 → v1.10.2, pflag v1.0.5 → v1.0.10
- `provider install llm` renamed to `provider install ollama`
- README: installation examples now use native Linux commands (apt, dnf, scoop)

### Fixed
- Interactive model selector: visual overflow with long text
- `eraseLines` line count incorrect with long detail items
- gemini-cli: removed `--sandbox` which requires privileged Docker
- Windows: 4 compatibility bugs fixed
- Fuzz tests: `context deadline exceeded` handled as expected timeout

## [0.2.0] — 2025-10-xx

### Added
- Providers: DeepSeek, OpenRouter
- Risk clusters with weighted risk scoring
- Impact analysis via `--impact`
- Security and code quality audit
- Spinner animations during long operations

## [0.1.0] — 2025-01-xx

### Added
- MVP: scan with Checkov, tfsec, Terrascan
- AI review via Ollama (local), Gemini, Claude, OpenAI
- Scorecard with Security, Compliance, Maintainability scores
- ASCII infrastructure diagram
- Drift detection with `--intelligence`
- Semantic exit codes (0/1/2) for CI/CD
- SARIF output for GitHub Actions
- Package manager updates (Homebrew, Scoop, APT, DNF)
- `tv` alias

[0.6.0]: https://github.com/leonamvasquez/terraview/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/leonamvasquez/terraview/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/leonamvasquez/terraview/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/leonamvasquez/terraview/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/leonamvasquez/terraview/compare/v0.2.5...v0.3.0
[0.2.5]: https://github.com/leonamvasquez/terraview/compare/v0.2.0...v0.2.5
[0.2.0]: https://github.com/leonamvasquez/terraview/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/leonamvasquez/terraview/releases/tag/v0.1.0
