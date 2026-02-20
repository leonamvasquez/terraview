![terraview](terraview.png)

**Escolha seu idioma:** [Português](README.md) | [English](README.en.md)

# terraview: Revisão Semântica de Planos Terraform com IA

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)

## Visão Geral

o **terraview** é uma ferramenta de linha de comando open-source que realiza **análise semântica de planos Terraform**, combinando regras determinísticas com revisão inteligente via múltiplos providers de IA (Ollama, Gemini, Claude, DeepSeek, OpenRouter).

100% local por padrão. Multi-provider de IA. Binário único sem dependências.

Ideal para times de DevOps, SRE e Platform Engineering que querem garantir qualidade, segurança e compliance da infraestrutura antes de qualquer `terraform apply`.

## Principais Diferenciais

- **Análise Determinística**: Regras YAML versionadas que detectam anti-padrões conhecidos (SGs abertos, criptografia ausente, IAM permissivo)
- **IA Multi-Provider**: Suporte a Ollama (local), Gemini, Claude, DeepSeek e OpenRouter com seleção interativa
- **100% Local por Padrão**: Nenhum dado enviado para servidores externos ao usar Ollama
- **Zero Configuração**: Detecta automaticamente projetos Terraform, roda `init + plan + show` sozinho
- **Seletor Interativo de IA**: `terraview ai list` abre um picker com setas do teclado para escolher provider e modelo
- **Scorecard Detalhado**: Scores de Segurança, Compliance, Manutenibilidade e Overall em escala 0-10
- **CI/CD Nativo**: Integração pronta com GitHub Actions e GitLab CI via exit codes semânticos
- **Auto-Atualização**: `terraview update` busca e instala a versão mais recente do GitHub
- **Alias nativo `tv`**: Instala o symlink `tv` automaticamente — `tv review` funciona igual a `terraview review`

## Instalação

### Script de instalação (recomendado)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Compilar do código-fonte

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Instalar o runtime de IA local (Ollama)

```bash
terraview install llm
```

Após a instalação:

```bash
terraview version   # ou: tv version
terraview --help
```

## Primeiros Passos

```bash
# Navegue para qualquer projeto Terraform
cd meu-projeto-terraform

# Revisar o plano (roda terraform init + plan automaticamente)
terraview review

# Usar o alias curto
tv review

# Revisar um plan.json existente
terraview review --plan plan.json

# Apenas regras determinísticas (sem IA)
terraview review --skip-llm

# Escolher provider de IA
terraview review --provider gemini
terraview review --provider claude
terraview review --provider openrouter

# Modo estrito (findings HIGH também retornam exit code 2)
terraview review --strict

# Verificar e aplicar o plano
terraview apply
```

## Comandos

### `terraview review`

Analisa um plano Terraform com regras determinísticas e revisão de IA.

Se `--plan` não for especificado, o terraview automaticamente:
1. Detecta arquivos `.tf` no diretório atual
2. Executa `terraform init` (se necessário)
3. Executa `terraform plan -out=tfplan`
4. Exporta `terraform show -json tfplan > plan.json`
5. Roda o pipeline de revisão

```bash
terraview review                          # detecção automática
terraview review --plan plan.json         # usar plan.json existente
terraview review --skip-llm               # apenas regras hard
terraview review --provider gemini        # usar Gemini
terraview review --model mistral:7b       # modelo específico
terraview review --format compact         # saída minimalista
terraview review --format json            # apenas review.json
```

### `terraview apply`

Roda a revisão completa e aplica o plano condicionalmente.

- **Bloqueia** se qualquer finding CRITICAL for detectado
- Exibe resumo e pede confirmação
- Use `--non-interactive` em pipelines CI/CD

```bash
terraview apply                           # interativo
terraview apply --non-interactive         # modo CI
```

### `terraview test`

Executa uma suíte de testes determinísticos (sem dependência de IA):

1. `terraform fmt -check` — verificação de formatação
2. `terraform validate` — validação de sintaxe
3. `terraform test` — testes nativos (Terraform 1.6+)
4. Regras hard — avaliação determinística

```bash
terraview test
terraview test --rules regras-customizadas.yaml
```

### `terraview drift`

Detecta e classifica drift de infraestrutura.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --format compact
```

### Gerenciamento de IA

#### `terraview ai list`

Abre um **seletor interativo** com setas do teclado para escolher o provider e modelo padrão. A escolha é salva globalmente em `~/.terraview/.terraview.yaml`.

```bash
terraview ai list      # seleção interativa
terraview ai use gemini gemini-2.0-flash   # definir sem interação (scripts/CI)
terraview ai current   # exibir provider atual
terraview ai test      # testar conectividade
```

#### `terraview install llm` / `terraview uninstall llm`

```bash
terraview install llm      # instalar Ollama + baixar modelo padrão
terraview uninstall llm    # remover Ollama e dados
```

### Utilitários

```bash
terraview version          # informações de versão
terraview update           # auto-atualização pelo GitHub
```

## Configuração (.terraview.yaml)

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

## Regras Disponíveis

As regras são definidas em YAML e suportam os seguintes operadores:

`equals` · `not_equals` · `contains` · `not_contains` · `exists` · `not_exists` · `is_true` · `is_false` · `is_action` · `contains_in_list`

### Regras Padrão

| ID | Nome | Severidade |
|----|------|------------|
| SEC001 | SSH Aberto para a Internet | HIGH |
| SEC002 | S3 Bucket sem Criptografia | HIGH |
| SEC003 | IAM Policy com Actions Wildcard | CRITICAL |
| SEC004 | IAM Policy com Resources Wildcard | HIGH |
| SEC005 | RDS Publicamente Acessível | HIGH |
| SEC006 | S3 Bucket com ACL Pública | HIGH |
| SEC007 | Security Group Permite Todo o Tráfego | CRITICAL |
| REL001 | RDS sem Multi-AZ | MEDIUM |
| REL002 | RDS sem Backup | HIGH |
| BP001 | S3 Bucket sem Versionamento | MEDIUM |
| BP002 | EBS Volume sem Criptografia | MEDIUM |
| COMP001 | CloudWatch Logs sem Retenção | LOW |
| TAG001 | Tags Obrigatórias Ausentes | MEDIUM |
| DEL001 | Exclusão de Recurso Crítico | HIGH |

### Regras Customizadas

```yaml
version: "1.0"
required_tags:
  - Environment
  - CostCenter
rules:
  - id: CUSTOM001
    name: Minha Regra Customizada
    description: "Descrição do que esta regra verifica"
    severity: HIGH
    category: security
    remediation: "Como corrigir"
    enabled: true
    targets:
      - aws_s3_bucket
    conditions:
      - field: algum_campo
        operator: equals
        value: "valor_ruim"
```

## Scores e Exit Codes

Os scores são calculados em escala 0-10 com penalidades ponderadas por severidade.

**Pesos de severidade:** CRITICAL=5.0, HIGH=3.0, MEDIUM=1.0, LOW=0.5, INFO=0.0

**Categorias:** Segurança (peso 3×), Compliance (2×), Manutenibilidade (1.5×), Confiabilidade (1×)

### Exit Codes

| Código | Significado |
|--------|-------------|
| 0 | Sem issues ou apenas MEDIUM/LOW/INFO |
| 1 | Findings de severidade HIGH |
| 2 | Findings CRITICAL (bloqueia o apply) |

## Integração CI/CD

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

      - name: Instalar terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Revisar plano
        run: terraview review --skip-llm

      - name: Comentar no PR
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

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│                      terraview CLI                      │
│   review │ apply │ test │ drift │ ai │ update │ install  │
└─────────────────────┬───────────────────────────────────┘
                      │
          ┌───────────┴────────────┐
          ▼                        ▼
┌─────────────────┐     ┌──────────────────────┐
│  Rules Engine   │     │    AI Providers       │
│  (YAML rules)   │     │  Ollama │ Gemini      │
│  Determinístico │     │  Claude │ DeepSeek    │
└────────┬────────┘     │  OpenRouter           │
         │              └──────────┬───────────┘
         │                         │
         └────────────┬────────────┘
                      ▼
          ┌───────────────────────┐
          │  Aggregator + Scorer  │
          │  review.json / .md    │
          └───────────────────────┘
```

## Desenvolvimento

```bash
make build        # compilar para a plataforma atual
make test         # executar testes com race detection
make test-short   # testes rápidos
make coverage     # relatório de cobertura
make dist         # build para todas as plataformas
make install      # instalar localmente (~/.local/bin)
make help         # listar todos os targets
```

## Roadmap

- [ ] Suporte a Azure e GCP
- [ ] Perfis de scoring customizáveis
- [ ] Formato de saída SARIF
- [ ] Análise com consciência de módulos Terraform
- [ ] Sistema de plugins para regras
- [ ] Histórico e tendências de scores
- [ ] Integração com políticas OPA/Rego

## Suporte e Contato

- **GitHub Issues**: [github.com/leonamvasquez/terraview/issues](https://github.com/leonamvasquez/terraview/issues)
- **GitHub Discussions**: [github.com/leonamvasquez/terraview/discussions](https://github.com/leonamvasquez/terraview/discussions)

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## Agradecimentos

- **Comunidade Open Source**: Go, Cobra, Terraform e todos os projetos que tornam este trabalho possível
- **Contribuidores**: Todos que reportam bugs, sugerem melhorias e enviam PRs
- **LINUXtips**: Pela inspiração e referência de como construir ferramentas de qualidade para a comunidade DevOps

---

## FAQ

**Q: O terraview funciona sem conexão com a internet?**
A: Sim. Usando Ollama como provider, toda a análise é feita localmente. Nenhum dado de infraestrutura é enviado para fora.

**Q: Preciso ter o Terraform instalado?**
A: Sim, se quiser usar a geração automática de planos (`terraview review` sem `--plan`). Se já tiver um `plan.json`, o Terraform não é necessário.

**Q: Como configuro um provider cloud (Gemini, Claude, etc.)?**
A: Execute `terraview ai list`, selecione o provider com as setas e confirme. O terraview mostrará qual variável de ambiente configurar (ex: `GEMINI_API_KEY`).

**Q: Posso usar o terraview em monorepos com múltiplos workspaces?**
A: Sim. Use `--dir` para especificar o workspace ou `--plan` com o `plan.json` gerado previamente.

**Q: Como atualizo para a versão mais recente?**
A: Execute `terraview update`. O comando verifica, baixa e instala automaticamente.

**Q: O que é o alias `tv`?**
A: Durante a instalação, é criado um symlink `tv -> terraview`. Você pode usar `tv review`, `tv ai list`, etc. como atalho.


## Install

```bash
# One-line install
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# Install LLM runtime (Ollama)
terraview install llm

# Or build from source
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

After installation:

```bash
terraview version
terraview --help
```

## Usage

```bash
# Navigate to any Terraform project
cd my-terraform-project

# Review the plan (auto-runs terraform init + plan if needed)
terraview review

# Review with an existing plan.json
terraview review --plan plan.json

# Review without AI (hard rules only)
terraview review --skip-llm

# Use a specific AI provider
terraview review --provider gemini
terraview review --provider claude
terraview review --provider deepseek

# Safe mode (light model, fewer resources)
terraview review --safe

# Output formats
terraview review --format compact          # minimal one-line output
terraview review --format json             # only write review.json

# Review, then apply if safe
terraview apply

# Run deterministic checks (no AI)
terraview test

# Detect infrastructure drift
terraview drift
```

## Philosophy: Infrastructure as Software

Infrastructure code deserves the same rigor as application code. This tool treats Terraform plans as first-class artifacts that should be reviewed with:

- **Deterministic rules** for known anti-patterns (open security groups, missing encryption, overly permissive IAM)
- **Semantic analysis** via AI for nuanced architectural and operational concerns
- **Versioned prompts** checked into source control alongside your infrastructure code
- **Structured output** that integrates into existing development workflows

## Commands

### Core Commands

#### `terraview review`

Analyzes a Terraform plan using deterministic rules and optional AI review.

If `--plan` is not specified, terraview automatically:
1. Detects `.tf` files in the current directory
2. Runs `terraform init` (if needed)
3. Runs `terraform plan -out=tfplan`
4. Exports `terraform show -json tfplan > plan.json`
5. Runs the review pipeline

```bash
terraview review                          # auto-detect and plan
terraview review --plan plan.json         # use existing plan
terraview review --skip-llm               # hard rules only
terraview review --provider gemini        # use Gemini AI
terraview review --model mistral:7b       # different model
terraview review --format compact         # minimal output
terraview review --strict                 # HIGH returns exit code 2
terraview review --safe                   # safe mode
```

#### `terraview apply`

Runs a full review, then conditionally applies the plan.

- **Blocks** if any CRITICAL findings are detected
- Shows review summary and asks for confirmation
- Use `--non-interactive` for CI pipelines

```bash
terraview apply                           # interactive
terraview apply --non-interactive         # CI mode
```

#### `terraview test`

Runs a deterministic test suite (no AI dependency):

1. `terraform fmt -check` — formatting verification
2. `terraform validate` — syntax and configuration checks
3. `terraform test` — native tests (Terraform 1.6+, if available)
4. Hard rules — deterministic rule evaluation

Exit codes: 0 = all passed, 1 = execution error, 2 = rule violations

```bash
terraview test
terraview test --rules custom-rules.yaml
```

#### `terraview drift`

Detect and classify infrastructure drift.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --format compact
```

### AI Management

#### `terraview ai`

Manage AI providers.

```bash
terraview ai list                         # list all providers and status
terraview ai current                      # show active provider
terraview ai test                         # validate provider connectivity
```

#### `terraview install llm`

Install the Ollama LLM runtime.

```bash
terraview install llm                     # install Ollama + pull default model
```

#### `terraview uninstall llm`

Remove the Ollama LLM runtime.

```bash
terraview uninstall llm                   # remove Ollama + data
```

### Utilities

```bash
terraview version                         # show version info
terraview update                          # self-update from GitHub
```

## CLI Flags

### Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--verbose, -v` | `false` | Enable verbose output |
| `--dir, -d` | `.` | Terraform workspace directory |

### Review Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--plan, -p` | (auto) | Path to plan JSON (auto-generates if omitted) |
| `--rules, -r` | (bundled) | Path to rules YAML file |
| `--prompts` | (bundled) | Path to prompts directory |
| `--output, -o` | `.` | Output directory for review files |
| `--provider` | (config) | AI provider (ollama, gemini, claude, deepseek) |
| `--model` | (config) | AI model to use |
| `--ollama-url` | (config) | Ollama server URL (legacy) |
| `--timeout` | (config) | AI request timeout in seconds |
| `--temperature` | (config) | AI temperature (0.0-1.0) |
| `--skip-llm` | `false` | Skip AI analysis |
| `--format` | `pretty` | Output format: pretty, compact, json |
| `--strict` | `false` | HIGH findings also return exit code 2 |
| `--safe` | `false` | Safe mode: light model, reduced resources |

### Apply Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--non-interactive` | `false` | Skip confirmation prompt (for CI) |
| All review flags | | Same as review command |

## Configuration (.terraview.yaml)

```yaml
llm:
  enabled: true
  provider: ollama                    # ollama, gemini, claude, deepseek
  model: llama3.1:8b
  url: http://localhost:11434
  api_key: ""                         # for cloud providers
  timeout_seconds: 120
  temperature: 0.2
  ollama:
    max_threads: 0                    # 0 = use all CPUs
    max_memory_mb: 0                  # 0 = no limit
    min_free_memory_mb: 1024

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
  rule_packs:
    - default
    - enterprise-security

output:
  format: pretty                      # pretty, compact, json
```

## Hard Rules

Rules are defined in YAML and support these condition operators:

- `equals` / `not_equals` — exact string match
- `contains` / `not_contains` — substring search
- `exists` / `not_exists` — field presence check
- `is_true` / `is_false` — boolean check
- `is_action` — match resource action (create, delete, update, replace)
- `contains_in_list` — check if list contains value

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
    description: "Description of what this checks"
    severity: HIGH
    category: security
    remediation: "How to fix it"
    enabled: true
    targets:
      - aws_s3_bucket
    conditions:
      - field: some_field
        operator: equals
        value: "bad_value"
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No issues or MEDIUM/LOW/INFO only |
| 1 | HIGH severity findings |
| 2 | CRITICAL severity findings (blocks apply) |

## CI Integration

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

      - name: Review
        run: terraview review --skip-llm

      - name: Post PR Comment
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

## Scoring

Scores are calculated on a 0-10 scale using weighted penalties:

**Severity weights:** CRITICAL=5.0, HIGH=3.0, MEDIUM=1.0, LOW=0.5, INFO=0.0

**Category weights:** Security=2.0, Compliance=1.5, Reliability=1.5, Best Practice=1.0, Maintainability=1.0

## Development

```bash
make build       # Build for current platform
make test        # Run tests with race detection
make dist        # Build for all platforms
make install     # Install locally
make help        # Show all targets
```

## Roadmap

- [ ] Azure and GCP rule sets
- [ ] Custom scoring profiles
- [ ] SARIF output format
- [ ] Terraform module-aware analysis
- [ ] Plugin system for custom rules
- [ ] Historical trend tracking
- [ ] Integration with OPA/Rego policies

## License

MIT
