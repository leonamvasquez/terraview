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

