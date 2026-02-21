![terraview](terraview.png)

**Escolha seu idioma:** [Português](README.md) | [English](README.en.md)

# terraview: Escaneamento de Segurança e Revisão com IA para Planos Terraform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.24+-blue.svg)](https://golang.org)

## Visão Geral

O **terraview** é uma ferramenta de linha de comando open-source que realiza **análise de segurança de planos Terraform**, combinando scanners externos (Checkov, tfsec, Terrascan, KICS) com revisão inteligente via múltiplos providers de IA (Ollama, Gemini, Claude, DeepSeek, OpenRouter).

Scanners rodam por padrão. IA é opt-in. Binário único sem dependências.

Ideal para times de DevOps, SRE e Platform Engineering que querem garantir segurança e compliance da infraestrutura antes de qualquer `terraform apply`.

## Principais Diferenciais

- **Security Scanners**: Integração automática com Checkov, tfsec, Terrascan e KICS — detecta o que está instalado e roda automaticamente
- **IA Multi-Provider**: Suporte a Ollama (local), Gemini, Claude, DeepSeek e OpenRouter com seleção interativa
- **Zero Configuração**: Detecta automaticamente projetos Terraform, roda `init + plan + show` sozinho
- **Seletor Interativo de Providers**: `terraview provider list` abre um picker com setas do teclado para escolher provider e modelo
- **Scorecard Detalhado**: Scores de Segurança, Compliance, Manutenibilidade e Overall em escala 0-10
- **Diagrama de Infraestrutura**: `--diagram` gera um diagrama ASCII da infraestrutura no plano
- **Blast Radius**: `--blast-radius` analisa o raio de impacto das mudanças
- **Code Smells**: `--smell` detecta anti-padrões de design na infraestrutura
- **Score Trends**: `--trend` rastreia e exibe tendências de scores ao longo do tempo
- **CI/CD Nativo**: Integração pronta com GitHub Actions e GitLab CI via exit codes semânticos
- **Auto-Atualização**: `terraview upgrade` busca e instala a versão mais recente do GitHub
- **Alias nativo `tv`**: Instala o symlink `tv` automaticamente — `tv plan` funciona igual a `terraview plan`

## Instalação

### Linux / macOS

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

> Se o PowerShell reclamar de política de execução, rode antes:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

O instalador baixa o binário `terraview.exe`, cria o alias `tv.exe` e adiciona tudo ao `PATH` do usuário automaticamente.

**Alternativa — download manual no Windows:**

```powershell
# Baixar o binário (substitua <VERSION> pela versão, ex: v0.1.0)
curl.exe -Lo terraview.exe https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-windows-amd64.exe

# Mover para um diretório no PATH
move terraview.exe C:\Windows\
```

### Compilar do código-fonte

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

### Instalar o runtime de IA local (Ollama)

```bash
terraview provider install
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

# Analisar o plano (roda terraform init + plan + scanners automaticamente)
terraview plan

# Usar o alias curto
tv plan

# Analisar um plan.json existente
terraview plan --plan plan.json

# Scanners + revisão com IA
terraview plan --ai

# Escolher provider de IA
terraview plan --ai --provider gemini
terraview plan --ai --provider claude
terraview plan --ai --provider openrouter

# Rodar scanners específicos
terraview plan --scanners checkov,tfsec

# Diagrama de infraestrutura
terraview plan --diagram

# Blast radius das mudanças
terraview plan --blast-radius

# Modo estrito (findings HIGH também retornam exit code 2)
terraview plan --strict

# Verificar e aplicar o plano
terraview apply
```

## Comandos

### `terraview plan`

Analisa um plano Terraform com scanners de segurança e revisão opcional de IA.

Se `--plan` não for especificado, o terraview automaticamente:
1. Detecta arquivos `.tf` no diretório atual
2. Executa `terraform init` (se necessário)
3. Executa `terraform plan -out=tfplan`
4. Exporta `terraform show -json tfplan > plan.json`
5. Roda os scanners e o pipeline de revisão

```bash
terraview plan                                # detecção automática + scanners
terraview plan --plan plan.json               # usar plan.json existente
terraview plan --ai                           # scanners + revisão com IA
terraview plan --ai --provider gemini         # usar Gemini
terraview plan --ai --model mistral:7b        # modelo específico
terraview plan --scanners checkov,tfsec       # scanners específicos
terraview plan --diagram                      # diagrama de infraestrutura
terraview plan --blast-radius                 # raio de impacto
terraview plan --smell                        # detectar code smells
terraview plan --trend                        # tendências de scores
terraview plan --format compact               # saída minimalista
terraview plan --format json                  # apenas review.json
terraview plan --format sarif                 # saída SARIF para CI
terraview plan --strict                       # HIGH retorna exit code 2
terraview plan --safe                         # modo seguro (modelo leve)
terraview plan --profile prod                 # perfil de revisão produção
terraview plan --findings checkov.json        # importar findings externos
```

> **Alias:** `terraview review` funciona como alias para `terraview plan`.

### `terraview apply`

Roda a revisão completa e aplica o plano condicionalmente.

- **Bloqueia** se qualquer finding CRITICAL for detectado
- Exibe resumo e pede confirmação
- Use `--non-interactive` em pipelines CI/CD

```bash
terraview apply                           # interativo
terraview apply --non-interactive         # modo CI
terraview apply --ai                      # revisão com IA + apply
```

### `terraview validate`

Executa uma suíte de validação determinística (sem dependência de IA):

1. `terraform fmt -check` — verificação de formatação
2. `terraform validate` — validação de sintaxe
3. `terraform test` — testes nativos (Terraform 1.6+)
4. Security Scanners — avaliação com scanners externos

```bash
terraview validate
terraview validate -v                     # modo verboso
```

> **Alias:** `terraview test` funciona como alias para `terraview validate`.

### `terraview drift`

Detecta e classifica drift de infraestrutura.

```bash
terraview drift
terraview drift --plan plan.json
terraview drift --intelligence            # classificação avançada + risk score
terraview drift --format compact
terraview drift --format json
```

### `terraview explain`

Gera uma explicação em linguagem natural da infraestrutura usando IA.

```bash
terraview explain
terraview explain --plan plan.json
terraview explain --provider gemini
terraview explain --format json
```

### Gerenciamento de Providers

#### `terraview provider list`

Abre um **seletor interativo** com setas do teclado para escolher o provider e modelo padrão. A escolha é salva globalmente em `~/.terraview/.terraview.yaml`.

```bash
terraview provider list                            # seleção interativa
terraview provider use gemini gemini-2.0-flash     # definir sem interação (scripts/CI)
terraview provider current                         # exibir provider atual
terraview provider test                            # testar conectividade
```

> **Alias:** `terraview ai` funciona como alias para `terraview provider`.

#### `terraview provider install` / `terraview provider uninstall`

```bash
terraview provider install      # instalar Ollama + baixar modelo padrão
terraview provider uninstall    # remover Ollama e dados
```

### Utilitários

```bash
terraview version          # informações de versão
terraview upgrade          # auto-atualização pelo GitHub
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

output:
  format: pretty                # pretty, compact, json, sarif
```

## Security Scanners

O terraview integra automaticamente com os seguintes scanners externos. Basta tê-los instalados — o terraview detecta e roda automaticamente (`--scanners auto`).

| Scanner | Descrição | Instalação |
|---------|-----------|------------|
| [Checkov](https://www.checkov.io/) | Scanner de segurança e compliance para IaC | `pip install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Análise estática de segurança para Terraform | `brew install tfsec` |
| [Terrascan](https://runterrascan.io/) | Detector de violations e compliance | `brew install terrascan` |
| [KICS](https://kics.io/) | Keeping Infrastructure as Code Secure | `brew install kics` |

Os findings de todos os scanners são normalizados, agregados e exibidos em um scorecard unificado.

```bash
terraview plan                              # roda todos os scanners disponíveis
terraview plan --scanners checkov,tfsec     # roda apenas os especificados
terraview plan --findings checkov.json      # importa findings de execução externa
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

      - name: Instalar Checkov
        run: pip install checkov

      - name: Instalar terraview
        run: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

      - name: Revisar plano
        run: terraview plan

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
    - pip install checkov
    - curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
    - terraview plan
  artifacts:
    paths: [review.json, review.md]
    when: always
```

## Arquitetura

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

- [x] Formato de saída SARIF
- [x] Histórico e tendências de scores
- [x] Perfis de scoring customizáveis
- [x] Integração com scanners externos (Checkov, tfsec, Terrascan, KICS)
- [x] Diagrama ASCII de infraestrutura
- [x] Análise de blast radius
- [x] Detecção de code smells
- [ ] Suporte a Azure e GCP
- [ ] Análise com consciência de módulos Terraform
- [ ] Integração com políticas OPA/Rego

## Suporte e Contato

- **GitHub Issues**: [github.com/leonamvasquez/terraview/issues](https://github.com/leonamvasquez/terraview/issues)
- **GitHub Discussions**: [github.com/leonamvasquez/terraview/discussions](https://github.com/leonamvasquez/terraview/discussions)

## Licença

Este projeto é distribuído sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

---

## FAQ

**Q: O terraview funciona sem conexão com a internet?**
A: Sim. Os scanners rodam localmente e, usando Ollama como provider de IA, toda a análise é feita sem enviar dados para fora.

**Q: Preciso ter o Terraform instalado?**
A: Sim, se quiser usar a geração automática de planos (`terraview plan` sem `--plan`). Se já tiver um `plan.json`, o Terraform não é necessário.

**Q: Preciso ter algum scanner instalado?**
A: Recomendado, mas não obrigatório. O terraview detecta automaticamente quais scanners estão disponíveis (`--scanners auto`). Sem nenhum scanner, apenas o pipeline de IA pode ser usado com `--ai`.

**Q: Como configuro um provider cloud (Gemini, Claude, etc.)?**
A: Execute `terraview provider list`, selecione o provider com as setas e confirme. O terraview mostrará qual variável de ambiente configurar (ex: `GEMINI_API_KEY`).

**Q: Posso usar o terraview em monorepos com múltiplos workspaces?**
A: Sim. Use `--dir` para especificar o workspace ou `--plan` com o `plan.json` gerado previamente.

**Q: Como atualizo para a versão mais recente?**
A: Execute `terraview upgrade`. O comando verifica, baixa e instala automaticamente.

**Q: O que é o alias `tv`?**
A: Durante a instalação, é criado um symlink `tv -> terraview`. Você pode usar `tv plan`, `tv provider list`, etc. como atalho.

**Q: Qual a diferença entre `terraview plan` e `terraview validate`?**
A: `plan` roda scanners e opcionalmente IA para uma análise completa. `validate` roda verificações determinísticas rápidas (fmt, validate, test, scanners) sem suporte a IA — ideal para pré-commit ou CI rápido.

