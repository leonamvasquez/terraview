# Arquitetura

## Visão geral do pipeline

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              terraview CLI                                │
│  scan | apply | diagram | explain | drift | provider | scanners | cache   │
└────────────────────────────────┬──────────────────────────────────────────┘
                                 │
                        ┌────────┴────────┐
                        ▼                 ▼
               Terraform Executor    Plan JSON (--plan)
                   init + plan            │
                   show -json             │
                        │                 │
                        └───────┬─────────┘
                                ▼
                   ┌─────────────────────────┐
                   │   Parser + Normalizer   │
                   │   NormalizedResource[]  │
                   └────────────┬────────────┘
                                │
                                ▼
                   ┌─────────────────────────┐
                   │     Topology Graph      │
                   └────────────┬────────────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
                     ▼                     ▼
          ┌─────────────────┐    ┌─────────────────┐
          │ Plan (original) │    │    Sanitizer    │
          │                 │    │  Plan (redacted)│
          └────────┬────────┘    └────────┬────────┘
                   │                      │
                   │             ┌────────┴────────┐
                   │             │    AI Cache     │
                   │             │  SHA256 + TTL   │
                   │             └───┬─────────┬───┘
                   │                 │         │
                   │              hit│     miss│
                   │                 │         ▼
          ┌────────┴───────┐         │   ┌─────────────────┐
          │   Scanner      │         │   │  AI Context     │
          │  ┌───────────┐ │         │   │  Analysis       │
          │  │ Checkov   │ │         │   └────────┬────────┘
          │  │ tfsec     │ │         │            │
          │  │ Terrascan │ │         │            ▼
          │  └───────────┘ │         │  ┌─────────────────┐
          └────────┬───────┘         │  │    Validator    │
                   │                 │  └────────┬────────┘
                   │                 │           │
                   └────────┬────────┴───────────┘
                            ▼
             ┌──────────────────────────┐
             │  Normalizer + Resolver   │
             │  Confidence Scorer       │
             └────────────┬─────────────┘
                          ▼
             ┌──────────────────────────┐
             │  Aggregator + Scorer     │
             │  ┌────────────────────┐  │
             │  │ Security      0-10 │  │
             │  │ Compliance    0-10 │  │
             │  │ Maintainab.   0-10 │  │
             │  │ Overall       0-10 │  │
             │  └────────────────────┘  │
             │  ┌────────────────────┐  │
             │  │ Risk Vectors       │  │
             │  │  network           │  │
             │  │  encryption        │  │
             │  │  identity          │  │
             │  │  governance        │  │
             │  │  observability     │  │
             │  └────────────────────┘  │
             │  Meta-analysis           │
             └────────────┬─────────────┘
                          ▼
             ┌──────────────────────────┐
             │  Output                  │
             │  pretty | compact | json │
             │  sarif  | markdown       │
             └──────────────────────────┘
```

## Componentes principais

### Parser + Normalizer

- Lê o plan JSON gerado pelo `terraform show -json`
- Normaliza recursos em `NormalizedResource[]` — estrutura unificada independente de provider cloud
- Informações extraídas: tipo, nome, endereço, valores de atributos, ações (create/update/delete)

### Topology Graph

- Constrói grafo de dependências entre recursos
- Usa 31 campos de referência para detectar relações (VPC → subnet → instance, etc.)
- Usado pelo diagrama ASCII, pela análise de impacto (blast radius) e pelo Validator

### Sanitizer

- Redacta valores sensíveis (passwords, tokens, ARNs, chaves PEM, JWTs, base64 longo) do plan JSON antes de enviar à IA
- Usa placeholders determinísticos (`[REDACTED-001]`, etc.) para preservar relações estruturais
- Produz um `RedactionManifest` para auditoria
- O plan original (não sanitizado) é usado pelos scanners locais

### Scanner (paralelo)

- Executa o scanner selecionado (Checkov, tfsec, Terrascan) como subprocesso
- Parseia a saída nativa e normaliza em `[]Finding`
- Degradação graciosa: se o scanner falhar, prossegue apenas com IA (confiança reduzida)

### AI Context Analysis (paralelo)

- Envia recursos sanitizados ao provider de IA para análise contextual
- Detecta: relações cross-resource, anti-patterns arquiteturais, vetores de risco
- Cache em disco (SHA-256 do plan como chave, TTL configurável)
- Retry inteligente: erros transientes (timeout, 429, 5xx) → retry com backoff; permanentes (401, 403) → falha imediata
- Degradação graciosa: se a IA falhar, prossegue apenas com scanner

### Validator

- Valida findings gerados pela IA contra o Topology Graph
- Descarta findings com `resource_id` inexistente no grafo (alucinações)
- Verifica tipo de recurso, severidade válida, campos obrigatórios preenchidos
- Remove duplicatas internas (mesmo recurso + categoria)
- Produz `ValidationReport` com findings válidos e descartados com motivos

### Normalizer + Resolver

- Deduplicação de findings entre scanner e IA
- Resolução de conflitos: scanner prevalece em divergência (confiança 0.80)
- Concordância entre fontes eleva confiança a 1.00
- Remediação do scanner enriquecida com contexto da IA quando ambos concordam

### Aggregator + Scorer

- Calcula scores 0–10 por categoria (Segurança, Compliance, Manutenibilidade)
- Risk Vectors: 5 eixos por recurso (network, encryption, identity, governance, observability) — 0–3 cada
- Pisos de proteção por severidade (MEDIUM não abaixa de 5.0, HIGH não abaixa de 2.0 sem CRITICAL)
- `--explain-scores` decompõe scores mostrando contribuição de cada finding
- Veredito e exit code

### Meta-analysis

- Correlação cross-tool entre findings de múltiplas fontes
- Recursos flagados por 2+ fontes recebem confiança elevada
- Detecção de gaps de cobertura (categorias sem findings, avisos de fonte única)
- Score unificado com penalidades por severidade + bônus por correlação

## Desenvolvimento

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make build        # build para plataforma atual
make test         # testes com race detection + coverage
make test-short   # testes rápidos (sem race detector)
make coverage     # relatório de cobertura HTML
make lint         # golangci-lint (ou go vet como fallback)
make clean        # remover artefatos de build
make dist         # build para todas as plataformas (linux/darwin/windows, amd64/arm64)
make docker-build # build da imagem Docker
make docker-run   # rodar no Docker com plan de exemplo
make install      # instalar localmente em ~/.local/bin + assets em ~/.terraview
make uninstall    # remover instalação local
make release      # criar draft de release no GitHub (requer gh CLI)
```

## Estrutura do projeto

```
cmd/                  # Comandos CLI (cobra)
internal/
  aggregator/         # Scoring, agregação e veredito
  ai/                 # Providers de IA e registry
  aicache/            # Cache em disco (SHA-256) + memória
  bininstaller/       # Instalador de binários (scanners)
  blast/              # Análise de impacto (blast radius)
  config/             # Configuração e persistência
  contextanalysis/    # Análise contextual de recursos
  diagram/            # Diagrama ASCII da infraestrutura
  downloader/         # Download de releases GitHub
  drift/              # Detecção e classificação de drift
  explain/            # Explicação em linguagem natural
  feature/            # Feature flags e detecção
  i18n/               # Internacionalização (en/pt-BR)
  importer/           # Importação de findings externos
  installer/          # Instalação de scanners
  meta/               # Meta-análise cross-tool
  normalizer/         # Deduplicação e normalização
  output/             # Formatadores de saída (pretty, json, sarif, md)
  parser/             # Parser de planos Terraform
  platform/           # Detecção de OS/arch
  regression/         # Detecção de regressões entre scans
  resolver/           # Resolução de conflitos scanner × IA
  riskvec/            # Vetores de risco (5 eixos)
  rules/              # Motor de regras e findings
  runtime/            # Detecção de runtime (Ollama, etc.)
  sanitizer/          # Redação de secrets antes da IA
  scanner/            # Integração com scanners externos
  scoring/            # Scores 0-10 + decomposição
  terraformexec/      # Executor de terraform (init/plan/show)
  topology/           # Grafo de dependências (31 ref fields)
  util/               # Utilitários compartilhados
  validator/          # Validação de findings da IA contra o grafo
  workspace/          # Detecção de workspace Terraform
prompts/              # Templates de prompts para IA
profiles/             # Perfis de severidade configuráveis
examples/             # Exemplos de configuração
```
