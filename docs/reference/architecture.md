# Arquitetura

## Visão geral do pipeline

```
┌───────────────────────────────────────────────────────────────────────────┐
│                              terraview CLI                                │
│  scan | apply | diagram | explain | drift | provider | scanners | cache  │
└────────────────────────────────┬──────────────────────────────────────────┘
                                 │
                        ┌────────┴────────┐
                        ▼                 ▼
               Terraform Executor    Plan JSON (--plan)
                   init + plan           │
                   show -json            │
                        │                │
                        └───────┬────────┘
                                ▼
                   ┌─────────────────────────┐
                   │   Parser + Normalizer    │
                   │   NormalizedResource[]   │
                   └────────────┬────────────┘
                                │
                                ▼
                       Topology Graph
                       (30+ ref fields)
                                │
               ┌────────────────┼────────────────┐
               │           PARALLEL              │
               ▼                                 ▼
      ┌──────────────┐              ┌──────────────────┐
      │   Scanner    │              │  AI Context      │
      │  Checkov     │              │  Analysis        │
      │  tfsec       │              │  (cross-resource │
      │  Terrascan   │              │   relationships, │
      │              │              │   risk vectors)  │
      └──────┬───────┘              └────────┬─────────┘
             │                               │
             │                      ┌────────┴─────────┐
             │                      │  AI Cache        │
             │                      │  (disk, TTL 24h) │
             │                      └────────┬─────────┘
             │                               │
             └──────────┬────────────────────┘
                        ▼
             ┌─────────────────────┐
             │  Normalizer         │ deduplicar scanner + AI
             │  Resolver           │ mesmo recurso+categoria → scanner prevalece
             └──────────┬──────────┘
                        ▼
             ┌─────────────────────┐
             │  Aggregator         │ scores 0-10 (segurança, compliance, manutenib.)
             │  Scorer             │ veredito + exit code
             │  Meta-analysis      │ correlação cross-tool
             └──────────┬──────────┘
                        ▼
             ┌─────────────────────┐
             │  Output             │
             │  pretty | compact   │
             │  json | sarif | md  │
             └─────────────────────┘
```

## Componentes principais

### Parser + Normalizer

- Lê o plan JSON gerado pelo `terraform show -json`
- Normaliza recursos em `NormalizedResource[]` — estrutura unificada independente de provider cloud
- Informações extraídas: tipo, nome, endereço, valores de atributos, ações (create/update/delete)

### Topology Graph

- Constrói grafo de dependências entre recursos
- Usa 30+ campos de referência para detectar relações (VPC → subnet → instance, etc.)
- Usado pelo diagrama ASCII e pela análise de impacto (blast radius)

### Scanner (paralelo)

- Executa o scanner selecionado (Checkov, tfsec, Terrascan) como subprocesso
- Parseia a saída nativa e normaliza em `[]Finding`
- Degradação graciosa: se o scanner falhar, prossegue apenas com IA (confiança reduzida)

### AI Context Analysis (paralelo)

- Envia recursos normalizados ao provider de IA para análise contextual
- Detecta: relações cross-resource, anti-patterns arquiteturais, vetores de risco
- Cache em disco (SHA-256 do plan como chave, TTL configurável)
- Retry inteligente: erros transientes (timeout, 429, 5xx) → retry com backoff; permanentes (401, 403) → falha imediata
- Degradação graciosa: se a IA falhar, prossegue apenas com scanner

### Normalizer + Resolver

- Deduplicação de findings entre scanner e IA
- Resolução de conflitos: scanner prevalece em divergência
- Concordância entre fontes eleva confiança

### Aggregator + Scorer

- Calcula scores 0–10 por categoria (Segurança, Compliance, Manutenibilidade)
- Blending de confiabilidade
- Pisos de proteção por severidade
- Veredito e exit code

### Meta-analysis

- Correlação cross-tool entre findings de múltiplas fontes
- Score unificado separado
- Contagem de concordâncias

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
  ai/                 # Providers de IA e registry
  parser/             # Parser de planos Terraform
  rules/              # Motor de regras e findings
  scanner/            # Integração com scanners externos
  config/             # Configuração e persistência
  output/             # Formatadores de saída
  aggregator/         # Scoring e agregação
  normalizer/         # Deduplicação e normalização
  topology/           # Grafo de dependências
  diagram/            # Diagrama ASCII
  blast/              # Análise de impacto
  drift/              # Detecção de drift
  ...
prompts/              # Templates de prompts para IA
profiles/             # Perfis de severidade configuráveis
examples/             # Exemplos de planos Terraform
```
