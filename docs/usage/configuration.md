# Configuração

O terraview pode ser configurado com um arquivo YAML. Por padrão, procura `.terraview.yaml` nos seguintes locais (em ordem de precedência):

1. Diretório do projeto (passado via `--dir`)
2. Diretório de trabalho atual
3. Home do usuário (`~/.terraview/.terraview.yaml`)

## Exemplo completo

Veja [`examples/.terraview.yaml`](https://github.com/leonamvasquez/terraview/blob/main/examples/.terraview.yaml) para referência completa com todos os campos documentados.

!!! warning "Aviso"
    Nunca commite `api_key` diretamente no `.terraview.yaml`. Prefira variáveis de ambiente (`ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.) ou adicione `.terraview.yaml` ao seu `.gitignore`. O terraview emite um aviso em stderr quando detecta `api_key` no arquivo de config.

```yaml
llm:
  enabled: true
  provider: ollama              # ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code
  model: llama3.1:8b            # modelo específico do provider
  url: http://localhost:11434   # URL customizada (relevante apenas para ollama)
  # api_key: ""                 # prefira variáveis de ambiente (ver aviso acima)
  timeout_seconds: 120          # timeout para chamadas LLM
  temperature: 0.2              # 0.0 a 1.0 (menor = mais determinístico)
  max_resources: 30             # máximo de recursos no prompt IA (padrão: 30)
  cache: false                  # habilitar cache persistente de respostas IA
  cache_ttl_hours: 24           # TTL do cache em horas (padrão: 24)
  ollama:
    num_ctx: 4096               # janela de contexto do modelo (padrão: 4096)
    max_threads: 0              # 0 = usar todos os CPUs
    max_memory_mb: 0            # 0 = sem limite
    min_free_memory_mb: 1024    # memória livre mínima para iniciar Ollama

scanner:
  default: checkov              # scanner padrão para "terraview scan"

scoring:
  severity_weights:
    critical: 5.0
    high: 3.0
    medium: 1.0
    low: 0.5

rules:
  required_tags:                # tags obrigatórias em todos os recursos
    - Environment
    - Owner
    - CostCenter
  disabled_rules:               # silenciar rule IDs específicos
    - CKV_AWS_79
  # enabled_rules: []           # se definido, apenas estas rules são avaliadas

output:
  format: pretty                # pretty, compact, json, sarif
```

## Seções de configuração

### `llm`

Configura o provider de IA e parâmetros da análise contextual.

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `enabled` | bool | `true` | Habilita/desabilita análise IA |
| `provider` | string | — | Provider de IA a usar |
| `model` | string | (varia) | Modelo específico do provider |
| `url` | string | — | URL customizada (apenas Ollama) |
| `api_key` | string | — | API key (prefira variáveis de ambiente) |
| `timeout_seconds` | int | `120` | Timeout para chamadas LLM |
| `temperature` | float | `0.2` | Temperatura de geração (0.0–1.0) |
| `max_resources` | int | `30` | Máximo de recursos no prompt |
| `cache` | bool | `false` | Habilitar cache persistente |
| `cache_ttl_hours` | int | `24` | TTL do cache em horas |

### `llm.ollama`

Configurações específicas para o provider Ollama (local).

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `num_ctx` | int | `4096` | Janela de contexto do modelo |
| `max_threads` | int | `0` | Threads (0 = todos os CPUs) |
| `max_memory_mb` | int | `0` | Memória máxima (0 = sem limite) |
| `min_free_memory_mb` | int | `1024` | Memória livre mínima |

### `scanner`

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `default` | string | `checkov` | Scanner padrão para `terraview scan` |

### `scoring`

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `severity_weights.critical` | float | `5.0` | Peso de findings CRITICAL |
| `severity_weights.high` | float | `3.0` | Peso de findings HIGH |
| `severity_weights.medium` | float | `1.0` | Peso de findings MEDIUM |
| `severity_weights.low` | float | `0.5` | Peso de findings LOW |

### `rules`

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `required_tags` | []string | — | Tags obrigatórias em recursos |
| `disabled_rules` | []string | — | Rule IDs a silenciar |
| `enabled_rules` | []string | — | Se definido, apenas estas rules |

### `output`

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `format` | string | `pretty` | Formato de saída padrão |
