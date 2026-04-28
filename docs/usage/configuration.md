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
  provider: ollama              # ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code, custom
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
  custom:                       # policy-as-code: regras nativas declaradas em YAML
    - id: ORG_S3_001
      severity: HIGH
      category: security
      message: "Bucket S3 sem tag 'DataClassification'"
      remediation: "Adicione a tag DataClassification (public|internal|confidential)"
      resource_type: aws_s3_bucket
      condition:
        field: tags.DataClassification
        op: not_null

history:
  enabled: true                 # habilitar gravação automática de resultados
  retention_days: 90            # auto-limpeza de registros antigos
  max_size_mb: 50               # tamanho máximo do banco SQLite

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
| `custom` | []CustomRule | — | Regras customizadas (policy-as-code) — ver abaixo |

### `rules.custom` — policy-as-code

Regras customizadas declaradas no `.terraview.yaml` são avaliadas pelo engine nativo do terraview, sem necessidade de Rego, Sentinel ou ferramenta externa. Cada regra produz um finding quando a condição dispara para um recurso.

**Campos da regra**

| Campo | Tipo | Obrigatório | Descrição |
|-------|------|-------------|-----------|
| `id` | string | sim | Identificador único (ex.: `ORG_S3_001`) |
| `severity` | string | sim | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` ou `INFO` |
| `category` | string | não | `security`, `compliance`, `best-practice`, `maintainability` ou `reliability` (padrão: `best-practice`) |
| `message` | string | sim | Texto exibido no finding |
| `remediation` | string | não | Instrução de correção |
| `resource_type` | string | não | Filtra a regra por tipo (ex.: `aws_s3_bucket`); se omitido, aplica a todos |
| `condition.field` | string | sim | Caminho dot-notation do atributo (ex.: `tags.team`, `versioning.enabled`) |
| `condition.op` | string | sim | Operador (ver tabela) |
| `condition.value` | string | depende | Valor de comparação (não usado em `is_null`/`not_null`) |

**Operadores suportados**

| Op | Dispara quando… |
|----|-----------------|
| `is_null` | campo ausente, `nil` ou string vazia |
| `not_null` | campo ausente, `nil` ou string vazia (alias semântico: campo é obrigatório) |
| `equals` | campo `≠` `value` |
| `not_equals` | campo `==` `value` |
| `contains` | campo NÃO contém `value` |
| `not_contains` | campo CONTÉM `value` |
| `matches` | campo NÃO casa com a regex `value` |
| `not_matches` | campo CASA com a regex `value` |

**Exemplos**

```yaml
rules:
  custom:
    # Exigir tag DataClassification em todos os buckets S3
    - id: ORG_S3_001
      severity: HIGH
      category: security
      message: "Bucket S3 sem tag 'DataClassification'"
      remediation: "Adicione tags = { DataClassification = 'public|internal|confidential' }"
      resource_type: aws_s3_bucket
      condition:
        field: tags.DataClassification
        op: not_null

    # Bloquear instâncias EC2 fora do padrão "t3.*"
    - id: ORG_EC2_001
      severity: MEDIUM
      message: "Tipo de instância fora do padrão corporativo (apenas t3.*)"
      resource_type: aws_instance
      condition:
        field: instance_type
        op: matches
        value: "^t3\\."

    # Proibir buckets públicos
    - id: ORG_S3_002
      severity: CRITICAL
      message: "Bucket S3 público detectado"
      resource_type: aws_s3_bucket
      condition:
        field: acl
        op: equals
        value: "public-read"
```

Findings de regras customizadas aparecem com `Source: custom` e participam normalmente do scoring, deduplicação e exit codes.

### `history`

Configura o armazenamento local de histórico de scans em SQLite.

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `enabled` | bool | `false` | Habilita gravação automática de resultados |
| `retention_days` | int | `90` | Auto-limpeza de registros mais antigos |
| `max_size_mb` | int | `50` | Tamanho máximo do banco SQLite |

```yaml
history:
  enabled: true
  retention_days: 90
  max_size_mb: 50
```

### `output`

| Campo | Tipo | Padrão | Descrição |
|-------|------|--------|-----------|
| `format` | string | `pretty` | Formato de saída padrão |
