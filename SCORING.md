# Metodologia de Scoring — Terraview

> Documento de referência para auditoria e transparência da pontuação de segurança.
> Gerado a partir do código-fonte (`internal/scoring/`, `internal/riskvec/`, `internal/aggregator/`).

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Eixos de Pontuação (3 scores)](#eixos-de-pontuação)
3. [Fórmula de Cálculo por Categoria](#fórmula-de-cálculo-por-categoria)
4. [Score Geral (Overall)](#score-geral-overall)
5. [Pesos de Severidade](#pesos-de-severidade)
6. [Pisos de Proteção (Floor Constraints)](#pisos-de-proteção)
7. [Blending de Confiabilidade](#blending-de-confiabilidade)
8. [Vetores de Risco (5 eixos)](#vetores-de-risco)
9. [Classificação de Findings nas Categorias](#classificação-de-findings-nas-categorias)
10. [Resolução de Conflitos (Scanner vs IA)](#resolução-de-conflitos)
11. [Confiança (Confidence)](#confiança)
12. [Código de Saída (Exit Code)](#código-de-saída)
13. [Exemplos Práticos](#exemplos-práticos)
14. [Notas e TODOs](#notas-e-todos)

---

## Visão Geral

O Terraview pontua infraestrutura Terraform em **3 eixos** (0–10 cada) mais um **Score Geral**:

| Eixo | Peso no Overall | Descrição |
|------|-----------------|-----------|
| **Segurança** | 3.0 (40.0%) | Falhas de segurança: rede exposta, criptografia faltante, IAM permissivo |
| **Conformidade** | 2.0 (26.7%) | Aderência a políticas organizacionais, tags obrigatórias, regulatório |
| **Manutenibilidade** | 1.5 (20.0%) | Boas práticas, nomenclatura, complexidade, legibilidade |
| *Confiabilidade* | 1.0 (13.3%) | Backup, HA, disaster recovery (blendado em Segurança e Conformidade) |

Cada finding detectado (scanner ou IA) é classificado em uma dessas categorias, e seu **peso de severidade** penaliza o score correspondente proporcionalmente ao total de recursos analisados.

---

## Eixos de Pontuação

### Segurança (`security`)

Recebe findings das categorias:
- `security` — diretamente

Também recebe contribuição indireta de `reliability` via blending (veja [Blending](#blending-de-confiabilidade)).

### Conformidade (`compliance`)

Recebe findings das categorias:
- `compliance` — diretamente

Também recebe contribuição indireta de `reliability` via blending.

### Manutenibilidade (`maintainability`)

Recebe findings das categorias:
- `maintainability`
- `best-practice`

### Confiabilidade (`reliability`)

Calculada separadamente, mas **não aparece como score individual** na saída. Em vez disso, é blendada nos scores de Segurança e Conformidade.

---

## Fórmula de Cálculo por Categoria

Para cada eixo (Segurança, Conformidade, Manutenibilidade, Confiabilidade):

```
weighted_sum = Σ peso_severidade(finding)    para cada finding na categoria
penalty_ratio = weighted_sum / max(total_recursos, 1)
score = 10.0 − min(penalty_ratio × 2.0, 10.0)
```

Onde:
- `peso_severidade` é o peso configurável de cada nível de severidade
- `total_recursos` é o número total de recursos no plano Terraform
- `2.0` é o **fator de escala** (hardcoded)
- O resultado é arredondado para 1 casa decimal e limitado a `[0.0, 10.0]`

**Sem findings = 10.0.** Sem recursos = 10.0.

---

## Score Geral (Overall)

```
overall = (sec × 3.0 + comp × 2.0 + maint × 1.5 + rel × 1.0) / 7.5
```

Onde `sec`, `comp`, `maint` e `rel` são os scores de cada categoria **após** o blending de confiabilidade e arredondamento.

---

## Pesos de Severidade

Configuráveis em `.terraview.yaml` sob `scoring.severity_weights`:

```yaml
scoring:
  severity_weights:
    critical: 5.0
    high: 3.0
    medium: 1.0
    low: 0.5
```

| Severidade | Peso Padrão | Descrição |
|------------|-------------|-----------|
| CRITICAL | 5.0 | Falha grave de segurança, risco imediato |
| HIGH | 3.0 | Risco significativo que deve ser corrigido |
| MEDIUM | 1.0 | Problema moderado, recomendação de correção |
| LOW | 0.5 | Melhoria sugerida, baixo impacto |
| INFO | 0.0 | Informativo, sem impacto no score |

---

## Pisos de Proteção

Para evitar penalizações desproporcionais, os scores por categoria têm pisos de proteção:

| Condição | Piso | Descrição |
|----------|------|-----------|
| Apenas MEDIUM ou inferior (sem HIGH/CRITICAL) | 5.0 | Findings leves nunca levam o score abaixo de 5.0 |
| Tem HIGH mas SEM CRITICAL | 2.0 | HIGH pode reduzir bastante, mas nunca abaixo de 2.0 |
| Tem CRITICAL | 0.0 | Sem piso — CRITICAL pode zerar completamente |

Esses pisos se aplicam **por categoria**, antes do cálculo do Overall.

---

## Blending de Confiabilidade

Quando existem findings de `reliability`, seus scores afetam Segurança e Conformidade:

```
segurança_final  = (segurança × 2 + confiabilidade) / 3
conformidade_final = (conformidade × 2 + confiabilidade) / 3
```

**Racional:** falhas de confiabilidade (falta de backup, sem HA) impactam tanto a postura de segurança quanto a conformidade com políticas.

---

## Vetores de Risco

Além dos 3 scores, cada recurso é avaliado em **5 vetores de risco** (0–3 cada, total máximo 15):

| Vetor | Range | Descrição | Categoria Dominante |
|-------|-------|-----------|---------------------|
| **Network** | 0–3 | Exposição de rede (portas abertas, public access) | security |
| **Encryption** | 0–3 | Risco de criptografia (dados at-rest/in-transit) | security |
| **Identity** | 0–3 | Risco de identidade (IAM permissivo, wildcards) | security |
| **Governance** | 0–3 | Risco de governança (tags faltantes, naming) | compliance |
| **Observability** | 0–3 | Risco de observabilidade (logs, monitoring) | reliability |

### Mapeamento de Features para Vetores

Os vetores são extraídos automaticamente de cada recurso Terraform pela heurística em `internal/feature/extractor.go`. A classificação usa:

- **Tipo do recurso** (ex: `aws_security_group` → Network, `aws_kms_key` → Encryption)
- **Valores do recurso** (ex: `ingress.cidr_blocks = ["0.0.0.0/0"]` → Network alto)

### Categoria Dominante

O vetor com maior valor determina a categoria dominante do recurso:

| Vetor mais alto | Categoria |
|-----------------|-----------|
| Network, Encryption, Identity | `security` |
| Governance | `compliance` |
| Observability | `reliability` |
| Todos zero | `best-practice` |

---

## Classificação de Findings nas Categorias

### Categorias canônicas

Cada finding tem um campo `category` que é normalizado para uma das 5 categorias canônicas:

| Categoria canônica | Variações aceitas |
|--------------------|-------------------|
| `security` | security, iam, encryption, network, SEC, SECURITY |
| `compliance` | compliance, regulatory |
| `best-practice` | best-practice, best_practice, convention, naming, tagging |
| `maintainability` | maintainability, readability, complexity |
| `reliability` | reliability, availability, disaster, backup |

Categoria vazia ou "unknown" → default para `security`.

### Mapeamento para Score

| Categoria | Score afetado |
|-----------|---------------|
| `security` | Segurança |
| `compliance` | Conformidade |
| `best-practice` | Manutenibilidade |
| `maintainability` | Manutenibilidade |
| `reliability` | Confiabilidade (blendada em Segurança + Conformidade) |

---

## Resolução de Conflitos

O Terraview pode receber findings de duas fontes simultâneas: **scanner** (Checkov, tfsec, etc.) e **IA** (análise contextual via LLM).

### Estágio 1 — Normalizer (`normalizer.Deduplicate`)

Algoritmo O(n) com lookup por hash:

1. **Findings do scanner são sempre preservados** (copiados primeiro para a lista de saída).
2. Para cada finding da IA:
   - **Regra 1 — Equivalente:** mesmo recurso + mesma categoria canônica → **descarta** o finding da IA. Se a IA tem remediação e o scanner não → **enriquece** o finding do scanner.
   - **Regra 2 — Mesmo recurso, categoria diferente:** mantém ambos.
   - **Regra 3 — Recurso único:** mantém o finding da IA.
3. A **severidade do scanner sempre prevalece** — nunca é substituída pela severidade da IA.

### Estágio 2 — Aggregator (`aggregator.deduplicateFindings`)

Trata duplicatas residuais (ex: dois scanners reportando o mesmo recurso + regra):

- **Chave:** `(lowercase(recurso), uppercase(ruleID))`
- **Conflito de severidade:** mantém a mais alta
- **Remediação:** preenche se a existente estiver vazia
- **Source:** concatena com `+` (ex: `"checkov+llm"`)

---

## Confiança

### Confiança do Veredito

A confiança (`confidence`) é uma propriedade do **veredito**, não de findings individuais:

| Condição | Confiança | Descrição |
|----------|-----------|-----------|
| CRITICAL encontrado, ou nenhum HIGH sem `--strict` | `high` | Decisão clara |
| HIGH encontrado, sem CRITICAL, sem `--strict` | `medium` | Ambiguidade: HIGH pode ou não ser bloqueante |

### Correlação Meta-Análise

Quando múltiplas fontes (scanner + IA + externo) reportam o mesmo recurso:

| Fontes concordantes | Confiança |
|---------------------|-----------|
| 3+ fontes | `high` |
| 2 fontes | `medium` |

> **TODO:** O struct `Finding` não possui campo `confidence` individual. A confiança aplica-se apenas ao veredito global e às correlações da meta-análise. Se for necessária confiança por finding no futuro, será preciso estender `rules.Finding`.

---

## Código de Saída

| Exit Code | Condição |
|-----------|----------|
| 0 | Nenhum finding CRITICAL ou HIGH |
| 1 | Pelo menos 1 finding HIGH (sem `--strict`) |
| 2 | Pelo menos 1 finding CRITICAL **OU** HIGH com `--strict` |

**Modo estrito (`--strict`):** promove findings HIGH para exit code 2.

---

## Exemplos Práticos

### Exemplo 1: Plano com mix de severidades

**Cenário:** 3 recursos, 4 findings:

| # | RuleID | Recurso | Severidade | Categoria |
|---|--------|---------|------------|-----------|
| 1 | CKV_AWS_18 | aws_s3_bucket.data | CRITICAL | security |
| 2 | CKV_AWS_23 | aws_security_group.web | HIGH | security |
| 3 | CKV_AWS_68 | aws_rds_instance.db | MEDIUM | compliance |
| 4 | TV_MAINT_01 | aws_instance.web | LOW | maintainability |

**Pesos (padrão):** CRITICAL=5.0, HIGH=3.0, MEDIUM=1.0, LOW=0.5

**Cálculo Segurança:**
```
findings security: [CRITICAL(5.0), HIGH(3.0)]
weighted_sum = 5.0 + 3.0 = 8.0
penalty_ratio = 8.0 / 3 = 2.667
score = 10.0 − min(2.667 × 2.0, 10.0) = 10.0 − 5.333 = 4.667
floor: tem CRITICAL → sem piso → score = 4.7
```

**Cálculo Conformidade:**
```
findings compliance: [MEDIUM(1.0)]
weighted_sum = 1.0
penalty_ratio = 1.0 / 3 = 0.333
score = 10.0 − min(0.333 × 2.0, 10.0) = 10.0 − 0.667 = 9.333
floor: apenas MEDIUM → piso 5.0 (não se aplica, score > 5.0) → score = 9.3
```

**Cálculo Manutenibilidade:**
```
findings maintainability: [LOW(0.5)]
weighted_sum = 0.5
penalty_ratio = 0.5 / 3 = 0.167
score = 10.0 − min(0.167 × 2.0, 10.0) = 10.0 − 0.333 = 9.667 → 9.7
floor: apenas LOW → piso 5.0 (não se aplica) → score = 9.7
```

**Cálculo Confiabilidade:**
```
Nenhum finding reliability → score = 10.0
Sem blending (sem findings reliability)
```

**Score Geral:**
```
overall = (4.7 × 3.0 + 9.3 × 2.0 + 9.7 × 1.5 + 10.0 × 1.0) / 7.5
        = (14.1 + 18.6 + 14.55 + 10.0) / 7.5
        = 57.25 / 7.5
        = 7.633 → 7.6
```

**Exit Code:** 2 (CRITICAL encontrado)

---

### Exemplo 2: Plano com muitos MEDIUM e conflito scanner/IA

**Cenário:** 2 recursos, 5 findings originais (3 scanner + 2 IA):

**Scanner:**

| # | RuleID | Recurso | Severidade | Categoria |
|---|--------|---------|------------|-----------|
| 1 | CKV_AWS_24 | aws_security_group.api | HIGH | security |
| 2 | CKV_AWS_33 | aws_rds_instance.db | MEDIUM | security |
| 3 | CKV_AWS_51 | aws_rds_instance.db | MEDIUM | compliance |

**IA:**

| # | RuleID | Recurso | Severidade | Categoria |
|---|--------|---------|------------|-----------|
| 4 | TV_AI_SEC | aws_security_group.api | CRITICAL | security |
| 5 | TV_AI_REL | aws_rds_instance.db | MEDIUM | reliability |

**Resolução de Conflitos (Estágio 1 — Normalizer):**

- Finding 4 (IA) vs Finding 1 (scanner): mesmo recurso (`aws_security_group.api`), mesma categoria canônica (`security`) → **equivalente** → **descartado**. Severidade do scanner (HIGH) prevalece sobre IA (CRITICAL).
- Finding 5 (IA): colide com Finding 2 e 3 (scanner) no recurso (`aws_rds_instance.db`), mas categoria `reliability` ≠ `security` e ≠ `compliance` → **Regra 2** → **mantido**.

**Findings após merge:** [1, 2, 3, 5] = 4 findings

**Cálculo Segurança:**
```
findings security: [HIGH(3.0), MEDIUM(1.0)]
weighted_sum = 3.0 + 1.0 = 4.0
penalty_ratio = 4.0 / 2 = 2.0
score = 10.0 − min(2.0 × 2.0, 10.0) = 10.0 − 4.0 = 6.0
floor: tem HIGH sem CRITICAL → piso 2.0 (não se aplica, score > 2.0) → score = 6.0
```

**Cálculo Conformidade:**
```
findings compliance: [MEDIUM(1.0)]
weighted_sum = 1.0
penalty_ratio = 1.0 / 2 = 0.5
score = 10.0 − min(0.5 × 2.0, 10.0) = 10.0 − 1.0 = 9.0
```

**Cálculo Manutenibilidade:**
```
Nenhum finding → score = 10.0
```

**Cálculo Confiabilidade:**
```
findings reliability: [MEDIUM(1.0)]
weighted_sum = 1.0
penalty_ratio = 1.0 / 2 = 0.5
score = 10.0 − min(0.5 × 2.0, 10.0) = 10.0 − 1.0 = 9.0
```

**Blending de Confiabilidade (reliability findings existem):**
```
segurança_final = (6.0 × 2 + 9.0) / 3 = 21.0 / 3 = 7.0
conformidade_final = (9.0 × 2 + 9.0) / 3 = 27.0 / 3 = 9.0
```

**Score Geral:**
```
overall = (7.0 × 3.0 + 9.0 × 2.0 + 10.0 × 1.5 + 9.0 × 1.0) / 7.5
        = (21.0 + 18.0 + 15.0 + 9.0) / 7.5
        = 63.0 / 7.5
        = 8.4
```

**Exit Code:** 1 (HIGH encontrado, sem CRITICAL após merge, sem `--strict`)

---

## Notas e TODOs

1. **TODO:** O fator de escala (`2.0`) da fórmula `penalty_ratio × scale_factor` é hardcoded e não configurável via `.terraview.yaml`. Considerar expor como `scoring.scale_factor`.

2. **TODO:** O struct `Finding` (`internal/rules/types.go`) não possui campo `confidence` por finding. A confiança é apenas do veredito global e das correlações meta-análise. Para auditoria completa, seria necessário rastrear a confiança individual.

3. **TODO:** A meta-análise (`internal/meta/analyzer.go`) calcula um `unified_score` separado com pesos diferentes (CRITICAL=3.0, HIGH=2.0, MEDIUM=0.8, LOW=0.3). Este score aparece em `review.json` sob `meta_analysis.unified_score` mas **não substitui** o score principal. A relação entre os dois scores pode causar confusão em auditoria.

4. **Nota:** O blending de confiabilidade só ocorre quando existem findings `reliability`. Se não houver, Segurança e Conformidade não são afetados.

5. **Nota:** A resolução de conflitos no Normalizer usa exclusivamente `resource + categoria canônica` — o `ruleID` é ignorado nesse estágio. Isso significa que dois findings com ruleIDs diferentes sobre o mesmo recurso e mesma categoria são tratados como equivalentes.

---

*Documento gerado a partir de `internal/scoring/scorer.go`, `internal/riskvec/scorer.go`, `internal/aggregator/aggregator.go`, `internal/normalizer/normalizer.go`. Consulte `--explain-scores` para ver a decomposição em tempo real.*
