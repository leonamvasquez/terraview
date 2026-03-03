# Cache de IA

O terraview possui cache persistente de respostas IA em disco (`~/.terraview/cache/`). Quando habilitado, re-execuções com o mesmo plan reutilizam a resposta anterior sem chamadas adicionais à API.

## Comandos

```bash
terraview cache status                      # exibir estatísticas do cache (entradas, tamanho, datas)
terraview cache clear                       # limpar todo o cache de respostas IA
```

## Configuração

Habilite no `.terraview.yaml`:

```yaml
llm:
  cache: true            # habilitar cache persistente
  cache_ttl_hours: 24    # TTL em horas (padrão: 24)
```

## Como funciona

O cache usa um **hash SHA-256 do plan JSON** como chave primária. Isso significa que:

- Plans idênticos reutilizam a mesma resposta IA
- Qualquer mudança no plan (mesmo mínima) gera nova chamada à API
- O TTL padrão é 24 horas — respostas mais antigas são ignoradas

## Localização

O cache é armazenado em `~/.terraview/cache/` como arquivos JSON individuais por hash do plan.

!!! tip "Dica"
    Para CI/CD, considere habilitar o cache e persistir o diretório `~/.terraview/cache/` entre runs (e.g., via `actions/cache`) para economizar chamadas à API.
