# Histórico de Scans

O terraview registra automaticamente os resultados de cada scan em um banco SQLite local (`~/.terraview/cache/history.db`). Isso permite acompanhar a evolução da postura de segurança ao longo do tempo.

## Comandos

### Listar scans

```bash
terraview history                           # últimos 20 scans, projeto atual
terraview history --all                     # todos os projetos
terraview history --limit 50                # limitar quantidade
terraview history --since 7d                # scans dos últimos 7 dias
terraview history --since 2025-01-01        # scans desde uma data
terraview history --format json             # saída JSON
terraview history --format csv              # saída CSV
```

### Tendências

```bash
terraview history trend                     # sparklines de scores e findings
terraview history trend --limit 30          # analisar últimos 30 scans
terraview history trend --since 30d         # tendência dos últimos 30 dias
```

Exibe sparklines e deltas percentuais para scores (Security, Compliance, Maintainability, Overall) e contagens de findings por severidade.

### Comparação

```bash
terraview history compare                   # último vs anterior
terraview history compare --with 5          # último vs scan #5
terraview history compare --since 7d        # último vs mais antigo em 7 dias
```

Mostra diferenças lado a lado entre dois scans: scores, contagem de findings e mudanças por severidade.

### Limpeza

```bash
terraview history clear                     # limpar projeto atual
terraview history clear --all               # limpar todos os projetos
terraview history clear --before 30d        # limpar mais antigos que 30 dias
```

### Exportação

```bash
terraview history export --format csv -o scans.csv   # exportar para CSV
terraview history export --format json -o scans.json # exportar para JSON
```

## Configuração

Habilite no `.terraview.yaml`:

```yaml
history:
  enabled: true              # habilitar gravação automática
  retention_days: 90         # auto-limpeza de registros antigos
  max_size_mb: 50            # tamanho máximo do banco SQLite
```

## Como funciona

- Cada scan grava um `ScanRecord` com: timestamp, project hash, scanner usado, scores (security, compliance, maintainability, overall), contagem de findings por severidade, e veredito
- O project hash é derivado do caminho absoluto do diretório — scans do mesmo projeto são agrupados
- A retenção automática remove registros mais antigos que `retention_days` ao abrir o banco
- O banco é armazenado em `~/.terraview/cache/history.db`

## Formatos de saída

| Formato | Uso |
|---------|-----|
| `pretty` | Tabela formatada para terminal (padrão) |
| `json` | JSON estruturado para integração |
| `csv` | CSV para importação em planilhas |

!!! tip "Dica"
    Para CI/CD, exporte o histórico como JSON e use-o para dashboards de tendência ou gates de qualidade customizados.
