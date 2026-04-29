# Scanners

## Scanners suportados

| Scanner | Descrição | Instalação |
|---------|-----------|------------|
| **builtin** | Scanner em Go puro embutido no terraview — 43 regras CKV_AWS, sem dependências externas | já incluído no binário |
| [Checkov](https://www.checkov.io/) | Scanner de segurança e compliance para IaC | `terraview scanners install checkov` |
| [tfsec](https://aquasecurity.github.io/tfsec/) | Análise estática de segurança para Terraform | `terraview scanners install tfsec` |
| [Terrascan](https://runterrascan.io/) | Detector de violations e compliance | `terraview scanners install terrascan` |

Os findings de todos os scanners são normalizados, deduplicados e exibidos em um scorecard unificado.

## Scanner `builtin` (sem dependências)

O `builtin` é um scanner em Go puro empacotado dentro do próprio binário do terraview. Ele roda sem `pip`, `npm` ou downloads externos — útil para CI air-gapped, imagens Docker mínimas e ambientes onde instalar scanners de terceiros é inviável.

```bash
terraview scan builtin                      # scanner embutido + IA (se configurada)
terraview scan builtin --static             # somente builtin, sem IA
```

Quando nenhum scanner externo é detectado no `PATH`, o terraview usa o `builtin` como fallback automático.

**Cobertura atual (43 regras CKV_AWS):** S3, RDS, EC2, Security Groups, Lambda, CloudFront, DynamoDB, ElastiCache, CloudWatch, EKS, ECS, ECR, SQS, SNS, IAM, CloudTrail, OpenSearch, MSK e RDS Cluster.

## Gerenciamento de scanners

```bash
terraview scanners list                     # listar scanners com status de instalação
terraview scanners install checkov          # instalar scanner específico
terraview scanners install tfsec terrascan  # instalar múltiplos scanners
terraview scanners install --all            # instalar todos os scanners faltantes
terraview scanners install --all --force    # forçar reinstalação de todos
terraview scanners default checkov          # definir scanner padrão
terraview scanners default                  # exibir scanner padrão atual
```

## Como funciona a integração

O terraview detecta automaticamente quais scanners estão instalados e roda o scanner padrão (ou o especificado via CLI). Os resultados passam por:

1. **Parser** — converte saída nativa do scanner para formato normalizado
2. **Normalização** — categorias canônicas (security, compliance, best-practice, etc.)
3. **Deduplicação** — remove findings duplicados entre scanner e IA
4. **Scoring** — calcula scores 0–10 por categoria

## Instalação cross-platform

O comando `terraview scanners install` suporta Linux, macOS e Windows:

- **Checkov** — instalado via `pip3` (requer Python 3)
- **tfsec** — binário estático baixado do GitHub Releases
- **Terrascan** — binário estático baixado do GitHub Releases

```bash
# Instalar todos os scanners de uma vez
terraview scanners install --all

# Forçar reinstalação
terraview scanners install --all --force
```
