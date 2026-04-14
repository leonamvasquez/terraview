# Configuração Rápida

Este guia mostra como configurar e rodar seu primeiro scan em menos de 5 minutos.

## 1. Instalar

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

## 2. Verificar o ambiente

```bash
terraview setup
```

Saída esperada:

```
  terraview setup
  ═══════════════

  Security Scanners

  [✓] checkov      3.2.504
  [✗] tfsec        Install with: terraview scanners install tfsec
  [✗] terrascan    Install with: terraview scanners install terrascan

  AI Providers

  [✓] ollama           running (llama3.1:8b)
  [✓] gemini-cli       gemini CLI installed
  [✓] claude-code      claude CLI installed
  [✗] gemini           GEMINI_API_KEY not set
  [✗] claude           ANTHROPIC_API_KEY not set

  AI ready (2 providers available)

  Quick Start

  terraview scan checkov              # scanner + IA (padrão)
  terraview scan checkov --static     # apenas scanner

  Install missing: terraview scanners install --all
```

## 3. Instalar scanners (se necessário)

```bash
terraview scanners install --all
```

## 4. Configurar IA (opcional)

```bash
# Seletor interativo com teste de conectividade
terraview provider list

# Ou definir diretamente via CLI
terraview provider use gemini-cli
terraview provider use ollama llama3.1:8b
```

!!! tip "Dica"
    A IA é opcional. Sem provider configurado, apenas o scanner roda. Com provider configurado, scanner e IA rodam **em paralelo** automaticamente.

## 5. Primeiro scan

```bash
cd meu-projeto-terraform

# Scan básico (scanner + IA se configurada)
terraview scan checkov

# Apenas scanner, sem IA
terraview scan checkov --static
```

## 6. Explorar os resultados

O scan gera automaticamente:

- `review.json` — resultado estruturado completo
- `review.md` — relatório em Markdown legível

Para SARIF (GitHub Security tab):

```bash
terraview scan checkov -f sarif -o ./reports
```

## Próximos passos

- [Comandos](../usage/commands.md) — referência completa
- [Configuração](../usage/configuration.md) — arquivo `.terraview.yaml`
- [AI Providers](../usage/ai-providers.md) — todos os providers suportados
- [Histórico](../usage/history.md) — tracking de scans ao longo do tempo
- [MCP Server](../usage/mcp.md) — integração com agentes AI
- [CI/CD](../integration/cicd.md) — integração com pipelines
