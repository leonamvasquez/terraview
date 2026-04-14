# MCP Server

O terraview inclui um servidor [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) que expõe suas funcionalidades para agentes AI via JSON-RPC 2.0 sobre stdio. Isso permite que ferramentas como **Claude Code**, **Cursor** e **Windsurf** chamem tools do terraview programaticamente.

## Iniciar o servidor

```bash
terraview mcp server
```

O servidor lê mensagens JSON-RPC de stdin e escreve respostas em stdout. Logs vão para stderr.

!!! note
    O alias `terraview mcp serve` continua funcionando para compatibilidade com integrações existentes.

## Registro com agentes AI

### Claude Code

```bash
claude mcp add terraview -- terraview mcp server
```

### Cursor

Crie ou edite `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "terraview": {
      "command": "terraview",
      "args": ["mcp", "server"]
    }
  }
}
```

### Windsurf

Consulte a documentação do Windsurf para registro de servidores MCP com o mesmo formato de comando.

## Tools expostas

O servidor MCP expõe 11 tools:

| Tool | Descrição | Requer IA |
|------|-----------|-----------|
| `terraview_scan` | Security scan com scorecard (0-10) e findings | Opcional |
| `terraview_explain` | Explicação da infraestrutura em linguagem natural | Sim |
| `terraview_diagram` | Diagrama ASCII da infraestrutura | Nao |
| `terraview_history` | Consultar histórico de scans | Nao |
| `terraview_history_trend` | Tendências de scores ao longo do tempo | Nao |
| `terraview_history_compare` | Comparar dois scans lado a lado | Nao |
| `terraview_impact` | Blast radius / análise de impacto de dependências | Nao |
| `terraview_cache` | Status e gerenciamento do cache de IA | Nao |
| `terraview_scanners` | Listar scanners disponíveis e status de instalação | Nao |
| `terraview_fix_suggest` | Sugestões de correção geradas por IA | Sim |
| `terraview_version` | Versão e informações do ambiente | Nao |

## Parâmetros das tools

Cada tool aceita parâmetros via JSON no campo `arguments` da mensagem `tools/call`. Parâmetros comuns:

| Parâmetro | Tipo | Descrição |
|-----------|------|-----------|
| `dir` | string | Diretório do workspace Terraform (default: `.`) |
| `plan` | string | Caminho para plan JSON pré-gerado |
| `scanner` | string | Scanner a usar: `checkov`, `tfsec`, `terrascan` |
| `static` | boolean | Desabilitar análise IA (apenas scanner) |

## Exemplo de mensagem

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "terraview_scan",
    "arguments": {
      "dir": "/path/to/terraform",
      "scanner": "checkov",
      "static": false
    }
  }
}
```

## Protocolo

O servidor implementa o MCP conforme a especificação:

- **Transporte:** stdio (stdin/stdout)
- **Formato:** JSON-RPC 2.0
- **Métodos:** `initialize`, `tools/list`, `tools/call`
- **Capabilities:** `tools`

!!! tip "Dica"
    O MCP server permite que agentes AI realizem análises de segurança de infraestrutura de forma autônoma, sem necessidade de interação manual com o CLI.
