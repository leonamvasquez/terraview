# AI Providers

O terraview suporta **8 providers de IA** organizados em três categorias.

---

## Providers via API (requer API key)

| Provider | Variável de ambiente | Modelo padrão | Exemplos de modelos |
|----------|---------------------|---------------|---------------------|
| **gemini** | `GEMINI_API_KEY` | gemini-2.5-flash | gemini-2.5-flash, gemini-2.5-pro, gemini-2.0-flash |
| **claude** | `ANTHROPIC_API_KEY` | claude-haiku-4-5 | claude-haiku-4-5, claude-sonnet-4-6, claude-opus-4-6 |
| **openai** | `OPENAI_API_KEY` | gpt-4o-mini | gpt-4o-mini, gpt-4o, o3-mini |
| **deepseek** | `DEEPSEEK_API_KEY` | deepseek-v3.2 | deepseek-chat, deepseek-reasoner |
| **openrouter** | `OPENROUTER_API_KEY` | google/gemini-2.5-flash | Qualquer modelo disponível no OpenRouter |

---

## Providers via CLI (subscription — sem API key)

| Provider | CLI necessário | Instalação | Modelo padrão |
|----------|---------------|------------|---------------|
| **gemini-cli** | `gemini` | `npm install -g @google/gemini-cli` | gemini-2.5-flash |
| **claude-code** | `claude` | `npm install -g @anthropic-ai/claude-code` | claude-haiku-4-5 |

Estes providers usam sua **assinatura pessoal** (Google/Anthropic) para billing. Não é necessário API key — basta ter o CLI instalado e autenticado.

---

## Provider local (sem internet)

| Provider | Requisito | Modelo padrão |
|----------|-----------|---------------|
| **ollama** | Ollama rodando localmente | llama3.1:8b |

```bash
terraview provider install ollama           # instalar Ollama + pull do modelo padrão
terraview provider install ollama --model codellama:13b  # modelo personalizado
```

---

## Integração com IAs por Assinatura

O terraview oferece integração nativa com **IAs por assinatura** — providers que utilizam o CLI oficial do Google (Gemini CLI) ou da Anthropic (Claude Code) para análise, cobrando na assinatura pessoal do desenvolvedor em vez de exigir API keys ou créditos pré-pagos.

### Como funciona

Em vez de fazer requisições HTTP diretas para APIs, o terraview invoca os binários CLI instalados localmente (`gemini` ou `claude`) como subprocessos. Isso significa que:

1. **Sem API key** — autenticação é feita pela sessão do CLI já logada na sua conta Google ou Anthropic
2. **Billing pela assinatura** — o custo é absorvido pelo plano que você já paga (Google One AI Premium, Anthropic Max, etc.)
3. **Sem configuração extra** — se o CLI funciona no seu terminal, funciona no terraview
4. **Mesmos modelos da API** — acesso a modelos como `gemini-3`, `gemini-2.5-pro`, `claude-sonnet-4-5`, `claude-opus-4-6`

### Configuração

```bash
# Gemini CLI (requer Google One AI Premium ou Google AI Studio login)
npm install -g @google/gemini-cli
gemini                                      # autenticar na primeira execução
terraview provider use gemini-cli           # definir como provider padrão

# Claude Code (requer Anthropic Max, Pro ou Team)
npm install -g @anthropic-ai/claude-code
claude                                      # autenticar na primeira execução
terraview provider use claude-code          # definir como provider padrão
```

### Uso

```bash
# Scan com Gemini CLI
terraview scan checkov --provider gemini-cli
terraview scan checkov --provider gemini-cli --model gemini-3

# Scan com Claude Code
terraview scan checkov --provider claude-code
terraview scan checkov --provider claude-code --model claude-opus-4-6

# Explicação de infraestrutura com provider CLI
terraview explain --provider claude-code

# Drift analysis com IA por assinatura
terraview drift --intelligence --provider gemini-cli
```

---

## API vs CLI (subscription) — quando usar cada um

| Aspecto | API (key) | CLI (subscription) |
|---------|-----------|-------------------|
| **Configuração** | Criar conta + gerar API key | Instalar CLI + fazer login |
| **Billing** | Pay-per-token (créditos) | Plano mensal fixo |
| **Ideal para** | CI/CD, pipelines automatizadas | Desenvolvimento local, uso pessoal |
| **Rate limits** | Limites da API (varia por tier) | Limites da assinatura |
| **Offline** | Não | Não (mas Ollama sim) |
| **Providers** | gemini, claude, openai, deepseek, openrouter | gemini-cli, claude-code |

!!! tip "Dica"
    Para uso local no dia a dia, providers por assinatura são a escolha mais prática — zero configuração de keys, billing simples. Para CI/CD, prefira providers via API (ou Ollama para ambientes air-gapped).
