# Variáveis de Ambiente

## AI Providers

| Variável             | Provider    | Descrição                     |
|----------------------|-------------|-------------------------------|
| `GEMINI_API_KEY`     | Gemini      | API key do Google Gemini      |
| `ANTHROPIC_API_KEY`  | Claude      | API key da Anthropic          |
| `OPENAI_API_KEY`     | OpenAI      | API key da OpenAI             |
| `DEEPSEEK_API_KEY`   | DeepSeek    | API key do DeepSeek           |
| `OPENROUTER_API_KEY` | OpenRouter  | API key do OpenRouter         |
| `CUSTOM_LLM_API_KEY` | Custom      | API key para provider customizado (OpenAI-compatible) |
| `CUSTOM_LLM_BASE_URL`| Custom      | URL base para provider customizado (alternativa ao `url` no config) |

O Ollama não requer API key. Os providers `gemini-cli` e `claude-code` autenticam via suas respectivas assinaturas CLI.

## Configuração global

| Variável    | Descrição                     |
|-------------|-------------------------------|
| `NO_COLOR`  | Desabilita saída colorida (qualquer valor) |

## Notas

- Variáveis de ambiente têm precedência sobre valores no `.terraview.yaml`
- O terraview emite um aviso em stderr quando detecta `api_key` no arquivo de config — prefira sempre variáveis de ambiente para credentials
- Para CI/CD, defina as variáveis como secrets do pipeline (e.g., `${{ secrets.GEMINI_API_KEY }}` no GitHub Actions)
