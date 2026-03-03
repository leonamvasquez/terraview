# Comandos

## Visão geral

```
$ terraview

Core Commands:
  scan        Security scan + AI contextual analysis (parallel)
  apply       Scan and conditionally apply the plan
  diagram     Generate ASCII infrastructure diagram
  explain     AI-powered infrastructure explanation
  drift       Detect and classify infrastructure drift

Provider Management:
  provider    Manage AI providers & LLM runtimes
              provider list | use | current | test
              provider install | uninstall

Scanner Management:
  scanners    Manage security scanners
              scanners list | install | default

Utilities:
  cache       Manage the AI response cache
              cache status | clear
  version     Show version information
  setup       Interactive environment setup

Flags:
  -d, --dir string        Terraform workspace directory (default ".")
  -p, --plan string       Path to terraform plan JSON (auto-generates if omitted)
  -f, --format string     Output format: pretty, compact, json, sarif
  -o, --output string     Output directory for generated files
      --provider string   AI provider (ollama, gemini, claude, openai, deepseek, openrouter, gemini-cli, claude-code)
      --model string      AI model to use
      --br                Output in Brazilian Portuguese (pt-BR)
      --no-color          Disable colored output
  -v, --verbose           Enable verbose output
```

---

## Scan

Por padrão, o terraview roda **ambos** o scanner de segurança e a análise contextual por IA **em paralelo**. A IA ativa automaticamente quando um provider está configurado (via `.terraview.yaml`, flag `--provider`, ou `terraview provider use`). Se nenhum provider estiver configurado, apenas o scanner roda.

```bash
terraview scan                              # auto-selecionar scanner padrão
terraview scan checkov                      # scan com Checkov (+ IA se provider configurado)
terraview scan tfsec                        # scan com tfsec
terraview scan terrascan                    # scan com Terrascan
terraview scan checkov --static             # apenas scanner, desabilitar IA
terraview scan checkov --all                # habilitar explain + diagram + impact
terraview scan checkov --explain            # scanner + IA + explicação em linguagem natural
terraview scan checkov --diagram            # scanner + IA + diagrama ASCII da infraestrutura
terraview scan checkov --impact             # scanner + IA + análise de raio de impacto
terraview scan checkov --plan plan.json     # usar plan JSON existente
terraview scan checkov -f sarif             # saída SARIF para CI
terraview scan checkov --strict             # HIGH também retorna exit code 2
terraview scan checkov --findings ext.json  # importar findings externos Checkov/tfsec/Trivy
```

### Configurando diretório ou arquivo de entrada

Escanear o diretório atual (detecta Terraform automaticamente):

```bash
terraview scan checkov
```

Ou um diretório específico:

```bash
terraview scan checkov -d /caminho/para/meu-projeto
```

Ou gerar o plan manualmente:

```bash
terraform init
terraform plan -out tf.plan
terraform show -json tf.plan > tf.json
terraview scan checkov --plan tf.json
```

Usar providers CLI (subscription — sem API key):

```bash
terraview scan checkov --provider gemini-cli --model gemini-3
terraview scan checkov --provider claude-code --model claude-sonnet-4-5
```

---

## Apply

Roda scan + aplica o plano condicionalmente. Bloqueia se houver findings CRITICAL. Exibe o resumo do scan e pede confirmação no modo interativo.

```bash
terraview apply checkov                     # interativo
terraview apply checkov --non-interactive   # modo CI (bloqueia CRITICAL, auto-aprova caso contrário)
terraview apply checkov --static            # apenas scanner + apply
terraview apply checkov --all               # tudo habilitado + apply
```

---

## Diagram

Gera um diagrama ASCII determinístico da infraestrutura. Não requer IA.

```bash
terraview diagram                           # diagrama do diretório atual
terraview diagram --plan plan.json          # diagrama de plan existente
terraview diagram --output ./reports        # salvar diagram.txt no diretório
```

---

## Explain

Gera uma explicação em linguagem natural da sua infraestrutura Terraform usando IA. Requer um provider configurado.

```bash
terraview explain                           # explicar projeto atual
terraview explain --plan plan.json          # explicar de plan existente
terraview explain --provider gemini         # usar provider específico
terraview explain --format json             # saída JSON estruturada
```

---

## Drift

Detecta e classifica drift de infraestrutura rodando `terraform plan` e analisando mudanças.

```bash
terraview drift                             # detecção básica de drift
terraview drift --plan plan.json            # de plan existente
terraview drift --intelligence              # avançado: classifica intencional vs suspeito
terraview drift --format compact            # resumo em uma linha
terraview drift --format json               # saída JSON
```

Exit codes: `0` = sem drift ou apenas baixo risco, `1` = risco HIGH, `2` = risco CRITICAL.

---

## Gerenciamento de providers

```bash
terraview provider list                     # seletor interativo (provider + modelo + teste de conectividade)
terraview provider use gemini gemini-2.5-pro  # definir provider via CLI (não-interativo)
terraview provider use ollama llama3.1:8b   # definir provider local
terraview provider current                  # exibir configuração atual
terraview provider test                     # testar conectividade do provider configurado
terraview provider install ollama           # instalar runtime Ollama + pull do modelo
terraview provider install ollama --model codellama:13b  # instalar com modelo específico
```

O comando `provider list` executa um **teste de integração automático**. Se o teste falhar, uma mensagem de diagnóstico é exibida:

- **CLI não instalado** → mostra comando de instalação (`npm install -g ...`)
- **API key ausente** → mostra variável de ambiente a configurar
- **API key inválida / rede** → sugere verificar credenciais e conectividade
- **Serviço local inacessível** → sugere verificar se o serviço está rodando

```
  [terraview] Testing connectivity with gemini-cli (gemini-3)... ✓

  ✓  Integration test passed — "gemini" CLI is installed and ready.
  ✓  Default provider: gemini-cli  model: gemini-3
     Saved to: ~/.terraview/.terraview.yaml
```

---

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

---

## Outros comandos

```bash
terraview setup                             # diagnóstico do ambiente
terraview version                           # versão, Go runtime, OS/arch
```

---

## Saída e formatos

```bash
terraview scan checkov                      # saída pretty (padrão)
terraview scan checkov -f compact           # resumo em uma linha
terraview scan checkov -f json              # JSON (review.json)
terraview scan checkov -f sarif             # SARIF (review.sarif.json) para GitHub Security tab
terraview scan checkov -o ./reports         # gravar review.json + review.md em ./reports
```

Todos os scans geram `review.json` e `review.md`. A saída SARIF é gerada quando `-f sarif` é usado.

---

## Exit Codes

| Código | Significado |
|--------|-------------|
| `0`    | Sem issues ou apenas MEDIUM/LOW/INFO |
| `1`    | Findings de severidade HIGH |
| `2`    | Findings CRITICAL (bloqueia apply) |

Modo estrito (`--strict`): promove findings HIGH para exit code 2.
