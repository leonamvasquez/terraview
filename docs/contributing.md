# Guia de Contribuição

Obrigado por querer contribuir com o terraview! Este guia explica como participar do projeto.

## Código de Conduta

Este projeto adota o [Contributor Covenant](https://www.contributor-covenant.org/pt-br/version/2/1/code_of_conduct/).
Ao contribuir, você concorda em seguir estas diretrizes.

## Como contribuir

### Reportando bugs

1. Verifique se o bug ainda não foi reportado nas [issues](https://github.com/leonamvasquez/terraview/issues)
2. Abra uma nova issue usando o template **Bug Report**
3. Inclua: versão (`terraview version`), OS, passos para reproduzir e saída esperada vs. obtida

### Sugerindo features

1. Abra uma issue usando o template **Feature Request**
2. Descreva o problema que a feature resolve (não apenas a solução)
3. Se possível, inclua exemplos de uso e casos de borda

### Enviando Pull Requests

1. Fork o repositório
2. Crie um branch a partir de `main`:
   ```bash
   git checkout -b feat/minha-feature
   # ou
   git checkout -b fix/descricao-do-bug
   ```
3. Faça suas mudanças seguindo os padrões abaixo
4. Rode os testes:
   ```bash
   make test
   make lint
   ```
5. Commit seguindo [Conventional Commits](#conventional-commits)
6. Abra o PR com o template preenchido

## Padrões de código

### Estilo Go

- Siga as convenções do `gofmt` e `golangci-lint`
- Funções públicas devem ter godoc
- Erros devem usar `%w` para wrapping (não `%v`)
- Prefira `errors.Is` / `errors.As` a comparação direta

### Conventional Commits

Os commits devem seguir o formato:

```
<tipo>(<escopo>): <descrição curta>

[corpo opcional]

[rodapé opcional]
```

**Tipos aceitos:**

| Tipo       | Quando usar                              |
|------------|------------------------------------------|
| `feat`     | Nova funcionalidade                      |
| `fix`      | Correção de bug                          |
| `docs`     | Apenas documentação                      |
| `refactor` | Refatoração sem mudança de comportamento |
| `test`     | Adicionar ou corrigir testes             |
| `perf`     | Melhoria de performance                  |
| `ci`       | Mudanças no pipeline de CI/CD            |
| `chore`    | Manutenção, deps, configurações          |
| `build`    | Mudanças no sistema de build             |

**Exemplos:**

```
feat(ai): adicionar provider gemini-cli via subprocess
fix(selector): corrigir contagem de linhas no eraseLines
docs(readme): atualizar exemplos de instalação para Linux
```

!!! note "Versionamento"
    Commits com `feat:` geram minor version bump. `fix:` gera patch. `BREAKING CHANGE:` no footer gera major version bump.

## Configurar ambiente de desenvolvimento

```bash
# Clonar
git clone https://github.com/leonamvasquez/terraview.git
cd terraview

# Dependências
go mod download

# Compilar e instalar localmente
make install

# Rodar testes
make test

# Lint
make lint

# Coverage
make coverage
```

## Estrutura do projeto

```
cmd/                  # Comandos CLI (cobra)
internal/
  ai/                 # Providers de IA e registry
  parser/             # Parser de planos Terraform
  rules/              # Motor de regras e findings
  scanner/            # Integração com scanners externos
  config/             # Configuração e persistência
  output/             # Formatadores de saída
  ...
prompts/              # Templates de prompts para IA
profiles/             # Perfis de severidade configuráveis
examples/             # Exemplos de planos Terraform
```

## Adicionando um novo provider de IA

1. Crie `internal/ai/providers/meu_provider.go`
2. Implemente a interface `ai.Provider` (Name, Validate, Analyze)
3. Registre via `init()` com `ai.Register(...)`
4. Adicione testes em `meu_provider_test.go`
5. Documente no README na seção de providers

Veja `internal/ai/providers/gemini.go` como referência.

## Testes

- Todo novo código deve ter testes unitários
- Use table-driven tests para cobrir múltiplos casos
- Mocks para dependências externas (HTTP, exec, filesystem)
- Fuzz tests para parsers e inputs não confiáveis

```bash
make test             # unitários + race detector
make coverage         # relatório HTML de cobertura
```

## Dúvidas

Abra uma [Discussion](https://github.com/leonamvasquez/terraview/discussions) no GitHub.
