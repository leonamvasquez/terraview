# TerraView × Terragrunt

Documentação completa da integração do TerraView com Terragrunt.

## Índice

- [O que é Terragrunt](#o-que-é-terragrunt)
- [Por que usar com TerraView](#por-que-usar-com-terraview)
- [Instalação](#instalação)
- [Uso básico](#uso-básico)
- [Auto-detecção](#auto-detecção)
- [Projetos multi-módulo](#projetos-multi-módulo)
- [Configurações avançadas](#configurações-avançadas)
- [Troubleshooting](#troubleshooting)
- [Exemplos do mundo real](#exemplos-do-mundo-real)
- [FAQ](#faq)

## O que é Terragrunt

[Terragrunt](https://terragrunt.io) é um wrapper leve do Terraform que adiciona:

1. **Gerenciamento centralizado de estado** — configure backends uma vez em `terragrunt.hcl`
2. **Orquestração de múltiplos módulos** — execute módulos na sequência correta com `run-all`
3. **Composição e herança** — reutilize configurações com `inputs`, `locals`, `include`, etc.
4. **Validação de dependências** — detecta ciclos e garante ordem de execução

Exemplo mínimo:

```hcl
# terragrunt.hcl
terraform {
  source = "../../../modules//vpc"
}

inputs = {
  vpc_cidr = "10.0.0.0/16"
  environment = "dev"
}

remote_state {
  backend = "s3"
  config = {
    bucket = "my-tfstate"
    key = "${path_relative_to_include()}/terraform.tfstate"
    region = "us-east-1"
  }
}
```

## Por que usar com TerraView

1. **Escanear múltiplos módulos em uma operação** — em vez de rodar `terraview scan` para cada módulo
2. **Análise contextual cross-módulo** — a IA vê a infraestrutura completa, detectando vulnerabilidades em cadeia
3. **Garantir dependências antes do scan** — Terragrunt resolve dependências automaticamente
4. **Monorepos** — organize ambientes (dev/staging/prd) em um único repositório com configs herdadas

## Instalação

### Pré-requisitos

1. **TerraView** v0.8.0+
2. **Terragrunt** v0.50+
3. **Terraform** >= 0.12

### Setup rápido

```bash
# Instalar TerraView (se não tiver)
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

# Instalar Terragrunt
brew install terragrunt    # macOS
# ou
choco install terragrunt   # Windows
# ou
https://terragrunt.gruntwork.io/docs/getting-started/install/  # Linux
```

Verificar instalação:

```bash
terraview version
terragrunt --version
```

## Uso básico

### Sintaxe

```bash
terraview scan <scanner> [flags] [--terragrunt [config-file]]
```

### Exemplos

**Auto-detecção:**
```bash
cd seu-projeto-terragrunt
terraview scan checkov --terragrunt
```

**Config específica:**
```bash
terraview scan checkov --terragrunt dev.hcl
terraview scan checkov --terragrunt /abs/path/to/terragrunt.hcl
```

**Com outros flags:**
```bash
terraview scan checkov --terragrunt -f json -o ./reports
terraview scan checkov --terragrunt --provider claude --static
```

## Auto-detecção

TerraView detecta automaticamente Terragrunt em dois casos:

### Caso 1: Terragrunt.hcl no diretório raiz

```bash
cd infrastructure/
ls terragrunt.hcl  # ✓ existe
terraview scan checkov              # auto-detecta, ativa modo Terragrunt
```

Mensagem no stderr:
```
[terraview] Auto-detected Terragrunt project at /path/to/infrastructure
[terraview] Terragrunt mode: auto-detect
```

### Caso 2: Flag explícito

```bash
cd /qualquer/lugar
terraview scan checkov --terragrunt -d /path/to/terragrunt/project
# Força modo Terragrunt mesmo sem terragrunt.hcl detectado
```

### Desativar auto-detecção

Para forçar Terraform em um projeto Terragrunt:

```bash
cd infrastructure/
# Não use --terragrunt
terraview scan checkov  # ignora terragrunt.hcl, usa Terraform
```

## Projetos multi-módulo

### Estrutura típica

```
infrastructure/
├── terragrunt.hcl                # Config raiz (incluída por todos os submódulos)
├── env.hcl                       # Variáveis compartilhadas
├── account.hcl                   # Conta AWS/configuração global
├── dev/
│   ├── terragrunt.hcl
│   ├── vpc/
│   │   ├── terragrunt.hcl
│   │   └── main.tf
│   ├── rds/
│   │   ├── terragrunt.hcl
│   │   └── main.tf
│   └── eks/
│       ├── terragrunt.hcl
│       └── main.tf
├── staging/
│   ├── terragrunt.hcl
│   ├── vpc/
│   │   └── terragrunt.hcl
│   └── rds/
│       └── terragrunt.hcl
└── prd/
    ├── terragrunt.hcl
    ├── vpc/
    │   └── terragrunt.hcl
    └── rds/
        └── terragrunt.hcl
```

### Escanear um módulo específico

```bash
cd infrastructure/dev/vpc
terraview scan checkov --terragrunt
# Escaneia apenas dev/vpc
```

### Escanear todos os módulos de um ambiente

```bash
cd infrastructure/dev
terraview scan checkov --terragrunt
# Escaneia dev/ + dev/vpc + dev/rds + dev/eks
# Usa terragrunt run-all plan para gerar planos de todos
```

### Escanear toda a infraestrutura

```bash
cd infrastructure
terraview scan checkov --terragrunt
# Escaneia dev/ + staging/ + prd/ + todos os submódulos
```

## Configurações avançadas

### Config personalizada com variáveis

```hcl
# terragrunt.hcl
locals {
  environment = get_env("TG_ENV", "dev")
  aws_region = "us-east-1"
}

terraform {
  source = get_parent_terragrunt_dir() + "//modules/vpc"
}

inputs = {
  environment = local.environment
  region = local.aws_region
  tags = {
    ManagedBy = "terragrunt"
    Env = local.environment
  }
}

remote_state {
  backend = "s3"
  config = {
    bucket = "${local.environment}-tfstate"
    key = "${path_relative_to_include()}/terraform.tfstate"
    region = local.aws_region
    encrypt = true
    dynamodb_table = "${local.environment}-tf-locks"
  }
}
```

Usar com TerraView:

```bash
TG_ENV=staging terraview scan checkov --terragrunt
```

### Dependências entre módulos

```hcl
# infrastructure/dev/rds/terragrunt.hcl
dependency "vpc" {
  config_path = "../vpc"
}

inputs = {
  vpc_id = dependency.vpc.outputs.vpc_id
  vpc_cidr = dependency.vpc.outputs.vpc_cidr
}
```

TerraView resolve automaticamente as dependências:

```bash
cd infrastructure/dev
terraview scan checkov --terragrunt
# Executa vpc → rds → eks na ordem correta
```

### Mock outputs para teste

```hcl
# terragrunt.hcl
terraform {
  # ...
}

# Mock de outputs para testes sem executar tudo
skip = get_env("TERRAGRUNT_SKIP", "false") == "true"
```

Teste sem executar:

```bash
TERRAGRUNT_SKIP=true terraview diagram --terragrunt
```

## Troubleshooting

### Erro: "terragrunt binary not found"

```bash
which terragrunt
# Se vazio, instale:
brew install terragrunt   # macOS
```

### Erro: "terragrunt config file not found"

Verifique o caminho:

```bash
terraview scan checkov --terragrunt /path/to/terragrunt.hcl

# Use caminhos absolutos para evitar confusão
terraview scan checkov --terragrunt $(pwd)/dev/terragrunt.hcl
```

### Erro: "dependency not found"

Garanta que o módulo dependência existe:

```bash
# Se vpc/ não existe, crie:
mkdir -p infrastructure/dev/vpc
cat > infrastructure/dev/vpc/terragrunt.hcl << 'EOF'
terraform {
  source = "../../../modules/vpc"
}
EOF
```

### Erro: "terraform version mismatch"

Terragrunt geralmente gerencia versões do Terraform. Verifique:

```bash
terragrunt --version
terraform version

# Atualize ambos se necessário
```

### Slow performance com multi-módulos

Para acelerar:

```bash
# Execute em paralelo (Terragrunt >= 0.50)
terraview scan checkov --terragrunt

# Ou reduza o contexto IA
terraview scan checkov --terragrunt --static  # scanner only, sem IA
```

## Exemplos do mundo real

### Exemplo 1: Monorepo AWS multi-ambiente

```
empresa-infra/
├── .terraview.yaml
├── terragrunt.hcl
├── env.hcl
├── dev/
│   ├── terragrunt.hcl
│   ├── vpc/
│   ├── rds/
│   └── eks/
├── staging/
│   ├── terragrunt.hcl
│   ├── vpc/
│   ├── rds/
│   └── eks/
└── prd/
    ├── terragrunt.hcl
    ├── vpc/
    ├── rds/
    └── eks/

# .terraview.yaml
llm:
  provider: claude
  model: claude-sonnet-4-6
scanner:
  default: checkov
```

Workflow:

```bash
# Escanear dev antes de merge
cd empresa-infra/dev
terraview scan checkov --terragrunt

# Escanear staging antes de promote
cd ../staging
terraview scan checkov --terragrunt

# Diagrama da prd
cd ../prd
terraview diagram --terragrunt
```

### Exemplo 2: Monorepo com múltiplas aplicações

```
applications/
├── app-a/
│   ├── terragrunt.hcl
│   ├── ecs/
│   └── rds/
├── app-b/
│   ├── terragrunt.hcl
│   └── ecs/
└── shared/
    ├── vpc/
    └── kms/
```

Escanear aplicação A:

```bash
cd applications/app-a
terraview scan checkov --terragrunt --provider gemini-cli
```

### Exemplo 3: CI/CD com GitHub Actions

```yaml
name: Terraform Security
on:
  pull_request:
    paths:
      - 'infrastructure/**'
      - '.terraview.yaml'

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Install dependencies
        run: |
          curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
          brew install terragrunt
      
      - name: Scan with TerraView
        run: |
          cd infrastructure/${{ github.base_ref }}
          terraview scan checkov --terragrunt -f sarif -o ./reports
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: infrastructure/reports/review.sarif.json
```

## FAQ

**P: Diferença entre `terraview scan` e `terragrunt run-all apply`?**

R: TerraView *escaneia* segurança; Terragrunt *executa* infraestrutura. São complementares:

```bash
# 1. Escaneia antes de aplicar
cd infrastructure/dev
terraview scan checkov --terragrunt

# 2. Se passar, aplica com Terragrunt
terragrunt run-all apply
```

---

**P: Posso usar `--terragrunt` sem `terragrunt.hcl`?**

R: Sim. Use um arquivo de config específico:

```bash
terraview scan checkov --terragrunt /path/to/custom/terragrunt.hcl
```

---

**P: Como desabilitar auto-detecção?**

R: Não use `--terragrunt` e remova `terragrunt.hcl`:

```bash
mv terragrunt.hcl terragrunt.hcl.bak
terraview scan checkov  # usa Terraform
```

---

**P: Qual é o overhead de performance?**

R: Terragrunt adiciona ~1-2 segundos por módulo. Para 10 módulos, ~20s total (vs Terraform puro: ~5s).

```bash
# Medir tempo
time terraview scan checkov --terragrunt
```

---

**P: Funciona com Tofu (OpenTofu)?**

R: Sim! Terragrunt suporta Tofu desde v0.50. Configure:

```hcl
# terragrunt.hcl
terraform {
  required_version = ">= 1.6"
}
```

E use o binário Tofu:

```bash
which tofu  # confirme que tofu está instalado
terraview scan checkov --terragrunt
```

---

**P: Como escanear apenas com Terragrunt, sem Terraform individual?**

R: Use diretamente:

```bash
cd infrastructure
terraview scan checkov --terragrunt  # escaneia todos os módulos em uma operação
```

TerraView usa `terragrunt run-all plan` internamente.
