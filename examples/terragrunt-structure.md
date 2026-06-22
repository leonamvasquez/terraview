# Terragrunt Project Structure Example

Este arquivo demonstra uma estrutura típica de projeto Terragrunt com TerraView.

## Estrutura de diretórios

```
infrastructure/
├── .terraview.yaml                    # Config do TerraView (aplicado a todo projeto)
├── terragrunt.hcl                     # Config raiz do Terragrunt
├── env.hcl                            # Variáveis compartilhadas
├── account.hcl                        # Configurações por conta AWS
│
├── _modules/                          # Módulos Terraform (fonte)
│   ├── vpc/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── rds/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── eks/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
│
├── dev/                               # Ambiente desenvolvimento
│   ├── terragrunt.hcl
│   ├── vpc/
│   │   ├── terragrunt.hcl             # Instancia _modules/vpc
│   │   └── terraform.tfvars
│   ├── rds/
│   │   ├── terragrunt.hcl             # Depende de vpc (dependency "vpc" {})
│   │   └── terraform.tfvars
│   └── eks/
│       ├── terragrunt.hcl             # Depende de vpc
│       └── terraform.tfvars
│
├── staging/                           # Ambiente staging
│   ├── terragrunt.hcl
│   ├── vpc/
│   │   └── terragrunt.hcl
│   ├── rds/
│   │   └── terragrunt.hcl
│   └── eks/
│       └── terragrunt.hcl
│
└── prd/                               # Ambiente produção
    ├── terragrunt.hcl
    ├── vpc/
    │   └── terragrunt.hcl
    ├── rds/
    │   └── terragrunt.hcl
    └── eks/
        └── terragrunt.hcl
```

## Conteúdo dos arquivos

### `terragrunt.hcl` (raiz)

```hcl
# Configuração compartilhada entre todos os ambientes

locals {
  # Extrair valores de env.hcl
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  
  aws_region = local.env_vars.locals.aws_region
  project_name = local.env_vars.locals.project_name
}

# Remote state centralizado
remote_state {
  backend = "s3"
  config = {
    bucket = "${local.project_name}-tfstate-${data.aws_caller_identity.current.account_id}"
    key = "${path_relative_to_include()}/terraform.tfstate"
    region = local.aws_region
    encrypt = true
    dynamodb_table = "${local.project_name}-tf-locks"
  }
}

# Gera provider Terraform automaticamente
generate "provider" {
  path = "provider.tf"
  if_exists = "overwrite"
  contents = <<-EOF
    terraform {
      required_version = ">= 1.0"
      required_providers {
        aws = {
          source = "hashicorp/aws"
          version = "~> 5.0"
        }
      }
    }

    provider "aws" {
      region = "${local.aws_region}"
      
      default_tags {
        tags = {
          Project = "${local.project_name}"
          Env = get_env("TG_ENV", "unknown")
          ManagedBy = "Terraform"
          ManagedByTool = "Terragrunt"
        }
      }
    }
  EOF
}
```

### `env.hcl`

```hcl
# Variáveis compartilhadas

locals {
  aws_region = "us-east-1"
  project_name = "myapp"
  
  # Mapping de ambientes
  env_config = {
    dev = {
      instance_type = "t3.small"
      db_instance_class = "db.t3.micro"
      replica_count = 1
    }
    staging = {
      instance_type = "t3.medium"
      db_instance_class = "db.t3.small"
      replica_count = 2
    }
    prd = {
      instance_type = "c5.large"
      db_instance_class = "db.r5.large"
      replica_count = 3
    }
  }
}
```

### `dev/terragrunt.hcl`

```hcl
# Configuração específica do ambiente dev

include "root" {
  path = find_in_parent_folders()
}

locals {
  environment = "dev"
  env_vars = read_terragrunt_config(find_in_parent_folders("env.hcl"))
  env_config = local.env_vars.locals.env_config[local.environment]
}

# Tagsadicionais para o ambiente
generate "tags" {
  path = "tags.tf"
  if_exists = "overwrite"
  contents = <<-EOF
    locals {
      environment = "${local.environment}"
      instance_type = "${local.env_config.instance_type}"
    }
  EOF
}
```

### `dev/vpc/terragrunt.hcl`

```hcl
include "root" {
  path = find_in_parent_folders()
}
include "env" {
  path = find_in_parent_folders("dev/terragrunt.hcl")
}

terraform {
  source = "${find_in_parent_folders("_modules")}/vpc"
}

inputs = {
  vpc_cidr = "10.0.0.0/16"
  environment = "dev"
  
  availability_zones = ["us-east-1a", "us-east-1b"]
  public_subnet_cidrs = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.11.0/24", "10.0.12.0/24"]
  
  enable_nat_gateway = true
  enable_vpn_gateway = false
  
  tags = {
    Name = "dev-vpc"
    Tier = "network"
  }
}
```

### `dev/rds/terragrunt.hcl`

```hcl
include "root" {
  path = find_in_parent_folders()
}
include "env" {
  path = find_in_parent_folders("dev/terragrunt.hcl")
}

terraform {
  source = "${find_in_parent_folders("_modules")}/rds"
}

# Depende de VPC para obter o subnet group
dependency "vpc" {
  config_path = "../vpc"
  
  mock_outputs = {
    db_subnet_group_name = "dev-db-subnet-group"
    db_security_group_id = "sg-12345678"
  }
  
  mock_outputs_allowed_terraform_commands = ["plan", "validate"]
}

inputs = {
  engine = "postgres"
  engine_version = "15.3"
  
  db_instance_class = "db.t3.micro"
  allocated_storage = 20
  max_allocated_storage = 100
  
  database_name = "myapp"
  database_user = "postgres"
  # database_password deve vir de variável de ambiente ou Secrets Manager
  
  subnet_group_name = dependency.vpc.outputs.db_subnet_group_name
  security_group_ids = [dependency.vpc.outputs.db_security_group_id]
  
  backup_retention_period = 7
  backup_window = "03:00-04:00"
  maintenance_window = "sun:04:00-sun:05:00"
  
  enable_deletion_protection = false
  
  environment = "dev"
  
  tags = {
    Name = "dev-postgres"
    Tier = "data"
  }
}
```

## Usar com TerraView

### Escanear um módulo específico

```bash
cd infrastructure/dev/vpc
terraview scan checkov --terragrunt

# Saída:
# [terraview] Auto-detected Terragrunt project at /path/to/infrastructure/dev/vpc
# [terraview] Terragrunt mode: auto-detect
# 
# ┌──────────────────────────┐
# │ Scorecard                │
# │ Segurança:      7.2 / 10 │
# │ Compliance:     8.5 / 10 │
# │ Manutenibilidade: 9.0/10│
# └──────────────────────────┘
# ...
```

### Escanear todo um ambiente

```bash
cd infrastructure/dev
terraview scan checkov --terragrunt

# Executa:
# 1. terragrunt plan no vpc/
# 2. terragrunt plan no rds/ (aguarda vpc terminar)
# 3. terragrunt plan no eks/ (aguarda vpc terminar)
# 4. Mescla os 3 planos
# 5. Executa scanner + IA sobre o merged plan
```

### Gerar diagrama multi-ambiente

```bash
cd infrastructure/dev
terraview diagram --terragrunt

# Mostra ASCII diagram de toda a topologia do dev
```

### Escanear com provider de IA específico

```bash
cd infrastructure/prd
terraview scan checkov --terragrunt --provider claude --model claude-opus-4-6

# IA analisa infraestrutura produção em detalhes
```

### Dry-run de fixes

```bash
cd infrastructure/staging
terraview scan checkov --terragrunt
terraview fix plan --terragrunt

# Mostra diffs dos fixes recomendados, sem aplicar
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Scan Terragrunt Infrastructure
on:
  pull_request:
    paths:
      - 'infrastructure/**'
      - '.terraview.yaml'
  push:
    branches:
      - main
    paths:
      - 'infrastructure/**'

jobs:
  scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        environment: [dev, staging, prd]
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup dependencies
        run: |
          # Install TerraView
          curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
          
          # Install Terragrunt
          sudo apt-get update && sudo apt-get install -y terragrunt
          
          # Ensure Terraform is installed
          terraform version
      
      - name: Scan ${{ matrix.environment }}
        env:
          AWS_REGION: us-east-1
          TG_ENV: ${{ matrix.environment }}
        run: |
          cd infrastructure/${{ matrix.environment }}
          terraview scan checkov --terragrunt -f sarif -o ../../reports
      
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/review.sarif.json
      
      - name: Comment on PR
        if: github.event_name == 'pull_request'
        uses: marocchino/sticky-pull-request-comment@v2
        with:
          path: reports/review.md
```

## Dicas de performance

1. **Use cache do Terraform**: Terragrunt reutiliza módulos automaticamente
2. **Paralelize submódulos**: Terragrunt usa `run-all` para paralelizar quando possível
3. **Reduza contexto IA**: Para infraestrutura muito grande, use `--static`:
   ```bash
   terraview scan checkov --terragrunt --static  # scanner only
   ```
4. **Use mocks em desenvolvimento**: Configure `mock_outputs` em dependências para testes rápidos

## Troubleshooting

**Erro: "dependency not found"**
```bash
# Garanta que o módulo dependência existe
ls infrastructure/dev/vpc/terragrunt.hcl
```

**Erro: "terraform version mismatch"**
```bash
# Sync versões
terraform version
terragrunt --version

# Upgrade se necessário
brew upgrade terraform terragrunt
```

**Slow performance**
```bash
# Use --static para pular IA
terraview scan checkov --terragrunt --static

# Ou reduza max_resources em .terraview.yaml
# llm:
#   max_resources: 15
```
