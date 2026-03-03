# Instalação

## Script de instalação (Linux, macOS, Windows WSL)

```bash
curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash
```

O script detecta automaticamente OS e arquitetura, baixa o binário correto do GitHub Releases e cria o alias `tv`.

## Homebrew (macOS / Linux)

```bash
brew install leonamvasquez/terraview/terraview
```

## Scoop (Windows)

```powershell
scoop bucket add terraview https://github.com/leonamvasquez/scoop-terraview.git
scoop install terraview
```

## APT — Debian / Ubuntu

```bash
# Adicionar repositório
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.deb.sh' | sudo bash

# Instalar
sudo apt update
sudo apt install terraview
```

## DNF / YUM — Fedora / RHEL / Amazon Linux

```bash
# Adicionar repositório
curl -1sLf 'https://dl.cloudsmith.io/public/workspace-for-leonam/terraview/setup.rpm.sh' | sudo bash

# Instalar
sudo dnf install terraview
```

## Docker

```bash
docker pull leonamvasquez/terraview:latest

# Uso
docker run --rm -v $(pwd):/workspace leonamvasquez/terraview scan checkov
```

Veja [Docker](../integration/docker.md) para mais opções.

## Windows — PowerShell (script direto)

```powershell
irm https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.ps1 | iex
```

## Download manual

```bash
# Substitua <VERSION>, <OS> e <ARCH> conforme seu sistema
# OS: linux, darwin, windows | ARCH: amd64, arm64
curl -Lo terraview.tar.gz https://github.com/leonamvasquez/terraview/releases/download/<VERSION>/terraview-<OS>-<ARCH>.tar.gz
tar -xzf terraview.tar.gz
sudo mv terraview /usr/local/bin/terraview
```

## Compilar do código-fonte

```bash
git clone https://github.com/leonamvasquez/terraview.git
cd terraview
make install
```

Compila o binário, instala em `~/.local/bin/terraview`, cria o symlink `tv` e copia os prompts para `~/.terraview/prompts/`.

## Atualização

Atualize o TerraView pelo seu gerenciador de pacotes:

```bash
# Homebrew
brew upgrade leonamvasquez/terraview/terraview

# Scoop
scoop update terraview

# APT
sudo apt update && sudo apt upgrade terraview

# DNF
sudo dnf upgrade terraview
```

## Autocompletar no shell

```bash
# Bash
terraview completion bash | sudo tee /etc/bash_completion.d/terraview > /dev/null
source /etc/bash_completion.d/terraview

# Zsh (adicione ao ~/.zshrc)
terraview completion zsh | sudo tee "${fpath[1]}/_terraview" > /dev/null

# Fish
terraview completion fish | source

# PowerShell (adicione ao seu $PROFILE)
terraview completion powershell | Out-File $PROFILE -Append
```

Após configurar, reabra o terminal e use `terraview <Tab>` para autocompletar comandos, flags e argumentos.

## Requisitos

- Terraform >= 0.12
- Um ou mais scanners instalados (Checkov, tfsec, Terrascan) — o terraview pode instalá-los por você via `terraview scanners install --all`
