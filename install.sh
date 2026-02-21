#!/usr/bin/env bash
set -euo pipefail

# terraview installer — works on Linux, macOS and Windows (Git Bash / WSL)
# Usage: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

REPO="leonamvasquez/terraview"
BINARY_NAME="terraview"
ASSETS_DIR="${HOME}/.terraview"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[info]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ok]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[warn]${NC}  $*" >&2; }
error() { echo -e "${RED}[error]${NC} $*" >&2; }

# Detect OS (including Windows via Git Bash / MSYS / Cygwin / WSL)
detect_os() {
    local os
    os="$(uname -s)"
    case "${os}" in
        Linux*)
            # Check if running under WSL
            if grep -qi microsoft /proc/version 2>/dev/null; then
                echo "windows"
            else
                echo "linux"
            fi
            ;;
        Darwin*)        echo "darwin" ;;
        CYGWIN*|MINGW*|MSYS*)  echo "windows" ;;
        *)
            error "Unsupported operating system: ${os}"
            exit 1
            ;;
    esac
}

# Detect architecture
detect_arch() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        i686|i386)
            error "32-bit (x86) is not supported. Please use a 64-bit system."
            exit 1
            ;;
        *)
            error "Unsupported architecture: ${arch}"
            exit 1
            ;;
    esac
}

# Get latest release version from GitHub
get_latest_version() {
    local version
    version="$(curl -sS "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' \
        | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')" || true

    if [ -z "${version}" ]; then
        version="v0.1.0"
        warn "Could not fetch latest version, defaulting to ${version}"
    fi

    echo "${version}"
}

# Determine install directory based on OS
get_install_dir() {
    local os="$1"
    if [ "${os}" = "windows" ]; then
        # On Windows (Git Bash / MSYS), use user-local dir
        local win_dir="${HOME}/.local/bin"
        mkdir -p "${win_dir}"
        echo "${win_dir}"
    else
        echo "/usr/local/bin"
    fi
}

# Configure PATH for shell profiles
configure_path() {
    local install_dir="$1"
    local os="$2"

    # Check if already in PATH
    if echo "${PATH}" | tr ':' '\n' | grep -qx "${install_dir}"; then
        return 0
    fi

    local shell_profile=""

    if [ "${os}" = "windows" ]; then
        # Git Bash uses ~/.bashrc or ~/.bash_profile
        if [ -f "${HOME}/.bashrc" ]; then
            shell_profile="${HOME}/.bashrc"
        else
            shell_profile="${HOME}/.bash_profile"
        fi
    else
        # Detect user's shell
        local user_shell
        user_shell="$(basename "${SHELL:-bash}")"
        case "${user_shell}" in
            zsh)  shell_profile="${HOME}/.zshrc" ;;
            bash)
                if [ -f "${HOME}/.bashrc" ]; then
                    shell_profile="${HOME}/.bashrc"
                else
                    shell_profile="${HOME}/.bash_profile"
                fi
                ;;
            fish) shell_profile="${HOME}/.config/fish/config.fish" ;;
            *)    shell_profile="${HOME}/.profile" ;;
        esac
    fi

    if [ -n "${shell_profile}" ]; then
        # Check if already added
        if ! grep -q "${install_dir}" "${shell_profile}" 2>/dev/null; then
            echo "" >> "${shell_profile}"
            echo "# Added by terraview installer" >> "${shell_profile}"
            echo "export PATH=\"${install_dir}:\$PATH\"" >> "${shell_profile}"
            info "Added ${install_dir} to PATH in ${shell_profile}"
        fi
    fi

    # Also export for current session
    export PATH="${install_dir}:${PATH}"
}

# Main installation
main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║        terraview installer            ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""

    local os arch version download_url asset_url tmp_dir install_dir bin_ext

    os="$(detect_os)"
    arch="$(detect_arch)"
    version="${TERRAVIEW_VERSION:-$(get_latest_version)}"
    install_dir="$(get_install_dir "${os}")"

    # Set binary extension and archive name
    if [ "${os}" = "windows" ]; then
        bin_ext=".exe"
    else
        bin_ext=""
    fi

    local display_os="${os}"
    case "${os}" in
        darwin)  display_os="macOS" ;;
        linux)   display_os="Linux" ;;
        windows) display_os="Windows" ;;
    esac

    info "OS:       ${display_os}"
    info "Arch:     ${arch}"
    info "Version:  ${version}"
    echo ""

    download_url="https://github.com/${REPO}/releases/download/${version}/${BINARY_NAME}-${os}-${arch}.tar.gz"
    asset_url="https://github.com/${REPO}/releases/download/${version}/terraview-assets.tar.gz"

    tmp_dir="$(mktemp -d)"
    trap '[[ -n "${tmp_dir:-}" ]] && rm -rf "${tmp_dir}"' EXIT

    # Download binary
    info "Downloading ${BINARY_NAME} ${version}..."
    if ! curl -sSL --fail -o "${tmp_dir}/binary.tar.gz" "${download_url}"; then
        error "Failed to download from ${download_url}"
        error ""
        error "The release may not exist yet. You can build from source instead:"
        error "  git clone https://github.com/${REPO}.git"
        error "  cd terraview"
        if [ "${os}" = "windows" ]; then
            error "  go build -o terraview.exe ."
        else
            error "  make install"
        fi
        exit 1
    fi

    # Extract binary
    info "Extracting binary..."
    tar -xzf "${tmp_dir}/binary.tar.gz" -C "${tmp_dir}"

    # Download assets (prompts + rules)
    info "Downloading assets..."
    if curl -sSL --fail -o "${tmp_dir}/assets.tar.gz" "${asset_url}" 2>/dev/null; then
        mkdir -p "${ASSETS_DIR}"
        tar -xzf "${tmp_dir}/assets.tar.gz" -C "${ASSETS_DIR}"
        ok "Assets installed to ${ASSETS_DIR}"
    else
        warn "Could not download assets. You can copy prompts/ and rules/ manually to ${ASSETS_DIR}/"
    fi

    # Find extracted binary
    local src_binary="${tmp_dir}/${BINARY_NAME}-${os}-${arch}${bin_ext}"
    if [ ! -f "${src_binary}" ]; then
        # Try without extension
        src_binary="${tmp_dir}/${BINARY_NAME}-${os}-${arch}"
    fi
    if [ ! -f "${src_binary}" ]; then
        error "Binary not found after extraction"
        exit 1
    fi

    # Install binary
    info "Installing to ${install_dir}..."
    if [ "${os}" = "windows" ]; then
        # Windows: copy to user-local dir (no sudo needed)
        cp "${src_binary}" "${install_dir}/${BINARY_NAME}${bin_ext}"
        # Create 'tv' alias (copy on Windows, symlinks need admin)
        cp "${src_binary}" "${install_dir}/tv${bin_ext}"
        ok "Alias 'tv' -> ${install_dir}/tv${bin_ext}"
    else
        # Unix: install to /usr/local/bin
        if [ -w "${install_dir}" ]; then
            cp "${src_binary}" "${install_dir}/${BINARY_NAME}"
            chmod +x "${install_dir}/${BINARY_NAME}"
            ln -sf "${install_dir}/${BINARY_NAME}" "${install_dir}/tv"
        else
            warn "Need elevated permissions to write to ${install_dir}"
            sudo cp "${src_binary}" "${install_dir}/${BINARY_NAME}"
            sudo chmod +x "${install_dir}/${BINARY_NAME}"
            sudo ln -sf "${install_dir}/${BINARY_NAME}" "${install_dir}/tv"
        fi
        ok "Alias 'tv' -> ${install_dir}/tv"
    fi

    # Configure PATH
    configure_path "${install_dir}" "${os}"

    # Verify
    if command -v "${BINARY_NAME}${bin_ext}" &>/dev/null || command -v "${BINARY_NAME}" &>/dev/null; then
        ok "Installed successfully!"
        echo ""
        "${install_dir}/${BINARY_NAME}${bin_ext}" version 2>/dev/null || true
        echo ""
        echo "  Get started:"
        echo "    cd your-terraform-project"
        echo "    terraview plan   # or: tv plan"
        echo ""
    else
        ok "Binary installed to ${install_dir}/${BINARY_NAME}${bin_ext}"
        warn ""
        warn "Restart your terminal (or run 'source ~/.bashrc') to use 'terraview' and 'tv'."
        echo ""
    fi
}

main "$@"
