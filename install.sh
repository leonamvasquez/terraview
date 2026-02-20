#!/usr/bin/env bash
set -euo pipefail

# terraview installer
# Usage: curl -sSL https://raw.githubusercontent.com/leonamvasquez/terraview/main/install.sh | bash

REPO="leonamvasquez/terraview"
BINARY_NAME="terraview"
INSTALL_DIR="/usr/local/bin"
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

# Detect OS
detect_os() {
    local os
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "${os}" in
        linux*)  echo "linux" ;;
        darwin*) echo "darwin" ;;
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

# Main installation
main() {
    echo ""
    echo "  ╔═══════════════════════════════════════╗"
    echo "  ║      terraview installer             ║"
    echo "  ╚═══════════════════════════════════════╝"
    echo ""

    local os arch version download_url asset_url tmp_dir

    os="$(detect_os)"
    arch="$(detect_arch)"
    version="${TERRAVIEW_VERSION:-$(get_latest_version)}"

    info "OS:       ${os}"
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
        error "  make install"
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

    # Install binary
    info "Installing to ${INSTALL_DIR}..."
    if [ -w "${INSTALL_DIR}" ]; then
        cp "${tmp_dir}/${BINARY_NAME}-${os}-${arch}" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        warn "Need elevated permissions to write to ${INSTALL_DIR}"
        sudo cp "${tmp_dir}/${BINARY_NAME}-${os}-${arch}" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Create 'tv' alias symlink
    if [ -w "${INSTALL_DIR}" ]; then
        ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/tv"
    else
        sudo ln -sf "${INSTALL_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/tv"
    fi
    ok "Alias 'tv' -> ${INSTALL_DIR}/tv"

    # Verify
    if command -v "${BINARY_NAME}" &>/dev/null; then
        ok "Installed successfully!"
        echo ""
        "${BINARY_NAME}" version
        echo ""
        echo "  Get started:"
        echo "    cd your-terraform-project"
        echo "    terraview review   # or: tv review"
        echo ""
    else
        warn "Binary installed but not found in PATH."
        warn "Add ${INSTALL_DIR} to your PATH:"
        warn "  export PATH=\"${INSTALL_DIR}:\$PATH\""
    fi
}

main "$@"
