#!/usr/bin/env bash
# ============================================================
# erreetool tool installer — Linux/macOS
# ------------------------------------------------------------
# Installs nmap, nuclei, whatweb, gobuster, sqlmap, feroxbuster,
# SecLists wordlists, and updates Nuclei templates.
# ============================================================

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

log()    { echo -e "${GRAY}[$(date '+%H:%M:%S')]${NC} $*"; }
success(){ echo -e "${GREEN}[OK]${NC}    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()  { echo -e "${RED}[ERR]${NC}   $*"; }
info()   { echo -e "${CYAN}[INFO]${NC}  $*"; }

# Config
FORCE=false
SKIP_WORDLISTS=false
INSTALL_DIR="${HOME}/.local/bin"
PACKAGE_MANAGER="auto"

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
    --force            Skip confirmation prompts
    --skip-wordlists   Skip SecLists download
    --dir PATH         Install directory (default: ~/.local/bin)
    --pm MANAGER       Package manager: apt, dnf, pacman, brew, auto (default)
    -h, --help         Show this help

Examples:
    $0                    # Interactive, auto-detect package manager
    $0 --force --pm apt   # Non-interactive, use apt
EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --force) FORCE=true ;;
        --skip-wordlists) SKIP_WORDLISTS=true ;;
        --dir) INSTALL_DIR="$2"; shift ;;
        --pm) PACKAGE_MANAGER="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) error "Unknown option: $1"; usage; exit 1 ;;
    esac
    shift
done

# Ensure install dir exists and is in PATH
mkdir -p "$INSTALL_DIR"
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *) warn "Adding $INSTALL_DIR to PATH (add to ~/.bashrc or ~/.zshrc)"
       echo "export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

# Detect package manager
detect_pm() {
    if [[ "$PACKAGE_MANAGER" != "auto" ]]; then
        echo "$PACKAGE_MANAGER"
        return
    fi
    if command -v apt-get >/dev/null; then echo "apt"
    elif command -v dnf >/dev/null; then echo "dnf"
    elif command -v pacman >/dev/null; then echo "pacman"
    elif command -v brew >/dev/null; then echo "brew"
    else echo "none"; fi
}

PM=$(detect_pm)
if [[ "$PM" == "none" ]]; then
    error "No supported package manager found (apt, dnf, pacman, brew)."
    exit 1
fi
info "Using package manager: $PM"

# Install a package via the detected PM
pm_install() {
    local pkg="$1"
    case "$PM" in
        apt)   sudo apt-get update && sudo apt-get install -y "$pkg" ;;
        dnf)   sudo dnf install -y "$pkg" ;;
        pacman) sudo pacman -S --noconfirm "$pkg" ;;
        brew)  brew install "$pkg" ;;
        *) return 1 ;;
    esac
}

# Generic tool installer
# Args: name, binary_name, [package_name], [manual_url], [version_check]
install_tool() {
    local name="$1"
    local binary="$2"
    local pkg="${3:-$binary}"
    local url="${4:-}"
    local version_cmd="${5:-$binary --version}"

    if command -v "$binary" >/dev/null; then
        success "$name already installed ($binary)"
        return 0
    fi

    info "Installing $name..."

    if pm_install "$pkg"; then
        success "$name installed via $PM"
        return 0
    fi

    if [[ -n "$url" ]]; then
        warn "Package manager failed, trying manual download..."
        install_manual "$name" "$binary" "$url" "$INSTALL_DIR"
        return $?
    fi

    error "Failed to install $name"
    return 1
}

# Manual download for tools not in repos
install_manual() {
    local name="$1"
    local binary="$2"
    local url="$3"
    local dest_dir="$4"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local archive="$tmp_dir/$(basename "$url")"

    trap 'rm -rf "$tmp_dir"' RETURN

    info "Downloading $name from $url..."
    if ! curl -fsSL -o "$archive" "$url"; then
        error "Download failed"
        return 1
    fi

    info "Extracting..."
    case "$archive" in
        *.zip)   unzip -q "$archive" -d "$tmp_dir" ;;
        *.tar.gz|*.tgz) tar -xzf "$archive" -C "$tmp_dir" ;;
        *.tar.xz) tar -xJf "$archive" -C "$tmp_dir" ;;
        *) error "Unknown archive format: $archive"; return 1 ;;
    esac

    # Find the binary
    local found
    found=$(find "$tmp_dir" -type f -name "$binary" 2>/dev/null | head -1)
    if [[ -z "$found" ]]; then
        # Try without extension for Windows builds
        found=$(find "$tmp_dir" -type f -name "${binary%.exe}" 2>/dev/null | head -1)
    fi

    if [[ -z "$found" ]]; then
        error "Binary $binary not found in archive"
        return 1
    fi

    chmod +x "$found"
    cp "$found" "$dest_dir/$binary"
    success "$name installed to $dest_dir/$binary"
    return 0
}

# ============================================================
# Tool definitions
# ============================================================
# install_tool "Name" "binary" "package" "manual_url" "version_check"

info "erreetool tool installer starting..."
info "Install directory: $INSTALL_DIR"

if [[ "$FORCE" != true ]]; then
    read -rp "Continue? [Y/n] " confirm
    [[ "$confirm" =~ ^[Nn] ]] && { warn "Cancelled"; exit 0; }
}

# Core tools
install_tool "Nmap"        "nmap"        "nmap"        ""               "nmap --version"
install_tool "Nuclei"      "nuclei"      "nuclei"      "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.7_linux_amd64.zip" "nuclei -version"
install_tool "WhatWeb"     "whatweb"     "whatweb"     "https://github.com/urbanadventurer/WhatWeb/releases/latest/download/whatweb-0.5.5-linux.tar.gz" "whatweb --version"
install_tool "Gobuster"    "gobuster"    "gobuster"    "https://github.com/OJ/gobuster/releases/latest/download/gobuster_3.6.0_linux_amd64.tar.gz" "gobuster version"
install_tool "SQLMap"      "sqlmap"      "sqlmap"      "https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip" "sqlmap --version"
install_tool "Feroxbuster" "feroxbuster" "feroxbuster" "https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_linux_amd64.tar.gz" "feroxbuster --version"

# Wordlists (SecLists)
if [[ "$SKIP_WORDLISTS" != true ]]; then
    info "Fetching SecLists wordlists..."
    WORDLIST_DIR="$INSTALL_DIR/../share/wordlists"
    mkdir -p "$WORDLIST_DIR"
    if [[ ! -d "$WORDLIST_DIR/SecLists" ]]; then
        git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WORDLIST_DIR/SecLists" 2>/dev/null \
            && success "SecLists cloned to $WORDLIST_DIR/SecLists" \
            || warn "SecLists clone failed (try manually: git clone https://github.com/danielmiessler/SecLists.git $WORDLIST_DIR/SecLists)"
    else
        info "SecLists already present, updating..."
        git -C "$WORDLIST_DIR/SecLists" pull --quiet 2>/dev/null && success "SecLists updated" || warn "SecLists update failed"
    fi
else
    info "Skipping wordlists (--skip-wordlists)"
fi

# Nuclei templates
info "Updating Nuclei templates..."
if command -v nuclei >/dev/null; then
    nuclei -update-templates -silent && success "Nuclei templates updated" || warn "Nuclei template update failed"
else
    warn "nuclei not in PATH, skipping template update"
fi

# Summary
info "=== Installation Summary ==="
for tool in nmap nuclei whatweb gobuster sqlmap feroxbuster; do
    if command -v "$tool" >/dev/null; then
        success "$tool: OK"
    else
        error "$tool: MISSING"
    fi
done

info "Verify with: erreetool doctor"
info "Add to shell rc if needed: export PATH=\"$INSTALL_DIR:\$PATH\""