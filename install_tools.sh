#!/bin/bash

set -e

success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
warn()    { echo -e "\033[1;33m[WARN]\033[0m $1"; }

# List of required tools
REQUIRED_TOOLS=(
    subfinder assetfinder chaos github-subdomains shodan
    dnsx naabu httpx nuclei gau waybackurls
    subzy katana linkfinder xnLinkFinder
)

# === ASK TO INSTALL SYSTEM DEPENDENCIES ===
ask_install_dependencies() {
    echo "🧰 Some tools require system packages (curl, git, libpcap, etc.)"
    echo -n "Do you want to install recommended system dependencies now? (y/n): "
    read -r dep_choice

    if [[ "$dep_choice" == "y" || "$dep_choice" == "Y" ]]; then
        sudo apt update
        sudo apt install -y curl wget git unzip jq whois libpcap-dev \
            build-essential pkg-config python3 python3-pip python3-venv pipx
        success "System dependencies installed"
    else
        warn "System dependencies not installed — some tools may fail later"
    fi
}

# === INSTALL GO (user space only) ===
install_go() {
    MIN_GO_VERSION="1.23"
    GO_VERSION="1.23.10"

    if command -v go &> /dev/null; then
        CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
        if [ "$(printf '%s\n' "$MIN_GO_VERSION" "$CURRENT" | sort -V | head -n1)" = "$MIN_GO_VERSION" ]; then
            success "Go version $CURRENT is already installed"
            return
        else
            warn "Go version $CURRENT is too old, upgrading..."
        fi
    else
        info "Go not detected, proceeding with user-space installation..."
    fi

    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    wget "https://go.dev/dl/${GO_TAR}"
    rm -rf "$HOME/go-sdk"
    mkdir -p "$HOME/go-sdk"
    tar -C "$HOME/go-sdk" --strip-components=1 -xzf "$GO_TAR"
    rm "$GO_TAR"

    export GOROOT="$HOME/go-sdk"
    export GOPATH="$HOME/go"
    export GOBIN="$GOPATH/bin"
    export PATH="$GOROOT/bin:$GOBIN:$PATH"

    if ! grep -q "go-sdk" ~/.bashrc; then
        echo 'export GOROOT=$HOME/go-sdk' >> ~/.bashrc
        echo 'export GOPATH=$HOME/go' >> ~/.bashrc
        echo 'export GOBIN=$GOPATH/bin' >> ~/.bashrc
        echo 'export PATH=$GOROOT/bin:$GOBIN:$PATH' >> ~/.bashrc
    fi

    go version || { echo "❌ Go install failed"; exit 1; }
    success "Go $GO_VERSION installed in user-space and configured for ~/go/bin"
}

# === INSTALL GO-BASED TOOL ===
install_tool() {
    local name="$1"
    local path="$2"
    info "Installing $name..."
    go install "$path@latest" || { echo "❌ Failed to install $name"; return 1; }
    success "$name installed successfully"
}

# === INSTALL SHODAN CLI ===
install_shodan() {
    python3 -m venv myenv
    source myenv/bin/activate
    info "Installing Shodan CLI using pip (user mode)..."
    sudo apt remove -y python3-shodan >/dev/null 2>&1 || true
    sudo rm -f /usr/bin/shodan

    python3 -m pip install --upgrade --user pip

    export PATH="$HOME/.local/bin:$PATH"
    if ! grep -q ".local/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
    fi

    python3 -m pip install --upgrade --user shodan
    success "Shodan CLI installed via pip"
}

# === PLACEHOLDER FOR OTHERS ===
install_linkfinder() { echo "(Add working LinkFinder install here)"; }
install_xnlinkfinder() { echo "(Add working xnLinkFinder install here)"; }

# === CHECK & INSTALL MISSING TOOLS ===
check_missing_tools() {
    MISSING_TOOLS=()

    echo "\n🔍 Checking required tools..."
    for tool in "${REQUIRED_TOOLS[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            echo "❌ $tool is NOT installed"
            MISSING_TOOLS+=("$tool")
        else
            echo "✅ $tool is installed"
        fi
    done

    echo ""
    if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
        success "All required tools are already installed 🎉"
        success "Don't forget to put API keys to .env for Shodan, Chaos and Github!"
        return
    else
        echo "⚠️  ${#MISSING_TOOLS[@]} tools are missing: ${MISSING_TOOLS[*]}"
        echo -n "Would you like to automatically install them now? (y/n): "
        read -r install_choice

        if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
            for tool in "${MISSING_TOOLS[@]}"; do
                case "$tool" in
                    subfinder) install_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder ;;
                    assetfinder) install_tool assetfinder github.com/tomnomnom/assetfinder ;;
                    chaos) install_tool chaos github.com/projectdiscovery/chaos-client/cmd/chaos ;;
                    github-subdomains) install_tool github-subdomains github.com/gwen001/github-subdomains ;;
                    shodan) install_shodan ;;
                    dnsx) install_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx ;;
                    naabu) install_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu;;
                    httpx) install_tool httpx github.com/projectdiscovery/httpx/cmd/httpx ;;
                    nuclei) install_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei ;;
                    gau) install_tool gau github.com/lc/gau/v2/cmd/gau ;;
                    waybackurls) install_tool waybackurls github.com/tomnomnom/waybackurls ;;
                    subzy) install_tool subzy github.com/PentestPad/subzy ;;
                    katana) install_tool katana github.com/projectdiscovery/katana/cmd/katana ;;
                    linkfinder) install_linkfinder ;;
                    xnlinkfinder) install_xnlinkfinder ;;
                    *) warn "No installer defined for $tool, skipping..." ;;
                esac
            done
        else
            echo "ℹ️  Please install the missing tools manually and rerun the script."
            exit 1
        fi
    fi
}

# === MAIN ===
ask_install_dependencies
install_go
check_missing_tools
