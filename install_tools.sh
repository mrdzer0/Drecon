#!/bin/bash

set -e

# === UTILITY FUNCTIONS ===
info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
warn()    { echo -e "\033[1;33m[WARN]\033[0m $1"; }

# === SYSTEM PREP ===
info "Installing core system dependencies..."
sudo apt update -y
sudo apt install -y curl wget git unzip jq whois libpcap-dev build-essential libpcap-dev pkg-config python3 python3-pip pipx python3-venv

# === GO CHECK & CONDITIONAL INSTALL ===
MIN_GO_VERSION="1.23"

go_needs_update() {
    local current
    current=$(go version 2>/dev/null | awk '{print $3}' | sed 's/go//')
    if [[ -z "$current" ]]; then
        return 0  # Go not installed
    fi
    # Compare versions
    [ "$(printf '%s\n' "$MIN_GO_VERSION" "$current" | sort -V | head -n1)" != "$MIN_GO_VERSION" ]
}

install_linkfinder() {
    if ! command -v linkfinder &> /dev/null; then
        info "Installing LinkFinder safely using virtualenv..."

        # Prepare temp install folder
        LINKFOLDER="$HOME/.local/share/linkfinder"
        mkdir -p "$LINKFOLDER"

        # Clone repo
        git clone https://github.com/GerbenJavado/LinkFinder.git /tmp/LinkFinder

        # Create virtual environment
        python3 -m venv "$LINKFOLDER/venv"
        source "$LINKFOLDER/venv/bin/activate"

        # Install requirements inside virtualenv
        pip install -r /tmp/LinkFinder/requirements.txt

        # Copy main script into persistent directory
        cp /tmp/LinkFinder/linkfinder.py "$LINKFOLDER/"

        # Create wrapper executable
        echo -e "#!/bin/bash\nsource \"$LINKFOLDER/venv/bin/activate\" && python3 \"$LINKFOLDER/linkfinder.py\" \"\$@\"" \
            | sudo tee /usr/local/bin/linkfinder > /dev/null
        sudo chmod +x /usr/local/bin/linkfinder

        # Clean up
        deactivate
        rm -rf /tmp/LinkFinder

        success "LinkFinder installed and callable as 'linkfinder'"
    else
        success "LinkFinder is already installed"
    fi
}

install_xnlinkfinder() {
    if ! command -v xnLinkFinder &> /dev/null; then
        info "Installing xnLinkFinder via pipx..."

        # Ensure pipx is installed
        sudo apt install -y pipx python3-venv
        export PATH="$HOME/.local/bin:$PATH"
        if ! grep -q "$HOME/.local/bin" ~/.bashrc; then
            echo 'export PATH=$PATH:$HOME/.local/bin' >> ~/.bashrc
        fi

        # Use pipx with --spec
        pipx install --spec git+https://github.com/xnl-h4ck3r/xnLinkFinder.git xnlinkfinder

        success "xnLinkFinder installed successfully via pipx"
    else
        success "xnLinkFinder is already installed"
    fi
}

install_shodan() {
    if ! command -v shodan &> /dev/null; then
        info "Installing Shodan CLI via pip..."
        pip install --user shodan

        # Ensure pip user bin is in PATH
        PIP_BIN=$(python3 -m site --user-base)/bin
        if ! echo "$PATH" | grep -q "$PIP_BIN"; then
            echo "export PATH=\$PATH:$PIP_BIN" >> ~/.bashrc
            export PATH=$PATH:$PIP_BIN
            success "Added $PIP_BIN to PATH"
        fi

        success "Shodan CLI installed and available as 'shodan'"
    else
        success "Shodan CLI is already available as 'shodan'"
    fi
}


install_go_if_needed() {
    MIN_GO_VERSION="1.23"

    # Check if Go exists and meets the version requirement
    if command -v go &> /dev/null; then
        CURRENT=$(go version | awk '{print $3}' | sed 's/go//')
        if [ "$(printf '%s\n' "$MIN_GO_VERSION" "$CURRENT" | sort -V | head -n1)" = "$MIN_GO_VERSION" ]; then
            success "Go version $CURRENT is already installed"
            return
        else
            warn "Go version $CURRENT is too old, upgrading..."
        fi
    else
        info "Go not detected, proceeding with installation..."
    fi

    # Download & install Go
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    GO_VERSION="1.23.10"
    GO_TAR="go${GO_VERSION}.linux-${ARCH}.tar.gz"
    wget "https://go.dev/dl/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "$GO_TAR"
    rm "$GO_TAR"

    # Update path for current session (immediate)
    export PATH="/usr/local/go/bin:$PATH"

    # Add to system-wide profile for future shells
    if ! grep -q "/usr/local/go/bin" /etc/profile; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    fi

    # Also update root's bashrc for sudo/root users
    if [ "$EUID" -eq 0 ] && ! grep -q "/usr/local/go/bin" ~/.bashrc; then
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    fi

    # Confirm install
    go version || { echo "❌ Go install failed"; exit 1; }

    success "Go $GO_VERSION installed and available"
}



# === SET GO ENV VARIABLES ===
install_go_if_needed
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"
export PATH="$PATH:$GOBIN"

if ! grep -q 'export GOBIN=' ~/.bashrc; then
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export GOBIN=\$GOPATH/bin" >> ~/.bashrc
    echo "export PATH=\$PATH:\$GOBIN" >> ~/.bashrc
fi

# === TOOL INSTALLATION FUNCTION ===
install_tool() {
    local name=$1
    local pkg=$2
    if ! command -v "$name" &> /dev/null; then
        info "Installing $name..."
        go install -v "$pkg@latest"
    else
        success "$name is already installed"
    fi
}

# === INSTALL TOOLS ===
info "Installing recon tools into ~/go/bin/..."

install_tool subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder
install_tool assetfinder github.com/tomnomnom/assetfinder
install_tool chaos github.com/projectdiscovery/chaos-client/cmd/chaos
install_tool github-subdomains github.com/gwen001/github-subdomains
install_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx
install_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu
install_tool httpx github.com/projectdiscovery/httpx/cmd/httpx
install_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_tool gau github.com/lc/gau/v2/cmd/gau
install_tool waybackurls github.com/tomnomnom/waybackurls
install_tool subzy github.com/PentestPad/subzy
install_tool katana github.com/projectdiscovery/katana/cmd/katana
install_linkfinder
install_xnlinkfinder

# === Post-Installation TOOLS ===
echo "=============================================================="
echo -e "\033[1;33m⚠️  POST-INSTALLATION REMINDERS — Manual Setup Required:\033[0m"
echo ""
echo -e "🔑 \033[1;36mSHODAN\033[0m"
echo "   → Run: shodan init YOUR_API_KEY"
echo "   → Get your API key from: https://account.shodan.io/"

echo -e "🔑 \033[1;36mCHAOS (ProjectDiscovery)\033[0m"
echo "   → Requires CHAOS_API_KEY in your environment"
echo "   → Export it like this:"
echo "      export CHAOS_KEY='your-key-here'"

echo -e "🔑 \033[1;36mGITHUB-SUBDOMAINS\033[0m"
echo "   → Requires GitHub API token with 'repo' scope"
echo "   → Export it as:"
echo "      export GITHUB_TOKEN='your-token-here'"

echo -e "💡 \033[1;32mDONE:\033[0m All tools are installed to ~/go/bin/ and ~/.local/bin/"
echo "   If commands aren't found, restart terminal or run: source ~/.bashrc"
echo "=============================================================="