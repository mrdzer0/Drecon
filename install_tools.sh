#!/bin/bash

set -e

# === UTILITY FUNCTIONS ===
info()    { echo -e "\033[1;34m[INFO]\033[0m $1"; }
success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
warn()    { echo -e "\033[1;33m[WARN]\033[0m $1"; }

# === SYSTEM PREP ===
info "Installing core system dependencies..."
sudo apt update -y
sudo apt install -y curl wget git unzip jq whois

# === GO CHECK & CONDITIONAL INSTALL ===
MIN_GO_VERSION="1.20"

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
        info "Installing LinkFinder..."

        # Remove any broken old symlink
        sudo rm -f /usr/local/bin/linkfinder

        # Clone and install dependencies
        git clone https://github.com/GerbenJavado/LinkFinder.git /tmp/LinkFinder
        pip install --user -r /tmp/LinkFinder/requirements.txt

        # Copy to a safe permanent location
        mkdir -p ~/.local/share/linkfinder
        cp /tmp/LinkFinder/linkfinder.py ~/.local/share/linkfinder/linkfinder.py

        # Create wrapper script
        echo -e "#!/bin/bash\npython3 ~/.local/share/linkfinder/linkfinder.py \"\$@\"" | sudo tee /usr/local/bin/linkfinder > /dev/null
        sudo chmod +x /usr/local/bin/linkfinder

        # Clean up temp folder
        rm -rf /tmp/LinkFinder

        success "LinkFinder installed and usable as 'linkfinder'"
    else
        success "LinkFinder is already available as 'linkfinder'"
    fi
}



install_xnlinkfinder() {
    if ! command -v xnlinkfinder &> /dev/null; then
        info "Installing xnLinkFinder via pip..."
        pip install xnLinkFinder

        # Ensure pip bin path is in PATH
        PIP_BIN=$(python3 -m site --user-base)/bin
        if ! echo "$PATH" | grep -q "$PIP_BIN"; then
            echo "export PATH=\$PATH:$PIP_BIN" >> ~/.bashrc
            export PATH=$PATH:$PIP_BIN
            success "Added $PIP_BIN to PATH"
        fi

        success "xnLinkFinder installed and available as 'xnlinkfinder'"
    else
        success "xnLinkFinder is already available as 'xnlinkfinder'"
    fi
}



if go_needs_update; then
    info "Installing or updating Go (version <$MIN_GO_VERSION or not found)..."
    ARCH=$(uname -m)
    PLATFORM="linux"

    case "$ARCH" in
        x86_64) ARCH=amd64 ;;
        aarch64 | arm64) ARCH=arm64 ;;
        *) echo "Unsupported architecture: $ARCH" && exit 1 ;;
    esac

    GO_VERSION="1.22.3"
    GO_TAR="go${GO_VERSION}.${PLATFORM}-${ARCH}.tar.gz"

    wget "https://go.dev/dl/${GO_TAR}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$GO_TAR"
    rm "$GO_TAR"

    export PATH=$PATH:/usr/local/go/bin
    echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
    source ~/.bashrc
else
    success "Go version is sufficient (>= $MIN_GO_VERSION)"
fi

# === SET GO ENV VARIABLES ===
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
install_tool shodan github.com/shodan-io/shodan/cli/shodan
install_tool dnsx github.com/projectdiscovery/dnsx/cmd/dnsx
install_tool naabu github.com/projectdiscovery/naabu/v2/cmd/naabu
install_tool httpx github.com/projectdiscovery/httpx/cmd/httpx
install_tool nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei
install_tool gau github.com/lc/gau/v2/cmd/gau
install_tool waybackurls github.com/tomnomnom/waybackurls
install_tool subzy github.com/LukaSikic/subzy
install_tool katana github.com/projectdiscovery/katana/cmd/katana
install_linkfinder
install_xnlinkfinder

success "All tools installed and ready at ~/go/bin/"
