#!/bin/bash

set -e

echo "[+] Updating package index..."
sudo apt update -y
sudo apt install -y curl wget git unzip jq whois

echo "[+] Setting up Go in user space..."

# Set Go version
GO_VERSION="1.22.3"
GO_TAR="go$GO_VERSION.linux-amd64.tar.gz"

# Download and install to ~/go-sdk (not /usr/local)
if [ ! -d "$HOME/go-sdk" ]; then
    wget https://go.dev/dl/$GO_TAR
    rm -rf "$HOME/go-sdk"
    mkdir -p "$HOME/go-sdk"
    tar -C "$HOME/go-sdk" --strip-components=1 -xzf $GO_TAR
    rm $GO_TAR
fi

# Set Go paths for user install
export GOROOT="$HOME/go-sdk"
export GOPATH="$HOME/go"
export GOBIN="$GOPATH/bin"
export PATH="$GOBIN:$GOROOT/bin:$PATH"

# Persist paths in .bashrc if not already there
if ! grep -q 'export GOROOT=' ~/.bashrc; then
    echo "export GOROOT=\$HOME/go-sdk" >> ~/.bashrc
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    echo "export GOBIN=\$GOPATH/bin" >> ~/.bashrc
    echo "export PATH=\$PATH:\$GOBIN:\$GOROOT/bin" >> ~/.bashrc
fi

# Confirm go works
"$GOROOT/bin/go" version

install_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "[+] Installing $1..."
        "$GOROOT/bin/go" install -v "$2"@latest
    else
        echo "[✓] $1 already installed at $(which $1)"
    fi
}

echo "[+] Installing recon tools into ~/go/bin..."

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

echo "[✓] All tools are installed in ~/go/bin/"
