#!/bin/bash

set -e

echo "[+] Memperbarui paket..."
sudo apt update -y
sudo apt install -y curl wget git unzip jq whois

echo "[+] Menginstal Go (jika belum ada)..."
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz
    echo "export PATH=\$PATH:/usr/local/go/bin" >> ~/.bashrc
    echo "export GOPATH=\$HOME/go" >> ~/.bashrc
    source ~/.bashrc
    rm go1.22.3.linux-amd64.tar.gz
fi

export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go

echo "[+] Menginstal subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "[+] Menginstal assetfinder..."
go install -v github.com/tomnomnom/assetfinder@latest

echo "[+] Menginstal chaos..."
go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest

echo "[+] Menginstal github-subdomains..."
go install -v github.com/gwen001/github-subdomains@latest

echo "[+] Menginstal shodan CLI..."
go install -v github.com/shodan-io/shodan/cli/shodan@latest

echo "[+] Menginstal dnsx..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

echo "[+] Menginstal naabu..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

echo "[+] Menginstal httpx..."
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

echo "[+] Menginstal nuclei..."
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

echo "[+] Menginstal gau..."
go install -v github.com/lc/gau/v2/cmd/gau@latest

echo "[+] Menginstal waybackurls..."
go install -v github.com/tomnomnom/waybackurls@latest

echo "[+] Menginstal subzy..."
go install -v github.com/LukaSikic/subzy@latest

echo "[+] Menginstal katana..."
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "[✔] Semua tools berhasil diinstal ke $GOPATH/bin. Tambahkan ke PATH jika belum."
echo "export PATH=\$PATH:\$HOME/go/bin" >> ~/.bashrc
source ~/.bashrc
