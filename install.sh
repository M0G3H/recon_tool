#!/bin/bash

set -e

RED="\033[91m"
GREEN="\033[92m"
YELLOW="\033[93m"
RESET="\033[0m"

INSTALL_DIR="$HOME/Desktop/recon_tool"

echo -e "${GREEN}[+] Installing recon_tool...${RESET}"

# 1. Create project directory
mkdir -p "$INSTALL_DIR"

# 2. Copy project files
cp recon_tool.sh report.py target.txt "$INSTALL_DIR/"

# 3. Install system dependencies
sudo apt update
sudo apt install -y \
    git curl wget unzip \
    python3 python3-pip python3-venv \
    nmap nikto sslscan \
    golang-go
sudo snap install dalfox

# 4. Install Python dependencies
python3 -m pip install --user wafw00f
pipx install arjun

# 5. Install Go-based security tools
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go get -u github.com/tomnomnom/gf

#install jexboss
git clone https://github.com/joaomatosf/jexboss.git /opt/jexboss
cd /opt/jexboss
pip install -r requires.txt
sudo chmod +x /opt/jexboss/jexboss.py
sudo ln -s /opt/jexboss/jexboss.py /usr/local/bin/jexboss

#install sqlmap
sudo git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
cd /opt/sqlmap
sudo chmod +x /opt/sqlmap/sqlmap.py
sudo ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# 6. Install Nuclei templates
nuclei -update-templates

echo -e "${GREEN}[+] Installation completed.${RESET}"
echo -e "${YELLOW}[*] Project directory: $INSTALL_DIR${RESET}"
echo -e "${YELLOW}[*] Run: $INSTALL_DIR/recon_tool.sh -full${RESET}"
