#!/bin/bash

# ========================================
# 自动化工具安装脚本
# 用于安装所有信息收集工具
# ========================================

set -e

echo "======================================="
echo "信息收集工具自动安装脚本"
echo "======================================="
echo ""

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检测操作系统
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/debian_version ]; then
            echo "debian"
        elif [ -f /etc/redhat-release ]; then
            echo "redhat"
        elif [ -f /etc/arch-release ]; then
            echo "arch"
        else
            echo "linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    else
        echo "unknown"
    fi
}

OS=$(detect_os)
echo -e "${GREEN}[*]${NC} 检测到操作系统: $OS"

# 安装Go环境
install_go() {
    if command -v go &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Go 已安装: $(go version)"
        return
    fi
    
    echo -e "${YELLOW}[*]${NC} 安装 Go..."
    
    GO_VERSION="1.21.5"
    
    case $OS in
        debian|linux)
            wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
            sudo tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
            rm go${GO_VERSION}.linux-amd64.tar.gz
            ;;
        macos)
            brew install go
            ;;
    esac
    
    # 设置环境变量
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export GOPATH=$HOME/go' >> ~/.bashrc
    echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc
    
    source ~/.bashrc
    
    echo -e "${GREEN}[✓]${NC} Go 安装完成"
}

# 安装Python3和pip
install_python() {
    if command -v python3 &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Python3 已安装"
        return
    fi
    
    echo -e "${YELLOW}[*]${NC} 安装 Python3..."
    
    case $OS in
        debian)
            sudo apt update
            sudo apt install -y python3 python3-pip
            ;;
        redhat)
            sudo dnf install -y python3 python3-pip
            ;;
        arch)
            sudo pacman -S --noconfirm python python-pip
            ;;
        macos)
            brew install python3
            ;;
    esac
    
    echo -e "${GREEN}[✓]${NC} Python3 安装完成"
}

# 安装基础依赖
install_dependencies() {
    echo -e "${YELLOW}[*]${NC} 安装基础依赖..."
    
    case $OS in
        debian)
            sudo apt update
            sudo apt install -y git curl wget jq dnsutils nmap chromium-browser
            ;;
        redhat)
            sudo dnf install -y git curl wget jq bind-utils nmap chromium
            ;;
        arch)
            sudo pacman -S --noconfirm git curl wget jq bind nmap chromium
            ;;
        macos)
            brew install git curl wget jq nmap
            brew install --cask chromium
            ;;
    esac
    
    echo -e "${GREEN}[✓]${NC} 基础依赖安装完成"
}

# 安装Go工具
install_go_tools() {
    echo -e "${YELLOW}[*]${NC} 安装 Go 工具..."
    
    # ProjectDiscovery工具
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
    go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
    
    # 其他Go工具
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/tomnomnom/httprobe@latest
    go install -v github.com/tomnomnom/meg@latest
    go install -v github.com/tomnomnom/gf@latest
    go install -v github.com/tomnomnom/qsreplace@latest
    go install -v github.com/tomnomnom/unfurl@latest
    
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/jaeles-project/gospider@latest
    go install -v github.com/hakluke/hakrawler@latest
    go install -v github.com/hakluke/hakcheckurl@latest
    go install -v github.com/hakluke/hakrevdns@latest
    
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/OJ/gobuster/v3@latest
    
    go install -v github.com/hahwul/dalfox/v2@latest
    go install -v github.com/lc/subjs@latest
    go install -v github.com/003random/getJS@latest
    
    go install -v github.com/sensepost/gowitness@latest
    
    go install -v github.com/d3mondev/puredns/v2@latest
    go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
    
    go install -v github.com/LukaSikic/subzy@latest
    go install -v github.com/haccer/subjack@latest
    
    go install -v github.com/projectdiscovery/proxify/cmd/proxify@latest
    go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
    
    go install -v github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
    go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
    
    echo -e "${GREEN}[✓]${NC} Go 工具安装完成"
}

# 安装Python工具
install_python_tools() {
    echo -e "${YELLOW}[*]${NC} 安装 Python 工具..."
    
    pip3 install --upgrade pip
    
    # 信息收集工具
    pip3 install sublist3r
    pip3 install dnspython
    pip3 install requests
    pip3 install beautifulsoup4
    
    # Arjun - 参数发现
    pip3 install arjun
    
    # LinkFinder - JS分析
    git clone https://github.com/GerbenJavado/LinkFinder.git /tmp/LinkFinder
    cd /tmp/LinkFinder
    pip3 install -r requirements.txt
    sudo python3 setup.py install
    cd -
    
    # CloudEnum
    git clone https://github.com/initstring/cloud_enum.git /tmp/cloud_enum
    cd /tmp/cloud_enum
    pip3 install -r requirements.txt
    sudo ln -s $(pwd)/cloud_enum.py /usr/local/bin/cloud_enum
    cd -
    
    # Photon - 爬虫
    pip3 install photon-python
    
    # Subover - 子域名接管
    pip3 install subover
    
    echo -e "${GREEN}[✓]${NC} Python 工具安装完成"
}

# 安装Amass
install_amass() {
    echo -e "${YELLOW}[*]${NC} 安装 Amass..."
    
    if command -v amass &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Amass 已安装"
        return
    fi
    
    case $OS in
        debian|linux)
            AMASS_VERSION="4.2.0"
            wget https://github.com/OWASP/Amass/releases/download/v${AMASS_VERSION}/amass_Linux_amd64.zip
            unzip amass_Linux_amd64.zip
            sudo mv amass_Linux_amd64/amass /usr/local/bin/
            rm -rf amass_Linux_amd64*
            ;;
        macos)
            brew install amass
            ;;
    esac
    
    echo -e "${GREEN}[✓]${NC} Amass 安装完成"
}

# 安装Massdns
install_massdns() {
    echo -e "${YELLOW}[*]${NC} 安装 Massdns..."
    
    if command -v massdns &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Massdns 已安装"
        return
    fi
    
    git clone https://github.com/blechschmidt/massdns.git /tmp/massdns
    cd /tmp/massdns
    make
    sudo make install
    cd -
    
    echo -e "${GREEN}[✓]${NC} Massdns 安装完成"
}

# 下载字典和配置文件
download_wordlists() {
    echo -e "${YELLOW}[*]${NC} 下载字典文件..."
    
    WORDLIST_DIR="$HOME/wordlists"
    mkdir -p $WORDLIST_DIR
    
    # DNS字典
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt -O $WORDLIST_DIR/dns-top1m.txt
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt -O $WORDLIST_DIR/dns-jhaddix.txt
    
    # 目录字典
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O $WORDLIST_DIR/common.txt
    wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-directories.txt -O $WORDLIST_DIR/directories.txt
    
    # DNS解析器列表
    wget -q https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O $WORDLIST_DIR/resolvers.txt
    
    echo -e "${GREEN}[✓]${NC} 字典下载完成: $WORDLIST_DIR"
}

# 更新Nuclei模板
update_nuclei_templates() {
    echo -e "${YELLOW}[*]${NC} 更新 Nuclei 模板..."
    
    nuclei -update-templates
    
    echo -e "${GREEN}[✓]${NC} Nuclei 模板更新完成"
}

# 配置文件
create_configs() {
    echo -e "${YELLOW}[*]${NC} 创建配置文件..."
    
    CONFIG_DIR="$HOME/.config/recon"
    mkdir -p $CONFIG_DIR
    
    # Subfinder配置
    cat > $CONFIG_DIR/subfinder-config.yaml << 'EOF'
# Subfinder Configuration
resolvers:
  - 1.1.1.1
  - 8.8.8.8
  - 8.8.4.4
sources:
  - alienvault
  - binaryedge
  - bufferover
  - censys
  - certspotter
  - crtsh
  - dnsdumpster
  - hackertarget
  - passivetotal
  - securitytrails
  - shodan
  - threatcrowd
  - virustotal
  - zoomeye
EOF

    # Amass配置
    cat > $CONFIG_DIR/amass-config.ini << 'EOF'
[scope]
port = 80,443,8080,8443

[resolvers]
resolver = 1.1.1.1
resolver = 8.8.8.8

[data_sources]
minimum_ttl = 1440

[bruteforce]
enabled = true
recursive = true
EOF

    echo -e "${GREEN}[✓]${NC} 配置文件创建完成: $CONFIG_DIR"
}

# 主安装流程
main() {
    echo ""
    echo -e "${GREEN}开始安装...${NC}"
    echo ""
    
    install_dependencies
    install_go
    install_python
    install_go_tools
    install_python_tools
    install_amass
    install_massdns
    download_wordlists
    update_nuclei_templates
    create_configs
    
    echo ""
    echo "======================================="
    echo -e "${GREEN}安装完成!${NC}"
    echo "======================================="
    echo ""
    echo "请运行以下命令更新环境变量:"
    echo "  source ~/.bashrc"
    echo ""
    echo "或者重新打开终端"
    echo ""
    echo "字典位置: $HOME/wordlists"
    echo "配置位置: $HOME/.config/recon"
    echo ""
}

main

