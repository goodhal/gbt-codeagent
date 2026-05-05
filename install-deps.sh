#!/bin/bash

# 代码审计平台 - 依赖工具自动安装脚本 (Linux/Mac)
# 用途：自动检测并安装项目所需的外部工具

set -e

echo "=========================================="
echo "  代码审计平台 - 依赖工具安装脚本"
echo "=========================================="
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
            OS="debian"
            echo -e "${GREEN}✓${NC} 检测到系统: Debian/Ubuntu"
        elif [ -f /etc/redhat-release ]; then
            OS="redhat"
            echo -e "${GREEN}✓${NC} 检测到系统: RedHat/CentOS"
        else
            OS="linux"
            echo -e "${GREEN}✓${NC} 检测到系统: Linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "${GREEN}✓${NC} 检测到系统: macOS"
    else
        echo -e "${RED}✗${NC} 不支持的操作系统: $OSTYPE"
        exit 1
    fi
}

# 检查命令是否存在
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# 检查工具是否已安装
check_tool() {
    local tool=$1
    local check_cmd=$2

    if eval "$check_cmd" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC} $tool 已安装"
        return 0
    else
        echo -e "${YELLOW}○${NC} $tool 未安装"
        return 1
    fi
}

# 安装 Node.js
install_nodejs() {
    echo ""
    echo "正在安装 Node.js..."

    if [ "$OS" = "macos" ]; then
        if command_exists brew; then
            brew install node
        else
            echo -e "${RED}✗${NC} 请先安装 Homebrew: https://brew.sh/"
            exit 1
        fi
    elif [ "$OS" = "debian" ]; then
        curl -fsSL https://deb.nodesource.com/setup_lts.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [ "$OS" = "redhat" ]; then
        curl -fsSL https://rpm.nodesource.com/setup_lts.x | sudo bash -
        sudo yum install -y nodejs
    fi

    echo -e "${GREEN}✓${NC} Node.js 安装完成"
}

# 安装 Git
install_git() {
    echo ""
    echo "正在安装 Git..."

    if [ "$OS" = "macos" ]; then
        brew install git
    elif [ "$OS" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y git
    elif [ "$OS" = "redhat" ]; then
        sudo yum install -y git
    fi

    echo -e "${GREEN}✓${NC} Git 安装完成"
}

# 安装 Python 和 pip
install_python() {
    echo ""
    echo "正在安装 Python 和 pip..."

    if [ "$OS" = "macos" ]; then
        brew install python3
    elif [ "$OS" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y python3 python3-pip
    elif [ "$OS" = "redhat" ]; then
        sudo yum install -y python3 python3-pip
    fi

    echo -e "${GREEN}✓${NC} Python 安装完成"
}

# 安装 unzip
install_unzip() {
    echo ""
    echo "正在安装 unzip..."

    if [ "$OS" = "macos" ]; then
        brew install unzip
    elif [ "$OS" = "debian" ]; then
        sudo apt-get update
        sudo apt-get install -y unzip
    elif [ "$OS" = "redhat" ]; then
        sudo yum install -y unzip
    fi

    echo -e "${GREEN}✓${NC} unzip 安装完成"
}

# 安装 Gitleaks
install_gitleaks() {
    echo ""
    echo "正在安装 Gitleaks..."

    if [ "$OS" = "macos" ]; then
        brew install gitleaks
    elif [ "$OS" = "debian" ]; then
        # 从 GitHub 下载最新版本
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        sudo mv gitleaks /usr/local/bin/
        rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    elif [ "$OS" = "redhat" ]; then
        GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
        wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
        sudo mv gitleaks /usr/local/bin/
        rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
    fi

    echo -e "${GREEN}✓${NC} Gitleaks 安装完成"
}

# 安装 Bandit
install_bandit() {
    echo ""
    echo "正在安装 Bandit..."
    pip3 install bandit
    echo -e "${GREEN}✓${NC} Bandit 安装完成"
}

# 安装 Semgrep
install_semgrep() {
    echo ""
    echo "正在安装 Semgrep..."

    if [ "$OS" = "macos" ]; then
        brew install semgrep
    else
        pip3 install semgrep
    fi

    echo -e "${GREEN}✓${NC} Semgrep 安装完成"
}

# 主函数
main() {
    echo "开始检测依赖工具..."
    echo ""

    # 检测操作系统
    detect_os
    echo ""

    # 检查必需工具
    echo "检查必需工具..."
    NEED_INSTALL=false

    # Node.js
    if ! check_tool "Node.js" "node --version"; then
        NEED_INSTALL=true
        INSTALL_NODEJS=true
    fi

    # Git
    if ! check_tool "Git" "git --version"; then
        NEED_INSTALL=true
        INSTALL_GIT=true
    fi

    # Python
    if ! check_tool "Python3" "python3 --version"; then
        NEED_INSTALL=true
        INSTALL_PYTHON=true
    fi

    # pip
    if ! check_tool "pip3" "pip3 --version"; then
        NEED_INSTALL=true
        INSTALL_PYTHON=true
    fi

    # unzip
    if ! check_tool "unzip" "unzip -v"; then
        NEED_INSTALL=true
        INSTALL_UNZIP=true
    fi

    echo ""
    echo "检查可选工具（用于增强扫描能力）..."

    # Gitleaks
    if ! check_tool "Gitleaks" "gitleaks version"; then
        INSTALL_GITLEAKS=true
    fi

    # Bandit
    if ! check_tool "Bandit" "bandit --version"; then
        INSTALL_BANDIT=true
    fi

    # Semgrep
    if ! check_tool "Semgrep" "semgrep --version"; then
        INSTALL_SEMGREP=true
    fi

    # 如果需要安装
    if [ "$NEED_INSTALL" = true ] || [ "$INSTALL_GITLEAKS" = true ] || [ "$INSTALL_BANDIT" = true ] || [ "$INSTALL_SEMGREP" = true ]; then
        echo ""
        echo "=========================================="
        echo "需要安装以下工具："
        [ "$INSTALL_NODEJS" = true ] && echo "  - Node.js (必需)"
        [ "$INSTALL_GIT" = true ] && echo "  - Git (必需)"
        [ "$INSTALL_PYTHON" = true ] && echo "  - Python3 & pip3 (必需)"
        [ "$INSTALL_UNZIP" = true ] && echo "  - unzip (必需)"
        [ "$INSTALL_GITLEAKS" = true ] && echo "  - Gitleaks (可选)"
        [ "$INSTALL_BANDIT" = true ] && echo "  - Bandit (可选)"
        [ "$INSTALL_SEMGREP" = true ] && echo "  - Semgrep (可选)"
        echo "=========================================="
        echo ""

        read -p "是否继续安装？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "安装已取消"
            exit 0
        fi

        # 安装必需工具
        [ "$INSTALL_NODEJS" = true ] && install_nodejs
        [ "$INSTALL_GIT" = true ] && install_git
        [ "$INSTALL_PYTHON" = true ] && install_python
        [ "$INSTALL_UNZIP" = true ] && install_unzip

        # 安装可选工具
        [ "$INSTALL_GITLEAKS" = true ] && install_gitleaks
        [ "$INSTALL_BANDIT" = true ] && install_bandit
        [ "$INSTALL_SEMGREP" = true ] && install_semgrep

        echo ""
        echo "=========================================="
        echo -e "${GREEN}✓${NC} 所有工具安装完成！"
        echo "=========================================="
    else
        echo ""
        echo "=========================================="
        echo -e "${GREEN}✓${NC} 所有依赖工具已安装！"
        echo "=========================================="
    fi

    echo ""
    echo "现在可以运行项目："
    echo "  npm install"
    echo "  node server.js"
    echo ""
}

# 运行主函数
main
