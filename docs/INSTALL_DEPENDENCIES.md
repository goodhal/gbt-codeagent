# 依赖工具安装指南

本文档说明如何安装代码审计平台所需的依赖工具。

## 📋 依赖工具列表

### 必需工具
- **Node.js** (v18+) - 运行服务器
- **Git** - 克隆仓库
- **Python 3** - 运行某些扫描工具
- **pip** - Python 包管理器

### 可选工具（增强扫描能力）
- **Gitleaks** - 密钥和敏感信息检测
- **Bandit** - Python 代码安全分析
- **Semgrep** - 多语言静态分析

### ZIP 解压工具
- **Linux/Mac**: `unzip` 命令
- **Windows**: PowerShell（系统自带）

---

## 🚀 自动安装（推荐）

我们提供了跨平台的自动安装脚本，可以一键检测并安装所有依赖工具。

### Windows

#### 方法 1: PowerShell（推荐）

以**管理员权限**运行 PowerShell，然后执行：

```powershell
.\install-deps.ps1
```

#### 方法 2: 命令提示符

以**管理员权限**运行 CMD，然后执行：

```cmd
install-deps.cmd
```

### Linux/Mac

在终端中执行：

```bash
chmod +x install-deps.sh
./install-deps.sh
```

或者：

```bash
bash install-deps.sh
```

---

## 🔧 手动安装

如果自动安装脚本无法运行，可以手动安装各个工具。

### Windows

#### 1. 安装 Chocolatey（包管理器）

以管理员权限运行 PowerShell：

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```

#### 2. 使用 Chocolatey 安装工具

```powershell
# 必需工具
choco install nodejs git python -y

# 可选工具
choco install gitleaks -y
pip install bandit semgrep
```

#### 或者手动下载安装

- **Node.js**: https://nodejs.org/
- **Git**: https://git-scm.com/
- **Python**: https://www.python.org/
- **Gitleaks**: https://github.com/gitleaks/gitleaks/releases

### Linux (Ubuntu/Debian)

```bash
# 更新包列表
sudo apt-get update

# 必需工具
sudo apt-get install -y nodejs npm git python3 python3-pip unzip

# 可选工具 - Gitleaks
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
sudo mv gitleaks /usr/local/bin/
rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

# 可选工具 - Bandit & Semgrep
pip3 install bandit semgrep
```

### Linux (CentOS/RHEL)

```bash
# 必需工具
sudo yum install -y nodejs git python3 python3-pip unzip

# 可选工具 - Gitleaks
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
wget "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
sudo mv gitleaks /usr/local/bin/
rm "gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"

# 可选工具 - Bandit & Semgrep
pip3 install bandit semgrep
```

### macOS

#### 使用 Homebrew（推荐）

```bash
# 安装 Homebrew（如果未安装）
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 必需工具
brew install node git python3

# 可选工具
brew install gitleaks semgrep
pip3 install bandit
```

---

## ✅ 验证安装

安装完成后，运行以下命令验证：

```bash
# 必需工具
node --version
git --version
python --version  # 或 python3 --version
pip --version     # 或 pip3 --version

# 可选工具
gitleaks version
bandit --version
semgrep --version

# ZIP 解压工具
unzip -v          # Linux/Mac
# Windows 使用 PowerShell，无需额外安装
```

所有命令都应该显示版本号，表示安装成功。

---

## 🎯 最低版本要求

- **Node.js**: v18.0.0+
- **Git**: v2.0.0+
- **Python**: v3.7.0+
- **Gitleaks**: v8.0.0+
- **Bandit**: v1.7.0+
- **Semgrep**: v1.0.0+

---

## 🔍 常见问题

### Q1: Windows 上提示"无法识别的命令"

**A**: 安装工具后需要重启终端或刷新环境变量：

```powershell
# PowerShell 刷新环境变量
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
```

或者直接重启终端。

### Q2: Linux 上 pip 安装失败

**A**: 可能需要使用 `pip3` 而不是 `pip`：

```bash
pip3 install bandit semgrep
```

或者使用 `--user` 参数：

```bash
pip install --user bandit semgrep
```

### Q3: macOS 上提示"command not found: brew"

**A**: 需要先安装 Homebrew：

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### Q4: Gitleaks 下载速度慢

**A**: 可以使用国内镜像或手动下载：

1. 访问 https://github.com/gitleaks/gitleaks/releases
2. 下载对应平台的二进制文件
3. 解压并移动到系统 PATH 目录

### Q5: 不想安装可选工具

**A**: 可选工具不是必需的，项目可以正常运行。它们只是提供额外的扫描能力：

- 没有 **Gitleaks**：无法检测密钥泄露
- 没有 **Bandit**：Python 项目扫描能力减弱
- 没有 **Semgrep**：多语言静态分析能力减弱

核心的 GB/T 国标审计功能不依赖这些工具。

---

## 📦 安装 Node.js 依赖

安装完系统依赖后，还需要安装项目的 Node.js 依赖：

```bash
npm install
```

---

## 🚀 启动项目

所有依赖安装完成后，可以启动项目：

```bash
node server.js
```

或使用快速启动脚本：

**Windows**:
```cmd
launch.cmd
```
或
```powershell
.\launch.ps1
```

**Linux/Mac**:
```bash
./launch.sh
```

---

## 📞 获取帮助

如果遇到安装问题，请：

1. 检查系统版本是否符合要求
2. 确认网络连接正常
3. 查看错误日志
4. 提交 Issue 到项目仓库

---

## 🔗 相关链接

- **Node.js**: https://nodejs.org/
- **Git**: https://git-scm.com/
- **Python**: https://www.python.org/
- **Chocolatey**: https://chocolatey.org/
- **Homebrew**: https://brew.sh/
- **Gitleaks**: https://github.com/gitleaks/gitleaks
- **Bandit**: https://github.com/PyCQA/bandit
- **Semgrep**: https://semgrep.dev/
