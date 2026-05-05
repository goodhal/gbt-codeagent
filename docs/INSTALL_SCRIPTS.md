# 依赖工具自动安装脚本 - 功能说明

## 📦 创建的文件

### 1. **install-deps.sh** (Linux/Mac)
- Bash 脚本
- 支持 Debian/Ubuntu、RedHat/CentOS、macOS
- 自动检测操作系统
- 彩色输出，用户友好

### 2. **install-deps.cmd** (Windows)
- 批处理脚本
- 使用 Chocolatey 包管理器
- 兼容性好，适合旧版 Windows

### 3. **install-deps.ps1** (Windows)
- PowerShell 脚本（推荐）
- 现代化界面
- 彩色输出
- 需要管理员权限

### 4. **docs/INSTALL_DEPENDENCIES.md**
- 详细的安装指南
- 包含手动安装步骤
- 常见问题解答
- 版本要求说明

---

## 🎯 功能特性

### 自动检测
- ✅ 检测操作系统类型
- ✅ 检测已安装的工具
- ✅ 显示工具版本信息
- ✅ 区分必需工具和可选工具

### 智能安装
- ✅ 只安装缺失的工具
- ✅ 跳过已安装的工具
- ✅ 用户确认后再安装
- ✅ 显示安装进度

### 包管理器支持
- **Windows**: Chocolatey
- **macOS**: Homebrew
- **Debian/Ubuntu**: apt-get
- **RedHat/CentOS**: yum
- **Python 工具**: pip/pip3

### 错误处理
- ✅ 检查包管理器是否存在
- ✅ 提供手动安装链接
- ✅ 友好的错误提示
- ✅ 安装失败不中断流程

---

## 📋 安装的工具

### 必需工具
| 工具 | 用途 | 安装方式 |
|------|------|---------|
| **Node.js** | 运行服务器 | choco/brew/apt/yum |
| **Git** | 克隆仓库 | choco/brew/apt/yum |
| **Python 3** | 运行扫描工具 | choco/brew/apt/yum |
| **pip** | Python 包管理 | 随 Python 安装 |
| **unzip** | 解压 ZIP 文件 | brew/apt/yum (Linux/Mac) |

### 可选工具（增强扫描）
| 工具 | 用途 | 安装方式 |
|------|------|---------|
| **Gitleaks** | 密钥泄露检测 | choco/brew/GitHub Release |
| **Bandit** | Python 安全分析 | pip |
| **Semgrep** | 多语言静态分析 | brew/pip |

---

## 🚀 使用方法

### Windows (PowerShell - 推荐)

1. 以**管理员权限**打开 PowerShell
2. 进入项目目录
3. 运行脚本：

```powershell
.\install-deps.ps1
```

### Windows (CMD)

1. 以**管理员权限**打开命令提示符
2. 进入项目目录
3. 运行脚本：

```cmd
install-deps.cmd
```

### Linux/Mac

1. 打开终端
2. 进入项目目录
3. 运行脚本：

```bash
chmod +x install-deps.sh
./install-deps.sh
```

或：

```bash
bash install-deps.sh
```

---

## 📊 脚本执行流程

```
开始
  ↓
检测操作系统
  ↓
检查必需工具
  ├─ Node.js
  ├─ Git
  ├─ Python
  └─ pip
  ↓
检查可选工具
  ├─ Gitleaks
  ├─ Bandit
  └─ Semgrep
  ↓
显示需要安装的工具列表
  ↓
用户确认 (Y/N)
  ↓
检查包管理器
  ├─ Windows: Chocolatey
  ├─ macOS: Homebrew
  └─ Linux: apt/yum
  ↓
如果包管理器不存在
  ├─ 提示安装包管理器
  └─ 或提供手动安装链接
  ↓
安装必需工具
  ↓
刷新环境变量
  ↓
安装可选工具
  ↓
显示安装结果
  ↓
提示下一步操作
  ↓
结束
```

---

## 🎨 输出示例

### Linux/Mac

```
==========================================
  代码审计平台 - 依赖工具安装脚本
==========================================

开始检测依赖工具...

✓ 检测到系统: Ubuntu

检查必需工具...
✓ Node.js 已安装
  v20.11.0
✓ Git 已安装
  git version 2.34.1
○ Python3 未安装
○ pip3 未安装

检查可选工具（用于增强扫描能力）...
○ Gitleaks 未安装
○ Bandit 未安装
○ Semgrep 未安装

==========================================
需要安装以下工具：
  - Python3 & pip3 (必需)
  - Gitleaks (可选)
  - Bandit (可选)
  - Semgrep (可选)
==========================================

是否继续安装？(y/n)
```

### Windows (PowerShell)

```
==========================================
  代码审计平台 - 依赖工具安装脚本
==========================================

开始检测依赖工具...

检查必需工具...
[√] Node.js 已安装
    v20.11.0
[√] Git 已安装
    git version 2.43.0.windows.1
[○] Python 未安装
[○] pip 未安装

检查可选工具（用于增强扫描能力）...
[○] Gitleaks 未安装
[○] Bandit 未安装
[○] Semgrep 未安装

==========================================
需要安装以下工具：
  - Python (必需)
  - pip (必需)
  - Gitleaks (可选)
  - Bandit (可选)
  - Semgrep (可选)
==========================================

是否继续安装？(Y/N)
```

---

## ⚙️ 技术细节

### Windows 脚本特点

**PowerShell 版本**:
- 使用 `#Requires -RunAsAdministrator` 强制管理员权限
- 彩色输出 (`Write-Host -ForegroundColor`)
- 异常处理 (`try-catch`)
- 函数化设计

**CMD 版本**:
- 兼容性更好
- 使用 `setlocal enabledelayedexpansion`
- 简单的错误检查

### Linux/Mac 脚本特点

- 使用 `set -e` 遇错即停
- ANSI 颜色代码
- 函数化设计
- 支持多种 Linux 发行版

### 包管理器检测

**Windows**:
```powershell
if (Test-Command "choco") {
    # Chocolatey 已安装
}
```

**macOS**:
```bash
if command_exists brew; then
    # Homebrew 已安装
fi
```

**Linux**:
```bash
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
elif [ -f /etc/redhat-release ]; then
    # RedHat/CentOS
fi
```

---

## 🔒 安全考虑

### 权限要求
- **Windows**: 需要管理员权限（安装到系统目录）
- **Linux/Mac**: 某些操作需要 `sudo`（脚本会提示）

### 网络安全
- 所有下载都使用 HTTPS
- 从官方源下载（GitHub Releases、官方包仓库）
- 不执行未验证的代码

### 用户控制
- 安装前需要用户确认
- 显示将要安装的工具列表
- 可以选择跳过可选工具

---

## 🐛 故障排除

### 问题 1: "权限被拒绝"

**Windows**:
- 右键点击 PowerShell/CMD
- 选择"以管理员身份运行"

**Linux/Mac**:
- 使用 `sudo` 运行脚本
- 或给脚本添加执行权限：`chmod +x install-deps.sh`

### 问题 2: "找不到包管理器"

**Windows**:
- 脚本会提示安装 Chocolatey
- 或手动访问 https://chocolatey.org/install

**macOS**:
- 脚本会提示安装 Homebrew
- 或手动访问 https://brew.sh/

### 问题 3: "网络连接失败"

- 检查网络连接
- 使用代理或 VPN
- 手动下载工具并安装

### 问题 4: "安装后命令不可用"

- 重启终端
- 或刷新环境变量（Windows）
- 检查 PATH 环境变量

---

## 📝 维护说明

### 更新工具版本

**Gitleaks**:
- 脚本自动获取最新版本
- 从 GitHub API 读取 latest release

**其他工具**:
- 包管理器会安装最新稳定版
- 可以在脚本中指定版本号

### 添加新工具

1. 在 `check_tool` 部分添加检测
2. 在 `install_*` 部分添加安装函数
3. 在主流程中调用

### 支持新平台

1. 在 `detect_os` 中添加检测逻辑
2. 为新平台添加安装命令
3. 测试并更新文档

---

## ✅ 测试清单

- [ ] Windows 10/11 (PowerShell)
- [ ] Windows 10/11 (CMD)
- [ ] Ubuntu 20.04/22.04
- [ ] CentOS 7/8
- [ ] macOS 12+
- [ ] 全新系统（无任何工具）
- [ ] 部分工具已安装
- [ ] 所有工具已安装
- [ ] 网络异常情况
- [ ] 权限不足情况

---

## 🔗 相关文档

- [依赖工具安装指南](INSTALL_DEPENDENCIES.md)
- [README.md](../README.md)
- [CLAUDE.md](../CLAUDE.md)

---

## 📞 支持

如果遇到问题：
1. 查看 [INSTALL_DEPENDENCIES.md](INSTALL_DEPENDENCIES.md)
2. 检查脚本输出的错误信息
3. 提交 Issue 到项目仓库
