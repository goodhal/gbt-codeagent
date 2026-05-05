# 代码审计批量辅助

一个前端可访问的代码审计工作台，支持从 GitHub 发现候选开源 Web CMS，或直接导入本地仓库，再通过规则层与大模型复核生成可下载的 HTML 报告。

> **源项目**：[Bai-codeagent](https://github.com/baianquanzu/Bai-codeagent)
> **GBT 审计集成**：基于 [gbt-code-audit-skill](https://github.com/goodhal/gbt-code-audit-skill) 的国标代码安全审计功能

## 适合做什么

- 批量发现候选开源 CMS 项目，并手动筛选审计目标
- 对选中目标生成本地审计镜像，减少直接在线分析带来的不稳定性
- 结合规则层与 LLM 复核，输出更清晰的审计说明
- 通过前端完成连接配置、任务发起、进度跟踪、结果查看和报告下载
- 基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计

## 核心能力

- GitHub 候选发现
  按 CMS 相关查询批量发现候选项目，支持分页选择要审计的目标。

- 本地镜像审计
  对选中目标先下载审计镜像，再执行规则层分析与大模型复核。

- 审计 Skill
  内置访问控制、初始化与配置、上传与存储、查询与注入、敏感信息等防御性审计能力。

- GB/T 国标代码安全审计
  基于中国国家标准的多语言漏洞检测，采用「快速扫描 + LLM 深度审计」双引擎。

- 向量数据库集成
  支持代码语义检索，提升漏洞发现的准确性和上下文理解能力。

- 模块化分析器
  支持静态分析、污点追踪、模式匹配等多种分析方式，便于扩展新语言和新规则。

- YAML 规则配置
  检测规则通过 YAML 文件配置，支持灵活的规则扩展和定制。

- HTML 报告导出
  输出结构化、可下载、适合留档的 HTML 审计报告。

- 环境自检
  前端可配置主流 LLM API 与 GitHub Token，并在页面中直接测试连接。

- 项目记忆
  保存常用查询、阈值和团队规则，减少重复配置。

- 状态持久化与断点恢复
  审计任务状态自动保存，支持暂停/恢复，长时审计更可靠。

- 代码检索增强 LLM 审计
  LLM 审计前自动索引代码，混合检索（语义+关键词）提供上下文增强。

- 沙箱验证
  自动验证发现的漏洞，降低误报率。

- AST 深度分析
  抽象语法树分析，提供漏洞上下文深度理解。

## GB/T 国标代码安全审计

### 功能介绍

基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计功能，支持多种编程语言的漏洞检测。

### 核心特性

- **国标合规**：严格遵循中国国家标准（GB/T 34943/34944/34946/39412）
- **双层检测**：快速扫描（正则表达式）+ LLM 深度审计（语义分析）
- **多语言支持**：Java、Python、C/C++、C#、Go、JavaScript、TypeScript、PHP、Ruby、Rust、Kotlin、Swift、Scala、Perl、Lua、Shell（16 种语言）
- **专业评分**：CVSS 三维评分系统（可达性、影响范围、利用复杂度）
- **详细报告**：包含漏洞类型、CWE、国标映射、修复建议等完整信息

### 三层审计分工

| 分工 | 负责方 | 发现的漏洞类型 |
|------|--------|---------------|
| **快速扫描** | 代码（正则表达式） | 高风险函数调用（命令注入、SQL注入、缓冲区溢出等） |
| **LLM审计** | LLM（语义分析） | 需要上下文分析的漏洞（业务逻辑、输入验证、认证安全等） |
| **LLM审查** | LLM（深入分析） | 复杂业务逻辑漏洞、漏洞验证、最终决策 |

### 支持的漏洞类型

- **严重漏洞**：认证绕过、权限缺失、命令注入、SQL注入、代码注入、反序列化
- **高危漏洞**：CSRF、会话固定、开放重定向、文件上传、并发安全、整数溢出、格式化字符串、SSRF、XXE
- **中危漏洞**：信息泄露、输入验证不足、异常处理不当、资源管理问题、认证信息暴露、信任边界违反

### 国家标准

- **GB/T 34943-2017**：C/C++ 语言源代码漏洞测试规范
- **GB/T 34944-2017**：Java 语言源代码漏洞测试规范
- **GB/T 34946-2017**：C# 语言源代码漏洞测试规范
- **GB/T 39412-2020**：网络安全技术 源代码漏洞检测规则

> **详细规则**：见 [docs/gbt-audit/reference/](docs/gbt-audit/reference/) 目录下的国标文件
> - [GBT_34943-2017.md](docs/gbt-audit/reference/GBT_34943-2017.md) - C/C++ 专用
> - [GBT_34944-2017.md](docs/gbt-audit/reference/GBT_34944-2017.md) - Java 专用
> - [GBT_34946-2017.md](docs/gbt-audit/reference/GBT_34946-2017.md) - C# 专用
> - [GBT_39412-2020.md](docs/gbt-audit/reference/GBT_39412-2020.md) - 通用基线（所有语言）

### 审计文档

完整的审计文档位于 [docs/](docs/) 目录：

- **[SKILL.md](docs/gbt-audit/skill.md)** - 主技能文档，包含审计原则、流程、质量标准
- **[LLM 审计执行指南](docs/gbt-audit/workflow/audit_workflow.md)** - LLM 审计执行流程和验证机制
- **[输出质量检查标准](docs/gbt-audit/workflow/quality_standards.md)** - 修复方案编写要求和验证机制
- **[审计覆盖率检查工具](src/tools/auditCoverageChecker.js)** - 验证审计完整性的工具

### 核心工具

| 工具 | 描述 | 路径 |
|------|------|------|
| `QuickScanService` | 快速扫描服务（166 条规则，16 种语言） | `src/services/quickScanService.js` |
| `ExternalToolService` | 外部工具集成（Gitleaks/Bandit/Semgrep） | `src/services/externalToolService.js` |
| `ValidationService` | 自动验证服务（去重 + 验证 + 行号修正 + 沙箱验证） | `src/services/validationService.js` |
| `DefensiveLlmReviewer` | LLM 深度审计服务（语义分析 + 漏洞验证 + 代码检索增强） | `src/services/llmReviewService.js` |
| `LLMFactory` | LLM 适配器工厂（OpenAI/Anthropic/Gemini） | `src/services/llmFactory.js` |
| `AuditCoverageChecker` | 审计覆盖率检查工具 | `src/tools/auditCoverageChecker.js` |
| `writeAuditHtmlReport` | HTML 报告生成 | `src/services/reportWriter.js` |
| `VectorStore` | 向量数据库服务（代码语义检索） | `src/services/vectorStore.js` |
| `EmbeddingsService` | 嵌入服务（代码向量化） | `src/services/embeddings.js` |
| `CodeRetriever` | 代码检索服务（代码索引 + 混合检索） | `src/services/retriever.js` |
| `StatePersistence` | 状态持久化（检查点 + 断点恢复） | `src/core/stateManager.js` |
| `CircuitBreaker` | 熔断器（熔断机制 + 自动恢复） | `src/core/circuitBreaker.js` |
| `ASTEnhancer` | AST 深度分析增强 | `src/services/astEnhancer.js` |

### CVSS 评分系统

采用三维评分公式：`score = R*0.40 + I*0.35 + C*0.25`

| 维度 | 说明 | 分值范围 |
|------|------|---------|
| **可达性 (R)** | HTTP直接可达/需要认证/需要管理员权限 | 0-3 |
| **影响范围 (I)** | RCE/数据泄露/有限泄露 | 0-3 |
| **利用复杂度 (C)** | 单次请求/多步操作/特定环境 | 0-3 |

### 漏洞编号系统

根据严重等级动态调整前缀：
- 严重 → C（如 C-CMD-001）
- 高危 → H（如 H-SQL-001）
- 中危 → M（如 M-XSS-001）
- 低危 → L（如 L-INFO-001）

## 页面截图

### 控制台首页

![控制台首页](docs/screenshots/dashboard.png)

### 审计报告详情

![审计报告详情](docs/screenshots/report-detail.png)

## 工作流

1. 在前端配置 LLM 提供商、模型、API Key 和 GitHub Token
2. 通过 GitHub 模式发现候选项目，或直接导入本地仓库
3. 手动选择需要审计的目标
4. 系统生成本地审计镜像
5. 执行规则层分析与 LLM 复核
6. 下载最终 HTML 报告

## 项目结构

```
gbt-codeagent/
├── server.js                    # HTTP 服务、任务编排、环境自检入口
├── public/                      # 前端页面、交互逻辑、样式与进度展示
├── src/
│   ├── agents/                  # 候选发现、本地导入、审计分析智能体
│   ├── analyzers/               # 模块化分析器（静态分析、污点追踪、模式匹配）
│   ├── config/                  # LLM 提供商配置、审计 Skill 配置、检测规则
│   ├── core/                    # 核心基础设施（熔断器、限流器、重试、状态管理、遥测）
│   ├── knowledge/               # 知识库（框架识别、漏洞知识）
│   ├── services/                # LLM 复核、报告生成、快速扫描、验证、向量存储等服务
│   ├── store/                   # 任务状态存储
│   ├── tools/                   # 审计覆盖率检查等工具
│   └── utils/                   # 文件工具、上下文管理
├── docs/
│   ├── gbt-audit/               # GBT 国标代码安全审计文档
│   │   ├── reference/           # 国标参考文件
│   │   ├── vulnerabilities/     # 漏洞知识库
│   │   └── workflow/            # 审计工作流与质量标准
│   └── screenshots/             # 页面截图
└── test-samples/                # 测试样本文件
```

## 本地运行

### 快速开始

#### 1. 安装依赖工具（推荐使用自动安装脚本）

**Windows (PowerShell - 管理员权限)**:
```powershell
.\install-deps.ps1
```

**Windows (CMD - 管理员权限)**:
```cmd
install-deps.cmd
```

**Linux/Mac**:
```bash
chmod +x install-deps.sh
./install-deps.sh
```

自动安装脚本会检测并安装以下工具：
- **必需**: Node.js, Git, Python, pip
- **可选**: Gitleaks, Bandit, Semgrep（用于增强扫描能力）

详细安装说明请查看：[依赖工具安装指南](docs/INSTALL_DEPENDENCIES.md)

#### 2. 安装 Node.js 依赖

```bash
npm install
```

#### 3. 启动服务器

```bash
node server.js
```

启动后访问：

[http://127.0.0.1:3001](http://127.0.0.1:3001)

### Windows 一键启动

```powershell
.\launch.cmd
```

或：

```powershell
.\launch.ps1
```

## 使用说明

- GitHub 模式不会在"候选发现"阶段直接调用大模型
- 只有在你选中目标并开始审计后，系统才会下载本地审计镜像并进入 LLM 复核
- 页面会实时展示镜像下载进度与 LLM 复核进度
- 结果输出偏向防御性代码审计说明，不包含攻击载荷或利用链细节
- 选择"GB/T 国标代码安全审计"技能可启用国标审计功能

## GBT 审计使用方法

1. 在审计配置中选择 "GB/T 国标代码安全审计" 技能
2. 选择要审计的项目和语言
3. 启动审计流程
4. 查看详细的审计报告（包含 CVSS 评分、国标映射、修复建议）

## 技术栈

- **后端**：Node.js (ES Modules)
- **前端**：原生 HTML/CSS/JavaScript
- **LLM**：OpenAI / Anthropic / Gemini / Qwen / DeepSeek / 百度 / MiniMax / 豆包（通过统一适配器）
- **外部工具**：Gitleaks / Bandit / Semgrep（可选集成）
- **韧性**：熔断器 + 指数退避重试 + 令牌桶限流 + 状态持久化
- **AST 分析**：抽象语法树构建 + 查询 + 增强
- **向量检索**：代码语义检索 + 关键词检索混合

## 许可证

见 [LICENSE](LICENSE) 文件。
