import { promises as fs } from "node:fs";
import path from "path";
import { withRetryWithFallback } from "../core/index.js";
import { ragService } from "../services/ragService.js";

export const THREE_LAYER_AUDIT = `
【三层审计分工 - 各自职责明确】

┌─────────────────────────────────────────────────────────────────────┐
│  第一层：快速扫描（代码负责） - 正则表达式检测高风险函数调用            │
│  第二层：LLM审计（LLM负责） - 语义分析检测上下文相关漏洞              │
│  第三层：LLM审查（LLM负责） - 复杂业务逻辑和漏洞验证                  │
└─────────────────────────────────────────────────────────────────────┘

【第一层：快速扫描（代码负责）】
职责：使用正则表达式搜索高风险函数调用
覆盖：命令注入、SQL注入、缓冲区溢出、硬编码凭证、弱加密、反序列化等
特点：高效率、低精度，特征明显，不需要上下文

【第二层：LLM审计（LLM负责）】（本层职责）
职责：语义分析，发现需要上下文分析的漏洞
覆盖：
- 输入验证问题：关键状态数据外部可控、数据真实性验证不足
- 业务逻辑问题：条件比较不充分、条件语句缺失默认情况、死代码
- 认证安全问题：身份鉴别过程暴露多余信息、身份鉴别被绕过
- 并发安全问题：未加限制的外部可访问锁、共享资源并发安全
- 会话安全问题：不同会话间信息泄露、会话固定
特点：低效率、高精度，需要理解代码上下文和业务逻辑

【第三层：LLM审查（LLM负责）】
职责：深入分析复杂业务逻辑，验证漏洞，做出最终决策
覆盖：认证流程、权限判断、状态转换、组合漏洞攻击链
特点：最高精度，需要深入理解业务逻辑`;

export const REVIEW_PRIORITY_LAYERS = `
【审查规则优先级分层 - 必须严格遵守】

🔴 安全问题（优先级最高）- 必须检测：
- SQL注入：用户输入直接拼接SQL语句
- 命令注入：执行系统命令时使用用户可控数据
- XSS漏洞：用户输入未经过滤直接输出到页面
- 敏感信息硬编码：密码、密钥、API密钥明文存储
- 不安全的反序列化：使用不可信数据进行反序列化
- 认证绕过：身份验证逻辑缺陷
- 权限控制缺失：水平越权、垂直越权
- SSRF：服务器端请求伪造
- 路径遍历：文件路径包含用户可控输入
- 文件上传漏洞：文件类型验证不足

🟠 性能问题（优先级次之）- 重点检测：
- 循环中的数据库查询：N+1查询问题
- 大对象的频繁创建：内存占用过高
- 未关闭的资源：数据库连接、文件流泄漏
- 重复计算：相同计算多次执行
- 低效算法：时间复杂度较高的实现

🟡 代码规范（优先级较低）- 参考检测：
- 命名规范：变量、函数命名不规范
- 注释缺失：关键逻辑缺少注释说明
- 方法过长：单方法超过50行
- 复杂度过高：圈复杂度超过15
- 魔法数字：未定义常量的硬编码数值`;

export const CORE_SECURITY_PRINCIPLES = `
【核心安全分析原则】

1. 深度分析优于广度扫描
   - 深入分析少数真实漏洞比报告大量误报更有价值
   - 每个发现都需要上下文验证
   - 理解业务逻辑后才能判断安全影响

2. 数据流追踪
   - 从用户输入（Source）到危险函数（Sink）
   - 识别所有数据处理和验证节点
   - 评估过滤和编码的有效性

3. 上下文感知分析
   - 不要孤立看待代码片段
   - 理解函数调用链和模块依赖
   - 考虑运行时环境和配置

4. 质量优先
   - 高置信度发现优于低置信度猜测
   - 提供明确的证据和复现步骤
   - 给出实际可行的修复建议`;

export const SEVERITY_CLASSIFICATION_GUIDE = `
【严重级别判定标准 - 必须严格区分】

🔴 critical（严重）- 仅以下情况：
- 可直接通过网络远程利用，无需认证
- 可导致远程代码执行(RCE)、系统完全控制
- 可导致任意文件读取/写入
- 可绕过身份认证直接访问核心功能
- 明确的命令注入、SQL注入且用户输入未经任何过滤直接到达危险函数
- 硬编码的生产环境密钥/凭证
- ⚠️ critical 只能用于最严重的问题，不能滥用

🟠 high（高危）- 以下情况：
- 需要普通用户认证后可利用
- 可导致重要数据泄露（用户密码、个人信息）
- CSRF 可导致关键操作（修改密码、转账）
- 反序列化漏洞（有实际风险）
- SSRF 可访问内网
- 权限控制缺失导致越权
- 会话固定、敏感信息在日志中泄露

🟡 medium（中危）- 以下情况：
- 需要特定条件才能利用（如需要管理员权限）
- 信息泄露但影响范围有限（如版本号、路径泄露）
- 配置不当但不直接导致安全漏洞
- 弱加密算法但仍需要其他条件才能利用
- 输入验证不足但已有部分防护
- 仅测试/开发环境风险
- 竞争条件但利用难度大

🟢 low（低危）- 以下情况：
- 几乎无法实际利用
- 仅理论风险，缺乏实际攻击路径
- 代码风格问题不直接导致安全漏洞
- 已废弃但未删除的调试代码（不影响生产）
- 框架已默认防护的潜在风险
- low 用于信息性发现，置信度应设为 0.3-0.5

⚠️ 判定原则：
- 不确定时应降级而非升级：有疑问时选较低级别
- 需要认证或特定条件才能利用的，不应评为 critical
- 仅理论风险无实际攻击路径的，评为 low
- 如果所有发现都是同一级别，说明判定标准有问题，请重新审视`;

export const FILE_VALIDATION_RULES = `
【文件路径验证规则 - 防止幻觉】

⚠️ 严禁行为：
- 禁止报告不存在的文件路径
- 禁止凭记忆或推测编造代码片段
- 禁止假设特定文件存在（如 config/database.py）
- 禁止报告注释行代码作为漏洞
- 禁止报告导入语句但无实际调用的代码

✅ 正确做法：
- 只报告提供代码片段中确实存在的漏洞
- 引用实际代码时使用提供的 snippet
- 行号必须在文件实际行数范围内
- 必须在源文件中验证行号对应实际代码行

🔥 宁可漏报，不可误报。质量优于数量。`;

export const VULNERABILITY_PRIORITIES = `
【LLM审计漏洞检测优先级 - 需要上下文分析的漏洞】

⚠️ 注意：以下列表是LLM审计需要重点关注的漏洞类型。SQL注入、命令注入、硬编码密码等高风险函数调用已由快速扫描覆盖，LLM不应重复检测。

🔴 Critical - 认证授权类（必须检测）：
1. 身份认证绕过 - 密码重置漏洞、会话管理缺陷、JWT验证缺失
2. 权限检查缺失 - 水平越权、垂直越权、权限提升
3. 关键状态数据外部可控 - 用户输入直接控制安全决策
4. 认证绕过 - 接口未授权访问、敏感端点暴露

🟠 High - 业务逻辑类（重点检测）：
1. 会话固定/会话劫持 - sessionId可预测、未设置HttpOnly/Secure标志
2. 条件判断不充分 - 缺少默认值、死代码、边界条件未处理
3. 状态绕过 - 订单状态非法跳转、支付流程绕过、状态机缺陷
4. 竞态条件 - 余额扣减并发问题、库存超卖、优惠券重复领取
5. Mass Assignment - 对象属性过度暴露、DTO未限制可修改字段
6. 多租户隔离缺陷 - 不同租户数据未正确隔离、租户ID可篡改

🟡 Medium - 上下文相关类（全面检测）：
1. 开放重定向 - 用户可控重定向目标、未验证跳转URL
2. 文件上传类型验证不足 - 仅客户端验证、文件类型绕过
3. 整数溢出 - 数值运算边界检查缺失
4. 配置安全 - 敏感配置硬编码、默认配置不安全
5. 日志注入 - 用户输入进入日志、敏感信息泄露

🟢 Info - 框架配置类（参考检测）：
1. CSRF防护缺失 - 状态改变接口无CSRF保护
2. CORS配置不当 - 允许任意来源、凭证泄露风险
3. 错误信息泄露敏感数据 - 详细错误信息暴露、堆栈跟踪泄露
4. 安全头缺失 - 缺少安全相关HTTP响应头`;

export const FALSE_POSITIVE_RULES = `
【误报判定规则 - 仅适用于LLM独立发现】

⚠️ 注意：以下规则仅适用于LLM独立发现的漏洞，不适用于规则层（heuristicFindings）的发现。

| 判定规则 | 特征 | 结论 |
|---------|------|------|
| 仅导入语句 | 只有 import/using，无实际调用 | 误报 |
| 测试/演示代码 | 位于 test/demo 目录或含测试注解 | 误报 |
| 框架自动防护 | 框架本身已做安全处理（如Spring Security） | 需验证上下文 |
| 规则层已有 | 已在heuristicFindings中标记 | 以规则层结论为准 |

⚠️ 判定流程：
1. 检查是否有实际调用（不只是导入）
2. 检查是否在测试/演示目录
3. 检查是否有安全防护措施
4. 规则层已有结论时，以规则层为准`;

export const DUAL_TRACK_AUDIT = `
【三轨审计模型 - Sink-driven、Control-driven 与 Config-driven】

LLM审计必须同时执行三条审计轨道，确保各类漏洞不被遗漏：

🔵 轨道一：Sink-driven（从危险代码向上追踪）
- 发现危险函数（如 Runtime.exec、SQL.execute、file.write）时启用
- 追踪数据从用户输入（Source）到危险函数（Sink）的传播路径
- 评估路径中的过滤和验证措施有效性
- 适用漏洞：SQL注入、命令注入、XSS、路径遍历、SSRF、反序列化、文件上传

🟢 轨道二：Control-driven（从端点向下检查安全控制）
- 发现API端点（如 /api/admin/*、/user/profile）时启用
- 检查是否有认证注解（@Auth、@LoginRequired、@PreAuthorize）
- 检查是否有权限校验（@Roles、@Permissions、hasRole）
- 检查是否有访问控制（直接对象引用检查、资源归属验证）
- 检查状态机转换是否合法（订单状态、支付流程）
- 适用漏洞：认证绕过、水平越权、垂直越权、IDOR、业务逻辑漏洞

🟡 轨道三：Config-driven（搜索配置检查安全基线）
- 发现配置文件（application.yml、config.py、web.config）时启用
- 检查认证配置（JWT密钥、密码策略、会话超时）
- 检查加密配置（TLS版本、证书有效性、密钥管理）
- 检查安全开关（CORS、CSRF防护、错误暴露、调试模式）
- 检查依赖配置（第三方库版本、已知CVE漏洞）
- 适用漏洞：配置错误、敏感信息泄露、供应链风险、弱加密

⚠️ 重要：认证绕过类漏洞单独使用Sink-driven无法发现！业务逻辑漏洞需要Control-driven！配置漏洞需要Config-driven！`;

export const LINE_NUMBER_VERIFICATION = `
【行号验证强制要求】

🔴 必须执行的验证步骤：
1. 使用 Grep 精确搜索问题代码关键字
2. 在源文件中确认行号对应实际代码行
3. 确认不是注释行、空行或无关代码

🔴 禁止行为：
- ❌ 凭记忆填写行号
- ❌ 根据函数名推断行号
- ❌ 报告注释行作为漏洞代码

🔴 正确流程：
发现漏洞 → Grep搜索精确位置 → 确认行号 → 创建发现

⚠️ ValidationService验证：验证逻辑使用关键词匹配，只要2个关键词重叠就认为匹配。LLM必须主动验证行号！`;

export const EVIDENCE_CONTRACT_GUIDE = `
【证据契约要求 - 每个漏洞必须提供标准证据】

🔴 核心原则：漏洞发现必须附带标准化证据点（EVID_*），用于后续验证和追溯。

【常见漏洞类型对应证据点】
| 漏洞类型 | 必须证据点 |
|---------|-----------|
| SQL注入 | EVID_SQL_EXEC_POINT, EVID_SQL_STRING_CONSTRUCTION, EVID_SQL_USER_PARAM_MAPPING |
| 命令注入 | EVID_CMD_EXEC_POINT, EVID_CMD_STRING_CONSTRUCTION, EVID_CMD_USER_PARAM_MAPPING |
| 文件操作 | EVID_FILE_READ_SINK, EVID_FILE_PATH_CONSTRUCTION, EVID_FILE_USER_PARAM_MAPPING |
| SSRF | EVID_SSRF_URL_CONSTRUCTION, EVID_SSRF_USER_PARAM_MAPPING, EVID_SSRF_DNSIP_AND_INNER_BLOCK |
| XXE | EVID_XXE_PARSER_CALL, EVID_XXE_INPUT_SOURCE, EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO |
| 反序列化 | EVID_DESER_CALLSITE, EVID_DESER_INPUT_SOURCE, EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN |
| XSS | EVID_XSS_OUTPUT_POINT, EVID_XSS_USER_INPUT_INTO_OUTPUT, EVID_XSS_ESCAPE_OR_RAW_CONTROL |
| 认证绕过 | EVID_AUTH_CHECK_BYPASS, EVID_AUTH_TOKEN_DECODE_JUDGMENT, EVID_AUTH_PERMISSION_CHECK_EXEC |

【证据点输出格式】
每个漏洞发现中必须包含 evidencePoints 数组，列出该漏洞涉及的所有证据点ID。

【证据完整性判定】
- ✅ COMPLETE: 所有关键证据点都存在
- ⚠️ PARTIAL: 部分证据点缺失，需人工复核
- ❌ UNRESOLVED: 关键证据点缺失，标记为待验证

⚠️ 注意：如果无法提供完整的证据链，必须将漏洞标记为"待验证"，不得直接标记为"已确认可利用"。`;

export const LANGUAGE_GBT_MAP = {
  'java': 'GBT_34944-2017.md',
  'python': 'GBT_39412-2020.md',
  'javascript': 'GBT_39412-2020.md',
  'typescript': 'GBT_39412-2020.md',
  'go': 'GBT_39412-2020.md',
  'ruby': 'GBT_39412-2020.md',
  'rust': 'GBT_39412-2020.md',
  'php': 'GBT_39412-2020.md',
  'cpp': 'GBT_34943-2017.md',
  'c': 'GBT_34943-2017.md',
  'csharp': 'GBT_34946-2017.md',
  'c#': 'GBT_34946-2017.md'
};

export const VULNERABILITY_FILES = {
  'sql_injection': 'sql_injection.md',
  'command_injection': 'command_injection.md',
  'code_injection': 'code_injection.md',
  'deserialization': 'deserialization.md',
  'hardcoded_credentials': 'hardcoded_credentials.md',
  'path_traversal': 'path_traversal.md',
  'weak_crypto': 'weak_crypto.md'
};

export const EVIDENCE_REQUIRED_MAP = {
  SQL_INJECTION: ['EVID_SQL_EXEC_POINT', 'EVID_SQL_STRING_CONSTRUCTION', 'EVID_SQL_USER_PARAM_MAPPING'],
  COMMAND_INJECTION: ['EVID_CMD_EXEC_POINT', 'EVID_CMD_STRING_CONSTRUCTION', 'EVID_CMD_USER_PARAM_MAPPING'],
  SSRF: ['EVID_SSRF_URL_CONSTRUCTION', 'EVID_SSRF_USER_PARAM_MAPPING', 'EVID_SSRF_DNSIP_AND_INNER_BLOCK'],
  XSS: ['EVID_XSS_OUTPUT_POINT', 'EVID_XSS_USER_INPUT_INTO_OUTPUT', 'EVID_XSS_ESCAPE_OR_RAW_CONTROL'],
  PATH_TRAVERSAL: ['EVID_FILE_READ_SINK', 'EVID_FILE_PATH_CONSTRUCTION', 'EVID_FILE_USER_PARAM_MAPPING'],
  DESERIALIZATION: ['EVID_DESER_CALLSITE', 'EVID_DESER_INPUT_SOURCE', 'EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN'],
  AUTH_BYPASS: ['EVID_AUTH_CHECK_BYPASS', 'EVID_AUTH_TOKEN_DECODE_JUDGMENT', 'EVID_AUTH_PERMISSION_CHECK_EXEC'],
  XXE: ['EVID_XXE_PARSER_CALL', 'EVID_XXE_INPUT_SOURCE', 'EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO'],
  FILE_OPERATION: ['EVID_FILE_READ_SINK', 'EVID_FILE_PATH_CONSTRUCTION', 'EVID_FILE_USER_PARAM_MAPPING']
};

export async function loadAuditKnowledge({ languages = [], vulnerabilityTypes = [] } = {}) {
  const docsDir = path.join(process.cwd(), "docs");
  const gbtAuditDir = path.join(docsDir, "gbt-audit");
  const knowledge = {};

  try {
    const skillContent = await fs.readFile(path.join(gbtAuditDir, "skill.md"), "utf8");
    const lines = skillContent.split('\n');
    let inMappingTable = false;
    let mappingLines = [];

    for (const line of lines) {
      if (line.includes('| 语言') && line.includes('GB/T')) {
        inMappingTable = true;
      }
      if (inMappingTable) {
        mappingLines.push(line);
        if (line.trim() === '|' && mappingLines.length > 5) {
          break;
        }
      }
    }

    knowledge.gbtMapping = mappingLines.join('\n');
  } catch (error) {
    knowledge.gbtMapping = '';
  }

  try {
    const workflowContent = await fs.readFile(path.join(gbtAuditDir, "workflow", "audit_workflow.md"), "utf8");
    const lines = workflowContent.split('\n');
    const languageSections = [];
    let capture = false;
    let section = [];

    const targetLanguages = languages.map(l => l.toLowerCase());
    const languageKeywords = {
      'python': '### Python 审计要点',
      'java': '### Java 审计要点',
      'cpp': '### C/C++ 审计要点',
      'c': '### C/C++ 审计要点',
      'csharp': '### C# 审计要点',
      'c#': '### C# 审计要点',
      'javascript': '### JavaScript 审计要点',
      'typescript': '### TypeScript 审计要点',
      'go': '### Go 审计要点',
      'ruby': '### Ruby 审计要点',
      'rust': '### Rust 审计要点',
      'php': '### PHP 审计要点'
    };

    for (const line of lines) {
      const matchedLang = targetLanguages.find(lang => line.includes(languageKeywords[lang]));
      if (matchedLang) {
        if (section.length > 0) {
          languageSections.push(section.join('\n'));
        }
        section = [line];
        capture = true;
      } else if (capture && line.startsWith('### ')) {
        languageSections.push(section.join('\n'));
        break;
      } else if (capture) {
        section.push(line);
      }
    }
    if (section.length > 0) {
      languageSections.push(section.join('\n'));
    }

    knowledge.languageAudit = languageSections.join('\n\n');
  } catch (error) {
    knowledge.languageAudit = '';
  }

  const gbtReferences = [];
  const uniqueGbtFiles = new Set();

  const baseStandard = 'GBT_39412-2020.md';
  if (!uniqueGbtFiles.has(baseStandard)) {
    uniqueGbtFiles.add(baseStandard);
    try {
      const content = await fs.readFile(path.join(gbtAuditDir, "reference", baseStandard), "utf8");
      gbtReferences.push(`\n\n=== ${baseStandard.replace('.md', '')} (通用基线) ===\n\n${content}`);
    } catch (error) {
    }
  }

  for (const lang of languages) {
    const gbtFile = LANGUAGE_GBT_MAP[lang.toLowerCase()];
    if (gbtFile && gbtFile !== baseStandard && !uniqueGbtFiles.has(gbtFile)) {
      uniqueGbtFiles.add(gbtFile);
      try {
        const content = await fs.readFile(path.join(gbtAuditDir, "reference", gbtFile), "utf8");
        gbtReferences.push(`\n\n=== ${gbtFile.replace('.md', '')} (${lang}) ===\n\n${content}`);
      } catch (error) {
      }
    }
  }
  knowledge.gbtReferences = gbtReferences.join('\n');

  const vulnReferences = [];
  const uniqueVulnFiles = new Set();
  for (const vulnType of vulnerabilityTypes) {
    const vulnFile = VULNERABILITY_FILES[vulnType.toLowerCase()];
    if (vulnFile && !uniqueVulnFiles.has(vulnFile)) {
      uniqueVulnFiles.add(vulnFile);
      try {
        const content = await fs.readFile(path.join(gbtAuditDir, "vulnerabilities", vulnFile), "utf8");
        vulnReferences.push(`\n\n=== ${vulnFile.replace('.md', '')} ===\n\n${content}`);
      } catch (error) {
      }
    }
  }
  knowledge.vulnerabilityReferences = vulnReferences.join('\n');

  try {
    const qualityContent = await fs.readFile(path.join(gbtAuditDir, "workflow", "quality_standards.md"), "utf8");
    const lines = qualityContent.split('\n');
    const prohibitedSection = [];
    const remediationExamples = [];
    let captureProhibited = false;
    let captureExamples = false;

    for (const line of lines) {
      if (line.includes('### ❌ 禁止以下敷衍内容')) {
        captureProhibited = true;
        prohibitedSection.push(line);
      } else if (captureProhibited && line.startsWith('### ')) {
        captureProhibited = false;
      } else if (captureProhibited) {
        prohibitedSection.push(line);
      }

      if (line.includes('| 漏洞类型') && line.includes('合格修复方案')) {
        captureExamples = true;
        remediationExamples.push(line);
      } else if (captureExamples && line.trim() === '|') {
        captureExamples = false;
      } else if (captureExamples) {
        remediationExamples.push(line);
      }
    }

    knowledge.qualityStandards = {
      prohibited: prohibitedSection.join('\n'),
      examples: remediationExamples.join('\n')
    };
  } catch (error) {
    knowledge.qualityStandards = { prohibited: '', examples: '' };
  }

  return knowledge;
}

export async function buildSystemPrompt(selectedSkills, auditKnowledge = {}, languages = []) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    "【角色】",
    "你是一个资深代码安全审计专家，专注于多语言代码的安全性、性能和代码质量审查。",
    "具备丰富的安全漏洞检测经验，熟悉 OWASP TOP 10、CWE 分类和 GB/T 国家标准。",
    "你的职责是对代码进行全面的安全审计，发现潜在漏洞并提供专业的修复建议。",
    "",
    "【行为准则】",
    "- 只输出风险说明、证据、影响、修复建议和安全验证建议",
    "- 不要提供利用步骤、payload、绕过思路、攻击链构造或 weaponization 细节",
    "- 如果证据不足，就降低置信度或不要报出该问题",
    "- 请只返回 JSON 对象，不要输出额外说明",
    "",
    REVIEW_PRIORITY_LAYERS,
    DUAL_TRACK_AUDIT,
    "",
    CORE_SECURITY_PRINCIPLES,
    SEVERITY_CLASSIFICATION_GUIDE,
    FILE_VALIDATION_RULES
  ];

  try {
    const knowledgeContext = await withRetryWithFallback(
      () => ragService.buildAuditContext({
        language: languages?.[0],
        fileCount: 3
      }),
      () => {
        console.warn('[LLM审计] RAG服务不可用，使用降级方案');
        return null;
      },
      { maxAttempts: 2, baseDelay: 500 }
    );
    if (knowledgeContext) {
      prompt.push("", knowledgeContext);
    }
  } catch (error) {
    console.warn('[LLM审计] 获取 RAG 知识失败:', error);
  }

  if (isGbtAudit) {
    prompt.push(
      THREE_LAYER_AUDIT,
      FALSE_POSITIVE_RULES,
      LINE_NUMBER_VERIFICATION,
      EVIDENCE_CONTRACT_GUIDE,
      "",
      "【GB/T 国标代码安全审计 - 核心原则】",
      "",
      "🔴 三条核心原则（必须遵守）：",
      "1. 独立性：LLM 审计必须完全独立，不查看快速扫描结果",
      "2. 全面性：必须覆盖所有源代码文件，不得遗漏",
      "3. 准确性：行号必须用代码行号验证，禁止凭记忆填写"
    );

    if (auditKnowledge.gbtMapping) {
      prompt.push(
        "",
        "【国标映射表】（必须严格遵守）：",
        "---",
        auditKnowledge.gbtMapping,
        "---"
      );
    }

    if (auditKnowledge.languageAudit) {
      prompt.push(
        "",
        "【语言特定审计要点】（必须遵循）：",
        "---",
        auditKnowledge.languageAudit,
        "---"
      );
    }

    if (auditKnowledge.gbtReferences) {
      prompt.push(
        "",
        "【国标规则详解】（参考使用）：",
        "---",
        auditKnowledge.gbtReferences,
        "---"
      );
    }

    if (auditKnowledge.vulnerabilityReferences) {
      prompt.push(
        "",
        "【漏洞类型详解】（参考使用）：",
        "---",
        auditKnowledge.vulnerabilityReferences,
        "---"
      );
    }

    if (auditKnowledge.qualityStandards?.prohibited) {
      prompt.push(
        "",
        "【修复方案禁止内容】（出现则验证失败）：",
        "---",
        auditKnowledge.qualityStandards.prohibited,
        "---"
      );
    }

    if (auditKnowledge.qualityStandards?.examples) {
      prompt.push(
        "",
        "【修复方案示例】（合格/不合格对比）：",
        "---",
        auditKnowledge.qualityStandards.examples,
        "---"
      );
    }
  }

  prompt.push("");
  prompt.push("关注的审计 Skill：");
  const skills = selectedSkills.map((skill) => `- ${skill.name}: ${skill.reviewPrompt}`).join("\n");
  prompt.push(skills);

  return prompt.join("\n");
}

export function buildUserPrompt({ project, selectedSkills, heuristicFindings, batch, codeContext = "", incrementalPrompt = "", validationFeedback = {}, codeGraphContext = null }) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    `项目名称：${project.name}`,
    `审计镜像路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
    `来源模式：${project.sourceType}`
  ];

  if (codeGraphContext) {
    const graphParts = ["", "【代码知识图谱分析】"];
    
    if (codeGraphContext.entryPoints && codeGraphContext.entryPoints.length > 0) {
      graphParts.push(`入口点（${codeGraphContext.entryPoints.length}个）：`);
      codeGraphContext.entryPoints.forEach((ep, i) => {
        graphParts.push(`  ${i + 1}. ${ep.name} (${ep.file})`);
      });
    }
    
    if (codeGraphContext.hubNodes && codeGraphContext.hubNodes.length > 0) {
      graphParts.push(`\n热点节点（高连接度，${codeGraphContext.hubNodes.length}个）：`);
      codeGraphContext.hubNodes.forEach((hub, i) => {
        graphParts.push(`  ${i + 1}. ${hub.name} (${hub.file}) - 连接度: ${hub.degree}`);
      });
    }
    
    if (codeGraphContext.criticalPaths && codeGraphContext.criticalPaths.length > 0) {
      graphParts.push(`\n关键执行路径（${codeGraphContext.criticalPaths.length}条）：`);
      codeGraphContext.criticalPaths.forEach((path, i) => {
        graphParts.push(`  ${i + 1}. ${path}`);
      });
    }
    
    if (codeGraphContext.architectureOverview) {
      const arch = codeGraphContext.architectureOverview;
      graphParts.push(`\n架构概览：`);
      graphParts.push(`  - 节点总数：${arch.totalNodes || 0}`);
      graphParts.push(`  - 边总数：${arch.totalEdges || 0}`);
      graphParts.push(`  - 模块社区数：${arch.communities || 0}`);
      
      if (arch.warnings && arch.warnings.length > 0) {
        graphParts.push(`\n架构警告：`);
        arch.warnings.forEach((warn, i) => {
          graphParts.push(`  ⚠️ ${warn}`);
        });
      }
    }
    
    prompt.push(graphParts.join("\n"));
  }

  if (codeContext) {
    prompt.push(codeContext);
  }

  if (incrementalPrompt) {
    prompt.push("", incrementalPrompt);
  }

  if (validationFeedback && Object.keys(validationFeedback).length > 0) {
    const feedbackParts = [];
    feedbackParts.push("【验证反馈 - 上一批次审计结果】");

    if (validationFeedback.hallucinations && validationFeedback.hallucinations.length > 0) {
      feedbackParts.push(`⚠️ 误报发现（${validationFeedback.hallucinations.length}个）：`);
      validationFeedback.hallucinations.slice(0, 3).forEach((h, i) => {
        feedbackParts.push(`  ${i + 1}. ${h.title || h.vulnId} - ${h.reason || '行号验证失败'}`);
      });
    }

    if (validationFeedback.correctedLines && validationFeedback.correctedLines.length > 0) {
      feedbackParts.push(`📝 行号修正（${validationFeedback.correctedLines.length}个）：`);
      feedbackParts.push("  请注意：之前报告的部分行号需要修正，请仔细验证");
    }

    if (validationFeedback.missingEvidence && validationFeedback.missingEvidence.length > 0) {
      feedbackParts.push(`🔍 证据缺失（${validationFeedback.missingEvidence.length}个）：`);
      validationFeedback.missingEvidence.slice(0, 3).forEach((m, i) => {
        feedbackParts.push(`  ${i + 1}. ${m.vulnId} 缺少证据点: ${m.missing.join(', ')}`);
      });
    }

    if (feedbackParts.length > 1) {
      prompt.push("", feedbackParts.join("\n"));
    }
  }

  if (isGbtAudit) {
    prompt = prompt.concat([
      "",
      "【审计任务】",
      "",
      "📋 项目信息：",
      `- 项目名称：${project.name}`,
      `- 审计路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
      `- 来源模式：${project.sourceType}`,
      "",
      "🔴 核心要求（再次强调）：",
      "- 独立审计：不查看快速扫描结果，独立发现所有安全问题",
      "- 全面覆盖：审计全部源代码文件，不得遗漏",
      "- 准确行号：需要验证行号，禁止凭记忆填写",
      "",
      "📝 输出要求：",
      "- 严格返回 JSON 格式，用 ```json 代码块包裹",
      "- 每个字段必须有值，禁止 null 或 undefined",
      "- evidence/impact 字数≥20，remediation 字数≥30",
      "- remediation 必须包含具体代码示例或 API 名称",
      "- score 范围 0-100，根据漏洞严重程度和数量计算",
      "- summary 提供整体评价，包括审计范围和风险等级",
      "",
      "📋 JSON 格式示例："
    ]);

    prompt.push(
      '```json',
      '{',
      '  "findings": [',
      '    {',
      '      "title": "身份认证绕过漏洞",',
      '      "severity": "high",',
      '      "confidence": 0.9,',
      '      "location": "src/controllers/AuthController.java:45",',
      '      "skillId": "gbt-code-audit",',
      '      "vulnType": "AUTH_BYPASS",',
      '      "cwe": "CWE-287",',
      '      "gbtMapping": "GB/T34944-6.3.1.2 身份鉴别被绕过；GB/T39412-6.3.1.2 身份鉴别被绕过",',
      '      "cvssScore": 8.5,',
      '      "language": "java",',
      '      "evidence": "代码中 adminCheck 方法仅验证用户名是否为 admin，未验证密码。攻击者构造用户名 admin 即可绕过认证。",',
      '      "impact": "攻击者可绕过身份认证访问管理功能，导致系统被完全控制，用户数据泄露。",',
      '      "remediation": "使用 Spring Security 的 BCryptPasswordEncoder 加密密码：BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(); boolean matches = encoder.matches(rawPassword, encodedPassword);",',
      '      "safeValidation": "验证登录接口是否正确调用 passwordEncoder.matches() 方法，检查数据库中密码是否为 BCrypt 格式（60 字符）",',
      '      "source": "username",',
      '      "sink": "adminCheck()",',
      '      "callChain": [{"method": "login", "file": "AuthController.java", "line": 45, "code": "if(username.equals(\\\"admin\\\")) {"}]',
      '    }',
      '  ],',
      '  "score": 75,',
      '  "summary": "本次审计共检查了 15 个源代码文件，发现 3 个安全问题（1个高危，2个中危）。整体安全状况中等，建议优先修复身份认证相关漏洞。代码质量较好，未发现严重的性能问题。"',
      '}',
      '```',
      "",
      "【Source→Sink 追踪要求】",
      "- 对于注入类漏洞（SQL注入、命令注入等），必须填写 source 和 sink 字段",
      "- source: 用户输入变量名或参数名",
      "- sink: 危险函数或方法名",
      "- callChain: 从 source 到 sink 的调用链，包含 method、file、line、code 字段",
      "- 如果无法确定完整调用链，callChain 可以为空数组",
      "",
      "【净化措施检查】",
      "- 检查是否存在 PreparedStatement、输入验证、编码等净化措施",
      "- 如果发现有效净化措施，降低漏洞严重程度或标记为误报",
      "- 在 evidence 中说明检查过程和结果"
    );
  } else {
    const skills = selectedSkills.map((skill) => `${skill.id}: ${skill.description}`).join("\n");

    const hasHeuristicContext = heuristicFindings && heuristicFindings.length > 0;
    const heuristicSummary = hasHeuristicContext
      ? heuristicFindings.slice(0, 10).map((finding) => `- ${finding.title} @ ${finding.location} (${finding.vulnType || 'unknown'})`).join("\n")
      : "";

    prompt = prompt.concat([
      "",
      `已启用 Skill：\n${skills}`,
      hasHeuristicContext ? `规则层发现（仅供参考，LLM应独立验证）：\n${heuristicSummary}` : "规则层未提供额外提示，LLM应独立进行全面审计。",
      "",
      "【重要】LLM 自主审计要求：",
      "- 不要受规则层发现的限制，独立发现所有安全问题",
      "- 可以发现任何类型的安全漏洞，不限于上述Skill列表",
      "- 包括但不限于：注入漏洞、XSS、CSRF、SSRF、路径遍历、敏感信息泄露、",
      "  认证绕过、访问控制、加密问题、反序列化、API安全、配置错误等",
      "- 输出所有发现的高置信度问题，不要限制数量",
      "- 每个漏洞都必须独立验证行号",
      "",
      "严格返回如下 JSON（包含 findings、score、summary）：",
      '{ "findings": [ { "title": "", "severity": "low|medium|high|critical", "confidence": 0.0, "location": "", "skillId": "", "vulnType": "VULN_TYPE", "cwe": "CWE-XXX", "evidence": "", "impact": "", "remediation": "", "safeValidation": "" } ], "score": 0-100, "summary": "整体评价" }'
    ]);
  }

  const snippets = batch.map((file) => `FILE: ${file.relativePath}\n\`\`\`${file.language}\n${file.content}\n\`\`\``).join("\n\n");
  prompt.push("");
  prompt.push(snippets);

  return prompt.join("\n\n");
}

export function createEnhancedPrompt(options = {}) {
  const {
    includeContextAnalysis = true,
    includeBusinessLogic = true,
    includeAttackChain = true,
    strictMode = true
  } = options;

  const enhancements = [];

  if (includeContextAnalysis) {
    enhancements.push(`
【上下文分析要求】
- 分析数据流：从用户输入到危险函数的完整路径
- 识别安全边界：信任边界、输入验证点、输出编码
- 评估验证有效性：验证是否充分、是否存在绕过
`);
  }

  if (includeBusinessLogic) {
    enhancements.push(`
【业务逻辑漏洞检测】
- 状态机漏洞：订单状态、支付流程、权限状态
- 条件竞争：并发场景下的状态不一致
- 水平越权：用户间数据访问
- 垂直越权：普通用户访问管理功能
`);
  }

  if (includeAttackChain) {
    enhancements.push(`
【攻击链分析】
- 单一漏洞利用链：入口点 → 传播路径 → 最终影响
- 组合漏洞：多个低危漏洞组合成高危攻击
- 攻击复杂度：利用难度、所需权限、影响范围
`);
  }

  if (strictMode) {
    enhancements.push(`
【严格模式】
- 每发现必须包含具体代码行号
- evidence 必须包含问题代码片段
- remediation 必须包含可执行的修复代码
- 禁止报告未经验证的猜测
`);
  }

  return enhancements.join('\n');
}

export function createIncrementalAuditPrompt(changedFiles) {
  return `
【增量审计任务】
仅审计以下变更文件：
${changedFiles.map(f => `- ${f}`).join('\n')}

变更文件需要重点关注：
1. 新增的危险函数调用
2. 修改的认证/授权逻辑
3. 变化的数据验证流程
4. 新的外部输入处理

其他文件如有严重问题会通过上下文分析被发现。
`;
}
