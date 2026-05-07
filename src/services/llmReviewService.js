import pLimit from "p-limit";
import { promises as fs } from "node:fs";
import path from "path";
import { inferFenceLanguage, collectFiles } from "../utils/fileUtils.js";
import { jsonrepair } from "jsonrepair";
import { withRetry, withRetryWithFallback, createRetryDecorator, CircuitBreaker, CircuitBreakerConfig, createReActAuditor, PromptCacheManager } from "../core/index.js";
import { createLocalToolExecutor } from "../tools/localToolExecutor.js";
import { buildReActSystemPrompt, buildReActInitialPrompt } from "../core/reactPrompts.js";
import { ragService } from "./ragService.js";
import { streamService } from "./streamService.js";
import { estimateTokens, countTokensTiktoken, getModelMaxTokens, PromptCompressor, IncrementalSummary, ContextConfig } from "../utils/contextManager.js";
import { fetchWithTimeout, globalLLMFactory } from "./llmFactory.js";
import { CodeRetriever } from "./retriever.js";
import { deduplicateAndSort, severityScore } from "../utils/findingsUtils.js";

const MAX_BATCHES = 16;
const MAX_FILES_PER_BATCH = 4;
const MAX_CHARS_PER_BATCH = 25_000;
const MAX_PARALLEL_REQUESTS = 3;
const FETCH_TIMEOUT_MS = 120_000;

const llmCircuitBreaker = new CircuitBreaker("llm-service", {
  failureThreshold: 3,
  successThreshold: 2,
  recoveryTimeout: 30000
});

const incrementalSummary = new IncrementalSummary();
const llmLimit = pLimit(3);
const promptCompressor = new PromptCompressor();
const promptCacheManager = new PromptCacheManager();

// 初始化 RAG 服务
async function initializeRAG() {
  try {
    await ragService.initialize({
      vectorPersistPath: path.join(process.cwd(), 'data', 'rag_vectors.json')
    });
    console.log('[LLM审计] RAG 服务初始化完成');
  } catch (error) {
    console.warn('[LLM审计] RAG 服务初始化失败，将使用关键词搜索:', error);
  }
}

// 在模块加载时初始化 RAG
initializeRAG();

const THREE_LAYER_AUDIT = `
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

const CORE_SECURITY_PRINCIPLES = `
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

const FILE_VALIDATION_RULES = `
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

const VULNERABILITY_PRIORITIES = `
【LLM审计漏洞检测优先级 - 需要上下文分析的漏洞】

⚠️ 注意：以下列表是LLM审计需要重点关注的漏洞类型。SQL注入、命令注入、硬编码密码等高风险函数调用已由快速扫描覆盖，LLM不应重复检测。

🔴 Critical - 认证授权类（必须检测）：
1. 身份认证绕过 - 密码重置漏洞、会话管理缺陷
2. 权限检查缺失 - 水平越权、垂直越权
3. 关键状态数据外部可控 - 用户输入直接控制安全决策

🟠 High - 业务逻辑类（重点检测）：
1. 会话固定/会话劫持
2. 条件判断不充分 - 缺少默认值、死代码
3. 状态绕过 - 订单状态、支付流程篡改

🟡 Medium - 上下文相关类（全面检测）：
1. 开放重定向
2. 文件上传类型验证不足
3. 并发安全问题 - 竞态条件
4. 整数溢出 - 数值运算边界检查

🟢 Info - 框架配置类（参考检测）：
1. CSRF防护缺失
2. CORS配置不当
3. 错误信息泄露敏感数据`;

const FALSE_POSITIVE_RULES = `
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

const LINE_NUMBER_VERIFICATION = `
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

const LANGUAGE_GBT_MAP = {
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

const VULNERABILITY_FILES = {
  'sql_injection': 'sql_injection.md',
  'command_injection': 'command_injection.md',
  'code_injection': 'code_injection.md',
  'deserialization': 'deserialization.md',
  'hardcoded_credentials': 'hardcoded_credentials.md',
  'path_traversal': 'path_traversal.md',
  'weak_crypto': 'weak_crypto.md'
};

async function loadAuditKnowledge({ languages = [], vulnerabilityTypes = [] } = {}) {
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

export class DefensiveLlmReviewer {
  async reviewProject({ project, selectedSkills, heuristicFindings, llmConfig, onProgress }) {
    if (!llmConfig?.apiKey) {
      return {
        status: "skipped",
        called: false,
        skipReason: "missing-api-key",
        summary: "未配置可用的 LLM API Key，本次没有调用大模型进行二次复核。",
        findings: [],
        warnings: []
      };
    }

    const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
    const files = await collectFilesWithContent(sourceRoot);
    if (!files.length) {
      return {
        status: "skipped",
        called: false,
        skipReason: "no-local-files",
        summary: "当前目标没有生成可供大模型复核的本地审计镜像，因此没有实际调用大模型。",
        findings: [],
        warnings: []
      };
    }

    const prioritizedFiles = rankFiles(files, heuristicFindings, selectedSkills);
    const batches = buildBatches(prioritizedFiles);
    const findings = [];
    const warnings = [];
    let reviewedFiles = 0;
    let reviewedBatches = 0;
    let completedBatches = 0;

    const languages = [...new Set(batches.flatMap(b => b.map(f => f.language)).filter(Boolean))];
    const vulnerabilityTypes = [...new Set(heuristicFindings.map(f => f.vulnType).filter(Boolean))];
    const auditKnowledge = await loadAuditKnowledge({ languages, vulnerabilityTypes });
    const systemPrompt = await buildSystemPrompt(selectedSkills, auditKnowledge, languages);
    const validBatches = batches.slice(0, MAX_BATCHES);

    onProgress?.({
      type: "llm-start",
      totalFiles: prioritizedFiles.length,
      totalBatches: validBatches.length,
      reviewedFiles: 0,
      reviewedBatches: 0,
      label: `正在准备 LLM 复核：${project.name}`
    });

    async function processBatch(batch, batchIndex) {
      onProgress?.({
        type: "llm-batch",
        currentBatch: batchIndex + 1,
        totalBatches: validBatches.length,
        batchSize: batch.length,
        reviewedFiles,
        reviewedBatches: completedBatches,
        totalFiles: prioritizedFiles.length,
        label: `正在并行 LLM 复核：第 ${batchIndex + 1} / ${validBatches.length} 批`
      });

      try {
        const healthScore = llmCircuitBreaker.getHealthScore?.();
        console.debug(`[LLM审计] 熔断器健康评分: ${healthScore}`);

        const responseText = await withReviewRetry(() => llmCircuitBreaker.callWithFallback(() =>
          requestStructuredReview({
            llmConfig,
            systemPrompt,
            userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings, batch })
          }),
          () => {
            console.warn('[LLM审计] LLM服务熔断，使用降级方案');
            return JSON.stringify({ findings: [] });
          }
        ));

        const parsed = parseJsonResponse(responseText);
        const normalized = normalizeFindings(parsed?.findings, selectedSkills);

        onProgress?.({
          type: "llm-batch-complete",
          currentBatch: batchIndex + 1,
          totalBatches: validBatches.length,
          batchSize: batch.length,
          reviewedFiles: reviewedFiles + batch.length,
          reviewedBatches: completedBatches + 1,
          totalFiles: prioritizedFiles.length,
          label: `LLM 已完成第 ${batchIndex + 1} 批复核`
        });

        return { success: true, findings: normalized, batchSize: batch.length };
      } catch (error) {
        console.error(`[LLM审计] 批次 ${batchIndex + 1} 出现错误:`, error.message);

        onProgress?.({
          type: "llm-batch-error",
          currentBatch: batchIndex + 1,
          totalBatches: validBatches.length,
          batchSize: batch.length,
          reviewedFiles,
          reviewedBatches: completedBatches,
          totalFiles: prioritizedFiles.length,
          label: `LLM 第 ${batchIndex + 1} 批复核出现错误`
        });

        return { success: false, error: error.message, batchSize: batch.length };
      }
    }

    for (let i = 0; i < validBatches.length; i += MAX_PARALLEL_REQUESTS) {
      const batchGroup = validBatches.slice(i, i + MAX_PARALLEL_REQUESTS);
      const results = await Promise.all(
        batchGroup.map((batch, idx) => processBatch(batch, i + idx))
      );

      for (const result of results) {
        if (result.success) {
          findings.push(...result.findings);
          reviewedFiles += result.batchSize;
        } else {
          warnings.push(result.error);
        }
        reviewedBatches++;
        completedBatches++;
      }
    }

    const dedupedFindings = deduplicateAndSort(findings).slice(0, 12);
    const truncated = prioritizedFiles.length > validBatches.flat().length;

    return {
      status: warnings.length && !reviewedBatches ? "failed" : warnings.length ? "partial" : "completed",
      called: true,
      skipReason: "",
      providerId: llmConfig.providerId,
      model: llmConfig.model,
      reviewedFiles,
      totalCandidateFiles: prioritizedFiles.length,
      reviewedBatches,
      skillsUsed: selectedSkills.map((skill) => skill.id),
      summary: buildSummary({ reviewedFiles, reviewedBatches, findings: dedupedFindings, truncated }),
      warnings,
      findings: dedupedFindings.map((finding) => ({ ...finding, source: "llm" }))
    };
  }

  async auditProject({ project, selectedSkills, llmConfig, onProgress }) {
    console.log(`[LLM审计] auditProject 开始 - 项目: ${project.name}, 提供商: ${llmConfig.providerId}, 模型: ${llmConfig.model}`);
    if (!llmConfig?.apiKey) {
      return {
        status: "skipped",
        called: false,
        skipReason: "missing-api-key",
        summary: "未配置可用的 LLM API Key，本次没有调用大模型进行独立审计。",
        findings: [],
        warnings: []
      };
    }

    const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
    const files = await collectFilesWithContent(sourceRoot);
    if (!files.length) {
      return {
        status: "skipped",
        called: false,
        skipReason: "no-local-files",
        summary: "当前目标没有生成可供大模型审计的本地审计镜像，因此没有实际调用大模型。",
        findings: [],
        warnings: []
      };
    }

    // 初始化代码检索器，建立项目代码索引
    let codeRetriever = null;
    try {
      codeRetriever = new CodeRetriever({ maxChunkSize: 800, overlap: 50 });
      await codeRetriever.initialize();
      console.log(`[LLM审计] 开始索引项目代码: ${files.length} 个文件`);
      for (const file of files.slice(0, 100)) {
        try {
          const content = await fs.readFile(file.path, "utf8");
          await codeRetriever.indexFile(file.path, content, file.language);
        } catch (e) {
        }
      }
      console.log(`[LLM审计] 代码索引完成，已索引 ${codeRetriever.chunks.size} 个代码块`);
    } catch (error) {
      console.warn(`[LLM审计] 代码索引失败: ${error.message}`);
      codeRetriever = null;
    }

    // 对于独立审计，我们处理所有文件，而不仅仅是排名靠前的文件
    const batches = buildBatches(files);
    const findings = [];
    const warnings = [];
    let auditedFiles = 0;
    let auditedBatches = 0;
    let completedBatches = 0;

    const languages = [...new Set(batches.flatMap(b => b.map(f => f.language)).filter(Boolean))];
    const auditKnowledge = await loadAuditKnowledge({ languages, vulnerabilityTypes: [] });
    const systemPrompt = await buildSystemPrompt(selectedSkills, auditKnowledge, languages);
    const validBatches = batches.slice(0, MAX_BATCHES);

    onProgress?.({
      type: "llm-start",
      totalFiles: files.length,
      totalBatches: validBatches.length,
      auditedFiles: 0,
      auditedBatches: 0,
      label: `正在准备 LLM 审计：${project.name}`
    });

    async function getCodeContextForBatch(batch, skillContext = "") {
      if (!codeRetriever || codeRetriever.chunks.size === 0) {
        return "";
      }

      try {
        const query = skillContext || "安全漏洞 注入 认证 授权 敏感数据";
        const results = await codeRetriever.hybridRetrieve(query, { k: 3, semanticWeight: 0.6, keywordWeight: 0.4 });

        if (results.length === 0) return "";

        const contextParts = ["\n\n【相关代码上下文】"];
        for (const result of results.slice(0, 2)) {
          contextParts.push(result.toContextString());
        }
        return contextParts.join("\n");
      } catch (error) {
        return "";
      }
    }

    async function processAuditBatch(batch, batchIndex) {
      onProgress?.({
        type: "llm-batch",
        currentBatch: batchIndex + 1,
        totalBatches: validBatches.length,
        batchSize: batch.length,
        auditedFiles,
        auditedBatches: completedBatches,
        totalFiles: files.length,
        label: `正在并行 LLM 审计：第 ${batchIndex + 1} / ${validBatches.length} 批`
      });

      const skillContext = selectedSkills.map(s => s.name).join(" ");
      const codeContext = await getCodeContextForBatch(batch, skillContext);

      try {
        const healthScore = llmCircuitBreaker.getHealthScore?.();
        console.debug(`[LLM审计] 熔断器健康评分: ${healthScore}`);

        const responseText = await withReviewRetry(() => llmCircuitBreaker.callWithFallback(() =>
          requestStructuredReview({
            llmConfig,
            systemPrompt,
            userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings: [], batch, codeContext })
          }),
          () => {
            console.warn('[LLM审计] LLM服务熔断，使用降级方案');
            return JSON.stringify({ findings: [] });
          }
        ));

        const parsed = parseJsonResponse(responseText);
        const normalized = normalizeFindings(parsed?.findings, selectedSkills);

        onProgress?.({
          type: "llm-batch-complete",
          currentBatch: batchIndex + 1,
          totalBatches: validBatches.length,
          batchSize: batch.length,
          auditedFiles: auditedFiles + batch.length,
          auditedBatches: completedBatches + 1,
          totalFiles: files.length,
          label: `LLM 已完成第 ${batchIndex + 1} 批审计`
        });

        return { success: true, findings: normalized, batchSize: batch.length };
      } catch (error) {
        console.error(`[LLM审计] 批次 ${batchIndex + 1} 出现错误:`, error.message);

        onProgress?.({
          type: "llm-batch-error",
          currentBatch: batchIndex + 1,
          totalBatches: validBatches.length,
          batchSize: batch.length,
          auditedFiles,
          auditedBatches: completedBatches,
          totalFiles: files.length,
          label: `LLM 第 ${batchIndex + 1} 批审计出现错误`
        });

        return { success: false, error: error.message, batchSize: batch.length };
      }
    }

    for (let i = 0; i < validBatches.length; i += MAX_PARALLEL_REQUESTS) {
      const batchGroup = validBatches.slice(i, i + MAX_PARALLEL_REQUESTS);
      const results = await Promise.all(
        batchGroup.map((batch, idx) => processAuditBatch(batch, i + idx))
      );

      for (const result of results) {
        if (result.success) {
          findings.push(...result.findings);
          auditedFiles += result.batchSize;
        } else {
          warnings.push(result.error);
        }
        auditedBatches++;
        completedBatches++;
      }
    }

    const dedupedFindings = deduplicateAndSort(findings).slice(0, 12);
    const truncated = files.length > validBatches.flat().length;
    console.log(`[LLM审计] auditProject 完成 - 审计文件数: ${auditedFiles}, 审计批次: ${auditedBatches}, 发现问题数: ${dedupedFindings.length}, 警告数: ${warnings.length}`);

    return {
      status: warnings.length && !auditedBatches ? "failed" : warnings.length ? "partial" : "completed",
      called: true,
      skipReason: "",
      providerId: llmConfig.providerId,
      model: llmConfig.model,
      auditedFiles,
      totalFiles: files.length,
      auditedBatches,
      skillsUsed: selectedSkills.map((skill) => skill.id),
      summary: buildSummary({ reviewedFiles: auditedFiles, reviewedBatches: auditedBatches, findings: dedupedFindings, truncated }),
      warnings,
      findings: dedupedFindings.map((finding) => ({ ...finding, source: "llm" }))
    };
  }

  async auditWithReAct({ project, selectedSkills, llmConfig, reactConfig = {}, onProgress }) {
    console.log(`[ReAct审计] auditWithReAct 开始 - 项目: ${project.name}, 提供商: ${llmConfig.providerId}, 模型: ${llmConfig.model}`);

    if (!llmConfig?.apiKey) {
      return {
        status: "skipped",
        called: false,
        skipReason: "missing-api-key",
        summary: "未配置可用的 LLM API Key，本次没有调用大模型进行 ReAct 推理审计。",
        findings: [],
        warnings: [],
        reactResult: null
      };
    }

    const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);

    const adapter = globalLLMFactory.createAdapter(llmConfig);
    const toolExecutor = createLocalToolExecutor(sourceRoot);

    const auditorConfig = {
      maxSteps: reactConfig.maxSteps || 15,
      temperature: reactConfig.temperature || 0.1,
      maxRetries: reactConfig.maxRetries || 3,
      verbose: reactConfig.verbose || false
    };

    const auditor = createReActAuditor(adapter, toolExecutor, auditorConfig);

    try {
      const files = await collectFiles(sourceRoot);
      if (!files.length) {
        return {
          status: "skipped",
          called: false,
          skipReason: "no-local-files",
          summary: "当前目标没有生成可供 ReAct 审计的本地审计镜像。",
          findings: [],
          warnings: [],
          reactResult: null
        };
      }

      const codeDiff = files.map(f => `FILE: ${f.relativePath}\n\`\`\`${f.language}\n${f.content}\n\`\`\``).join('\n\n');
      const projectInfo = {
        name: project.name,
        path: project.localPath || sourceRoot,
        language: files[0]?.language || 'unknown'
      };

      onProgress?.({
        type: "react-start",
        projectName: project.name,
        totalFiles: files.length,
        label: `正在启动 ReAct 推理审计：${project.name}`
      });

      const reactResult = await auditor.audit({
        systemPrompt: await buildReActSystemPrompt(),
        initialPrompt: buildReActInitialPrompt(codeDiff, projectInfo),
        projectInfo
      });

      const findings = reactResult.issues.map(issue => ({
        title: issue.desc || issue.type || 'ReAct 发现',
        severity: issue.level || 'medium',
        confidence: 0.8,
        location: issue.file || 'n/a',
        skillId: selectedSkills[0]?.id || 'gbt-code-audit',
        evidence: issue.code || issue.desc || '',
        impact: `ReAct 推理发现：${issue.type} 相关风险`,
        remediation: issue.suggestion || issue.FixSuggestion || '建议进行安全代码审查',
        safeValidation: '建议使用工具验证问题代码并确认修复',
        source: 'react'
      }));

      onProgress?.({
        type: "react-complete",
        projectName: project.name,
        totalSteps: reactResult.steps.length,
        findingsCount: findings.length,
        label: `ReAct 推理审计完成：发现 ${findings.length} 个问题`
      });

      return {
        status: reactResult.error ? "partial" : "completed",
        called: true,
        skipReason: "",
        providerId: llmConfig.providerId,
        model: llmConfig.model,
        totalSteps: reactResult.steps.length,
        skillsUsed: selectedSkills.map((skill) => skill.id),
        summary: `ReAct 推理审计完成，共 ${reactResult.steps.length} 步推理，发现 ${findings.length} 个安全问题。`,
        warnings: reactResult.error ? [reactResult.error] : [],
        findings,
        reactResult: reactResult.toJSON()
      };
    } catch (error) {
      console.error(`[ReAct审计] auditWithReAct 错误:`, error.message);
      return {
        status: "failed",
        called: false,
        skipReason: "react-error",
        summary: `ReAct 审计失败：${error.message}`,
        findings: [],
        warnings: [error.message],
        reactResult: null
      };
    }
  }
}

const withReviewRetry = createRetryDecorator({ 
  maxAttempts: 2, 
  baseDelay: 1000,
  onRetry: (error, attempt, max) => {
    console.warn(`[LLM审计] 请求重试 ${attempt}/${max}: ${error.message}`);
  }
});

async function requestStructuredReview({ llmConfig, systemPrompt, userPrompt }) {
  const compatibility = llmConfig.compatibility || llmConfig.defaults?.compatibility || "openai";
  const model = llmConfig.model || 'gpt-3.5-turbo';
  const maxTokens = getModelMaxTokens(model);

  const systemTokens = estimateTokens(systemPrompt);
  const userTokens = estimateTokens(userPrompt);
  const totalTokens = systemTokens + userTokens;
  const contextUsage = ((totalTokens / maxTokens) * 100).toFixed(1);

  console.log(`[LLM审计] 开始请求 - 提供商: ${llmConfig.providerId}, 兼容性: ${compatibility}, 模型: ${model}`);
  console.log(`[LLM审计] Token 估算 - System: ${systemTokens}, User: ${userTokens}, 总计: ${totalTokens}, 模型上限: ${maxTokens}, 使用率: ${contextUsage}%`);

  let optimizedSystem = systemPrompt;
  let optimizedUser = userPrompt;

  if (totalTokens > maxTokens * ContextConfig.SAFETY_MARGIN) {
    console.log(`[LLM审计] 上下文超限，开始压缩...`);
    const availableTokens = Math.floor(maxTokens * ContextConfig.SAFETY_MARGIN) - systemTokens - 100;
    if (availableTokens > 0) {
      optimizedUser = promptCompressor.truncateToFit(userPrompt, availableTokens);
      console.log(`[LLM审计] 压缩后 User Token: ${estimateTokens(optimizedUser)}`);
    }
  }

  // 检查 Prompt Cache 是否可用
  const providerLower = llmConfig.providerId?.toLowerCase() || '';
  const usePromptCache = promptCacheManager.supportsCaching(model, providerLower);
  if (usePromptCache) {
    console.log(`[LLM审计] 使用 Prompt Cache: ${providerLower}/${model}`);
  }

  if (compatibility === "anthropic") {
    console.log(`[LLM审计] 使用 Anthropic 兼容模式`);
    let response;
    try {
      response = await fetchWithTimeout(`${stripTrailingSlash(llmConfig.baseUrl)}/v1/messages`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": llmConfig.apiKey,
          "anthropic-version": "2023-06-01"
        },
        body: JSON.stringify({
          model: llmConfig.model,
          max_tokens: 4096,
          temperature: 0.1,
          system: optimizedSystem,
          messages: [{ role: "user", content: optimizedUser }]
        })
      });
    } catch (fetchError) {
      if (fetchError.name === 'AbortError') {
        console.error(`[LLM审计] Anthropic API请求超时`);
        throw new Error(`LLM 复核超时：Anthropic 请求在 ${FETCH_TIMEOUT_MS / 1000} 秒内未返回`);
      }
      console.error(`[LLM审计] Anthropic API请求异常:`, fetchError.message);
      throw fetchError;
    }

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Anthropic 返回 ${response.status}`);
    }

    const data = await response.json();
    return (data.content || []).map((item) => item.text || "").join("\n");
  }

  if (compatibility === "gemini") {
    console.log(`[LLM审计] 使用 Gemini 兼容模式`);
    let response;
    try {
      response = await fetchWithTimeout(
        `${stripTrailingSlash(llmConfig.baseUrl)}/v1beta/models/${encodeURIComponent(llmConfig.model)}:generateContent?key=${encodeURIComponent(llmConfig.apiKey)}`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            systemInstruction: { parts: [{ text: optimizedSystem }] },
            contents: [{ role: "user", parts: [{ text: optimizedUser }] }],
            generationConfig: {
              temperature: 0.1,
              maxOutputTokens: 4096
            }
          })
        }
      );
    } catch (fetchError) {
      if (fetchError.name === 'AbortError') {
        console.error(`[LLM审计] Gemini API请求超时`);
        throw new Error(`LLM 复核超时：Gemini 请求在 ${FETCH_TIMEOUT_MS / 1000} 秒内未返回`);
      }
      console.error(`[LLM审计] Gemini API请求异常:`, fetchError.message);
      throw fetchError;
    }

    if (!response.ok) {
      throw new Error(`LLM 复核失败：Gemini 返回 ${response.status}`);
    }

    const data = await response.json();
    return data.candidates?.[0]?.content?.parts?.map((item) => item.text || "").join("\n") || "";
  }

  console.log(`[LLM审计] 使用 OpenAI 兼容模式 (默认)`);
  console.log(`[LLM审计] 发送请求到: ${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`);
  let response;
  try {
    response = await fetchWithTimeout(`${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${llmConfig.apiKey}`
      },
      body: JSON.stringify({
        model: llmConfig.model,
        temperature: 0.1,
        max_tokens: 4096,
        messages: [
          { role: "system", content: optimizedSystem },
          { role: "user", content: optimizedUser }
        ]
      })
    });
  } catch (fetchError) {
    if (fetchError.name === 'AbortError') {
      console.error(`[LLM审计] API请求超时 - 超时时间: ${FETCH_TIMEOUT_MS}ms`);
      throw new Error(`LLM 复核超时：请求在 ${FETCH_TIMEOUT_MS / 1000} 秒内未返回`);
    }
    console.error(`[LLM审计] API请求异常:`, fetchError.message);
    throw fetchError;
  }

  if (!response.ok) {
    console.error(`[LLM审计] API请求失败 - 状态码: ${response.status}, 状态文本: ${response.statusText}`);
    throw new Error(`LLM 复核失败：模型端点返回 ${response.status}`);
  }

  console.log(`[LLM审计] API请求成功 - 状态码: ${response.status}`);
  const data = await response.json();
  console.log(`[LLM审计] 收到响应数据，choices数量: ${data.choices?.length || 0}`);
  
  // 调试：打印响应结构
  if (data.choices && data.choices.length > 0) {
    const firstChoice = data.choices[0];
    console.log(`[LLM审计] 响应类型: ${typeof firstChoice}`);
    console.log(`[LLM审计] 响应包含 message: ${'message' in firstChoice}`);
    console.log(`[LLM审计] message类型: ${typeof firstChoice.message}`);
    if (firstChoice.message) {
      console.log(`[LLM审计] message包含 content: ${'content' in firstChoice.message}`);
      console.log(`[LLM审计] content类型: ${typeof firstChoice.message.content}`);
      console.log(`[LLM审计] content长度: ${String(firstChoice.message.content).length}`);
    }
    // 尝试其他可能的响应格式
    if (firstChoice.text) {
      console.log(`[LLM审计] 发现 text 字段，长度: ${firstChoice.text.length}`);
    }
  }
  
  // 支持多种响应格式，包括带有思考过程的格式
  let content = data.choices?.[0]?.message?.content || 
                data.choices?.[0]?.text || 
                data.text || 
                "";
  
  // 如果 content 为空，但有 reasoning_content，尝试提取最终答案
  if (!content && data.choices?.[0]?.message?.reasoning_content) {
    console.log(`[LLM审计] content为空，但发现 reasoning_content，长度: ${data.choices[0].message.reasoning_content.length}`);
    const reasoning = data.choices[0].message.reasoning_content;
    // 尝试从思考内容中提取最终答案（通常在思考过程之后）
    const finalAnswerMatch = reasoning.match(/(?:Final Answer|最终答案|总结|结论)\s*[:：]\s*([\s\S]*)$/i);
    if (finalAnswerMatch) {
      content = finalAnswerMatch[1].trim();
      console.log(`[LLM审计] 从 reasoning_content 中提取到答案，长度: ${content.length}`);
    }
  }
  
  console.log(`[LLM审计] 提取的内容长度: ${content.length}`);
  return content;
}

async function buildSystemPrompt(selectedSkills, auditKnowledge = {}, languages = []) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    "你是一个防御性代码审计助手。",
    "只输出风险说明、证据、影响、修复建议和安全验证建议。",
    "不要提供利用步骤、payload、绕过思路、攻击链构造或 weaponization 细节。",
    "如果证据不足，就降低置信度或不要报出该问题。",
    "请只返回 JSON 对象，不要输出额外说明。",
    CORE_SECURITY_PRINCIPLES,
    FILE_VALIDATION_RULES
  ];

  // 添加 RAG 知识参考
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

function buildUserPrompt({ project, selectedSkills, heuristicFindings, batch, codeContext = "" }) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    `项目名称：${project.name}`,
    `审计镜像路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
    `来源模式：${project.sourceType}`
  ];

  if (codeContext) {
    prompt.push(codeContext);
  }

  if (isGbtAudit) {
    prompt = prompt.concat([
      "",
      "【审计任务】",
      "",
      "� 项目信息：",
      `- 项目名称：${project.name}`,
      `- 审计路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
      `- 来源模式：${project.sourceType}`,
      "",
      "🔴 核心要求（再次强调）：",
      "- 独立审计：不查看快速扫描结果，独立发现所有安全问题",
      "- 全面覆盖：审计全部源代码文件，不得遗漏",
      "- 准确行号：使用 Grep 验证行号，禁止凭记忆填写",
      "",
      "📝 输出要求：",
      "- 严格返回 JSON 格式，用 ```json 代码块包裹",
      "- 每个字段必须有值，禁止 null 或 undefined",
      "- evidence/impact 字数≥20，remediation 字数≥30",
      "- remediation 必须包含具体代码示例或 API 名称",
      "",
      "📋 JSON 格式示例："
    ]);
    
    // 添加详细的 JSON 格式示例
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
      '      "safeValidation": "验证登录接口是否正确调用 passwordEncoder.matches() 方法，检查数据库中密码是否为 BCrypt 格式（60 字符）"',
      '    }',
      '  ]',
      '}',
      '```'
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
      "严格返回如下 JSON：",
      '{ "findings": [ { "title": "", "severity": "low|medium|high|critical", "confidence": 0.0, "location": "", "skillId": "", "vulnType": "VULN_TYPE", "cwe": "CWE-XXX", "evidence": "", "impact": "", "remediation": "", "safeValidation": "" } ] }'
    ]);
  }

  const snippets = batch.map((file) => `FILE: ${file.relativePath}\n\`\`\`${file.language}\n${file.content}\n\`\`\``).join("\n\n");
  prompt.push("");
  prompt.push(snippets);

  return prompt.join("\n\n");
}

async function collectFilesWithContent(root) {
  try {
    const output = [];
    await walk(root, root, output);
    return output;
  } catch {
    return [];
  }
}

async function walk(root, currentPath, output) {
  const entries = await fs.readdir(currentPath, { withFileTypes: true });
  for (const entry of entries) {
    const target = path.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      await walk(root, target, output);
      continue;
    }

    if (!entry.isFile()) {
      continue;
    }

    const language = inferFenceLanguage(target);
    if (!language) {
      continue;
    }

    const content = await fs.readFile(target, "utf8");
    output.push({
      fullPath: target,
      relativePath: path.relative(root, target).replaceAll("\\", "/"),
      content,
      language
    });
  }
}

function rankFiles(files, heuristicFindings, selectedSkills) {
  const locationHints = new Set(heuristicFindings.map((finding) => finding.location).filter(Boolean));
  const keywordHints = selectedSkills.flatMap((skill) =>
    skill.reviewPrompt.toLowerCase().split(/[^\p{L}\p{N}_-]+/u).filter((token) => token.length > 3)
  );

  const languageBoost = {
    "java": 1.2,
    "csharp": 1.2,
    "cpp": 1.1,
    "python": 1.1,
    "javascript": 1.0,
    "typescript": 1.0,
    "go": 1.0,
    "php": 1.0
  };

  return [...files]
    .map((file) => {
      const loweredPath = file.relativePath.toLowerCase();
      const baseScore = Math.min(file.content.length / 200, 80);
      const langBoost = languageBoost[file.language] || 1.0;
      let score = baseScore * langBoost;

      if (locationHints.has(file.relativePath)) {
        score += 120;
      }
      if (/(auth|permission|policy|access|role|admin|upload|secret|query|config|service|controller)/.test(loweredPath)) {
        score += 60;
      }
      for (const keyword of keywordHints) {
        if (loweredPath.includes(keyword)) {
          score += 5;
        }
      }

      return { ...file, score };
    })
    .sort((a, b) => b.score - a.score);
}

function buildBatches(files) {
  const batches = [];
  let currentBatch = [];
  let currentChars = 0;

  for (const file of files) {
    const snippetLength = file.content.length + file.relativePath.length;
    if (currentBatch.length && (currentBatch.length >= MAX_FILES_PER_BATCH || currentChars + snippetLength > MAX_CHARS_PER_BATCH)) {
      batches.push(currentBatch);
      currentBatch = [];
      currentChars = 0;
    }

    currentBatch.push(file);
    currentChars += snippetLength;
  }

  if (currentBatch.length) {
    batches.push(currentBatch);
  }

  return batches;
}

function parseJsonResponse(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) {
    console.log('[LLM 审计] 响应为空，返回空结果');
    return { findings: [] };
  }

  console.log(`[LLM 审计] 收到响应文本，长度：${trimmed.length} 字符`);
  console.log(`[LLM 审计] 响应前 500 字符：${trimmed.slice(0, 500)}`);
  
  let candidate = trimmed;
  
  // 尝试从 markdown 代码块中提取 JSON
  const jsonBlockMatch = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (jsonBlockMatch && jsonBlockMatch[1]) {
    candidate = jsonBlockMatch[1].trim();
    console.log('[LLM 审计] 从 markdown 代码块中提取 JSON');
  }

  // 首先尝试直接解析
  try {
    const parsed = JSON.parse(candidate);
    console.log(`[LLM 审计] JSON 直接解析成功，findings 数量：${parsed?.findings?.length || 0}`);
    return parsed;
  } catch (e) {
    // 直接解析失败，使用 repairJson 修复
  }

  // 使用 jsonrepair 库修复损坏的 JSON
  try {
    console.log('[LLM 审计] 尝试使用 jsonrepair 修复 JSON');
    const repaired = jsonrepair(candidate);
    const parsed = JSON.parse(repaired);
    console.log(`[LLM 审计] jsonrepair 修复成功，findings 数量：${parsed?.findings?.length || 0}`);
    return parsed;
  } catch (e) {
    console.log(`[LLM 审计] jsonrepair 修复失败：${e.message}`);
  }

  // 最后尝试：提取平衡的 JSON 对象并修复
  try {
    const balanced = extractBalancedJson(candidate);
    if (balanced) {
      console.log('[LLM 审计] 尝试修复提取的平衡 JSON');
      const repaired = jsonrepair(balanced);
      const parsed = JSON.parse(repaired);
      console.log(`[LLM 审计] 平衡 JSON 修复成功，findings 数量：${parsed?.findings?.length || 0}`);
      return parsed;
    }
  } catch (e) {
    console.log(`[LLM 审计] 平衡 JSON 修复失败：${e.message}`);
  }
  
  // 所有尝试都失败
  console.log('[LLM 审计] JSON 解析失败，返回空 findings 数组');
  return { findings: [] };
}

/**
 * 提取平衡的 JSON 对象（处理嵌套的括号）
 */
function extractBalancedJson(text) {
  const start = text.indexOf('{');
  if (start === -1) return null;
  
  let braceCount = 0;
  let inString = false;
  let escape = false;
  
  for (let i = start; i < text.length; i++) {
    const char = text[i];
    
    if (escape) {
      escape = false;
      continue;
    }
    
    if (char === '\\' && inString) {
      escape = true;
      continue;
    }
    
    if (char === '"' && !escape) {
      inString = !inString;
      continue;
    }
    
    if (!inString) {
      if (char === '{') {
        braceCount++;
      } else if (char === '}') {
        braceCount--;
        if (braceCount === 0) {
          return text.substring(start, i + 1);
        }
      }
    }
  }
  
  return null;
}

function normalizeFindings(findings, selectedSkills) {
  const validSkillIds = new Set(selectedSkills.map((skill) => skill.id));
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  console.log(`[LLM 审计] normalizeFindings - 输入 findings 数量：${findings?.length || 0}`);
  
  if (!Array.isArray(findings)) {
    console.log('[LLM 审计] normalizeFindings - findings 不是数组，返回空数组');
    return [];
  }

  const normalized = findings
    .map((finding) => {
      const normalized = {
        title: safeString(finding.title, "LLM 复核发现"),
        severity: normalizeSeverity(finding.severity),
        confidence: clampConfidence(finding.confidence),
        location: safeString(finding.location, "n/a"),
        skillId: validSkillIds.has(finding.skillId) ? finding.skillId : selectedSkills[0]?.id || "access-control",
        evidence: safeString(finding.evidence, "模型复核认为这里存在值得继续人工确认的实现迹象。"),
        impact: safeString(finding.impact, "该实现如果在真实部署中成立，可能扩大管理面、数据面或配置暴露面。"),
        remediation: safeString(finding.remediation, "建议结合服务端收口、权限校验和配置默认值治理进行修复。"),
        safeValidation: safeString(finding.safeValidation, "建议在本地或测试环境里补充代码走读与单元测试来确认边界。")
      };

      if (isGbtAudit && finding.skillId === "gbt-code-audit") {
        normalized.vulnType = safeString(finding.vulnType, "UNKNOWN");
        normalized.cwe = safeString(finding.cwe, "CWE-000");
        normalized.gbtMapping = safeString(finding.gbtMapping, "GB/T39412-2020 通用基线");
        normalized.cvssScore = clampCvssScore(finding.cvssScore);
        normalized.language = safeString(finding.language, "unknown");
      }

      return normalized;
    })
    .filter((finding) => {
      const pass = finding.confidence >= 0.55;
      if (!pass) {
        console.log(`[LLM 审计] 过滤发现：${finding.title} - 置信度 ${finding.confidence} < 0.55`);
      }
      return pass;
    });

  console.log(`[LLM 审计] normalizeFindings - 输出 findings 数量：${normalized.length}`);
  return normalized;
}

function buildSummary({ reviewedFiles, reviewedBatches, findings, truncated }) {
  const parts = [`LLM 已对 ${reviewedBatches} 个批次、${reviewedFiles} 个本地源码文件进行了二次复核。`];
  if (findings.length) {
    parts.push(`最终保留 ${findings.length} 条较高置信度的模型复核结果。`);
  } else {
    parts.push("模型没有额外保留到足够高置信度的问题。");
  }
  if (truncated) {
    parts.push("由于镜像较大，本次优先复核了高信号文件，未覆盖全部镜像文件。");
  }
  return parts.join("");
}

function stripTrailingSlash(value) {
  return String(value || "").replace(/\/+$/, "");
}

function normalizeSeverity(value) {
  const validSeverities = ["critical", "high", "medium", "low", "info"];
  return validSeverities.includes(value) ? value : "low";
}

function clampConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 0.65;
  }
  if (numeric < 0) {
    return 0;
  }
  if (numeric > 1) {
    return 1;
  }
  return numeric;
}

function safeString(value, fallback) {
  const text = String(value || "").trim();
  return text || fallback;
}

function clampCvssScore(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return 5.0;
  }
  if (numeric < 0) {
    return 0.0;
  }
  if (numeric > 10) {
    return 10.0;
  }
  return Math.round(numeric * 10) / 10;
}
