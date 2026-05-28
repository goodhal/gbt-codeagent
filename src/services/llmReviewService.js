import pLimit from "p-limit";
import { promises as fs } from "node:fs";
import path from "path";
import { inferFenceLanguage, collectFiles } from "../utils/fileUtils.js";
import { jsonrepair } from "jsonrepair";
import { withRetry, withRetryWithFallback, CircuitBreaker, CircuitBreakerConfig, createReActAuditor } from "../core/index.js";
import { createLocalToolExecutor } from "../tools/localToolExecutor.js";
import { buildReActSystemPrompt, buildReActInitialPrompt } from "../core/reactPrompts.js";
import { streamService } from "./streamService.js";
import { estimateTokens, getModelMaxTokens, PromptCompressor, IncrementalSummary, ContextConfig } from "../utils/contextManager.js";
import { fetchWithTimeout, globalLLMFactory } from "./llmFactory.js";
import { LLMOptimizer } from "./llmOptimizer.js";
import {
  loadAuditKnowledge,
  buildSystemPrompt,
  buildUserPrompt,
  buildToolEnabledUserPrompt,
  getAuditToolDefinitions,
  createEnhancedPrompt,
  createIncrementalAuditPrompt,
  EVIDENCE_REQUIRED_MAP,
  EVIDENCE_CONTRACT_GUIDE
} from "../config/llmPrompts.js";
import OWASP_MAPPING from "../config/owaspMapping.js";

import { callLLM } from "./llmFactory.js";
import { AuditCandidateFilter } from "./auditCandidateFilter.js";
import { AuditFailureTracker, TokenPreChecker, AgentOutputValidator } from "./auditEnhancer.js";

import { loadAuditParams, getMaxBatches, getMaxFilesPerBatch, getMaxCharsPerBatch, getMaxParallelRequests, getFetchTimeoutMs } from "../config/auditParamsConfig.js";
import { smartFileFilter } from "./smartFileFilter.js";

const llmCircuitBreaker = new CircuitBreaker("llm-service", {
  failureThreshold: 3,
  successThreshold: 2,
  recoveryTimeout: 30000
});

const incrementalSummary = new IncrementalSummary();
const llmLimit = pLimit(3);
const promptCompressor = new PromptCompressor();
const llmOptimizer = new LLMOptimizer();
llmOptimizer.initialize().catch(err => console.warn('[LLM审计] 优化器初始化失败:', err.message));

const auditCandidateFilter = new AuditCandidateFilter({ candidateScoreThreshold: 12 });
const auditFailureTracker = new AuditFailureTracker(0.3);
const tokenPreChecker = new TokenPreChecker({ overheadTokens: 512, safetyMargin: 0.85 });
const agentOutputValidator = new AgentOutputValidator();

export class DefensiveLlmReviewer {
  async reviewProject({ project, selectedSkills, heuristicFindings, llmConfig, onProgress, useStreaming = false, taskId }) {
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
    auditFailureTracker.reset();
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

    const projectHash = llmOptimizer.computeProjectHash(files);
    const cachedResult = llmOptimizer.getCachedResults(projectHash, files);

    if (cachedResult?.isCacheHit) {
      console.log(`[LLM优化] 缓存命中，返回 ${cachedResult.cachedFindings.length} 条缓存结果`);
      await llmOptimizer.recordAuditResult(project.id, cachedResult.cachedFindings, true);
      return {
        status: "completed",
        called: true,
        skipReason: "cache-hit",
        summary: `使用缓存结果（${cachedResult.cachedFindings.length}条），无需调用LLM`,
        findings: cachedResult.cachedFindings.map(f => ({ ...f, source: "llm" })),
        warnings: [],
        cached: true
      };
    }

    let filesToAudit = files;
    if (cachedResult?.changedFiles?.length > 0) {
      console.log(`[LLM优化] 检测到 ${cachedResult.changedFiles.length} 个变更文件，进行增量审计`);
      filesToAudit = llmOptimizer.filterUnchangedFiles(files, cachedResult.changedFiles);
      filesToAudit = llmOptimizer.prioritizeFiles(filesToAudit, heuristicFindings);

      const incrementalPrompt = createIncrementalAuditPrompt(cachedResult.changedFiles);
      if (filesToAudit.length === 0) {
        console.log(`[LLM优化] 所有文件未变更，使用缓存结果`);
        return {
          status: "completed",
          called: true,
          skipReason: "incremental-no-changes",
          summary: "所有文件无变更，使用缓存结果",
          findings: cachedResult.cachedFindings.map(f => ({ ...f, source: "llm" })),
          warnings: [],
          cached: true
        };
      }
    } else {
      filesToAudit = llmOptimizer.prioritizeFiles(files, heuristicFindings);
    }

    const tokenBudget = llmOptimizer.calculateTokenBudget(filesToAudit);
    if (tokenBudget.needsCompression) {
      console.log(`[LLM优化] Token超预算，需要压缩 (${tokenBudget.compressionRatio * 100}%)`);
    }

    const prioritizedFiles = rankFiles(filesToAudit, heuristicFindings, selectedSkills);

    if (heuristicFindings && heuristicFindings.length > 0) {
      const filterResult = auditCandidateFilter.filterCandidatesLenient(heuristicFindings);
      if (filterResult.stats.filtered > 0) {
        console.log(`[LLM审计] 候选预筛选: ${filterResult.stats.passed}/${filterResult.stats.totalCandidates} 高分候选送入LLM, ${filterResult.stats.filtered} 低风险跳过`);
        for (const item of filterResult.filtered.slice(0, 3)) {
          console.log(`[LLM审计]   跳过: ${item.title} (评分: ${item._auditScore}, 优先级: ${item._auditPriority})`);
        }
      }
      for (const item of filterResult.passed) {
        if (item._auditPriority === "high" || item._auditPriority === "medium") {
          const idx = prioritizedFiles.findIndex(f => f.relativePath === item.location);
          if (idx >= 0) {
            prioritizedFiles[idx].score += item._auditScore * 2;
          }
        }
      }
      prioritizedFiles.sort((a, b) => (b.score || 0) - (a.score || 0));
    }

    const languages = [...new Set(prioritizedFiles.map(f => f.language).filter(Boolean))];
    const vulnerabilityTypes = [...new Set(heuristicFindings.map(f => f.vulnType).filter(Boolean))];
    const selectedSkillIds = selectedSkills.map(s => s.id);
    const auditKnowledge = await loadAuditKnowledge({ languages, vulnerabilityTypes, selectedSkillIds });
    const systemPrompt = await buildSystemPrompt(selectedSkills, auditKnowledge, languages);
    const enhancedPrompt = createEnhancedPrompt({
      includeContextAnalysis: true,
      includeBusinessLogic: true,
      includeAttackChain: true,
      strictMode: true
    });
    const fullSystemPrompt = systemPrompt + '\n\n' + enhancedPrompt;

    const modelMaxTokens = getModelMaxTokens(llmConfig.model);
    const effectiveMaxTokens = Math.floor(modelMaxTokens * 0.85);
    let finalSystemPrompt = fullSystemPrompt;
    let systemPromptTokens = estimateTokens(fullSystemPrompt);
    const maxSystemBudget = Math.floor(effectiveMaxTokens * 0.65);
    if (systemPromptTokens > maxSystemBudget) {
      console.warn(`[LLM审计] System Prompt 过大 (${systemPromptTokens} tokens)，压缩至 ${maxSystemBudget}`);
      finalSystemPrompt = promptCompressor.truncateToFit(fullSystemPrompt, maxSystemBudget);
      systemPromptTokens = estimateTokens(finalSystemPrompt);
    }
    const userPromptTemplateOverhead = 2500;
    const availableTokensPerBatch = Math.max(4000, effectiveMaxTokens - systemPromptTokens - userPromptTemplateOverhead);
    console.log(`[LLM审计] Token预算 - 模型上限: ${modelMaxTokens}, 有效上限: ${effectiveMaxTokens}, System: ${systemPromptTokens}, 每批可用: ${availableTokensPerBatch}`);

    const batches = buildBatches(prioritizedFiles, availableTokensPerBatch);
    const findings = [];
    const warnings = [];
    let reviewedFiles = 0;
    let reviewedBatches = 0;

    let incrementalPrompt = '';
    if (cachedResult?.changedFiles?.length > 0) {
      incrementalPrompt = createIncrementalAuditPrompt(cachedResult.changedFiles);
    }

    const validBatches = batches.slice(0, getMaxBatches());

    onProgress?.({
      type: "llm-start",
      totalFiles: prioritizedFiles.length,
      totalBatches: validBatches.length,
      reviewedFiles: 0,
      reviewedBatches: 0,
      label: `正在准备 LLM 复核：${project.name}`
    });

    const effectiveMaxParallel = getMaxParallelRequests();
    for (let i = 0; i < validBatches.length; i += effectiveMaxParallel) {
      const batchGroup = validBatches.slice(i, i + effectiveMaxParallel);
      const results = await Promise.all(
        batchGroup.map((batch, idx) => runBatch({
          project, selectedSkills, llmConfig, finalSystemPrompt, sourceRoot, validBatches, warnings, taskId, onProgress,
          batch, batchIndex: i + idx,
          totalFiles: prioritizedFiles.length,
          heuristicFindings,
          incrementalPrompt,
          onComplete: (n) => { reviewedFiles += n; reviewedBatches++; }
        }))
      );

      for (const result of results) {
        if (result.success) {
          findings.push(...result.findings);
        } else {
          warnings.push(result.error);
        }
      }
    }

    const filteredFindings = findings.map(f => {
      const validation = llmOptimizer.validateFinding(f);
      if (!validation.isValid) {
        console.log(`[LLM优化] 发现无效结果: ${f.title}, 问题: ${validation.issues.join(', ')}`);
      }
      return llmOptimizer.enhanceFindingWithContext(f, { projectId: project.id });
    });

    const validFindings = filteredFindings.filter(f => {
      const fp = llmOptimizer.isFalsePositive(f, { filePath: f.location });
      return !fp.isFP;
    });

    const confidenceFiltered = llmOptimizer.filterByConfidence(validFindings, 0.5);
    const dedupedFindings = llmOptimizer.deduplicateFindings(confidenceFiltered);
    const rankedFindings = llmOptimizer.rankFindings(dedupedFindings);
    const truncated = prioritizedFiles.length > validBatches.flat().length;

    llmOptimizer.cacheResults(projectHash, files, rankedFindings);
    await llmOptimizer.recordAuditResult(project.id, rankedFindings, true);

    const optimizationReport = llmOptimizer.generateAuditReport({
      cachedFindings: cachedResult?.cachedFindings?.length || 0,
      changedFiles: cachedResult?.changedFiles || [],
      findings: rankedFindings
    });

    const incompleteReport = auditFailureTracker.isAboveThreshold() ? auditFailureTracker.buildIncompleteReport() : null;

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
      summary: incompleteReport
        ? `${buildSummary({ reviewedFiles, reviewedBatches, findings: rankedFindings, truncated })} [警告: ${incompleteReport.message}]`
        : buildSummary({ reviewedFiles, reviewedBatches, findings: rankedFindings, truncated }),
      warnings: [...warnings, ...(incompleteReport ? [incompleteReport.message] : [])],
      findings: rankedFindings.map((finding) => ({ ...finding, source: "llm" })),
      optimizerReport: optimizationReport,
      failureTracker: incompleteReport,
      failureStats: auditFailureTracker.getStats()
    };
  }

  async auditProject({ project, selectedSkills, llmConfig, codeGraphContext, codeGraph, routeTable = null, onProgress, useStreaming = false, taskId }) {
    console.log(`[LLM审计] auditProject 开始 - 项目: ${project.name}, 提供商: ${llmConfig.providerId}, 模型: ${llmConfig.model}`);
    console.log(`[LLM审计] 代码知识图谱上下文: ${codeGraphContext ? '已提供' : '未提供'}`);
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
    auditFailureTracker.reset();
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

    // 对于独立审计，我们处理所有文件，而不仅仅是排名靠前的文件
    const languages = [...new Set(files.map(f => f.language).filter(Boolean))];
    const auditKnowledge = await loadAuditKnowledge({ languages, vulnerabilityTypes: [], selectedSkillIds: selectedSkills.map(s => s.id) });
    const systemPrompt = await buildSystemPrompt(selectedSkills, auditKnowledge, languages);

    const modelMaxTokens = getModelMaxTokens(llmConfig.model);
    const effectiveMaxTokens = Math.floor(modelMaxTokens * 0.85);
    let finalSystemPrompt = systemPrompt;
    let systemPromptTokens = estimateTokens(systemPrompt);
    const maxSystemBudget = Math.floor(effectiveMaxTokens * 0.65);
    if (systemPromptTokens > maxSystemBudget) {
      console.warn(`[LLM审计] System Prompt 过大 (${systemPromptTokens} tokens)，压缩至 ${maxSystemBudget}`);
      finalSystemPrompt = promptCompressor.truncateToFit(systemPrompt, maxSystemBudget);
      systemPromptTokens = estimateTokens(finalSystemPrompt);
    }
    const userPromptTemplateOverhead = 2500;
    const availableTokensPerBatch = Math.max(4000, effectiveMaxTokens - systemPromptTokens - userPromptTemplateOverhead);
    console.log(`[LLM审计] Token预算 - 模型上限: ${modelMaxTokens}, 有效上限: ${effectiveMaxTokens}, System: ${systemPromptTokens}, 每批可用: ${availableTokensPerBatch}`);

    const batches = buildBatches(files, availableTokensPerBatch);
    const findings = [];
    const warnings = [];
    let auditedFiles = 0;
    let auditedBatches = 0;

    const validBatches = batches.slice(0, getMaxBatches());

    onProgress?.({
      type: "llm-start",
      totalFiles: files.length,
      totalBatches: validBatches.length,
      auditedFiles: 0,
      auditedBatches: 0,
      label: `正在准备 LLM 审计：${project.name}`
    });

    let routeChecklist = "";
    if (routeTable?.routes?.length > 0) {
      const routeSummary = routeTable.routes.slice(0, 50).map(r =>
        `  ${r.httpMethod || 'ANY'} ${r.urlPath || r.route} → ${r.entryFile || r.file}:${r.entryMethod || ''}`
      ).join('\n');
      routeChecklist = `\n\n【项目路由清单 — 全部入口点（共${routeTable.count}个）】\n${routeSummary}\n\n**审计要求：必须确保上述每个路由的以下方面都被检查过：**\n1. 认证鉴权（是否 @PreAuthorize / 拦截器覆盖 / 匿名可访问）\n2. 输入参数是否进入危险sink（SQL/命令/文件/反序列化/模板）\n3. 是否存在越权风险（查询其他用户数据而不校验所有者）`;
    }

    const effectiveMaxParallel = getMaxParallelRequests();
    for (let i = 0; i < validBatches.length; i += effectiveMaxParallel) {
      const batchGroup = validBatches.slice(i, i + effectiveMaxParallel);
      const results = await Promise.all(
        batchGroup.map((batch, idx) => runBatch({
          project, selectedSkills, llmConfig, finalSystemPrompt, sourceRoot, validBatches, warnings, taskId, onProgress,
          batch, batchIndex: i + idx,
          counterName: "审计",
          totalFiles: files.length,
          heuristicFindings: [],
          routeChecklist,
          onComplete: (n) => { auditedFiles += n; auditedBatches++; }
        }))
      );

      for (const result of results) {
        if (result.success) {
          findings.push(...result.findings);
        } else {
          warnings.push(result.error);
        }
      }
    }

    // 验证管线（与 reviewProject 保持一致）：逐条校验 + 误报检测 + 置信度过滤
    const filteredFindings = findings.map(f => {
      const validation = llmOptimizer.validateFinding(f);
      if (!validation.isValid) {
        console.log(`[LLM优化] 发现无效结果: ${f.title}, 问题: ${validation.issues.join(', ')}`);
      }
      return llmOptimizer.enhanceFindingWithContext(f, { projectId: project.id });
    });

    const dedupedFindingsNoFP = filteredFindings.filter(f => {
      const fp = llmOptimizer.isFalsePositive(f, { filePath: f.location });
      return !fp.isFP;
    });

    const confidenceFiltered = llmOptimizer.filterByConfidence(dedupedFindingsNoFP, 0.5);

    const dedupedFindings = llmOptimizer.deduplicateFindings(confidenceFiltered);
    const rankedFindings = llmOptimizer.rankFindings(dedupedFindings);
    const truncated = files.length > validBatches.flat().length;

    const projectHash = llmOptimizer.computeProjectHash(files);
    llmOptimizer.cacheResults(projectHash, files, rankedFindings);
    await llmOptimizer.recordAuditResult(project.id, rankedFindings, true);

    console.log(`[LLM审计] auditProject 完成 - 审计文件数: ${auditedFiles}, 审计批次: ${auditedBatches}, 发现问题数: ${rankedFindings.length}, 警告数: ${warnings.length}`);

    const incompleteReport = auditFailureTracker.isAboveThreshold() ? auditFailureTracker.buildIncompleteReport() : null;

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
      summary: incompleteReport
        ? `${buildSummary({ reviewedFiles: auditedFiles, reviewedBatches: auditedBatches, findings: rankedFindings, truncated })} [警告: ${incompleteReport.message}]`
        : buildSummary({ reviewedFiles: auditedFiles, reviewedBatches: auditedBatches, findings: rankedFindings, truncated }),
      warnings: [...warnings, ...(incompleteReport ? [incompleteReport.message] : [])],
      findings: rankedFindings.map((finding) => ({ ...finding, source: "llm" })),
      failureTracker: incompleteReport,
      failureStats: auditFailureTracker.getStats()
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
      maxSteps: reactConfig.maxSteps || 30,
      temperature: reactConfig.temperature || 0.1,
      maxRetries: reactConfig.maxRetries || 3,
      verbose: reactConfig.verbose || false
    };

    const auditor = createReActAuditor(adapter, toolExecutor, auditorConfig);
    auditFailureTracker.reset();

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

      const systemPrompt = await buildReActSystemPrompt();
      const initialPrompt = buildReActInitialPrompt(codeDiff, projectInfo);
      const tokenCheck = tokenPreChecker.checkPrompts(systemPrompt, initialPrompt, llmConfig.model);
      if (!tokenCheck.ok) {
        console.warn(`[ReAct审计] Token预检失败，跳过审计: ${tokenCheck.error}`);
        return {
          status: "skipped",
          called: false,
          skipReason: "token-overflow",
          summary: `ReAct 审计超出 Token 限制 (${tokenCheck.usagePercent}%)，跳过本轮。`,
          findings: [],
          warnings: [`Token预检失败: ${tokenCheck.error}`],
          reactResult: null
        };
      }
      console.log(`[ReAct审计] Token预检通过 - 总计: ${tokenCheck.currentTokens}, 上限: ${tokenCheck.maxTokens} (${tokenCheck.usagePercent}%)`);

      onProgress?.({
        type: "react-start",
        projectName: project.name,
        totalFiles: files.length,
        label: `正在启动 ReAct 推理审计：${project.name}`
      });

      const reactResult = await auditor.audit({
        systemPrompt,
        initialPrompt,
        projectInfo
      });

      auditFailureTracker.recordSuccess();

      const rawFindings = reactResult.issues.map(issue => ({
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

      const validationResult = agentOutputValidator.validateFindings(rawFindings);
      if (validationResult.totalInvalid > 0) {
        console.warn(`[ReAct审计] 输出校验: ${validationResult.totalValid}/${validationResult.totalIn} 有效, ${validationResult.totalInvalid} 无效`);
      }
      const findings = validationResult.valid;

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
        reactResult: reactResult.toJSON(),
        failureStats: auditFailureTracker.getStats()
      };
    } catch (error) {
      console.error(`[ReAct审计] auditWithReAct 错误:`, error.message);
      auditFailureTracker.recordFailure(error.message);
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

const withReviewRetry = async (fn) => {
  return await withRetry(fn, {
    maxAttempts: 2,
    baseDelay: 1000,
    onRetry: (error, attempt, max) => {
      console.warn(`[LLM审计] 请求重试 ${attempt}/${max}: ${error.message}`);
    }
  });
};

function sanitizeContent(str) {
  if (!str || typeof str !== 'string') return str;
  return str
    .replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/g, '\uFFFD')
    .replace(/(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD')
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
}

const MAX_TOOL_ROUNDS = 12;

const _toolExecutors = new Map();
function getToolExecutor(sourceRoot) {
  let executor = _toolExecutors.get(sourceRoot);
  if (!executor) {
    executor = createLocalToolExecutor(sourceRoot);
    _toolExecutors.set(sourceRoot, executor);
  }
  return executor;
}

async function executeToolCall(toolCall, sourceRoot, batchFindings = null) {
  const fn = toolCall.function;
  const name = fn.name;
  let args;
  try { args = JSON.parse(fn.arguments || '{}'); } catch (_) { args = {}; }
  
  console.log(`[LLM工具] ${name}(${JSON.stringify(args).slice(0, 120)})`);
  
  const maxRetries = 1;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const executor = getToolExecutor(sourceRoot);
      let result;
      if (name === 'read_file') {
        result = await executor.executeFileContent({ file_path: args.file_path });
      } else if (name === 'search_code') {
        let fileType = args.file_pattern;
        if (fileType && fileType.startsWith('*.')) fileType = fileType.slice(2);
        result = await executor.executeSearchCode({ query: args.query, file_type: fileType });
      } else if (name === 'list_files') {
        result = await executor.executeProjectStructure({});
      } else if (name === 'write_finding') {
        const finding = {
          title: args.title,
          severity: args.severity || 'medium',
          location: args.location,
          vulnType: args.vulnType,
          cwe: args.cwe || '',
          evidence: args.evidence,
          impact: args.impact || '',
          remediation: args.remediation || '',
          safeValidation: args.safeValidation || '',
          confidence: 0.9,
          skillId: 'gbt-code-audit',
          source: 'llm',
        };
        if (batchFindings) {
          batchFindings.push(finding);
          console.log(`[LLM工具] write_finding 已记录：${args.title?.slice(0,60)} (累计${batchFindings.length}个)`);
        }
        result = { recorded: true, count: batchFindings ? batchFindings.length : 0 };
      } else {
        result = { error: `Unknown tool: ${name}` };
      }
      const summary = typeof result === 'string' ? result.slice(0, 200) : JSON.stringify(result).slice(0, 200);
      console.log(`[LLM工具] ${name} 结果: ${summary}...`);
      return typeof result === 'string' ? result : JSON.stringify(result);
    } catch (e) {
      if (attempt < maxRetries) {
        console.warn(`[LLM工具] ${name} 执行失败(${attempt + 1}/${maxRetries + 1}): ${e.message}，重试...`);
        await new Promise(r => setTimeout(r, 500));
      } else {
        console.error(`[LLM工具] ${name} 执行失败(${maxRetries + 1}次): ${e.message}`);
        return JSON.stringify({ error: e.message });
      }
    }
  }
}

async function requestWithTools({ llmConfig, messages, tools }) {
  const model = llmConfig.model || 'gpt-3.5-turbo';
  const clean = (s) => sanitizeContent(typeof s === 'string' ? s : JSON.stringify(s));

  console.log(`[LLM审计] 工具模式请求 - 模型: ${model}, 消息数: ${messages.length}`);
  
  const body = {
    model,
    temperature: 0,
    max_tokens: 4096,
    messages: messages.map(m => {
      const msg = { role: m.role, content: m.content ? clean(m.content) : null };
      if (m.tool_calls) msg.tool_calls = m.tool_calls;
      if (m.tool_call_id) msg.tool_call_id = m.tool_call_id;
      if (m.name) msg.name = m.name;
      if (m.reasoning_content) msg.reasoning_content = m.reasoning_content;
      return msg;
    }),
    tools,
    tool_choice: "auto"
  };

  const response = await fetchWithTimeout(
    `${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${llmConfig.apiKey}`
      },
      body: JSON.stringify(body)
    }
  );

  if (!response.ok) {
    let errorBody = '';
    try { errorBody = await response.text(); } catch (_) {}
    console.error(`[LLM审计] 工具模式请求失败 - 状态码: ${response.status}`, errorBody.slice(0, 500));
    throw new Error(`LLM 复核失败：模型端点返回 ${response.status}`);
  }

  const data = await response.json();
  const choice = data.choices?.[0];
  const message = choice?.message || {};
  return {
    content: message.content || '',
    toolCalls: message.tool_calls || [],
    finishReason: choice?.finish_reason || '',
    reasoningContent: message.reasoning_content || ''
  };
}

async function runToolEnabledAudit({ llmConfig, systemPrompt, userPrompt, sourceRoot, findingsAccumulator }) {
  const tools = getAuditToolDefinitions();
  const messages = [
    { role: "system", content: sanitizeContent(systemPrompt) },
    { role: "user", content: sanitizeContent(userPrompt) }
  ];

  let allContent = '';
  const startTime = Date.now();
  const batchFindings = []; // write_finding 工具写入的发现

  for (let round = 0; round < MAX_TOOL_ROUNDS; round++) {
    const result = await withReviewRetry(() => 
      llmCircuitBreaker.callWithFallback(
        () => requestWithTools({ llmConfig, messages, tools }),
        () => { throw new Error('LLM服务熔断'); }
      )
    );

    if (result.toolCalls && result.toolCalls.length > 0) {
      messages.push({
        role: "assistant",
        content: result.content || null,
        tool_calls: result.toolCalls,
        ...(result.reasoningContent ? { reasoning_content: result.reasoningContent } : {})
      });

      for (const tc of result.toolCalls) {
        const toolResult = await executeToolCall(tc, sourceRoot, batchFindings);
        messages.push({
          role: "tool",
          tool_call_id: tc.id,
          content: toolResult
        });
      }

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`[LLM工具] 第 ${round + 1} 轮完成，${result.toolCalls.length} 个工具调用，已用时 ${elapsed}s`);
    } else {
      const content = result.content || '';
      allContent = content;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`[LLM工具] 第 ${round + 1} 轮无工具调用，审计完成，总用时 ${elapsed}s`);
      break;
    }
  }

  // 合并 write_finding 工具产生的发现
  if (findingsAccumulator && batchFindings.length > 0) {
    findingsAccumulator.push(...batchFindings);
  }

  return { content: allContent, findings: batchFindings };
}

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

  optimizedSystem = sanitizeContent(optimizedSystem);
  optimizedUser = sanitizeContent(optimizedUser);

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
          temperature: 0,
          system: optimizedSystem,
          messages: [{ role: "user", content: optimizedUser }]
        })
      });
    } catch (fetchError) {
      if (fetchError.name === 'AbortError') {
        console.error(`[LLM审计] Anthropic API请求超时`);
        throw new Error(`LLM 复核超时：Anthropic 请求在 ${getFetchTimeoutMs() / 1000} 秒内未返回`);
      }
      console.error(`[LLM审计] Anthropic API请求异常:`, fetchError.message);
      throw fetchError;
    }

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      console.error(`[LLM审计] Anthropic API请求失败 - 状态码: ${response.status}`, errBody.slice(0, 300));
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
              temperature: 0,
              maxOutputTokens: 4096
            }
          })
        }
      );
    } catch (fetchError) {
      if (fetchError.name === 'AbortError') {
        console.error(`[LLM审计] Gemini API请求超时`);
        throw new Error(`LLM 复核超时：Gemini 请求在 ${getFetchTimeoutMs() / 1000} 秒内未返回`);
      }
      console.error(`[LLM审计] Gemini API请求异常:`, fetchError.message);
      throw fetchError;
    }

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      console.error(`[LLM审计] Gemini API请求失败 - 状态码: ${response.status}`, errBody.slice(0, 300));
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
        temperature: 0,
        max_tokens: 4096,
        messages: [
          { role: "system", content: optimizedSystem },
          { role: "user", content: optimizedUser }
        ]
      })
    });
  } catch (fetchError) {
    if (fetchError.name === 'AbortError') {
      console.error(`[LLM审计] API请求超时 - 超时时间: ${getFetchTimeoutMs()}ms`);
      throw new Error(`LLM 复核超时：请求在 ${getFetchTimeoutMs() / 1000} 秒内未返回`);
    }
    console.error(`[LLM审计] API请求异常:`, fetchError.message);
    throw fetchError;
  }

  if (!response.ok) {
    let errorBody = '';
    try { errorBody = await response.text(); } catch (_) {}
    console.error(`[LLM审计] API请求失败 - 状态码: ${response.status}`, errorBody ? `| 响应: ${errorBody.slice(0, 500)}` : '');
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

async function requestStructuredReviewStream({ llmConfig, systemPrompt, userPrompt, onToken, batchIndex, totalBatches, taskId }) {
  const compatibility = llmConfig.compatibility || llmConfig.defaults?.compatibility || "openai";
  const model = llmConfig.model || 'gpt-3.5-turbo';
  const maxTokens = getModelMaxTokens(model);

  let optimizedSystem = systemPrompt;
  let optimizedUser = userPrompt;
  const systemTokens = estimateTokens(systemPrompt);
  const userTokens = estimateTokens(userPrompt);
  const totalTokens = systemTokens + userTokens;

  if (totalTokens > maxTokens * ContextConfig.SAFETY_MARGIN) {
    const availableTokens = Math.floor(maxTokens * ContextConfig.SAFETY_MARGIN) - systemTokens - 100;
    if (availableTokens > 0) {
      optimizedUser = promptCompressor.truncateToFit(userPrompt, availableTokens);
    }
  }

  optimizedSystem = sanitizeContent(optimizedSystem);
  optimizedUser = sanitizeContent(optimizedUser);

  let fullText = '';

  const emitToken = (token) => {
    if (token) {
      fullText += token;
      streamService.emitLLMStreamToken(token, batchIndex, totalBatches, taskId);
      if (onToken) onToken(token);
    }
  };

  if (compatibility === "anthropic") {
    const response = await fetchWithTimeout(`${stripTrailingSlash(llmConfig.baseUrl)}/v1/messages`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": llmConfig.apiKey,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: llmConfig.model,
        max_tokens: 4096,
        temperature: 0,
        stream: true,
        system: optimizedSystem,
        messages: [{ role: "user", content: optimizedUser }]
      })
    });

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      console.error(`[LLM审计] 流式Anthropic API请求失败 - 状态码: ${response.status}`, errBody.slice(0, 300));
      throw new Error(`LLM 复核失败：Anthropic 返回 ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data: ')) continue;
        try {
          const evt = JSON.parse(trimmed.slice(6));
          if (evt.type === 'content_block_delta') {
            emitToken(evt.delta?.text || '');
          }
        } catch (e) { /* skip */ }
      }
    }

    streamService.emitLLMComplete({ model, provider: llmConfig.providerId }, taskId);
    return fullText;
  }

  if (compatibility === "gemini") {
    const response = await fetchWithTimeout(
      `${stripTrailingSlash(llmConfig.baseUrl)}/v1beta/models/${encodeURIComponent(llmConfig.model)}:streamGenerateContent?alt=sse&key=${encodeURIComponent(llmConfig.apiKey)}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: optimizedSystem }] },
          contents: [{ role: "user", parts: [{ text: optimizedUser }] }],
          generationConfig: { temperature: 0, maxOutputTokens: 4096 }
        })
      }
    );

    if (!response.ok) {
      const errBody = await response.text().catch(() => '');
      console.error(`[LLM审计] 流式Gemini API请求失败 - 状态码: ${response.status}`, errBody.slice(0, 300));
      throw new Error(`LLM 复核失败：Gemini 返回 ${response.status}`);
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop() || '';
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('data: ')) continue;
        try {
          const parsed = JSON.parse(trimmed.slice(6));
          const text = parsed.candidates?.[0]?.content?.parts?.map(p => p.text || "").join("") || "";
          if (text) emitToken(text);
        } catch (e) { /* skip */ }
      }
    }

    streamService.emitLLMComplete({ model, provider: llmConfig.providerId }, taskId);
    return fullText;
  }

  const response = await fetchWithTimeout(`${stripTrailingSlash(llmConfig.baseUrl)}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${llmConfig.apiKey}`
    },
    body: JSON.stringify({
      model: llmConfig.model,
      temperature: 0,
      max_tokens: 4096,
      stream: true,
      messages: [
        { role: "system", content: optimizedSystem },
        { role: "user", content: optimizedUser }
      ]
    })
  });

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    console.error(`[LLM审计] 流式API请求失败 - 状态码: ${response.status}`, errBody.slice(0, 300));
    throw new Error(`LLM 复核失败：模型端点返回 ${response.status}`);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop() || '';
    for (const line of lines) {
      if (line.startsWith('data: ')) {
        const data = line.slice(6);
        if (data === '[DONE]') continue;
        try {
          const parsed = JSON.parse(data);
          emitToken(parsed.choices?.[0]?.delta?.content || '');
        } catch (e) { /* skip */ }
      }
    }
  }

  streamService.emitLLMComplete({ model, provider: llmConfig.providerId }, taskId);
  return fullText;
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
  const pendingDirs = [];
  const pendingFiles = [];

  for (const entry of entries) {
    const target = path.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      pendingDirs.push(target);
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    const language = inferFenceLanguage(target);
    if (!language) {
      continue;
    }
    pendingFiles.push({ target, language });
  }

  const fileReads = pendingFiles.map(async ({ target, language }) => {
    const rawContent = await fs.readFile(target, "utf8");
    const relativePath = path.relative(root, target).replaceAll("\\", "/");

    if (rawContent.length > 15000) {
      try {
        const { CodeSplitter } = await import("./splitter.js");
        const splitter = new CodeSplitter({ maxChunkSize: 8000, overlap: 200 });
        const chunks = splitter.splitFileSemantic(rawContent, relativePath, language, 8000);
        for (const chunk of chunks) {
          output.push({
            fullPath: target,
            relativePath: relativePath,
            content: chunk.content,
            language,
            lineStart: chunk.lineStart,
            lineEnd: chunk.lineEnd,
            chunkLabel: `${relativePath}#L${chunk.lineStart}-L${chunk.lineEnd}`,
            _semanticChunk: true
          });
        }
      } catch {
        output.push({ fullPath: target, relativePath, content: rawContent, language });
      }
    } else {
      output.push({ fullPath: target, relativePath, content: rawContent, language });
    }
  });

  await Promise.all(fileReads);

  for (const dir of pendingDirs) {
    await walk(root, dir, output);
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
      // controller/config/util/Security 文件强制优先审查（即使无快扫命中），解决覆盖率不足问题
      if (/(\/controller\/|\/config\/|\/util\/|security|auth|login|admin)/i.test(file.relativePath)) {
        score += 200; // 确保排名最前，必定进入批次
      } else if (/(auth|permission|policy|access|role|upload|secret|query|service)/.test(loweredPath)) {
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

function buildBatches(files, availableTokensPerBatch = Infinity) {
  // 按优先级排序：T1(controller/filter) > T2(service/util) > T3(entity/dto)
  // 同Tier内按风险评分降序，确保高信号文件始终在前几批
  const sorted = [...files].sort((a, b) => {
    const pathA = a.relativePath || a.fullPath || '';
    const pathB = b.relativePath || b.fullPath || '';
    const tierOrder = { T1: 0, T2: 1, T3: 2 };
    const tierA = tierOrder[smartFileFilter.getTier(pathA)] ?? 1;
    const tierB = tierOrder[smartFileFilter.getTier(pathB)] ?? 1;
    if (tierA !== tierB) return tierA - tierB;
    // 同Tier：文件短（精准）的优先
    return (a.content?.length || 0) - (b.content?.length || 0);
  });

  const batches = [];
  let currentBatch = [];
  let currentTokens = 0;
  const maxFiles = getMaxFilesPerBatch();
  const maxChars = Math.min(getMaxCharsPerBatch(), availableTokensPerBatch * 4);
  let currentChars = 0;

  for (const file of sorted) {
    const fileTokens = estimateTokens(file.content) + 10;
    const fileChars = file.content.length + file.relativePath.length;

    const wouldExceed = currentBatch.length >= maxFiles
      || currentTokens + fileTokens > availableTokensPerBatch
      || currentChars + fileChars > maxChars;

    if (currentBatch.length && wouldExceed) {
      batches.push(currentBatch);
      currentBatch = [];
      currentTokens = 0;
      currentChars = 0;
    }

    currentBatch.push(file);
    currentTokens += fileTokens;
    currentChars += fileChars;
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
    const count = parsed?.findings?.length || 0;
    console.log(`[LLM 审计] jsonrepair 修复成功，findings 数量：${count}`);
    if (count > 0) return parsed;
    // 修复成功但 findings 为空 → 尝试文本提取兜底
    console.log('[LLM 审计] jsonrepair 返回空 findings，尝试文本提取兜底');
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
      const count = parsed?.findings?.length || 0;
      console.log(`[LLM 审计] 平衡 JSON 修复成功，findings 数量：${count}`);
      if (count > 0) return parsed;
      console.log('[LLM 审计] 平衡 JSON 返回空 findings，尝试文本提取兜底');
    }
  } catch (e) {
    console.log(`[LLM 审计] 平衡 JSON 修复失败：${e.message}`);
  }
  
  // JSON 解析无效或空 findings → 从 markdown 文本中正则提取
  console.log('[LLM 审计] 尝试从 markdown 文本提取发现');
  const textFindings = extractFindingsFromText(trimmed);
  if (textFindings.length > 0) {
    console.log(`[LLM 审计] 文本提取成功，提取到 ${textFindings.length} 个发现（低置信度）`);
    return { findings: textFindings };
  }
  console.log('[LLM 审计] 未能提取任何发现，返回空 findings 数组');
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

/**
 * 从 markdown 文本中正则提取漏洞发现（JSON 解析失败时的降级方案）
 * 匹配常见的 LLM 输出模式：
 * - | 文件名 | 端点 | 问题描述 |  (表格行)
 * - **漏洞类型** in 文件名: 描述  (加粗标记)
 * - N. 漏洞类型 — 文件名: 描述   (编号列表)
 */
function extractFindingsFromText(text) {
  const findings = [];
  const lines = text.split('\n');

  // 模式 1: 匹配 markdown 表格行 | 文件 | 端点 | 问题 |
  let inTable = false;
  let tableHeaders = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
      const cells = trimmed.split('|').filter(c => c.trim()).map(c => c.trim());
      if (!inTable) {
        // 检测表头行：包含"文件""端点""问题"等关键词
        const headerText = cells.join(' ').toLowerCase();
        if (headerText.includes('文件') || headerText.includes('端点') || headerText.includes('问题') || headerText.includes('漏洞') || headerText.includes('发现')) {
          tableHeaders = cells;
          inTable = true;
        }
        continue;
      }
      // 跳过分隔行 (---|---|---)
      if (cells.length > 0 && cells[0].includes('---')) continue;
      
      // 提取文件名和问题描述
      if (cells.length >= 2) {
        const fileCell = cells[0];
        const descCell = cells[cells.length - 1];
        if (descCell.toLowerCase().includes('漏洞') || descCell.toLowerCase().includes('注入') || descCell.toLowerCase().includes('绕过') || descCell.toLowerCase().includes('泄露') || descCell.toLowerCase().includes('风险') || descCell.toLowerCase().includes('越权') || descCell.toLowerCase().includes('遍历') || descCell.toLowerCase().includes('注入')) {
          const title = descCell.length > 120 ? descCell.slice(0, 120) + '...' : descCell;
          findings.push({
            title,
            severity: 'medium',
            confidence: 0.55,
            location: fileCell.includes('.') ? fileCell : (fileCell + ':?'),
            skillId: 'gbt-code-audit',
            evidence: descCell,
            description: descCell,
            source: 'llm',
          });
        }
      }
      continue;
    }
    inTable = false;
  }

  // 模式 2: 匹配带文件名和漏洞关键词的文本行（如 "ProcessBuilder.java: 命令注入漏洞"）
  if (findings.length === 0) {
    const filePattern = /[a-zA-Z_][a-zA-Z0-9_]*\.(java|py|js|ts|php|rb|cpp|c|cs|go|rs)['":\s]+([^。\n]{10,})/gi;
    let match;
    while ((match = filePattern.exec(text)) !== null) {
      const filePath = match[1] ? match[0].split(match[1])[0] + match[1] : match[0].split(/['":\s]+/)[0];
      const desc = match[2].trim();
      if (/(漏洞|注入|绕过|泄露|遍历|越权|篡改|伪造|命令执行|RCE|XSS|SSRF|SQL|DESERIALIZATION)/i.test(desc) && desc.length > 10) {
        const title = desc.length > 120 ? desc.slice(0, 120) + '...' : desc;
        findings.push({
          title,
          severity: 'medium',
          confidence: 0.55,
          location: filePath.includes(':') ? filePath : (filePath + ':?'),
          skillId: 'gbt-code-audit',
          evidence: desc,
          description: desc,
          source: 'llm',
        });
      }
    }
  }

  // 去重
  const seen = new Set();
  return findings.filter(f => {
    const key = f.location + '|' + f.title.slice(0, 30);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
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
        safeValidation: safeString(finding.safeValidation, "建议在本地或测试环境里补充代码走读与单元测试来确认边界。"),
        // 新增字段（可选，LLM 不保证一定输出）
        evidenceLabel: finding.evidenceLabel || null,
        attackVector: safeString(finding.attackVector || finding.attack_vector, ""),
        exploitPrerequisites: safeString(finding.exploitPrerequisites || finding.exploit_prerequisites, ""),
        retestChecklist: finding.retestChecklist || finding.retest_checklist || null,
        attackPathPriority: finding.attackPathPriority || finding.attack_path_priority || null,
        attackPathScore: finding.attackPathScore || finding.attack_path_score || null,
        killSwitchInfo: safeString(finding.killSwitchInfo || finding.kill_switch_info, ""),
        description: safeString(finding.description || finding.desc, ""),
        type: safeString(finding.type || finding.root_cause, ""),
        hedgedLanguage: finding.hedged_language !== undefined ? !!finding.hedged_language : (finding.hedgedLanguage !== undefined ? !!finding.hedgedLanguage : null),
      };

      if (isGbtAudit && finding.skillId === "gbt-code-audit") {
        normalized.vulnType = safeString(finding.vulnType, "UNKNOWN");
        normalized.cwe = safeString(finding.cwe, "CWE-000");
        normalized.gbtMapping = safeString(finding.gbtMapping, "GB/T39412-2020 通用基线");
        normalized.cvssScore = clampCvssScore(finding.cvssScore);
        normalized.language = safeString(finding.language, "unknown");
        
        // 添加 OWASP 字段
        const vulnType = normalized.vulnType;
        const owaspIds = OWASP_MAPPING[vulnType] || [];
        normalized.owaspIds = owaspIds;
        normalized.owasp = owaspIds.join(", ");
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

/**
 * 单文件审计（Token 预检失败时的降级路径）
 * 确保每个文件都能被审计，不因 token 限制而丢失
 */
async function processSingleFile({ llmConfig, systemPrompt, userPrompt, sourceRoot, file, batchHeuristicFindings, incPrompt, routeChecklist, project, selectedSkills }) {
  try {
    const toolFindings = [];
    const result = await withReviewRetry(() =>
      llmCircuitBreaker.callWithFallback(
        () => runToolEnabledAudit({ llmConfig, systemPrompt, userPrompt, sourceRoot, findingsAccumulator: toolFindings }),
        () => { throw new Error('LLM服务熔断'); }
      )
    );
    const parsed = parseJsonResponse(result.content || '');
    const rawFindings = [...(toolFindings || []), ...(parsed?.findings || [])];
    console.log(`[LLM审计] 单文件 ${file.relativePath} 审计完成，发现 ${rawFindings.length} 个`);
    return { success: true, findings: rawFindings };
  } catch (error) {
    console.warn(`[LLM审计] 单文件 ${file.relativePath} 审计失败 (${error.message})，回退嵌入模式`);
    try {
      const fallbackPrompt = buildUserPrompt({ project, selectedSkills, heuristicFindings: batchHeuristicFindings, batch: [file], incrementalPrompt: incPrompt }) + routeChecklist;
      const responseText = await withReviewRetry(() =>
        requestStructuredReview({ llmConfig, systemPrompt, userPrompt: fallbackPrompt })
      );
      const parsed = parseJsonResponse(responseText);
      return { success: true, findings: parsed?.findings || [] };
    } catch (e2) {
      console.error(`[LLM审计] 单文件 ${file.relativePath} 彻底失败: ${e2.message}`);
      return { success: false, findings: [], error: e2.message };
    }
  }
}

async function runBatch({ project, selectedSkills, llmConfig, finalSystemPrompt, sourceRoot, validBatches, warnings, taskId, onProgress, batch, batchIndex, counterName = "复核", totalFiles, heuristicFindings: hf, incrementalPrompt: incPrompt = "", routeChecklist = "", onComplete }) {
  onProgress?.({
    type: "llm-batch",
    currentBatch: batchIndex + 1,
    totalBatches: validBatches.length,
    batchSize: batch.length,
    totalFiles,
    label: `正在${counterName}：第 ${batchIndex + 1} / ${validBatches.length} 批`
  });

  try {
    const batchFiles = batch.map(f => f.relativePath);
    const batchHeuristicFindings = (hf || []).filter(f => {
      if (!f.location && !f.file) return false;
      const loc = (f.location || f.file || '').split(':')[0];
      return batchFiles.some(bf => loc.includes(bf) || bf.includes(loc));
    }).sort((a, b) => {
      const severityOrder = { 'critical': 0, 'high': 1, 'medium': 2, 'low': 3, '严重': 0, '高危': 1, '中危': 2, '低危': 3 };
      return (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    });
    const userPrompt = buildToolEnabledUserPrompt({ project, batch, heuristicFindings: batchHeuristicFindings, incrementalPrompt: incPrompt }) + routeChecklist;
    const tokenCheck = tokenPreChecker.checkPrompts(finalSystemPrompt, userPrompt, llmConfig.model);
    if (!tokenCheck.ok) {
      // Token 预检失败 → 降级为逐文件审计，绝不跳过文件
      console.warn(`[LLM审计] Token预检失败(${tokenCheck.usagePercent}%)，降级为逐文件审计`);
      warnings.push(`批次 ${batchIndex + 1} Token超限，自动拆分为逐文件审计 (${tokenCheck.usagePercent}%)`);
      const allFindings = [];
      for (const singleFile of batch) {
        const singleBatch = [singleFile];
        const singlePrompt = buildToolEnabledUserPrompt({ project, batch: singleBatch, heuristicFindings: batchHeuristicFindings, incrementalPrompt: incPrompt }) + routeChecklist;
        const singleCheck = tokenPreChecker.checkPrompts(finalSystemPrompt, singlePrompt, llmConfig.model);
        if (!singleCheck.ok) {
          // 单文件仍超限 → 截断文件内容后重试
          console.warn(`[LLM审计] 单文件Token预检失败(${singleCheck.usagePercent}%)，截断文件内容`);
          try {
            const truncated = singleFile.content.slice(0, Math.floor(singleFile.content.length * 0.5));
            const shortBatch = [{ ...singleFile, content: truncated }];
            const shortPrompt = buildToolEnabledUserPrompt({ project, batch: shortBatch, heuristicFindings: batchHeuristicFindings, incrementalPrompt: incPrompt }) + routeChecklist;
            const shortCheck = tokenPreChecker.checkPrompts(finalSystemPrompt, shortPrompt, llmConfig.model);
            if (!shortCheck.ok) {
              warnings.push(`文件 ${singleFile.relativePath} Token超限，已跳过`);
              continue;
            }
            const shortResult = await processSingleFile({ llmConfig, systemPrompt: finalSystemPrompt, userPrompt: shortPrompt, sourceRoot, file: singleFile, batchHeuristicFindings, incPrompt, routeChecklist, project, selectedSkills });
            if (shortResult.success) allFindings.push(...shortResult.findings);
          } catch (e) { warnings.push(`文件 ${singleFile.relativePath} 审计失败: ${e.message}`); }
        } else {
          try {
            const singleResult = await processSingleFile({ llmConfig, systemPrompt: finalSystemPrompt, userPrompt: singlePrompt, sourceRoot, file: singleFile, batchHeuristicFindings, incPrompt, routeChecklist, project, selectedSkills });
            if (singleResult.success) allFindings.push(...singleResult.findings);
          } catch (e) { warnings.push(`文件 ${singleFile.relativePath} 审计失败: ${e.message}`); }
        }
      }
      onComplete?.(batch.length);
      return { success: true, findings: allFindings, batchSize: batch.length };
    }
    console.log(`[LLM审计] Token预检通过 - 总计: ${tokenCheck.currentTokens}, 上限: ${tokenCheck.maxTokens} (${tokenCheck.usagePercent}%)`);

    let responseText;
    console.log(`[SSE诊断] 即将调用 emitLLMStart，taskId=${taskId}`);
    streamService.emitLLMStart(llmConfig.model, { batchIndex: batchIndex + 1, totalBatches: validBatches.length }, taskId);
    console.log(`[SSE诊断] emitLLMStart 调用完成`);
    let toolFindings = [];
    try {
      const result = await withReviewRetry(() => llmCircuitBreaker.callWithFallback(() =>
        runToolEnabledAudit({ llmConfig, systemPrompt: finalSystemPrompt, userPrompt, sourceRoot, findingsAccumulator: toolFindings }),
        () => { throw new Error('LLM服务熔断'); }
      ));
      responseText = result.content || '';
      if (result.findings && result.findings.length > 0) {
        console.log(`[LLM审计] write_finding 工具产出 ${result.findings.length} 个发现`);
      }
    } catch (toolError) {
      console.warn(`[LLM审计] 工具模式失败 (${toolError.message})，回退到嵌入代码模式`);
      const fallbackPrompt = buildUserPrompt({ project, selectedSkills, heuristicFindings: batchHeuristicFindings, batch, incrementalPrompt: incPrompt }) + routeChecklist;
      // 降级路径绕过熔断器：工具模式失败不意味着标准API也失败（可能是模型不支持function calling等）
      responseText = await withReviewRetry(() =>
        requestStructuredReview({ llmConfig, systemPrompt: finalSystemPrompt, userPrompt: fallbackPrompt })
      );
    }

    const parsed = parseJsonResponse(responseText);
    // 合并 write_finding 工具产出和 JSON 解析结果（工具产出优先、质量更高）
    const rawFindings = [...(toolFindings || []), ...(parsed?.findings || [])];
    const validationResult = agentOutputValidator.validateFindings(rawFindings);
    if (validationResult.totalInvalid > 0) {
      console.warn(`[LLM审计] 批次 ${batchIndex + 1} 输出校验: ${validationResult.totalValid}/${validationResult.totalIn} 有效, ${validationResult.totalInvalid} 无效`);
      for (const inv of validationResult.invalid.slice(0, 3)) {
        console.warn(`[LLM审计]   无效项: ${inv.issues.join('; ')}`);
      }
    }

    const normalized = normalizeFindings(validationResult.valid, selectedSkills);
    auditFailureTracker.recordSuccess();

    // 发送批次结果摘要到前端 SSE
    const batchSummary = normalized.length > 0 
      ? `发现 ${normalized.length} 个问题：${normalized.map(f => f.title?.slice(0,60)).join(' | ')}` 
      : '本批次未发现新问题';
    streamService.emitLLMStreamToken(batchSummary, batchIndex + 1, validBatches.length, taskId);

    onComplete?.(batch.length);

    onProgress?.({
      type: "llm-batch-complete",
      currentBatch: batchIndex + 1,
      totalBatches: validBatches.length,
      batchSize: batch.length,
      totalFiles,
      label: `已完成第 ${batchIndex + 1} 批${counterName}`
    });

    return { success: true, findings: normalized, batchSize: batch.length };
  } catch (error) {
    console.error(`[LLM审计] 批次 ${batchIndex + 1} 出现错误:`, error.message);
    streamService.emitError(`LLM审计批次${batchIndex + 1}`, error.message, taskId);
    auditFailureTracker.recordFailure(error.message);

    onProgress?.({
      type: "llm-batch-error",
      currentBatch: batchIndex + 1,
      totalBatches: validBatches.length,
      batchSize: batch.length,
      totalFiles,
      label: `第 ${batchIndex + 1} 批${counterName}出现错误`
    });

    return { success: false, error: error.message, batchSize: batch.length };
  }
}

function normalizeSeverity(value) {
  const mapping = {
    "严重": "critical",
    "高危": "high",
    "中危": "medium",
    "低危": "low",
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info"
  };
  const key = (value || "").toLowerCase();
  return mapping[key] || mapping[value] || "medium";
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

// 自洽审查已移除 — 无代码上下文导致误杀 64/64
