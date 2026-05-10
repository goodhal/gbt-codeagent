import pLimit from "p-limit";
import { promises as fs } from "node:fs";
import path from "path";
import { inferFenceLanguage, collectFiles } from "../utils/fileUtils.js";
import { jsonrepair } from "jsonrepair";
import { withRetry, withRetryWithFallback, CircuitBreaker, CircuitBreakerConfig, createReActAuditor, PromptCacheManager } from "../core/index.js";
import { createLocalToolExecutor } from "../tools/localToolExecutor.js";
import { buildReActSystemPrompt, buildReActInitialPrompt } from "../core/reactPrompts.js";
import { ragService } from "./ragService.js";
import { streamService } from "./streamService.js";
import { estimateTokens, countTokensTiktoken, getModelMaxTokens, PromptCompressor, IncrementalSummary, ContextConfig } from "../utils/contextManager.js";
import { fetchWithTimeout, globalLLMFactory } from "./llmFactory.js";
import { CodeRetriever } from "./retriever.js";
import { deduplicateAndSort, severityScore } from "../utils/findingsUtils.js";
import { LLMOptimizer } from "./llmOptimizer.js";
import {
  loadAuditKnowledge,
  buildSystemPrompt,
  buildUserPrompt,
  createEnhancedPrompt,
  createIncrementalAuditPrompt,
  EVIDENCE_REQUIRED_MAP,
  EVIDENCE_CONTRACT_GUIDE
} from "../config/llmPrompts.js";
import OWASP_MAPPING from "../config/owaspMapping.js";

const MAX_BATCHES = 16;
const MAX_FILES_PER_BATCH = 6;
const MAX_CHARS_PER_BATCH = 35_000;
const MAX_PARALLEL_REQUESTS = 5;
const FETCH_TIMEOUT_MS = 150_000;

const llmCircuitBreaker = new CircuitBreaker("llm-service", {
  failureThreshold: 3,
  successThreshold: 2,
  recoveryTimeout: 30000
});

const incrementalSummary = new IncrementalSummary();
const llmLimit = pLimit(3);
const promptCompressor = new PromptCompressor();
const promptCacheManager = new PromptCacheManager();
const llmOptimizer = new LLMOptimizer();
llmOptimizer.initialize().catch(err => console.warn('[LLM审计] 优化器初始化失败:', err.message));

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
    const enhancedPrompt = createEnhancedPrompt({
      includeContextAnalysis: true,
      includeBusinessLogic: true,
      includeAttackChain: true,
      strictMode: true
    });
    const fullSystemPrompt = systemPrompt + '\n\n' + enhancedPrompt;

    let incrementalPrompt = '';
    if (cachedResult?.changedFiles?.length > 0) {
      incrementalPrompt = createIncrementalAuditPrompt(cachedResult.changedFiles);
    }

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
            systemPrompt: fullSystemPrompt,
            userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings, batch, incrementalPrompt })
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
    const rankedFindings = llmOptimizer.rankFindings(dedupedFindings).slice(0, 12);
    const truncated = prioritizedFiles.length > validBatches.flat().length;

    llmOptimizer.cacheResults(projectHash, files, rankedFindings);
    await llmOptimizer.recordAuditResult(project.id, rankedFindings, true);

    const optimizationReport = llmOptimizer.generateAuditReport({
      cachedFindings: cachedResult?.cachedFindings?.length || 0,
      changedFiles: cachedResult?.changedFiles || [],
      findings: rankedFindings
    });

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
      summary: buildSummary({ reviewedFiles, reviewedBatches, findings: rankedFindings, truncated }),
      warnings,
      findings: rankedFindings.map((finding) => ({ ...finding, source: "llm" })),
      optimizerReport: optimizationReport
    };
  }

  async auditProject({ project, selectedSkills, llmConfig, codeGraphContext, onProgress }) {
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
    // 自动判断：小项目（≤50文件）跳过索引，收益小而开销大
    const EMBEDDING_MAX_CONCURRENCY = 5;
    const CODE_INDEX_MIN_FILES = 50;
    let codeRetriever = null;

    if (files.length >= CODE_INDEX_MIN_FILES) {
      try {
        codeRetriever = new CodeRetriever({ maxChunkSize: 800, overlap: 50 });
        await codeRetriever.initialize();
        console.log(`[LLM审计] 开始并行索引项目代码: ${files.length} 个文件 (并发 ${EMBEDDING_MAX_CONCURRENCY})`);
        const filesToIndex = files.slice(0, 100);
        const indexLimit = pLimit(EMBEDDING_MAX_CONCURRENCY);
        let indexedCount = 0;

        const tasks = filesToIndex.map((file) =>
          indexLimit(async () => {
            try {
              await codeRetriever.indexFile(file.fullPath, file.content, file.language);
            } catch (e) {
            }
            indexedCount++;
            if (indexedCount % 10 === 0 || indexedCount === filesToIndex.length) {
              onProgress?.({
                type: "llm-indexing",
                totalFiles: files.length,
                indexedFiles: indexedCount,
                label: `正在索引项目代码：${indexedCount} / ${filesToIndex.length} 个文件`
              });
            }
          })
        );

        await Promise.all(tasks);
        console.log(`[LLM审计] 代码索引完成，已索引 ${codeRetriever.chunks.size} 个代码块`);
      } catch (error) {
        console.warn(`[LLM审计] 代码索引失败: ${error.message}`);
        codeRetriever = null;
      }
    } else {
      console.log(`[LLM审计] 跳过代码索引：项目文件数 ${files.length} < 阈值 ${CODE_INDEX_MIN_FILES}`);
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
            userPrompt: buildUserPrompt({ project, selectedSkills, heuristicFindings: [], batch, codeContext, codeGraphContext })
          }),
          () => {
            console.warn('[LLM审计] LLM服务熔断，使用降级方案');
            return JSON.stringify({ findings: [] });
          }
        ));

        const parsed = parseJsonResponse(responseText);
        const normalized = normalizeFindings(parsed?.findings, selectedSkills);

        return { success: true, findings: normalized, batchSize: batch.length };
      } catch (error) {
        console.error(`[LLM审计] 批次 ${batchIndex + 1} 出现错误:`, error.message);
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

        onProgress?.({
          type: "llm-batch-complete",
          currentBatch: completedBatches,
          totalBatches: validBatches.length,
          auditedFiles,
          totalFiles: files.length,
          label: `LLM 已审计 ${auditedFiles} / ${files.length} 个文件`
        });
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

const withReviewRetry = async (fn) => {
  return await withRetry(fn, {
    maxAttempts: 2,
    baseDelay: 1000,
    onRetry: (error, attempt, max) => {
      console.warn(`[LLM审计] 请求重试 ${attempt}/${max}: ${error.message}`);
    }
  });
};

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
    const content = await fs.readFile(target, "utf8");
    output.push({
      fullPath: target,
      relativePath: path.relative(root, target).replaceAll("\\", "/"),
      content,
      language
    });
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
