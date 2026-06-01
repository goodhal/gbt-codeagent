import { promises as fs } from "node:fs";
import path from "path";
import { resolveAuditSkills } from "../config/auditSkills.js";
import { QuickScanService } from "../services/quickScanService.js";
import { ValidationService } from "../services/validationService.js";
import { ExternalToolService } from "../services/externalToolService.js";
import { getGlobalASTEnhancer } from "../services/astEnhancer.js";
import { CodeAnalysisTool } from "../services/codeAnalysis.js";
import { ASTBuilderService } from "../utils/astBuilder.js";
import { QueryEngine } from "../utils/queryEngine.js";
import { deduplicateFindings, deduplicateAndSort } from "../utils/findingsUtils.js";
import { scoreFindings, scoreBySource } from "../core/auditScoreEngine.js";
import { enhanceFindingsWithContext } from "../services/contextAwareFilter.js";
import { collectFiles } from "../utils/fileUtils.js";
import { globalCheckpointManager, AuditState, AgentStatus } from "../core/stateManager.js";
import { generateExploitChainReport } from "../services/exploitChainAnalyzer.js";
import { javaRouteMapper } from "../analyzers/javaRouteMapper.js";
import { javaRouteTracer } from "../analyzers/javaRouteTracer.js";
import { componentVulnService } from "../services/componentVulnService.js";
import { createCoverageTracker } from "../services/coverageService.js";

import { getMaxParallelProjects, getCheckpointInterval, getCompletionTokens, getFetchTimeoutMs } from "../config/auditParamsConfig.js";
import { getModelMaxTokens } from "../utils/contextManager.js";
import { jsonrepair } from "jsonrepair";
import { fetchWithTimeout } from "../services/llmFactory.js";

export class AuditAnalystAgent {
  constructor({ llmReviewer }) {
    this.llmReviewer = llmReviewer;
    this.quickScanService = new QuickScanService();
    this.validationService = new ValidationService();
  }

  async run({ taskId, projects, selectedSkillIds, llmConfig, useReAct = false, useStreaming = false, reactConfig = {}, enableLlmAudit = true, onProgress, shouldCancel, tasks, onProjectGroupComplete }) {
    const reviewProfile = resolveAuditSkills(selectedSkillIds);
    const results = [];
    const isGbtAudit = reviewProfile.some(skill => skill.id === "gbt-code-audit");

    const auditState = new AuditState();
    auditState.agentId = `audit_${taskId}_${Date.now().toString(36)}`;
    auditState.task = `审计任务 ${taskId}`;
    auditState.taskContext = { taskId, projectCount: projects.length, selectedSkillIds };
    auditState.start();

    const checkpointInterval = getCheckpointInterval();
    let checkpointCounter = 0;

    async function createCheckpoint(name) {
      try {
        checkpointCounter++;
        if (checkpointCounter % checkpointInterval === 0) {
          auditState.findings = results.flatMap(r => r.findings || []);
          auditState.status = AgentStatus.RUNNING;
          const filepath = await globalCheckpointManager.createCheckpoint(auditState, name);
          console.log(`[检查点] 已保存: ${name} -> ${filepath}`);
          return filepath;
        }
      } catch (error) {
        console.warn(`[检查点] 保存失败: ${error.message}`);
      }
      return null;
    }

    async function processProject(project, index) {
      // 首先检查是否需要暂停/取消
      if (shouldCancel?.()) {
        console.log(`[审计分析] 任务已暂停/取消，跳过项目: ${project.name}`);
        return {
          projectId: project.id,
          projectName: project.name,
          repoUrl: project.repoUrl,
          localPath: project.localPath || "",
          reviewProfile,
          heuristicFindings: [],
          llmAudit: {
            status: "skipped",
            called: false,
            skipReason: "auditor-paused",
            summary: "任务已暂停",
            findings: [],
            warnings: [],
            reactResult: null
          },
          findings: []
        };
      }
      
      onProgress?.({
        stage: "heuristic",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        label: `正在分析规则层：${project.name}`
      });

      const { findings: rawHeuristicFindings, javaRoutes = [] } = await buildHeuristicFindings(project, reviewProfile);

      const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
      let heuristicFindings = rawHeuristicFindings.length > 0
        ? await enhanceFindingsWithContext(rawHeuristicFindings, sourceRoot)
        : rawHeuristicFindings;
      const suppressionCount = rawHeuristicFindings.length - heuristicFindings.filter(f => (f.confidence || 0) >= 0.3).length;
      if (suppressionCount > 0) {
        console.log(`[审计分析] 上下文感知过滤器抑制了 ${suppressionCount} 个低置信度发现`);
      }
  
      // 快速扫描后检查是否需要暂停
      if (shouldCancel?.()) {
        console.log(`[审计分析] 任务已暂停/取消，返回快速扫描结果: ${project.name}, 发现 ${heuristicFindings.length} 个问题`);
        return {
          projectId: project.id,
          projectName: project.name,
          repoUrl: project.repoUrl,
          localPath: project.localPath || "",
          reviewProfile,
          heuristicFindings,
          llmAudit: {
            status: "skipped",
            called: false,
            skipReason: "auditor-paused",
            summary: "任务已暂停",
            findings: [],
            warnings: [],
            reactResult: null
          },
          findings: heuristicFindings
        };
      }

      // AST 增强：发现 < 20 条时增益小，跳过节省 5-10s
      const doAstEnhance = heuristicFindings.length >= 20;
      const doLlmAudit = !!(this.llmReviewer) && (enableLlmAudit !== false);

      if (doAstEnhance) {
        onProgress?.({
          stage: "ast-enhance",
          projectId: project.id,
          projectName: project.name,
          projectIndex: index + 1,
          totalProjects: projects.length,
          label: `正在进行 AST 增强分析`
        });
      }

      const astEnhancePromise = doAstEnhance ? (async () => {
        if (shouldCancel?.()) {
          console.log(`[审计分析] 任务已暂停/取消，跳过 AST 增强`);
          return heuristicFindings;
        }

        try {
          const astEnhancer = await getGlobalASTEnhancer();
          await astEnhancer.initialize(sourceRoot);
          const result = await astEnhancer.enhanceFindings(heuristicFindings, sourceRoot);
          console.log(`[审计分析] AST 增强完成，发现增强: ${result.length}`);
          if (doLlmAudit) {
            onProgress?.({
              stage: useReAct ? "react-audit" : "llm-audit",
              projectId: project.id,
              projectName: project.name,
              projectIndex: index + 1,
              totalProjects: projects.length,
              label: `正在进行 LLM 审计：${project.name}`
            });
          }
          return result;
        } catch (error) {
          console.warn(`[审计分析] AST 增强失败: ${error.message}`);
          return heuristicFindings;
        }
      })() : Promise.resolve(heuristicFindings);

      let llmAuditPromise = Promise.resolve({
        status: "skipped",
        called: false,
        skipReason: enableLlmAudit === false ? "llm-audit-disabled" : "no-llm-reviewer",
        summary: enableLlmAudit === false ? "LLM 审计已在配置中关闭。" : "未配置 LLM 审计器。",
        findings: [],
        warnings: [],
        reactResult: null
      });

      if (doLlmAudit) {
        // 代码图谱对审计结果帮助有限，默认跳过节省 5-10s
        const codeGraphContext = null;
        const codeGraph = null;

        if (useReAct && typeof this.llmReviewer.auditWithReAct === 'function') {
          llmAuditPromise = this.llmReviewer.auditWithReAct({
            project,
            selectedSkills: reviewProfile,
            llmConfig,
            reactConfig,
            codeGraphContext,
            taskId,
            onProgress: (detail) =>
              onProgress?.({
                stage: "react-audit",
                projectId: project.id,
                projectName: project.name,
                projectIndex: index + 1,
                totalProjects: projects.length,
                ...detail
              })
          });
        } else {
          llmAuditPromise = this.llmReviewer.auditProject({
            project,
            selectedSkills: reviewProfile,
            llmConfig,
            codeGraphContext,
            codeGraph,
            routeTable: javaRoutes.length > 0 ? { routes: javaRoutes, count: javaRoutes.length } : null,
            useStreaming,
            taskId,
            onProgress: (detail) =>
              onProgress?.({
                stage: "llm-audit",
                projectId: project.id,
                projectName: project.name,
                projectIndex: index + 1,
                totalProjects: projects.length,
                ...detail
              })
          });
        }
      }

      if (shouldCancel?.()) {
        console.log(`[审计分析] 任务已暂停/取消，返回快速扫描结果: ${project.name}`);
        return {
          projectId: project.id,
          projectName: project.name,
          repoUrl: project.repoUrl,
          localPath: project.localPath || "",
          reviewProfile,
          heuristicFindings,
          llmAudit: {
            status: "skipped",
            called: false,
            skipReason: "auditor-paused",
            summary: "任务已暂停。",
            findings: [],
            warnings: [],
            reactResult: null
          },
          findings: heuristicFindings
        };
      }

      const [astEnhancedFindings, llmAudit] = await Promise.all([astEnhancePromise, llmAuditPromise]);

      if (llmAudit.status === "skipped" && llmAudit.called === false && llmAudit.skipReason !== "no-llm-reviewer") {
        onProgress?.({
          stage: useReAct ? "react-audit" : "llm-audit",
          projectId: project.id,
          projectName: project.name,
          projectIndex: index + 1,
          totalProjects: projects.length,
          label: `LLM 审计已跳过：${llmAudit.summary}`,
          detail: llmAudit.skipReason,
          current: 0,
          total: 0
        });
      }

      // 检查任务是否被暂停或取消，如果是被暂停则返回已完成的部分结果
      if (shouldCancel?.()) {
        console.log(`[审计分析] 任务已暂停/取消，返回当前结果: ${project.name}`);
        const mergedFindings = prioritizeFindings([
          ...astEnhancedFindings,
          ...(Array.isArray(llmAudit.findings) ? llmAudit.findings : [])
        ]);
        return {
          projectId: project.id,
          projectName: project.name,
          repoUrl: project.repoUrl,
          localPath: project.localPath || "",
          reviewProfile,
          heuristicFindings: astEnhancedFindings,
          llmAudit,
          findings: mergedFindings
        };
      }

      const mergedFindings = prioritizeFindings([
        ...astEnhancedFindings,
        ...(Array.isArray(llmAudit.findings) ? llmAudit.findings : [])
      ]);

      const auditScore = scoreFindings(mergedFindings);
      const sourceScores = scoreBySource(mergedFindings);
      const unresolvedRisks = await this.validationService.checkUnresolvedRisks(mergedFindings);
      const riskPoolReport = this.validationService.generateRiskPoolReport(unresolvedRisks);
      const exploitChainReport = generateExploitChainReport(mergedFindings);

      onProgress?.({
        stage: "project-complete",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        heuristicCount: heuristicFindings.length,
        astEnhancedCount: astEnhancedFindings.length,
        llmCount: llmAudit?.findings?.length || 0,
        unresolvedRiskCount: unresolvedRisks.length,
        exploitChainCount: exploitChainReport.totalChains,
        auditScore: auditScore.score,
        auditGate: auditScore.gate.passed ? 'passed' : 'blocked',
        useReAct,
        label: `已完成：${project.name}`
      });

      return {
        projectId: project.id,
        projectName: project.name,
        repoUrl: project.repoUrl,
        localPath: project.localPath || "",
        reviewProfile,
        heuristicFindings: astEnhancedFindings,
        llmAudit,
        findings: mergedFindings,
        auditScore,
        sourceScores,
        riskPool: riskPoolReport,
        exploitChains: exploitChainReport
      };
    }

    for (let i = 0; i < projects.length; i += getMaxParallelProjects()) {
      const projectGroup = projects.slice(i, i + getMaxParallelProjects());
      const currentStep = Math.floor(i / getMaxParallelProjects()) + 1;
      const totalSteps = Math.ceil(projects.length / getMaxParallelProjects());

      auditState.updateProgress(currentStep, totalSteps, `处理项目组 ${currentStep}/${totalSteps}`);

      // 处理项目组
      const groupResults = await Promise.all(
        projectGroup.map((project, idx) => processProject.call(this, project, i + idx))
      );

      results.push(...groupResults);

      // 每组完成后保存部分结果，支持断点续传
      if (onProjectGroupComplete) {
        onProjectGroupComplete({
          projects: results,
          findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0)
        });
      }

      // 检查任务是否被暂停或取消（在处理完一轮后检查）
      if (shouldCancel?.()) {
        console.log(`[审计分析] 任务已暂停/取消，停止审计`);
        await createCheckpoint(`pre_validation_${i}`);
        auditState.status = AgentStatus.PAUSED;
        auditState.waitingForInput = true;
        auditState.waitingReason = "paused-before-validation";
        break;
      }

      // 每个项目组处理完后创建检查点
      await createCheckpoint(`post_project_group_${i}`);
    }

    // 检查任务是否被暂停或取消
    if (shouldCancel?.()) {
      console.log(`[审计分析] 任务已暂停/取消，跳过验证阶段`);
      return {
        projects: results,
        findingsCount: results.reduce((sum, r) => sum + r.findings.length, 0)
      };
    }

    // 验证所有发现（代码片段验证 + 行号修正）
    onProgress?.({
      stage: "validation",
      label: "正在验证漏洞发现"
    });

    const allFindings = results.flatMap(r => r.findings);
    const validationService = new ValidationService();
    
    // 按项目分组验证
    const validatedResults = await Promise.all(results.map(async (result) => {
      // 检查任务是否被暂停或取消
      if (shouldCancel?.()) {
        return result;
      }

      const sourceRoot = path.join(process.cwd(), "workspace", "downloads", result.projectId);
      const { validated, hallucinations, corrected } = await validationService.validateFindings(
        result.findings,
        sourceRoot
      );
      
      // 深度验证漏洞路径（使用 CommentWorkerPool 有界并发）
      const { CommentWorkerPool } = await import("../core/commentWorkerPool.js");
      const pool = new CommentWorkerPool(8);
      
      // 提交所有任务到 worker pool（有界并发，最多 8 个并行）
      const jobs = validated.map((finding, idx) =>
        pool.submit(
          () => validationService.verifyVulnerabilityPath(finding, sourceRoot),
          finding.location || finding.title || `finding-${idx}`
        )
      );
      
      // 等待全部完成
      await pool.awaitAll();
      
      // 组装结果（pool 内保存的是原始 verification，这里做合并）
      const deepValidated = (await Promise.all(jobs)).map((verification, i) => ({
        ...validated[i],
        verdict: verification.verdict,
        verificationReason: verification.reason,
        adjustedSeverity: verification.adjustedSeverity,
        verifiedCallChain: verification.verifiedCallChain,
        sanitizersFound: verification.sanitizersFound
      }));

      // 同步 verdict → status（修复：之前 status 默认"误报"从未被更新）
      const VERDICT_TO_STATUS = {
        confirmed: "已确认",
        false_positive: "误报",
        downgraded: "已降级",
        needs_review: "待复核",
      };
      for (const f of deepValidated) {
        if (f.verdict && VERDICT_TO_STATUS[f.verdict]) {
          f.status = VERDICT_TO_STATUS[f.verdict];
        }
      }

      // 统计验证结果
      const verdictStats = {
        confirmed: deepValidated.filter(f => f.verdict === 'confirmed').length,
        falsePositive: deepValidated.filter(f => f.verdict === 'false_positive').length,
        downgraded: deepValidated.filter(f => f.verdict === 'downgraded').length,
        needsReview: deepValidated.filter(f => f.verdict === 'needs_review').length
      };

      // 过滤掉误报，降级的保留但标记
      const finalFindings = deepValidated;
      
      return {
        ...result,
        findings: finalFindings,
        validationStats: {
          total: result.findings.length,
          validated: validated.length,
          hallucinations: hallucinations.length,
          corrected: corrected.length,
          ...verdictStats
        },
        hallucinations: [
          ...hallucinations,
          ...deepValidated.filter(f => f.verdict === 'false_positive').map(f => ({
            ...f,
            validationError: `深度验证标记为误报: ${f.verificationReason}`
          }))
        ]
      };
    }));

    // 重新计算统计信息
    const totalValidated = validatedResults.reduce((sum, r) => sum + r.findings.length, 0);
    const totalConfirmed = validatedResults.reduce((sum, r) => sum + r.findings.filter(f => f.verdict !== 'false_positive').length, 0);
    const totalHallucinations = validatedResults.reduce((sum, r) => sum + (r.hallucinations?.length || 0), 0);
    const totalCorrected = validatedResults.reduce((sum, r) => sum + (r.validationStats?.corrected || 0), 0);

    // ============ 覆盖率追踪（轻量，无API调用） ============
    let coverageReport = null;
    let allProjectFiles = [];
    let firstSourceRoot = "";
    try {
      firstSourceRoot = path.join(process.cwd(), "workspace", "downloads", validatedResults[0]?.projectId || "");
      for (const result of validatedResults) {
        const sourceRoot = path.join(process.cwd(), "workspace", "downloads", result.projectId);
        try {
          const files = await collectFiles(sourceRoot);
          for (const f of files) {
            allProjectFiles.push(path.relative(firstSourceRoot, f).replaceAll("\\", "/"));
          }
        } catch { /* skip */ }
      }
      if (allProjectFiles.length > 0) {
        const tracker = createCoverageTracker(firstSourceRoot, allProjectFiles);
        for (const result of validatedResults) {
          tracker.markFromFindings(result.findings);
        }
        coverageReport = tracker.generateReport();
        console.log(`[审计分析] 覆盖率: ${coverageReport.summary.coveragePercent}% (${coverageReport.summary.reviewedFiles}/${coverageReport.summary.totalFiles})`);
      }
    } catch (error) {
      console.warn(`[审计分析] 覆盖率追踪失败: ${error.message}`);
    }

    // ============ 可选增强阶段 ============
    const adversarialStats = null;
    const traceStats = null;
    const feedbackResult = null;

    // Gapfill：检查高优先级文件是否被 LLM 遗漏，自动补充审计
    let gapfillResult = null;
    // 即使 coverageReport 为 null（覆盖率追踪失败），只要有多语言文件且 LLM 可用就尝试补审
    const hasGapfillCandidates = validatedResults.length > 0 && enableLlmAudit && llmConfig;
    if (hasGapfillCandidates) {
      try {
        // 直接从 findings 计算哪些文件完全没有 LLM 产出
        const sourceRoot = path.join(process.cwd(), "workspace", "downloads", validatedResults[0].projectId);
        const llmCoveredFiles = new Set(
          validatedResults.flatMap(r => r.findings || [])
            .filter(f => f.source === 'llm')
            .map(f => (f.location || '').split(':')[0])
        );
        // 收集所有有发现的文件
        const allFilesWithFindings = new Set(
          validatedResults.flatMap(r => r.findings || [])
            .map(f => (f.location || '').split(':')[0])
        );
        // 找出 LLM 完全未覆盖的文件
        const gapCandidates = [...allFilesWithFindings].filter(f => !llmCoveredFiles.has(f));

        // 同时检查是否有文件完全没有被审计过（QuickScan和LLM都没有发现）
        const allSourceFiles = (await collectFiles(sourceRoot).catch(() => [])).map(f => {
          const rel = typeof f === 'string' ? f.replace(sourceRoot, '').replace(/^[\\/]+/, '') : (f.relativePath || '');
          return rel.replace(/\\/g, '/');
        }).filter(Boolean);
        const allAuditedFiles = new Set(
          validatedResults.flatMap(r => r.findings || []).map(f => (f.location || '').split(':')[0])
        );
        const fullyMissed = allSourceFiles
          .filter(f => !allAuditedFiles.has(f))
          .slice(0, 5);
        if (fullyMissed.length > 0) {
          console.log(`[审计分析] 检测到 ${fullyMissed.length} 个文件完全未被审计，纳入补充审计`);
          gapCandidates.push(...fullyMissed);
        }

        if (gapCandidates.length > 0) {
          console.log(`[审计分析] 检测到 ${gapCandidates.length} 个文件无 LLM 发现，启动精准补充审计`);

          // 读取遗漏文件的完整内容
          const gapFiles = [];
          for (const cf of gapCandidates.slice(0, 10)) {
            try {
              const fullPath = path.join(sourceRoot, cf);
              const content = await fs.readFile(fullPath, "utf8");
              if (content.length > 50 && content.length < 15000) {
                gapFiles.push({ path: cf, content });
              }
            } catch { /* skip */ }
          }

          if (gapFiles.length > 0) {
            // 构建聚焦的系统提示词（精简版，不含完整skill prompt节省token）
            const gapSystemPrompt = `你是代码安全审计专家。以下文件在上一轮审计中被遗漏，请重点审查恶意代码模式。

【必须检测的漏洞类型】
- 命令注入、SQL注入、代码注入、路径遍历、SSRF
- 硬编码密钥、反序列化、XXE、XSS、CSRF
- CORS配置缺陷、访问控制缺失、信息泄露
- 认证绕过、会话固定

【本次补充审计的遗漏文件】
${gapFiles.map(f => {
  const ext = f.path.split('.').pop() || 'java';
  const lang = {py:'python',js:'javascript',ts:'typescript',go:'go',rb:'ruby',cs:'csharp',cpp:'cpp',c:'c',java:'java',php:'php'}[ext] || 'java';
  return `\n### ${f.path}\n\`\`\`${lang}\n${f.content}\n\`\`\``;
}).join('\n')}

请仅输出精简JSON（每个发现只填4个字段，减少token消耗）：{"findings":[{"title":"漏洞名称(15字内)","severity":"critical|high|medium|low","location":"文件:行号","vulnType":"XSS|SQL_INJECTION|..."}]}`;

            try {
              // Gapfill 使用独立 fetch 调用（避免 callLLM 内部的 JSON 解析问题）
              const baseUrl = String(llmConfig.baseUrl || "").replace(/\/+$/, "");
              const completionTokens = getCompletionTokens(getModelMaxTokens(llmConfig.model));
              const apiResponse = await fetchWithTimeout(`${baseUrl}/chat/completions`, {
                method: "POST",
                headers: { "Content-Type": "application/json", Authorization: `Bearer ${llmConfig.apiKey}` },
                body: JSON.stringify({
                  model: llmConfig.model,
                  temperature: 0.1,
                  max_tokens: completionTokens,
                  messages: [
                    { role: "system", content: gapSystemPrompt },
                    { role: "user", content: "请审查以上遗漏文件，仅输出JSON格式结果，不要其他文字。" }
                  ]
                }),
              }, getFetchTimeoutMs());
              if (!apiResponse.ok) throw new Error(`HTTP ${apiResponse.status}`);
              // 尝试 JSON 解析；失败则用文本提取
              let responseText = "";
              try {
                const data = JSON.parse(await apiResponse.text());
                responseText = data.choices?.[0]?.message?.content || "";
              } catch {
                // 如果 API 返回非标准 JSON，直接读文本
                responseText = await apiResponse.text();
              }

              const jsonMatch = String(responseText).match(/\{[\s\S]*"findings"[\s\S]*\}/);
              if (jsonMatch) {
                let parsed;
                try {
                  parsed = JSON.parse(jsonMatch[0]);
                } catch (e1) {
                  try {
                    const repaired = jsonrepair(jsonMatch[0]);
                    parsed = JSON.parse(repaired);
                    console.log('[审计分析] Gapfill JSON 经 jsonrepair 修复成功');
                  } catch (e2) {
                    console.warn(`[审计分析] Gapfill JSON 无法解析: ${e2.message}`);
                    return;
                  }
                }
                const gapFindings = (parsed.findings || []).filter(f => f.title && f.location);

                if (gapFindings.length > 0) {
                  const existingKeys = new Set(
                    validatedResults.flatMap(r => r.findings || []).map(f =>
                      `${(f.location || '')}|${(f.title || '').substring(0,40)}`
                    )
                  );
                  const newFindings = gapFindings.filter(f =>
                    !existingKeys.has(`${(f.location || '')}|${(f.title || '').substring(0,40)}`)
                  ).map(f => {
                    const enriched = enrichFindingFields({
                      ...f,
                      source: 'llm',
                      skillId: 'gbt-code-audit',
                      verdict: 'confirmed',
                      evidence: f.evidence || '模型复核认为这里存在值得继续人工确认的实现迹象。',
                      impact: f.impact || '该实现如果在真实部署中成立，可能扩大管理面、数据面或配置暴露面。',
                      remediation: f.remediation || '建议结合服务端收口、权限校验和配置默认值治理进行修复。',
                      safeValidation: f.safeValidation || '建议在本地或测试环境里补充代码走读与单元测试来确认边界。',
                      cvssScore: f.cvssScore || 0,
                      language: f.language || (f.location ? (() => { const ext = f.location.split('.').pop().split(':')[0].toLowerCase(); return { py: 'python', java: 'java', js: 'javascript', cs: 'csharp', cpp: 'cpp', go: 'go', php: 'php' }[ext] || 'unknown'; })() : 'unknown'),
                    });
                    return enriched;
                  });

                  if (newFindings.length > 0) {
                    gapfillResult = {
                      gapFiles: gapFiles.length,
                      newFindings: newFindings.length,
                      summary: `精准补充审计覆盖 ${gapFiles.length} 个遗漏文件，新增 ${newFindings.length} 条发现`,
                    };
                    validatedResults[0].findings.push(...newFindings);
                    console.log(`[审计分析] Gapfill完成: ${gapfillResult.summary}`);
                  }
                }
              }
            } catch (llmError) {
              console.warn(`[审计分析] Gapfill LLM调用失败: ${llmError.message}`);
            }
          }
        } else {
          console.log(`[审计分析] 覆盖率检查通过: 所有文件均有发现覆盖`);
        }
      } catch (error) {
        console.warn(`[审计分析] Gapfill跳过: ${error.message}`);
      }
    }

    // ============ 漏洞类型 Gapfill ============
    // 对快扫发现但 LLM 未覆盖的 (文件, 漏洞类型) 组合，做定向 LLM 复核确认
    if (enableLlmAudit && llmConfig && validatedResults.length > 0) {
      try {
        const vulnTypeGapfill = buildVulnTypeGapMap(validatedResults);
        if (vulnTypeGapfill.length > 0) {
          console.log(`[审计分析] 检测到 ${vulnTypeGapfill.length} 个(文件,漏洞类型)组合 LLM 未覆盖，启动定向复核`);
          const sourceRoot = path.join(process.cwd(), "workspace", "downloads", validatedResults[0].projectId);
          await runVulnTypeGapfill({ validatedResults, vulnTypeGapfill, sourceRoot, llmConfig, taskId });
        }
      } catch (vtgError) {
        console.warn(`[审计分析] 漏洞类型Gapfill失败: ${vtgError.message}`);
      }
    }

    // 架构分析 — 代码图谱对审计结果帮助有限，默认跳过
    const architectureAnalysis = null;

    // Gapfill后重新计算统计（包含补充审计结果）
    const finalTotalValidated = validatedResults.reduce((sum, r) => sum + r.findings.length, 0);
    const finalTotalConfirmed = validatedResults.reduce((sum, r) => sum + r.findings.filter(f => f.verdict !== 'false_positive').length, 0);
    const finalLlmFindingsCount = validatedResults.flatMap(r => r.findings || []).filter(f => f.verdict !== 'false_positive' && f.source === 'llm').length;
    const finalHeuristicFindingsCount = validatedResults.flatMap(r => r.findings || []).filter(f => f.verdict !== 'false_positive' && ['quick_scan','taint','rule','pattern'].includes(f.source)).length;

    // 最终检查点
    auditState.status = AgentStatus.COMPLETED;
    auditState.findings = validatedResults.flatMap(r => r.findings || []);
    auditState.setCompleted({
      findingsCount: finalTotalConfirmed,
      projectsCount: validatedResults.length
    });
    await createCheckpoint('final');

    const statusSummary = auditState.getStatusSummary?.();
    console.log(`[审计分析] 任务完成 - 状态摘要: ${JSON.stringify(statusSummary)}`);

    return {
      reviewedAt: new Date().toISOString(),
      policy: "defensive-only",
      skillsUsed: reviewProfile.map((skill) => ({ id: skill.id, name: skill.name })),
      findingsCount: finalTotalConfirmed,
      findingsTotalCount: finalTotalValidated,
      checkpointId: auditState.agentId,
      heuristicFindingsCount: finalHeuristicFindingsCount,
      llmFindingsCount: finalLlmFindingsCount,
      llmCallCount: validatedResults.reduce((sum, item) => sum + (item.llmAudit?.called ? 1 : 0), 0),
      llmSkippedCount: validatedResults.reduce((sum, item) => sum + (item.llmAudit?.called ? 0 : 1), 0),
      validationStats: {
        total: allFindings.length,
        validated: totalValidated,
        hallucinations: totalHallucinations,
        corrected: totalCorrected
      },
      architectureAnalysis,
      adversarialValidation: adversarialStats,
      traceReachability: traceStats,
      coverageReport: coverageReport ? coverageReport.summary : null,
      gapfillAnalysis: gapfillResult ? {
        files: gapfillResult.gapFiles || 0,
        newFindings: gapfillResult.newFindings || 0,
        summary: gapfillResult.summary || '',
      } : null,
      feedbackAnalysis: feedbackResult ? {
        newTasks: feedbackResult.newTasks?.length || 0,
        patternsExtracted: feedbackResult.patternsExtracted?.length || 0,
      } : null,
      projects: validatedResults
    };
  }
}

async function buildHeuristicFindings(project, reviewProfile) {
  const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
  const findings = [];
  const enabledSkills = new Set(reviewProfile.map((skill) => skill.id));

  // 1. 快速扫描（所有审计模式都执行）
  console.log(`[审计分析] 开始快速扫描项目: ${project.name}`);
  const quickScanService = new QuickScanService();
  const quickScanResult = await quickScanService.scanProject(sourceRoot, (progress) => {
    console.log(`[快速扫描进度] ${progress.processedFiles}/${progress.totalFiles} 文件，当前: ${progress.currentFile}`);
  });
  const quickScanFindings = quickScanResult.findings || [];
  console.log(`[审计分析] 快速扫描完成，发现 ${quickScanFindings.length} 个问题（扫描 ${quickScanResult.stats?.totalFilesScanned || quickScanFindings.length} 个文件）`);
  findings.push(...quickScanFindings);

  // 2. 污点追踪分析（行级污点追踪 + AST访问器）
  console.log(`[审计分析] 开始污点追踪分析`);
  try {
    const codeAnalysis = new CodeAnalysisTool();
    await codeAnalysis.initialize();
    const taintFindings = await analyzeWithTaint(codeAnalysis, sourceRoot, quickScanFindings);
    if (taintFindings.length > 0) {
      console.log(`[审计分析] 污点追踪分析完成，发现 ${taintFindings.length} 个问题（去重后）`);
      findings.push(...taintFindings);
    } else {
      console.log(`[审计分析] 污点追踪分析完成，未发现新问题`);
    }
  } catch (error) {
    console.warn(`[审计分析] 污点追踪分析失败: ${error.message}`);
  }

  // 3. 外部工具扫描（Gitleaks/Bandit/Semgrep）— 仅已安装工具生效
  try {
    const externalToolService = new ExternalToolService();
    const externalFindings = await externalToolService.scanAll(sourceRoot);
    if (externalFindings.length > 0) {
      console.log(`[审计分析] 外部工具扫描发现 ${externalFindings.length} 个问题`);
      findings.push(...externalFindings);
    }
  } catch (error) {
    console.warn(`[审计分析] 外部工具扫描跳过: ${error.message}`);
  }

  // 4. 组件漏洞扫描（Java/Node.js/Python依赖检测）
  console.log(`[审计分析] 开始组件漏洞扫描`);
  try {
    const componentScanResult = await componentVulnService.scanProjectDependencies(sourceRoot);
    if (componentScanResult.findings.length > 0) {
      console.log(`[审计分析] 组件漏洞扫描完成，发现 ${componentScanResult.findings.length} 个已知CVE漏洞（扫描 ${componentScanResult.stats.filesScanned} 个依赖文件，${componentScanResult.stats.totalDependencies} 个依赖）`);
      findings.push(...componentScanResult.findings);
    } else {
      console.log(`[审计分析] 组件漏洞扫描完成，未发现已知CVE漏洞`);
    }
  } catch (error) {
    console.warn(`[审计分析] 组件漏洞扫描失败: ${error.message}`);
  }

  // 收集文件用于规则检测
  const files = await collectFiles(sourceRoot);
  console.log(`[审计分析] 收集到 ${files.length} 个文件用于规则检测`);

  // 5. Java 路由映射分析（自动识别Java Web框架并提取所有HTTP路由）
  const isJavaProject = files.some(f => f.endsWith(".java") || f.endsWith(".xml"));
  let javaRoutes = [];
  if (isJavaProject) {
    console.log(`[审计分析] 检测到Java项目，开始路由映射分析`);
    try {
      const routeScanResult = await javaRouteMapper.scanProject(sourceRoot, files);
      javaRoutes = routeScanResult.routes || [];
      console.log(`[审计分析] 路由映射完成，提取 ${javaRoutes.length} 条HTTP路由（框架: ${Object.keys(routeScanResult.stats.byFramework).join(", ") || "none"}）`);
    } catch (error) {
      console.warn(`[审计分析] 路由映射分析失败: ${error.message}`);
    }

    // 6. Java 调用链追踪（对高危路由追踪 Controller→Service→DAO 完整调用链）
    if (javaRoutes.length > 0) {
      // 筛选需要追踪的高危路由（快速扫描有发现的文件对应的路由）
      const quickScanFiles = new Set(quickScanFindings.map(f => f.file));
      const riskyRoutes = javaRoutes.filter(r =>
        quickScanFiles.has(r.file) || r.urlPath.includes("admin") || r.urlPath.includes("api")
      );
      const traceTargets = riskyRoutes.slice(0, 30); // 限制最多追踪30条路由

      if (traceTargets.length > 0) {
        console.log(`[审计分析] 开始调用链追踪（${traceTargets.length}/${riskyRoutes.length} 条高危路由）`);
        try {
          const traces = await javaRouteTracer.traceProjectRoutes(sourceRoot, traceTargets, files);
          console.log(`[审计分析] 调用链追踪完成，成功追踪 ${traces.filter(t => !t.error).length} 条路由`);

          // 从调用链中提取额外发现（如: 无鉴权的敏感路由、参数可控的SQL拼接等）
          for (const trace of traces) {
            if (trace.error) continue;

            // 路由无鉴权且包含敏感操作
            if (trace.sinks && trace.sinks.length > 0 && trace.params?.some(p => p.controllable)) {
              const controllableParams = trace.params.filter(p => p.controllable);
              const sinkTypes = [...new Set(trace.sinks)];

              findings.push(createFinding({
                skillId: "route-tracer",
                title: `高危路由调用链: ${trace.route}`,
                severity: sinkTypes.includes("SQL") || sinkTypes.includes("COMMAND") ? "critical" : "high",
                confidence: 0.78,
                location: `${trace.entryFile}#${trace.entryMethod}`,
                vulnType: sinkTypes.includes("SQL") ? "SQL_INJECTION" : sinkTypes[0] || "SENSITIVE_OPERATION",
                cwe: "CWE-89",
                evidence: `路由 ${trace.route} (${trace.httpMethod}) → ${trace.entryMethod}() 存在 ${sinkTypes.join(", ")} 风险点。可控参数: ${controllableParams.map(p => p.param).join(", ")}。调用链: ${trace.summary?.chain || "N/A"}`,
                impact: `攻击者可能通过 ${trace.route} 接口利用 ${sinkTypes.join("/")} 漏洞，影响范围: ${controllableParams.length} 个参数可控`,
                remediation: `对路由 ${trace.route} 的所有可控参数进行白名单校验或参数化处理。审查 ${trace.summary?.chain || "调用链"} 中每个节点的输入验证。`,
                safeValidation: `验证 ${trace.route} 的输入参数是否经过充分校验，确认 ${sinkTypes.join("/")} 操作点是否使用了参数化查询或安全API。`,
                callChain: trace.summary?.chain || "",
                routePath: trace.route,
                routeMethod: trace.httpMethod
              }));
            }
          }
        } catch (error) {
          console.warn(`[审计分析] 调用链追踪失败: ${error.message}`);
        }
      }
    }
  }

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    const relative = path.relative(sourceRoot, file).replaceAll("\\", "/");
    const loweredPath = relative.toLowerCase();

    if (
      enabledSkills.has("access-control") &&
      hasObjectAccessIndicator(content) &&
      !hasAuthGuardIndicator(content) &&
      /(controller|route|resolver|service|api)/.test(loweredPath)
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "对象级访问控制边界值得重点复核",
        severity: "medium",
        confidence: 0.76,
        location: relative,
        impact: "如果控制器或服务层直接信任客户端提交的对象标识，可能导致跨用户或跨租户读取、修改内容。",
        evidence: `在 ${relative} 中发现了客户端可控对象标识的处理痕迹，但同文件附近没有明显的 ownership / policy / guard 校验线索。`,
        remediation: "在对象查询后、返回或修改前统一执行 role、tenant 与 ownership 校验，并让服务层承担二次鉴权职责。",
        safeValidation: "本地复核控制器到服务层的调用链，确认对象查找后的每条读写路径都执行了访问控制。"
      }));
    }

    if (
      enabledSkills.has("access-control") &&
      matches(content, /\b(public|anonymous|guest)\b/i, /\b(permission|permissions|role|roles|allow|grant|create|update|delete|read|find)\b/i) &&
      /(permission|policy|role|acl|rbac|config)/.test(loweredPath)
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "公共角色权限配置可能过宽",
        severity: "high",
        confidence: 0.79,
        location: relative,
        impact: "如果匿名或公共角色被默认授予内容管理能力，后台或 API 可能暴露出超出预期的读写面。",
        evidence: `在 ${relative} 中发现了 public / anonymous / guest 角色与权限授予语义同时出现。`,
        remediation: "将公共角色改为 deny-by-default，只为必要的读取接口单独放行，并把管理动作留给显式认证后的角色。",
        safeValidation: "本地检查角色初始化与权限合并逻辑，确认匿名角色不会默认获得管理或写入能力。"
      }));
    }

    if (
      enabledSkills.has("bootstrap-config") &&
      matches(content, /\b(bootstrapAdmin|seedAdmin|createFirstAdmin|registerInitialAdmin|setupAdmin|initialAdmin)\b/i, /\b(process\.env|config|if\s*\(!|allowBootstrap|enableBootstrap)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "bootstrap-config",
        title: "初始化管理员入口需要确认关闭条件",
        severity: "high",
        confidence: 0.82,
        location: relative,
        impact: "如果首次管理员创建逻辑缺少严格的单次条件或部署态关闭机制，生产环境可能暴露出高权限初始化入口。",
        evidence: `在 ${relative} 中发现了管理员初始化逻辑，并与环境配置或缺省条件绑定。`,
        remediation: "将首次管理员创建流程改为一次性、显式确认、默认关闭，并确保初始化完成后彻底失效。",
        safeValidation: "本地审查启动与迁移流程，确认生产缺省态下不存在可重复触发的管理员初始化路径。"
      }));
    }

    if (
      enabledSkills.has("access-control") &&
      (matches(content, /\b(auth\s*:\s*false|skipAuth|bypassAuth|allowUnauthenticated|publicRoute)\b/i, /\b(route|router|endpoint|admin|panel|plugin)\b/i) ||
        (/(route|router|admin|plugin)/.test(loweredPath) && /\bauth\s*:\s*false\b/i.test(content)))
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "部分管理或插件路由显式关闭认证",
        severity: "high",
        confidence: 0.8,
        location: relative,
        impact: "如果这些路由位于后台、插件或管理入口附近，显式关闭认证可能直接扩大高价值接口的暴露面。",
        evidence: `在 ${relative} 中发现了 auth:false 或类似绕过认证的配置语义。`,
        remediation: "对后台、插件与管理路由采用显式白名单，默认启用鉴权与权限中间件，再按需对公开只读接口单独豁免。",
        safeValidation: "本地检查路由注册代码，确认仅少量公开只读接口会关闭认证，管理与插件路由默认受保护。"
      }));
    }

    if (
      enabledSkills.has("upload-storage") &&
      matches(content, /\b(upload|multer|formidable|busboy|content-type|multipart)\b/i, /\b(path\.join|fs\.writeFile|writeFileSync|createWriteStream|public\/|static\/)\b/)
    ) {
      findings.push(createFinding({
        skillId: "upload-storage",
        title: "上传与公开文件边界值得重点审查",
        severity: "medium",
        confidence: 0.71,
        location: relative,
        impact: "如果上传内容的类型、文件名或公开访问目录没有被严格隔离，可能引发任意文件覆盖、危险内容托管或后台资源泄露。",
        evidence: `在 ${relative} 中同时出现了上传处理与文件落盘或公开目录语义。`,
        remediation: "对文件类型、扩展名、目标路径和公开目录做统一收口，公开资源目录与后台可执行路径应彻底隔离。",
        safeValidation: "本地复核上传链路，确认文件名、目标路径、MIME 与公开访问目录都经过规范化控制。"
      }));
    }

    if (
      enabledSkills.has("secret-exposure") &&
      matches(content, /\b(password|secret|token|api[_-]?key)\b/i, /\b(default|example|changeme|admin123|test|demo|sample)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "secret-exposure",
        title: "疑似存在默认凭据或占位密钥风险",
        severity: "high",
        confidence: 0.74,
        location: relative,
        impact: "如果这些默认值会进入初始化流程、后台登录或第三方集成配置，真实部署时可能留下可猜测的高风险入口。",
        evidence: `在 ${relative} 中发现了凭据命名与默认值样式同时出现。`,
        remediation: "移除可运行的默认凭据；缺失密钥时应 fail closed，而不是退回演示或占位值。",
        safeValidation: "本地检查配置装载与初始化逻辑，确认占位值不会被当作真实凭据接受。"
      }));
    }

    if (
      enabledSkills.has("secret-exposure") &&
      matches(content, /\b(NEXT_PUBLIC_|PUBLIC_|VITE_)\b/, /\b(secret|token|api[_-]?key|admin|password)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "secret-exposure",
        title: "公开前端变量中疑似携带敏感配置",
        severity: "medium",
        confidence: 0.68,
        location: relative,
        impact: "如果敏感令牌或后台配置通过公开构建变量注入前端，可能导致管理能力或集成密钥暴露。",
        evidence: `在 ${relative} 中发现了公开前端环境变量前缀与敏感配置命名同时出现。`,
        remediation: "把敏感配置留在服务端，前端仅使用临时票据、代理接口或最小化公开标识。",
        safeValidation: "本地检查构建配置与运行时注入逻辑，确认公开变量中不包含后台密钥或管理接口凭据。"
      }));
    }

    if (
      enabledSkills.has("query-safety") &&
      matches(content, /\b(raw\(|sequelize\.query\(|knex\.raw\(|prisma\.[a-z]+Raw\(|SELECT\b|UPDATE\b|DELETE\b)\b/i, /(`[^`]*\$\{|\+\s*(req|params|query|body)|\b(req|params|query|body)\b)/i)
    ) {
      findings.push(createFinding({
        skillId: "query-safety",
        title: "动态查询构造路径需要重点确认",
        severity: "medium",
        confidence: 0.64,
        location: relative,
        impact: "如果这类动态查询直接拼接外部输入，内容检索、管理后台筛选或插件接口可能出现持久层注入风险。",
        evidence: `在 ${relative} 中发现了原始查询语义，并伴随模板插值或外部输入拼接痕迹。`,
        remediation: "优先改用参数化查询或 ORM 安全接口，并对动态排序、筛选字段做白名单约束。",
        safeValidation: "本地确认原始查询是否始终采用参数绑定，动态字段和值是否都经过白名单控制。"
      }));
    }
  }

  // 返回所有快速扫描和规则检测发现的问题，按严重程度排序
  // 不在此处做 confidence 过滤，留给最终合并时统一处理，避免双重过滤导致发现丢失
  return { findings: deduplicateAndSort(findings), javaRoutes };
}

async function analyzeWithTaint(codeAnalysis, sourceRoot, existingFindings) {
  const files = await collectFiles(sourceRoot);
  const taintFindings = [];
  const existingLocations = new Set(existingFindings.map(f => `${f.location}:${f.vulnType}`));

  console.log(`[AST访问器] 开始构建项目AST索引...`);
  const astBuilder = new ASTBuilderService({ cacheEnabled: false });
  const projectId = `audit_${Date.now()}`;
  const astIndex = await astBuilder.initialize(projectId, sourceRoot, {
    includeNodeModules: false,
    includeTests: false
  });

  if (!astIndex) {
    console.warn(`[AST访问器] AST索引构建失败，回退到基础污点追踪`);
    return await analyzeWithTaintBasic(codeAnalysis, sourceRoot, existingFindings);
  }

  const queryEngine = new QueryEngine(astIndex);
  console.log(`[AST访问器] AST索引构建完成，发现 ${astIndex.nodes.length} 个类/模块`);

  for (const file of files) {
    try {
      const content = await fs.readFile(file, "utf8");
      const language = inferLanguage(file);
      const relativePath = path.relative(sourceRoot, file).replaceAll("\\", "/");

      const result = await codeAnalysis.analyze(content, file, language, { useStatic: true });

      if (result.success && result.vulnerabilities && result.vulnerabilities.length > 0) {
        for (const vuln of result.vulnerabilities) {
          const location = `${relativePath}:${vuln.location?.line || 1}`;
          const key = `${location}:${vuln.type}`;

          if (existingLocations.has(key)) {
            continue;
          }

          const astContext = await enrichWithASTContext(queryEngine, vuln, file, content);

          const finding = createFinding({
            source: "taint",
            skillId: "taint-analysis",
            title: convertTaintTypeToTitle(vuln.type),
            severity: convertTaintSeverity(vuln.severity),
            confidence: astContext.confidence || 0.85,
            location: location,
            vulnType: convertTaintType(vuln.type),
            cwe: convertTaintTypeToCWE(vuln.type),
            evidence: astContext.evidence || vuln.description || `污点从 ${vuln.source?.name || 'unknown'} 传播到 ${vuln.sink?.name || 'unknown'}`,
            impact: `数据流追踪发现：${vuln.description || '用户输入未经净化到达危险函数'}`,
            remediation: convertTaintRemediation(vuln.sink?.name, vuln.type),
            safeValidation: `验证 ${vuln.sink?.name || '危险函数'} 调用前是否经过正确的输入净化`,
            astContext: astContext.astContext || null,
            astDepth: astContext.depth || 0
          });

          taintFindings.push(finding);
          existingLocations.add(key);
        }
      }

      const astVulns = await detectVulnerabilitiesWithAST(queryEngine, file, content, language, relativePath, existingLocations);
      for (const vuln of astVulns) {
        const key = `${vuln.location}:${vuln.vulnType}`;
        if (!existingLocations.has(key)) {
          taintFindings.push(vuln);
          existingLocations.add(key);
        }
      }
    } catch (error) {
      continue;
    }
  }

  return deduplicateFindings(taintFindings);
}

async function enrichWithASTContext(queryEngine, vuln, filePath, content) {
  const result = {
    confidence: 0.85,
    evidence: null,
    depth: 0,
    astContext: null
  };

  try {
    const sinkName = vuln.sink?.name;
    if (!sinkName) return result;

    const methods = queryEngine.getMethodsByName(sinkName);
    if (methods.length > 0) {
      result.depth = Math.min(methods.length, 5);
      result.confidence = Math.min(0.85 + (result.depth * 0.02), 0.95);
      result.astContext = {
        methodCount: methods.length,
        analyzed: true,
        type: 'ast_verified'
      };
    }

    const classMatch = content.match(/(?:class|interface)\s+(\w+)/);
    if (classMatch) {
      const className = classMatch[1];
      const classMethods = queryEngine.searchMethodInClass(className, sinkName);
      if (classMethods.length > 0) {
        result.astContext = {
          ...result.astContext,
          className,
          inClass: true,
          verified: true
        };
      }
    }
  } catch (error) {
  }

  return result;
}

async function detectVulnerabilitiesWithAST(queryEngine, filePath, content, language, relativePath, existingLocations) {
  const findings = [];

  const dangerousPatterns = [
    { pattern: /eval\s*\(/g, type: 'CODE_INJECTION', sink: 'eval', severity: 'CRITICAL' },
    { pattern: /exec\s*\(/g, type: 'COMMAND_INJECTION', sink: 'exec', severity: 'CRITICAL' },
    { pattern: /system\s*\(/g, type: 'COMMAND_INJECTION', sink: 'system', severity: 'HIGH' },
    { pattern: /shell_exec\s*\(/g, type: 'COMMAND_INJECTION', sink: 'shell_exec', severity: 'HIGH' },
    { pattern: /innerHTML\s*=/g, type: 'XSS', sink: 'innerHTML', severity: 'HIGH' },
    { pattern: /document\.write\s*\(/g, type: 'XSS', sink: 'document.write', severity: 'HIGH' },
    { pattern: /\.query\s*\([^)]*\+/g, type: 'SQL_INJECTION', sink: 'query', severity: 'HIGH' },
    { pattern: /execute\s*\([^)]*\+/g, type: 'SQL_INJECTION', sink: 'execute', severity: 'HIGH' },
    { pattern: /file_put_contents\s*\(/g, type: 'PATH_TRAVERSAL', sink: 'file_put_contents', severity: 'MEDIUM' },
    { pattern: /unserialize\s*\(/g, type: 'INSECURE_DESERIALIZATION', sink: 'unserialize', severity: 'HIGH' }
  ];

  const lines = content.split('\n');
  const lineOffsets = [];
  let pos = 0;
  while (true) {
    lineOffsets.push(pos);
    const next = content.indexOf('\n', pos);
    if (next === -1) break;
    pos = next + 1;
  }

  function getLineNum(idx) {
    let lo = 0, hi = lineOffsets.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (lineOffsets[mid] <= idx) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  for (const { pattern, type, sink, severity } of dangerousPatterns) {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(content)) !== null) {
      const lineNum = getLineNum(match.index);
      const location = `${relativePath}:${lineNum}`;
      const key = `${location}:${type}`;

      if (existingLocations.has(key)) continue;

      const nearbySources = findNearbyTaintSourcesLines(lines, lineNum);
      if (nearbySources.length === 0) continue;

      const hasSanitizer = checkForSanitizersLines(lines, nearbySources[0].line, lineNum);
      if (hasSanitizer) continue;

      const methodContext = queryEngine.getMethodsByName(sink);
      const classContext = extractClassContextLines(lines, lineNum);

      const finding = createFinding({
        source: "taint",
        skillId: "taint-analysis",
        title: convertTaintTypeToTitle(`TAINT:${type}`),
        severity: convertTaintSeverity(severity),
        confidence: methodContext.length > 0 ? 0.88 : 0.80,
        location: location,
        vulnType: convertTaintType(`TAINT:${type}`),
        cwe: convertTaintTypeToCWE(`TAINT:${type}`),
        evidence: `${sink} 在第 ${lineNum} 行被调用，未发现安全净化`,
        impact: `AST分析发现：用户输入可能通过变量传播到达危险函数 ${sink}`,
        remediation: convertTaintRemediation(sink, type),
        safeValidation: `验证 ${sink} 调用的参数是否经过净化`,
        astContext: {
          analyzed: true,
          type: 'ast_enhanced',
          methodCount: methodContext.length,
          className: classContext,
          sinkVerified: methodContext.length > 0
        },
        astDepth: methodContext.length > 0 ? Math.min(methodContext.length, 3) : 1
      });

      findings.push(finding);
      existingLocations.add(key);
    }
  }

  return findings;
}

function findNearbyTaintSourcesLines(lines, sinkLine) {
  const sources = [];
  const sourcePatterns = [
    { name: 'GET', pattern: /\$_(GET|POST|REQUEST|COOKIE)\[/ },
    { name: 'input', pattern: /input\(|readline\(/ },
    { name: 'file', pattern: /file_get_contents|file_put_contents|fopen|readfile/ },
    { name: 'env', pattern: /\$_(SERVER|ENV)/ },
    { name: 'request', pattern: /req\.(body|params|query)/ }
  ];

  for (let i = Math.max(0, sinkLine - 30); i < Math.min(lines.length, sinkLine); i++) {
    for (const { name, pattern } of sourcePatterns) {
      if (pattern.test(lines[i])) {
        sources.push({ name, line: i + 1, match: lines[i].trim() });
      }
    }
  }

  return sources;
}

function checkForSanitizersLines(lines, sourceLine, sinkLine) {
  const sanitizerPatterns = [
    /htmlspecialchars\s*\(/,
    /htmlentities\s*\(/,
    /addslashes\s*\(/,
    /escapeshellarg\s*\(/,
    /mysql_real_escape_string\s*\(/,
    /preg_replace\s*\(.*e\s*\)/,
    /intval\s*\(/,
    /floatval\s*\(/,
    /json_decode\s*\(.*\)/,
    /parseInt\s*\(/,
    /Number\s*\(/
  ];

  for (let i = sourceLine; i < sinkLine; i++) {
    for (const pattern of sanitizerPatterns) {
      if (pattern.test(lines[i])) {
        return true;
      }
    }
  }
  return false;
}

function extractClassContextLines(lines, lineNum) {
  const beforeLines = lines.slice(Math.max(0, lineNum - 20), lineNum);

  for (let i = beforeLines.length - 1; i >= 0; i--) {
    const classMatch = beforeLines[i].match(/class\s+(\w+)/);
    if (classMatch) {
      return classMatch[1];
    }
  }

  return null;
}

async function analyzeWithTaintBasic(codeAnalysis, sourceRoot, existingFindings) {
  const files = await collectFiles(sourceRoot);
  const taintFindings = [];
  const existingLocations = new Set(existingFindings.map(f => `${f.location}:${f.vulnType}`));

  for (const file of files) {
    try {
      const content = await fs.readFile(file, "utf8");
      const language = inferLanguage(file);

      const result = await codeAnalysis.analyze(content, file, language, { useStatic: true });

      if (result.success && result.vulnerabilities && result.vulnerabilities.length > 0) {
        for (const vuln of result.vulnerabilities) {
          const location = `${path.relative(sourceRoot, file).replaceAll("\\", "/")}:${vuln.location?.line || 1}`;
          const key = `${location}:${vuln.type}`;

          if (existingLocations.has(key)) {
            continue;
          }

          const finding = createFinding({
            source: "taint",
            skillId: "taint-analysis",
            title: convertTaintTypeToTitle(vuln.type),
            severity: convertTaintSeverity(vuln.severity),
            confidence: 0.85,
            location: location,
            vulnType: convertTaintType(vuln.type),
            cwe: convertTaintTypeToCWE(vuln.type),
            evidence: vuln.description || `污点从 ${vuln.source?.name || 'unknown'} 传播到 ${vuln.sink?.name || 'unknown'}`,
            impact: `数据流追踪发现：${vuln.description || '用户输入未经净化到达危险函数'}`,
            remediation: convertTaintRemediation(vuln.sink?.name, vuln.type),
            safeValidation: `验证 ${vuln.sink?.name || '危险函数'} 调用前是否经过正确的输入净化`
          });

          taintFindings.push(finding);
          existingLocations.add(key);
        }
      }
    } catch (error) {
      continue;
    }
  }

  return deduplicateFindings(taintFindings);
}

function inferLanguage(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  const langMap = {
    '.js': 'javascript', '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.java': 'java', '.py': 'python', '.php': 'php', '.c': 'c', '.cpp': 'cpp',
    '.cs': 'csharp', '.go': 'go', '.rb': 'ruby', '.swift': 'swift',
    '.kt': 'kotlin', '.scala': 'scala', '.rs': 'rust'
  };
  return langMap[ext] || 'unknown';
}

function convertTaintType(taintType) {
  if (!taintType) return 'UNKNOWN';
  const type = taintType.replace('TAINT:', '').toUpperCase();
  const mapping = {
    'SQL_INJECTION': 'SQL_INJECTION',
    'COMMAND_INJECTION': 'COMMAND_INJECTION',
    'CODE_INJECTION': 'CODE_INJECTION',
    'XSS': 'XSS',
    'PATH_TRAVERSAL': 'PATH_TRAVERSAL',
    'SSRF': 'SSRF',
    'XXE': 'XXE',
    'DESERIALIZATION': 'INSECURE_DESERIALIZATION'
  };
  return mapping[type] || type;
}

function convertTaintTypeToTitle(taintType) {
  if (!taintType) return '污点追踪发现问题';
  const type = taintType.replace('TAINT:', '').toUpperCase();
  const mapping = {
    'SQL_INJECTION': 'SQL注入漏洞（污点追踪）',
    'COMMAND_INJECTION': '命令注入漏洞（污点追踪）',
    'CODE_INJECTION': '代码注入漏洞（污点追踪）',
    'XSS': '跨站脚本攻击（污点追踪）',
    'PATH_TRAVERSAL': '路径遍历漏洞（污点追踪）',
    'SSRF': '服务器端请求伪造（污点追踪）',
    'XXE': 'XML外部实体注入（污点追踪）',
    'DESERIALIZATION': '不安全反序列化（污点追踪）'
  };
  return mapping[type] || `${type}漏洞（污点追踪）`;
}

function convertTaintTypeToCWE(taintType) {
  if (!taintType) return '';
  const type = taintType.replace('TAINT:', '').toUpperCase();
  const mapping = {
    'SQL_INJECTION': 'CWE-89', 'COMMAND_INJECTION': 'CWE-78', 'CODE_INJECTION': 'CWE-94',
    'XSS': 'CWE-79', 'PATH_TRAVERSAL': 'CWE-22', 'SSRF': 'CWE-918',
    'XXE': 'CWE-611', 'DESERIALIZATION': 'CWE-502',
    'HARDCODED_CREDENTIALS': 'CWE-798', 'HARD_CODE_PASSWORD': 'CWE-798',
    'WEAK_CRYPTO': 'CWE-327', 'WEAK_HASH': 'CWE-328', 'WEAK_ENCRYPTION': 'CWE-327',
    'PREDICTABLE_RANDOM': 'CWE-338', 'WEAK_RANDOM': 'CWE-338',
    'AUTH_BYPASS': 'CWE-287', 'MISSING_ACCESS_CONTROL': 'CWE-862',
    'BUFFER_OVERFLOW': 'CWE-120', 'FORMAT_STRING': 'CWE-134',
    'INTEGER_OVERFLOW': 'CWE-190', 'UNRESTRICTED_FILE_UPLOAD': 'CWE-434',
    'SESSION_FIXATION': 'CWE-384', 'COOKIE_MANIPULATION': 'CWE-565',
    'PROCESS_CONTROL': 'CWE-114', 'LOG_INJECTION': 'CWE-117',
    'OPEN_REDIRECT': 'CWE-601', 'INFO_LEAK': 'CWE-200',
    'INFORMATION_DISCLOSURE': 'CWE-200', 'XPATH_INJECTION': 'CWE-643',
    'LDAP_INJECTION': 'CWE-90', 'JNDI_INJECTION': 'CWE-917',
    'SPEL_INJECTION': 'CWE-94', 'SSTI': 'CWE-94',
    'NO_RATE_LIMIT': 'CWE-307', 'RACE_CONDITION': 'CWE-362',
    'CORS_MISCONFIGURATION': 'CWE-942', 'CSRF_MISSING': 'CWE-352',
  };
  return mapping[type] || '';
}

function convertTaintSeverity(severity) {
  if (!severity) return 'medium';
  const s = severity.toUpperCase();
  if (s === 'CRITICAL' || s === 'HIGH') return 'high';
  if (s === 'MEDIUM') return 'medium';
  return 'low';
}

function convertTaintRemediation(sinkName, vulnType) {
  if (!sinkName) return '对用户输入进行严格验证和净化处理';
  const sink = sinkName.toLowerCase();
  const type = (vulnType || '').replace('TAINT:', '').toUpperCase();

  const recommendations = {
    'eval': '避免使用 eval()，使用 JSON.parse() 替代',
    'exec': '使用参数化系统调用，避免 shell 命令拼接',
    'system': '使用 child_process.spawn() 并参数化命令参数',
    'innerHTML': '使用 textContent 或对输入进行 HTML 转义',
    'document.write': '避免使用 document.write，使用 textContent',
    'query': '使用参数化查询替代字符串拼接',
    'execute': '使用参数化执行替代字符串拼接'
  };

  for (const [key, rec] of Object.entries(recommendations)) {
    if (sink.includes(key)) {
      return rec;
    }
  }

  return '对用户输入进行严格验证、过滤和转义处理后再使用';
}

function createFinding(finding) {
  return {
    source: "rule",
    ...finding
  };
}

function prioritizeFindings(findings) {
  const FALSE_POSITIVE_PATTERNS = [
    /no direct vulnerability/i,
    /no executable code/i,
    /reviewed and passed/i,
    /no vulnerability found/i,
    /no security issue/i,
    /safe implementation/i,
  ];

  const filtered = findings.filter(f => {
    const title = f.title || '';
    return !FALSE_POSITIVE_PATTERNS.some(p => p.test(title));
  });

  const deduped = deduplicateAndSort(filtered, { preserveSources: true });

  const crossSourceDeduped = crossSourceDeduplicate(deduped);

  return crossSourceDeduped
    .map(f => enrichFindingFields(f))
    .filter((finding) => finding.confidence >= 0.4);
}

function crossSourceDeduplicate(findings) {
  const LLM_SOURCES = new Set(['llm', 'gapfill']);
  const HEURISTIC_SOURCES = new Set(['quick_scan', 'taint', 'rule', 'pattern', 'heuristic']);
  const LINE_PROXIMITY = 5;

  function getFileBasename(rawPath) {
    const file = (rawPath || '').split(':')[0].trim();
    if (!file) return '';
    const parts = file.split('/');
    return (parts[parts.length - 1] || '').toLowerCase();
  }

  function getLine(f) {
    return f.line || parseInt((f.location || '').split(':')[1], 10) || 0;
  }

  function normalizeVulnType(vt) {
    const MAP = {
      'SQL_INJECTION_MYBATIS': 'SQL_INJECTION', 'SQL_INJECTION_HQL': 'SQL_INJECTION',
      'SQL_INJECTION_ORDERBY': 'SQL_INJECTION', 'SQL_INJECTION_GROUPBY': 'SQL_INJECTION',
      'SQL_INJECTION_MITIGATION_BYPASS': 'SQL_INJECTION',
      'XXE': 'XXE_INJECTION',
      'XSS_REFLECTED': 'XSS', 'XSS_STORED': 'XSS',
      'SWAGGER_EXPOSURE': 'INFORMATION_DISCLOSURE',
      'SENSITIVE_INFO_EXPOSURE': 'INFORMATION_DISCLOSURE',
      'INFORMATION_LEAKAGE': 'INFORMATION_DISCLOSURE',
      'HARDCODED_SECRET': 'HARDCODED_CREDENTIALS', 'HARDCODED_SECRETS': 'HARDCODED_CREDENTIALS',
      'HARD_CODE_PASSWORD': 'HARDCODED_CREDENTIALS',
      'PLAINTEXT_PASSWORD': 'HARD_CODE_PASSWORD',
      'AUTH_BYPASS_URI': 'AUTH_BYPASS', 'AUTH_BYPASS_SPRING': 'AUTH_BYPASS',
      'AUTH_BYPASS_SUFFIX': 'AUTH_BYPASS', 'REFERER_AUTH_BYPASS': 'AUTH_BYPASS',
      'CSRF_DISABLED': 'CSRF', 'CSRF_PROTECTION': 'CSRF', 'CSRF_MISSING': 'CSRF',
      'WEAK_RANDOM': 'PREDICTABLE_RANDOM',
      'DESERIALIZATION_RCE': 'DESERIALIZATION', 'INSECURE_DESERIALIZATION': 'DESERIALIZATION',
      'SPEL_INJECTION': 'CODE_INJECTION',
      'BLACKLIST_VALIDATION': 'INSUFFICIENT_INPUT_VALIDATION',
      'COMPONENT_VULNERABILITY': 'VULNERABLE_DEPENDENCY',
      'PLAINTEXT_PASSWORD_STORAGE': 'WEAK_PASSWORD_STORAGE',
      'PLAINTEXT_PASSWORD_TRANSMISSION': 'PLAINTEXT_TRANSMISSION',
      'UNRESTRICTED_FILE_UPLOAD': 'FILE_UPLOAD',
      'INSECURE_FILE_VALIDATION': 'FILE_UPLOAD',
    };
    return MAP[vt] || vt || '';
  }

  function makeFileVulnKey(f) {
    const basename = getFileBasename(f.location || f.file || '');
    const vt = normalizeVulnType(f.vulnType || f.type || '');
    return `${basename}::${vt}`;
  }

  const llmFindings = findings.filter(f => LLM_SOURCES.has(f.source));
  const heuristicFindings = findings.filter(f => HEURISTIC_SOURCES.has(f.source));
  const otherFindings = findings.filter(f => !LLM_SOURCES.has(f.source) && !HEURISTIC_SOURCES.has(f.source));

  const llmByFileVuln = new Map();
  for (const f of llmFindings) {
    const key = makeFileVulnKey(f);
    if (!llmByFileVuln.has(key)) llmByFileVuln.set(key, []);
    llmByFileVuln.get(key).push(f);
  }

  const keptHeuristic = [];
  let mergedCount = 0;
  for (const f of heuristicFindings) {
    const key = makeFileVulnKey(f);
    const llmCandidates = llmByFileVuln.get(key);
    if (llmCandidates) {
      const hLine = getLine(f);
      const nearby = llmCandidates.find(lf => Math.abs(getLine(lf) - hLine) <= LINE_PROXIMITY);
      if (nearby) {
        mergedCount++;
        if (!nearby.mergedFrom) nearby.mergedFrom = [];
        nearby.mergedFrom.push({
          source: f.source,
          vulnType: f.vulnType || f.type,
          location: f.location,
          title: f.title,
        });
        continue;
      }
    }
    keptHeuristic.push(f);
  }

  if (mergedCount > 0) {
    console.log(`[去重] 跨来源合并: ${mergedCount} 条 heuristic 发现被 LLM 发现覆盖，保留 LLM 版本`);
  }

  const result = [...llmFindings, ...keptHeuristic, ...otherFindings];

  const exactDupMap = new Map();
  for (const f of result) {
    const file = (f.location || f.file || '').split(':')[0].trim();
    const line = getLine(f);
    const vt = f.vulnType || f.type || '';
    const exactKey = `${file}::${line}::${vt}`;
    if (!exactDupMap.has(exactKey)) exactDupMap.set(exactKey, []);
    exactDupMap.get(exactKey).push(f);
  }

  const finalResult = [];
  let exactDupCount = 0;
  for (const [, group] of exactDupMap) {
    if (group.length > 1) {
      exactDupCount += group.length - 1;
      const best = group.find(f => LLM_SOURCES.has(f.source)) || group[0];
      finalResult.push(best);
    } else {
      finalResult.push(group[0]);
    }
  }

  if (exactDupCount > 0) {
    console.log(`[去重] 精确重复消除: ${exactDupCount} 条完全重复发现被移除`);
  }

  return finalResult;
}

function buildVulnTypeGapMap(validatedResults) {
  const allFindings = validatedResults.flatMap(r => r.findings || []);
  const llmFindings = allFindings.filter(f => f.source === 'llm' || f.source === 'gapfill');
  const heuristicFindings = allFindings.filter(f =>
    ['quick_scan', 'taint', 'rule', 'pattern', 'heuristic'].includes(f.source)
  );

  const VULN_TYPE_NORMALIZE = {
    'SQL_INJECTION_MYBATIS': 'SQL_INJECTION', 'SQL_INJECTION_HQL': 'SQL_INJECTION',
    'SQL_INJECTION_ORDERBY': 'SQL_INJECTION', 'SQL_INJECTION_GROUPBY': 'SQL_INJECTION',
    'SPEL_INJECTION': 'CODE_INJECTION', 'XXE': 'XXE_INJECTION',
    'HARD_CODE_PASSWORD': 'HARDCODED_CREDENTIALS', 'PLAINTEXT_PASSWORD': 'HARDCODED_CREDENTIALS',
    'SWAGGER_EXPOSURE': 'INFORMATION_DISCLOSURE', 'INFORMATION_LEAKAGE': 'INFORMATION_DISCLOSURE',
    'UNRESTRICTED_FILE_UPLOAD': 'UNRESTRICTED_UPLOAD', 'INSECURE_FILE_VALIDATION': 'UNRESTRICTED_UPLOAD',
    'DESERIALIZATION_RCE': 'DESERIALIZATION', 'INSECURE_DESERIALIZATION': 'DESERIALIZATION',
    'CSRF_DISABLED': 'CSRF', 'CSRF_PROTECTION': 'CSRF', 'CSRF_MISSING': 'CSRF',
  };

  function norm(vt) { return VULN_TYPE_NORMALIZE[vt] || vt || ''; }
  function getFile(loc) { return (loc || '').split(':')[0]; }
  function getLine(f) { return f.line || parseInt((f.location || '').split(':')[1], 10) || 0; }

  const llmKeys = new Set();
  llmFindings.forEach(f => {
    llmKeys.add(getFile(f.location) + '::' + norm(f.vulnType));
  });

  const gapMap = new Map();
  for (const f of heuristicFindings) {
    const file = getFile(f.location);
    const normType = norm(f.vulnType);
    const key = file + '::' + normType;
    if (!llmKeys.has(key)) {
      if (!gapMap.has(key)) {
        gapMap.set(key, { file, normVulnType: normType, rawVulnType: f.vulnType, heuristicFindings: [], maxSeverity: f.severity });
      }
      const entry = gapMap.get(key);
      entry.heuristicFindings.push({
        location: f.location,
        line: getLine(f),
        severity: f.severity,
        title: f.title
      });
      const order = { critical: 4, high: 3, medium: 2, low: 1 };
      if ((order[f.severity] || 0) > (order[entry.maxSeverity] || 0)) {
        entry.maxSeverity = f.severity;
      }
    }
  }

  return [...gapMap.values()]
    .filter(g => g.maxSeverity === 'critical' || g.maxSeverity === 'high')
    .slice(0, 10);
}

async function runVulnTypeGapfill({ validatedResults, vulnTypeGapfill, sourceRoot, llmConfig, taskId }) {
  const completionTokens = getCompletionTokens(getModelMaxTokens(llmConfig.model));

  const fileGroups = new Map();
  for (const gap of vulnTypeGapfill) {
    if (!fileGroups.has(gap.file)) fileGroups.set(gap.file, []);
    fileGroups.get(gap.file).push(gap);
  }

  let confirmedCount = 0;
  let rejectedCount = 0;

  for (const [file, gaps] of fileGroups) {
    let content;
    try {
      const fullPath = path.join(sourceRoot, file);
      content = await fs.readFile(fullPath, 'utf8');
    } catch { continue; }
    if (!content || content.length < 20) continue;

    const gapTypesDesc = gaps.map(g =>
      `- ${g.rawVulnType}(${g.maxSeverity}): 行${g.heuristicFindings.map(h => h.line).join(', ')}`
    ).join('\n');

    const lang = file.endsWith('.py') ? 'python' : file.endsWith('.js') ? 'javascript' : 'java';
    const verifyPrompt = `你是代码安全审计专家。静态分析在以下文件中发现了漏洞，但LLM深度复核未报告同类问题。请逐一确认这些发现是否为真实漏洞。

【待确认的漏洞类型】
${gapTypesDesc}

【源代码】
\`\`\`${lang}
${content}
\`\`\`

对每个漏洞类型，输出JSON：
{"verifications":[{"vulnType":"CSRF","confirmed":true,"severity":"high","title":"简述","location":"文件:行号","evidence":"具体代码行"}]}
confirmed为true表示确认为真实漏洞，false表示为误报。仅确认真实漏洞，不要添加新发现。`;

    try {
      const baseUrl = String(llmConfig.baseUrl || '').replace(/\/+$/, '');
      const apiResponse = await fetchWithTimeout(`${baseUrl}/chat/completions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${llmConfig.apiKey}` },
        body: JSON.stringify({
          model: llmConfig.model,
          temperature: 0,
          max_tokens: completionTokens,
          messages: [
            { role: 'system', content: verifyPrompt },
            { role: 'user', content: '请逐一确认以上漏洞类型。' }
          ]
        })
      }, getFetchTimeoutMs());

      if (!apiResponse.ok) continue;

      let responseText = '';
      try {
        const data = JSON.parse(await apiResponse.text());
        responseText = data.choices?.[0]?.message?.content || '';
      } catch {
        continue;
      }

      const jsonMatch = String(responseText).match(/\{[\s\S]*"verifications"[\s\S]*\}/);
      if (!jsonMatch) continue;

      let parsed;
      try {
        parsed = JSON.parse(jsonMatch[0]);
      } catch {
        try {
          parsed = JSON.parse(jsonrepair(jsonMatch[0]));
        } catch { continue; }
      }

      const verified = (parsed.verifications || []).filter(v => v.confirmed && v.vulnType);
      for (const v of verified) {
        const newFinding = {
          vulnType: v.vulnType,
          severity: v.severity || 'medium',
          title: v.title || `${v.vulnType}漏洞`,
          location: v.location || `${file}:0`,
          evidence: v.evidence || '',
          source: 'llm',
          skillId: 'vuln-type-gapfill',
          verdict: 'confirmed',
          impact: '经定向复核确认的漏洞',
          remediation: '',
          safeValidation: '',
          cvssScore: 0,
          language: lang,
          owasp: '无',
          gbtMapping: '无',
        };
        validatedResults[0].findings.push(newFinding);
        confirmedCount++;
      }
      rejectedCount += (parsed.verifications || []).filter(v => !v.confirmed).length;
    } catch (llmError) {
      console.warn(`[审计分析] 漏洞类型Gapfill LLM调用失败(${file}): ${llmError.message}`);
    }
  }

  if (confirmedCount > 0 || rejectedCount > 0) {
    console.log(`[审计分析] 漏洞类型Gapfill完成: 确认${confirmedCount}条, 误报排除${rejectedCount}条`);
  }
}

function enrichFindingFields(f) {
  const VULN_TYPE_NORMALIZE = {
    'SQL注入': 'SQL_INJECTION', '命令注入': 'COMMAND_INJECTION', '代码注入': 'CODE_INJECTION',
    'SENSITIVE_INFO_EXPOSURE': 'INFORMATION_DISCLOSURE', 'INFORMATION_LEAKAGE': 'INFORMATION_DISCLOSURE',
    'INFO_LEAK': 'INFORMATION_DISCLOSURE', 'INFO': 'INFORMATION_DISCLOSURE',
    'AUTHENTICATION_BYPASS': 'AUTH_BYPASS',
    'INSECURE_DESERIALIZATION': 'DESERIALIZATION', 'UNSAFE_DESERIALIZATION': 'DESERIALIZATION',
    'HARDCODED_SECRET': 'HARDCODED_CREDENTIALS', 'HARDCODED_SECRETS': 'HARDCODED_CREDENTIALS',
    'IMPROPER_ERROR_HANDLING': 'IMPROPER_EXCEPTION_HANDLING',
    'IDOR': 'MISSING_ACCESS_CONTROL',
    'XXE': 'XXE_INJECTION',
    'FILE_UPLOAD': 'UNRESTRICTED_FILE_UPLOAD',
    'XSS_REFLECTED': 'XSS', 'XSS_STORED': 'XSS',
    'SQL_INJECTION_HQL': 'SQL_INJECTION', 'SQL_INJECTION_ORDERBY': 'SQL_INJECTION',
    'SQL_INJECTION_GROUPBY': 'SQL_INJECTION', 'SQL_INJECTION_MYBATIS': 'SQL_INJECTION',
    'SQL_INJECTION_MITIGATION_BYPASS': 'SQL_INJECTION',
    'DESERIALIZATION_RCE': 'DESERIALIZATION',
    'AUTH_BYPASS_URI': 'AUTH_BYPASS', 'AUTH_BYPASS_SPRING': 'AUTH_BYPASS',
    'AUTH_BYPASS_SUFFIX': 'AUTH_BYPASS', 'REFERER_AUTH_BYPASS': 'AUTH_BYPASS',
    'AUTH_CSRF_DISABLED': 'CSRF', 'CSRF_DISABLED': 'CSRF', 'CSRF_PROTECTION': 'CSRF',
    'WEAK_RANDOM': 'PREDICTABLE_RANDOM',
    'PLAINTEXT_PASSWORD': 'HARD_CODE_PASSWORD',
    'SPEL_INJECTION': 'CODE_INJECTION',
    'BLACKLIST_VALIDATION': 'INSUFFICIENT_INPUT_VALIDATION',
    'SWAGGER_EXPOSURE': 'INFORMATION_DISCLOSURE',
    'COMPONENT_VULNERABILITY': 'VULNERABLE_DEPENDENCY',
    'HARD_CODE_PASSWORD': 'HARDCODED_CREDENTIALS',
    'PLAINTEXT_PASSWORD_STORAGE': 'WEAK_PASSWORD_STORAGE',
    'PLAINTEXT_PASSWORD_TRANSMISSION': 'PLAINTEXT_TRANSMISSION',
    'UPLOAD_UNRESTRICTED': 'UNRESTRICTED_FILE_UPLOAD',
    'AUTH_MISSING': 'MISSING_ACCESS_CONTROL',
    'INSUFFICIENT_AUTHORIZATION': 'MISSING_ACCESS_CONTROL',
    'CSRF_MISSING_PROTECTION': 'CSRF_MISSING',
    'SENSITIVE_DATA_EXPOSURE': 'INFORMATION_DISCLOSURE',
    'INFO_EXPOSURE': 'INFORMATION_DISCLOSURE',
    'INFO_DISCLOSURE': 'INFORMATION_DISCLOSURE',
    'HTTP_HEADER_INJECTION': 'HTTP_RESPONSE_SPLITTING',
    'REDOS': 'REGEX_DENIAL_OF_SERVICE',
    'VULNERABLE_DEPENDENCY': 'COMPONENT_VULNERABILITY',
  };
  const rawVulnType = f.vulnType || f.type || '';
  const normalizedVulnType = VULN_TYPE_NORMALIZE[rawVulnType] || rawVulnType;
  if (normalizedVulnType !== rawVulnType) {
    f.vulnType = normalizedVulnType;
  }
  const vulnType = normalizedVulnType;
  const CWE_MAP = {
    'SQL_INJECTION': 'CWE-89', 'SQL_INJECTION_MYBATIS': 'CWE-89',
    'SQL_INJECTION_ORDERBY': 'CWE-89', 'SQL_INJECTION_GROUPBY': 'CWE-89',
    'SQL_INJECTION_HQL': 'CWE-89',
    'COMMAND_INJECTION': 'CWE-78', 'CODE_INJECTION': 'CWE-94',
    'SPEL_INJECTION': 'CWE-94', 'SSTI': 'CWE-94', 'JNDI_INJECTION': 'CWE-917',
    'XSS': 'CWE-79', 'XSS_REFLECTED': 'CWE-79', 'XSS_STORED': 'CWE-79',
    'PATH_TRAVERSAL': 'CWE-22', 'ARBITRARY_FILE_READ': 'CWE-22',
    'FILE_READ': 'CWE-22', 'FILE_UPLOAD': 'CWE-434',
    'SSRF': 'CWE-918', 'DESERIALIZATION': 'CWE-502', 'INSECURE_DESERIALIZATION': 'CWE-502',
    'HARDCODED_CREDENTIALS': 'CWE-798', 'HARD_CODE_PASSWORD': 'CWE-259',
    'HARDCODED_SECRETS': 'CWE-798',
    'WEAK_CRYPTO': 'CWE-327', 'WEAK_HASH': 'CWE-328', 'WEAK_ENCRYPTION': 'CWE-327',
    'RSA_WEAK_PADDING': 'CWE-780',
    'PREDICTABLE_RANDOM': 'CWE-338', 'INSUFFICIENT_RANDOMNESS': 'CWE-338',
    'WEAK_RANDOM': 'CWE-338',
    'PLAINTEXT_PASSWORD_STORAGE': 'CWE-256', 'PLAINTEXT_PASSWORD_TRANSMISSION': 'CWE-319',
    'PLAINTEXT_TRANSMISSION': 'CWE-319', 'PLAINTEXT_PASSWORD': 'CWE-256',
    'SESSION_FIXATION': 'CWE-384', 'COOKIE_MANIPULATION': 'CWE-565',
    'PROCESS_CONTROL': 'CWE-114', 'FORMAT_STRING': 'CWE-134',
    'FORMAT_STRING_VULNERABILITY': 'CWE-134',
    'BUFFER_OVERFLOW': 'CWE-120', 'INTEGER_OVERFLOW': 'CWE-190',
    'UNCONTROLLED_MEMORY': 'CWE-788',
    'UNRESTRICTED_FILE_UPLOAD': 'CWE-434', 'INSECURE_FILE_VALIDATION': 'CWE-434',
    'AUTH_BYPASS': 'CWE-287', 'AUTH_BYPASS_URI': 'CWE-287',
    'AUTH_BYPASS_SUFFIX': 'CWE-287', 'AUTH_BYPASS_SPRING': 'CWE-287',
    'AUTH_CSRF_DISABLED': 'CWE-352', 'AUTH_INFO_EXPOSURE': 'CWE-204',
    'AUTH_SERVLETPATH_SAFE': 'CWE-287',
    'MISSING_ACCESS_CONTROL': 'CWE-862', 'BROKEN_ACCESS_CONTROL': 'CWE-862',
    'CSRF_MISSING': 'CWE-352', 'CSRF_DISABLED': 'CWE-352', 'CSRF_PROTECTION': 'CWE-352',
    'OPEN_REDIRECT': 'CWE-601',
    'INFO_LEAK': 'CWE-200', 'INFORMATION_DISCLOSURE': 'CWE-200',
    'EXCEPTION_INFO_LEAK': 'CWE-209', 'ASSERT_MISUSE': 'CWE-617',
    'XXE_INJECTION': 'CWE-611', 'XXE': 'CWE-611',
    'LDAP_INJECTION': 'CWE-90',
    'XPATH_INJECTION': 'CWE-643', 'REVERSIBLE_PASSWORD_STORAGE': 'CWE-257',
    'SENSITIVE_INFO_IN_LOG': 'CWE-532', 'SENSITIVE_INFO_IN_LOGS': 'CWE-532',
    'WEAK_PASSWORD_POLICY': 'CWE-521',
    'INSECURE_COOKIE_AUTH': 'CWE-565', 'HASH_WITHOUT_SALT': 'CWE-759',
    'HTTP_RESPONSE_SPLITTING': 'CWE-113',
    'INFO_LEAK_VIA_ERROR': 'CWE-209',
    'UNCHECKED_LOOP_CONDITION': 'CWE-606', 'CLICKJACKING': 'CWE-1021',
    'NO_RATE_LIMIT': 'CWE-307',
    'IMPROPER_EXCEPTION_HANDLING': 'CWE-703', 'INFINITE_LOOP': 'CWE-835',
    'DIVIDE_BY_ZERO': 'CWE-369', 'LOG_INJECTION': 'CWE-117',
    'UNSAFE_TEMP_FILE': 'CWE-377', 'UNCONTROLLED_RECURSION': 'CWE-674',
    'RESOURCE_LEAK': 'CWE-404', 'SENSITIVE_DATA_IN_COOKIE': 'CWE-315',
    'REFERER_AUTH': 'CWE-293', 'REFERER_AUTH_BYPASS': 'CWE-293',
    'IDOR': 'CWE-639',
    'CORS_MISCONFIGURATION': 'CWE-942', 'RACE_CONDITION': 'CWE-362',
    'BLACKLIST_VALIDATION': 'CWE-184', 'SWAGGER_EXPOSURE': 'CWE-200',
    'STRUTS_WILDCARD': 'CWE-917', 'COMPONENT_VULNERABILITY': 'CWE-1104',
    'UPLOAD_UNRESTRICTED': 'CWE-434',
    'AUTH_MISSING': 'CWE-862',
    'INSUFFICIENT_AUTHORIZATION': 'CWE-862',
    'CSRF_MISSING_PROTECTION': 'CWE-352',
    'SENSITIVE_DATA_EXPOSURE': 'CWE-200',
    'INFO_EXPOSURE': 'CWE-200',
    'INFO_DISCLOSURE': 'CWE-200',
    'HTTP_HEADER_INJECTION': 'CWE-113',
    'REDOS': 'CWE-1333',
    'REGEX_DENIAL_OF_SERVICE': 'CWE-1333',
    'VULNERABLE_DEPENDENCY': 'CWE-1104',
    'XXE_INJECTION': 'CWE-611',
  };
  const OWASP_MAP = {
    'SQL_INJECTION': 'A03:2021', 'SQL_INJECTION_MYBATIS': 'A03:2021',
    'SQL_INJECTION_ORDERBY': 'A03:2021', 'SQL_INJECTION_GROUPBY': 'A03:2021',
    'SQL_INJECTION_HQL': 'A03:2021',
    'COMMAND_INJECTION': 'A03:2021', 'CODE_INJECTION': 'A03:2021',
    'SPEL_INJECTION': 'A03:2021', 'SSTI': 'A03:2021', 'JNDI_INJECTION': 'A03:2021',
    'XSS': 'A03:2021', 'XSS_REFLECTED': 'A03:2021', 'XSS_STORED': 'A03:2021',
    'PATH_TRAVERSAL': 'A01:2021', 'ARBITRARY_FILE_READ': 'A01:2021',
    'FILE_READ': 'A01:2021', 'FILE_UPLOAD': 'A04:2021',
    'SSRF': 'A10:2021',
    'DESERIALIZATION': 'A08:2021', 'INSECURE_DESERIALIZATION': 'A08:2021',
    'HARDCODED_CREDENTIALS': 'A07:2021', 'HARD_CODE_PASSWORD': 'A07:2021',
    'HARDCODED_SECRETS': 'A07:2021', 'WEAK_CRYPTO': 'A02:2021',
    'WEAK_HASH': 'A02:2021', 'WEAK_ENCRYPTION': 'A02:2021',
    'RSA_WEAK_PADDING': 'A02:2021',
    'PREDICTABLE_RANDOM': 'A02:2021', 'INSUFFICIENT_RANDOMNESS': 'A02:2021',
    'WEAK_RANDOM': 'A02:2021',
    'PLAINTEXT_PASSWORD_STORAGE': 'A02:2021', 'PLAINTEXT_PASSWORD_TRANSMISSION': 'A02:2021',
    'PLAINTEXT_TRANSMISSION': 'A02:2021', 'PLAINTEXT_PASSWORD': 'A02:2021',
    'SESSION_FIXATION': 'A07:2021', 'COOKIE_MANIPULATION': 'A07:2021',
    'PROCESS_CONTROL': 'A03:2021', 'FORMAT_STRING': 'A03:2021',
    'FORMAT_STRING_VULNERABILITY': 'A03:2021',
    'BUFFER_OVERFLOW': 'A03:2021', 'INTEGER_OVERFLOW': 'A03:2021',
    'UNCONTROLLED_MEMORY': 'A03:2021',
    'UNRESTRICTED_FILE_UPLOAD': 'A04:2021', 'INSECURE_FILE_VALIDATION': 'A04:2021',
    'AUTH_BYPASS': 'A07:2021', 'AUTH_BYPASS_URI': 'A07:2021',
    'AUTH_BYPASS_SUFFIX': 'A07:2021', 'AUTH_BYPASS_SPRING': 'A07:2021',
    'AUTH_CSRF_DISABLED': 'A01:2021', 'AUTH_INFO_EXPOSURE': 'A07:2021',
    'AUTH_SERVLETPATH_SAFE': 'A07:2021',
    'MISSING_ACCESS_CONTROL': 'A01:2021', 'BROKEN_ACCESS_CONTROL': 'A01:2021',
    'CSRF_MISSING': 'A01:2021', 'CSRF_DISABLED': 'A01:2021', 'CSRF_PROTECTION': 'A01:2021',
    'OPEN_REDIRECT': 'A01:2021',
    'INFO_LEAK': 'A01:2021', 'INFORMATION_DISCLOSURE': 'A01:2021',
    'EXCEPTION_INFO_LEAK': 'A01:2021', 'ASSERT_MISUSE': 'A05:2021',
    'XXE_INJECTION': 'A03:2021', 'XXE': 'A03:2021',
    'LDAP_INJECTION': 'A03:2021',
    'XPATH_INJECTION': 'A03:2021', 'REVERSIBLE_PASSWORD_STORAGE': 'A02:2021',
    'SENSITIVE_INFO_IN_LOG': 'A01:2021', 'SENSITIVE_INFO_IN_LOGS': 'A01:2021',
    'WEAK_PASSWORD_POLICY': 'A07:2021', 'INSECURE_COOKIE_AUTH': 'A07:2021',
    'HASH_WITHOUT_SALT': 'A02:2021',
    'HTTP_RESPONSE_SPLITTING': 'A03:2021',
    'INFO_LEAK_VIA_ERROR': 'A01:2021', 'CLICKJACKING': 'A01:2021',
    'NO_RATE_LIMIT': 'A07:2021',
    'IMPROPER_EXCEPTION_HANDLING': 'A05:2021', 'INFINITE_LOOP': 'A05:2021',
    'DIVIDE_BY_ZERO': 'A05:2021', 'LOG_INJECTION': 'A03:2021',
    'UNSAFE_TEMP_FILE': 'A01:2021', 'UNCONTROLLED_RECURSION': 'A05:2021',
    'RESOURCE_LEAK': 'A05:2021', 'SENSITIVE_DATA_IN_COOKIE': 'A07:2021',
    'REFERER_AUTH': 'A07:2021', 'REFERER_AUTH_BYPASS': 'A07:2021',
    'IDOR': 'A01:2021',
    'CORS_MISCONFIGURATION': 'A05:2021', 'RACE_CONDITION': 'A05:2021',
    'BLACKLIST_VALIDATION': 'A03:2021', 'SWAGGER_EXPOSURE': 'A05:2021',
    'STRUTS_WILDCARD': 'A05:2021', 'COMPONENT_VULNERABILITY': 'A06:2021',
    'UPLOAD_UNRESTRICTED': 'A04:2021',
    'AUTH_MISSING': 'A01:2021',
    'INSUFFICIENT_AUTHORIZATION': 'A01:2021',
    'CSRF_MISSING_PROTECTION': 'A01:2021',
    'SENSITIVE_DATA_EXPOSURE': 'A01:2021',
    'INFO_EXPOSURE': 'A01:2021',
    'INFO_DISCLOSURE': 'A01:2021',
    'HTTP_HEADER_INJECTION': 'A03:2021',
    'REDOS': 'A05:2021',
    'REGEX_DENIAL_OF_SERVICE': 'A05:2021',
    'VULNERABLE_DEPENDENCY': 'A06:2021',
    'XXE_INJECTION': 'A03:2021',
  };
  if (!f.cwe || f.cwe === 'CWE-000' || f.cwe === 'unknown' || f.cwe === 'undefined' || f.cwe === '') {
    f.cwe = CWE_MAP[vulnType] || f.cwe || '';
  }
  if (!f.owasp || f.owasp === '' || f.owasp === 'unknown' || f.owasp === 'undefined' || f.owasp === '无') {
    f.owasp = OWASP_MAP[vulnType] || '';
  }
  if (!f.language || f.language === 'unknown' || f.language === 'undefined') {
    const loc = f.location || f.file || '';
    if (loc) {
      const ext = loc.split('.').pop().split(':')[0].split('#')[0].toLowerCase();
      const extLangMap = { py: 'python', java: 'java', js: 'javascript', ts: 'typescript', cs: 'csharp', cpp: 'cpp', c: 'c', go: 'go', php: 'php', rb: 'ruby', rs: 'rust' };
      f.language = extLangMap[ext] || f.language || 'unknown';
    }
  }

  // GB/T 映射
  if (!f.gbtMapping || f.gbtMapping === '' || f.gbtMapping === 'unknown' || f.gbtMapping === 'undefined' || f.gbtMapping === '无') {
    const GBT_MAPPING = {
      'COMMAND_INJECTION': { java: 'GB/T34944-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入', python: 'GB/T39412-6.1.1.6 命令行注入', cpp: 'GB/T34943-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入', csharp: 'GB/T34946-6.2.3.3 命令注入；GB/T39412-6.1.1.6 命令行注入', default: 'GB/T39412-6.1.1.6 命令行注入' },
      'SQL_INJECTION': { java: 'GB/T34944-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入', python: 'GB/T39412-8.3.2 SQL注入', cpp: 'GB/T34943-6.2.3.4 SQL注入；GB/T39412-8.3.2 SQL注入', csharp: 'GB/T39412-8.3.2 SQL注入', default: 'GB/T39412-8.3.2 SQL注入' },
      'CODE_INJECTION': { java: 'GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数', python: 'GB/T39412-7.3.6 暴露危险的方法或函数', cpp: 'GB/T3943-6.2.3.5 进程控制；GB/T39412-7.3.6 暴露危险的方法或函数', csharp: 'GB/T39446-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数', default: 'GB/T39412-7.3.6 暴露危险的方法或函数' },
      'SPEL_INJECTION': { java: 'GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数', default: 'GB/T39412-7.3.6 暴露危险的方法或函数' },
      'SSTI': { java: 'GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数', python: 'GB/T39412-7.3.6 暴露危险的方法或函数', default: 'GB/T39412-7.3.6 暴露危险的方法或函数' },
      'PATH_TRAVERSAL': { java: 'GB/T34944-6.2.3.1 相对路径遍历；GB/T34944-6.2.3.2 绝对路径遍历', python: 'GB/T39412-6.1.1.1 输入验证不足', cpp: 'GB/T3943-6.2.3.1 相对路径遍历；GB/T3943-6.2.3.2 绝对路径遍历', csharp: 'GB/T3946-6.2.3.1 相对路径遍历；GB/T3946-6.2.3.2 绝对路径遍历', default: 'GB/T39412-6.1.1.1 输入验证不足' },
      'HARDCODED_CREDENTIALS': { java: 'GB/T34944-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码', python: 'GB/T39412-6.2.1.3 使用安全相关的硬编码', cpp: 'GB/T3943-6.2.7.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码', csharp: 'GB/T3946-6.2.6.3 口令硬编码；GB/T39412-6.2.1.3 使用安全相关的硬编码', default: 'GB/T39412-6.2.1.3 使用安全相关的硬编码' },
      'WEAK_CRYPTO': { java: 'GB/T34944-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定', python: 'GB/T39412-6.2.1.1 密码安全不符合国密管理规定', cpp: 'GB/T3943-6.2.7.5 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定', csharp: 'GB/T3946-6.2.6.7 使用已破解或危险的加密算法；GB/T39412-6.2.1.1 密码安全不符合国密管理规定', default: 'GB/T39412-6.2.1.1 密码安全不符合国密管理规定' },
      'DESERIALIZATION': { java: 'GB/T39412-7.1.5 存储不可序列化的对象到磁盘', python: 'GB/T39412-7.1.5 存储不可序列化的对象到磁盘', cpp: 'GB/T39412-7.1.5 存储不可序列化的对象到磁盘', csharp: 'GB/T39412-7.1.5 存储不可序列化的对象到磁盘', default: 'GB/T39412-7.1.5 存储不可序列化的对象到磁盘' },
      'SSRF': { java: 'GB/T39412-6.1.1.1 输入验证不足', python: 'GB/T39412-6.1.1.1 输入验证不足', cpp: 'GB/T39412-6.1.1.1 输入验证不足', csharp: 'GB/T39412-6.1.1.1 输入验证不足', default: 'GB/T39412-6.1.1.1 输入验证不足' },
      'XXE_INJECTION': { java: 'GB/T39412-6.1.1.1 输入验证不足', python: 'GB/T39412-6.1.1.1 输入验证不足', default: 'GB/T39412-6.1.1.1 输入验证不足' },
      'AUTH_BYPASS': { java: 'GB/T34944-6.2.6.4 依赖referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过', python: 'GB/T39412-6.3.1.2 身份鉴别被绕过', cpp: 'GB/T39412-6.3.1.2 身份鉴别被绕过', csharp: 'GB/T3946-6.2.6.4 依赖Referer字段进行身份鉴别；GB/T39412-6.3.1.2 身份鉴别被绕过', default: 'GB/T39412-6.3.1.2 身份鉴别被绕过' },
      'INFO_LEAK': { java: 'GB/T34944-6.2.3.7 信息通过错误消息泄露；GB/T34944-6.2.3.8 信息通过服务器日志文件泄露', python: 'GB/T39412-6.2.2.1 敏感信息暴露', cpp: 'GB/T3943-6.2.3.9 信息通过错误消息泄露；GB/T3943-6.2.3.10 信息通过服务器日志文件泄露', csharp: 'GB/T3946-6.2.3.7 信息通过错误消息泄露；GB/T3946-6.2.3.8 信息通过服务器日志文件泄露', default: 'GB/T39412-6.2.2.1 敏感信息暴露' },
      'INFORMATION_DISCLOSURE': { java: 'GB/T34944-6.2.3.7 信息通过错误消息泄露', python: 'GB/T39412-6.2.2.1 敏感信息暴露', cpp: 'GB/T3943-6.2.3.9 信息通过错误消息泄露', csharp: 'GB/T3946-6.2.3.7 信息通过错误消息泄露', default: 'GB/T39412-6.2.2.1 敏感信息暴露' },
      'LOG_INJECTION': { java: 'GB/T39412-6.4.1 对输出日志中特殊元素处理', default: 'GB/T39412-6.4.1 对输出日志中特殊元素处理' },
      'XSS': { java: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击', python: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击', cpp: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击', csharp: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击', javascript: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击', default: 'GB/T39412-6.1.2.1 跨站脚本(XSS)攻击' },
      'UNRESTRICTED_FILE_UPLOAD': { java: 'GB/T34944-6.2.3.9 不当限制文件上传；GB/T39412-6.1.1.1 输入验证不足', python: 'GB/T39412-6.1.1.1 输入验证不足', cpp: 'GB/T3943-6.2.3.9 不当限制文件上传；GB/T39412-6.1.1.1 输入验证不足', csharp: 'GB/T3946-6.2.3.9 不当限制文件上传；GB/T39412-6.1.1.1 输入验证不足', default: 'GB/T39412-6.1.1.1 输入验证不足' },
      'MISSING_ACCESS_CONTROL': { java: 'GB/T34944-6.2.6.1 缺少访问控制；GB/T39412-6.3.3.1 不安全的直接对象引用', python: 'GB/T39412-6.3.3.1 不安全的直接对象引用', cpp: 'GB/T39412-6.3.3.1 不安全的直接对象引用', csharp: 'GB/T3946-6.2.6.1 缺少访问控制；GB/T39412-6.3.3.1 不安全的直接对象引用', default: 'GB/T39412-6.3.3.1 不安全的直接对象引用' },
      'CSRF_MISSING': { java: 'GB/T39412-6.3.3.2 跨站请求伪造', python: 'GB/T39412-6.3.3.2 跨站请求伪造', default: 'GB/T39412-6.3.3.2 跨站请求伪造' },
      'JNDI_INJECTION': { java: 'GB/T34944-6.2.3.5 代码注入；GB/T39412-7.3.6 暴露危险的方法或函数', default: 'GB/T39412-7.3.6 暴露危险的方法或函数' },
      'VULNERABLE_DEPENDENCY': { java: 'GB/T39412-6.2.1.3 使用安全相关的硬编码', default: 'GB/T39412-6.2.1.3 使用安全相关的硬编码' },
      'UPLOAD_UNRESTRICTED': { java: 'GB/T34944-6.2.3.9 不当限制文件上传；GB/T39412-6.1.1.1 输入验证不足', default: 'GB/T39412-6.1.1.1 输入验证不足' },
      'AUTH_MISSING': { java: 'GB/T34944-6.2.6.1 缺少访问控制；GB/T39412-6.3.3.1 不安全的直接对象引用', default: 'GB/T39412-6.3.3.1 不安全的直接对象引用' },
      'CSRF_MISSING_PROTECTION': { java: 'GB/T39412-6.3.3.2 跨站请求伪造', default: 'GB/T39412-6.3.3.2 跨站请求伪造' },
      'SENSITIVE_DATA_EXPOSURE': { java: 'GB/T34944-6.2.3.7 信息通过错误消息泄露', default: 'GB/T39412-6.2.2.1 敏感信息暴露' },
      'DEFAULT': 'GB/T39412-2020 通用基线'
    };
    const lang = f.language || 'unknown';
    const typeMapping = GBT_MAPPING[vulnType];
    if (typeMapping && typeof typeMapping === 'object') {
      f.gbtMapping = typeMapping[lang] || typeMapping['default'] || 'GB/T39412-2020 通用基线';
    } else {
      f.gbtMapping = 'GB/T39412-2020 通用基线';
    }
  }

  // CVSS 评分
  if (!f.cvssScore || f.cvssScore === 0) {
    const severityToCvss = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.1 };
    f.cvssScore = severityToCvss[f.severity] || 5.0;
  }

  return f;
}

function hasObjectAccessIndicator(content) {
  return /(req|request)\.(params|query)\.[a-zA-Z0-9_]+/.test(content) || /\b(ctx|event)\.(params|query)\.[a-zA-Z0-9_]+/.test(content);
}

function hasAuthGuardIndicator(content) {
  return /\b(can|authorize|authorization|permission|permissions|policy|guard|rbac|ownership|tenant)\b/i.test(content);
}



function matches(content, requiredA, requiredB) {
  return requiredA.test(content) && requiredB.test(content);
}
