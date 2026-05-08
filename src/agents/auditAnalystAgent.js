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
import { deduplicateFindings, deduplicateAndSort, severityScore } from "../utils/findingsUtils.js";
import { collectFiles } from "../utils/fileUtils.js";
import { globalCheckpointManager, AuditState, AgentStatus } from "../core/stateManager.js";

const MAX_PARALLEL_PROJECTS = 2;

export class AuditAnalystAgent {
  constructor({ llmReviewer }) {
    this.llmReviewer = llmReviewer;
    this.quickScanService = new QuickScanService();
  }

  async run({ taskId, projects, selectedSkillIds, llmConfig, useReAct = false, reactConfig = {}, enableLlmAudit = true, onProgress, shouldCancel, tasks, onProjectGroupComplete }) {
    const reviewProfile = resolveAuditSkills(selectedSkillIds);
    const results = [];
    const isGbtAudit = reviewProfile.some(skill => skill.id === "gbt-code-audit");

    const auditState = new AuditState();
    auditState.agentId = `audit_${taskId}_${Date.now().toString(36)}`;
    auditState.task = `审计任务 ${taskId}`;
    auditState.taskContext = { taskId, projectCount: projects.length, selectedSkillIds };
    auditState.start();

    const CHECKPOINT_INTERVAL = 3;
    let checkpointCounter = 0;

    async function createCheckpoint(name) {
      try {
        checkpointCounter++;
        if (checkpointCounter % CHECKPOINT_INTERVAL === 0) {
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

      const heuristicFindings = await buildHeuristicFindings(project, reviewProfile);
  
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

      const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);

      const doAstEnhance = heuristicFindings.length > 0;
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
        if (useReAct && typeof this.llmReviewer.auditWithReAct === 'function') {
          llmAuditPromise = this.llmReviewer.auditWithReAct({
            project,
            selectedSkills: reviewProfile,
            llmConfig,
            reactConfig,
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

      onProgress?.({
        stage: "project-complete",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        heuristicCount: heuristicFindings.length,
        astEnhancedCount: astEnhancedFindings.length,
        llmCount: llmAudit?.findings?.length || 0,
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
        findings: mergedFindings
      };
    }

    for (let i = 0; i < projects.length; i += MAX_PARALLEL_PROJECTS) {
      const projectGroup = projects.slice(i, i + MAX_PARALLEL_PROJECTS);
      const currentStep = Math.floor(i / MAX_PARALLEL_PROJECTS) + 1;
      const totalSteps = Math.ceil(projects.length / MAX_PARALLEL_PROJECTS);

      auditState.updateProgress(currentStep, totalSteps, `处理项目组 ${currentStep}/${totalSteps}`);
      auditState.recordResourceUsage();

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
      
      return {
        ...result,
        findings: validated,
        validationStats: {
          total: result.findings.length,
          validated: validated.length,
          hallucinations: hallucinations.length,
          corrected: corrected.length
        },
        hallucinations
      };
    }));

    // 重新计算统计信息
    const totalValidated = validatedResults.reduce((sum, r) => sum + r.findings.length, 0);
    const totalHallucinations = validatedResults.reduce((sum, r) => sum + (r.hallucinations?.length || 0), 0);
    const totalCorrected = validatedResults.reduce((sum, r) => sum + (r.validationStats?.corrected || 0), 0);

    // 最终检查点
    auditState.status = AgentStatus.COMPLETED;
    auditState.findings = validatedResults.flatMap(r => r.findings || []);
    auditState.setCompleted({
      findingsCount: totalValidated,
      projectsCount: validatedResults.length
    });
    await createCheckpoint('final');

    const statusSummary = auditState.getStatusSummary?.();
    console.log(`[审计分析] 任务完成 - 状态摘要: ${JSON.stringify(statusSummary)}`);

    return {
      reviewedAt: new Date().toISOString(),
      policy: "defensive-only",
      skillsUsed: reviewProfile.map((skill) => ({ id: skill.id, name: skill.name })),
      findingsCount: totalValidated,
      checkpointId: auditState.agentId,
      heuristicFindingsCount: validatedResults.reduce((sum, item) => sum + item.heuristicFindings.length, 0),
      llmFindingsCount: validatedResults.reduce((sum, item) => sum + (item.llmAudit?.findings?.length || 0), 0),
      llmCallCount: validatedResults.reduce((sum, item) => sum + (item.llmAudit?.called ? 1 : 0), 0),
      llmSkippedCount: validatedResults.reduce((sum, item) => sum + (item.llmAudit?.called ? 0 : 1), 0),
      validationStats: {
        total: allFindings.length,
        validated: totalValidated,
        hallucinations: totalHallucinations,
        corrected: totalCorrected
      },
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
  const quickScanFindings = await quickScanService.scanProject(sourceRoot, (progress) => {
    console.log(`[快速扫描进度] ${progress.processedFiles}/${progress.totalFiles} 文件，当前: ${progress.currentFile}`);
  });
  console.log(`[审计分析] 快速扫描完成，发现 ${quickScanFindings.length} 个问题`);
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

  // 3. 外部工具扫描（Gitleaks/Bandit/Semgrep）（所有审计模式都执行）
  console.log(`[审计分析] 开始外部工具扫描`);
  const externalToolService = new ExternalToolService();
  const externalFindings = await externalToolService.scanAll(sourceRoot);
  console.log(`[审计分析] 外部工具扫描完成，发现 ${externalFindings.length} 个问题`);
  findings.push(...externalFindings);

  // 收集文件用于规则检测
  const files = await collectFiles(sourceRoot);
  console.log(`[审计分析] 收集到 ${files.length} 个文件用于规则检测`);

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
  return prioritizeFindings(findings);
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

  for (const { pattern, type, sink, severity } of dangerousPatterns) {
    let match;
    const regex = new RegExp(pattern.source, pattern.flags);
    while ((match = regex.exec(content)) !== null) {
      const lineNum = content.substring(0, match.index).split('\n').length;
      const location = `${relativePath}:${lineNum}`;
      const key = `${location}:${type}`;

      if (existingLocations.has(key)) continue;

      const nearbySources = findNearbyTaintSources(content, lineNum);
      if (nearbySources.length === 0) continue;

      const hasSanitizer = checkForSanitizers(content, nearbySources[0].line, lineNum);
      if (hasSanitizer) continue;

      const methodContext = queryEngine.getMethodsByName(sink);
      const classContext = extractClassContext(content, lineNum);

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

function findNearbyTaintSources(content, sinkLine) {
  const sources = [];
  const sourcePatterns = [
    { name: 'GET', pattern: /\$_(GET|POST|REQUEST|COOKIE)\[/ },
    { name: 'input', pattern: /input\(|readline\(/ },
    { name: 'file', pattern: /file_get_contents|file_put_contents|fopen|readfile/ },
    { name: 'env', pattern: /\$_(SERVER|ENV)/ },
    { name: 'request', pattern: /req\.(body|params|query)/ }
  ];

  const lines = content.split('\n');
  for (let i = Math.max(0, sinkLine - 30); i < Math.min(lines.length, sinkLine); i++) {
    for (const { name, pattern } of sourcePatterns) {
      if (pattern.test(lines[i])) {
        sources.push({ name, line: i + 1, match: lines[i].trim() });
      }
    }
  }

  return sources;
}

function checkForSanitizers(content, sourceLine, sinkLine) {
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

  const lines = content.split('\n');
  for (let i = sourceLine; i < sinkLine; i++) {
    for (const pattern of sanitizerPatterns) {
      if (pattern.test(lines[i])) {
        return true;
      }
    }
  }
  return false;
}

function extractClassContext(content, lineNum) {
  const lines = content.split('\n');
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
  if (!taintType) return 'CWE-000';
  const type = taintType.replace('TAINT:', '').toUpperCase();
  const mapping = {
    'SQL_INJECTION': 'CWE-89',
    'COMMAND_INJECTION': 'CWE-78',
    'CODE_INJECTION': 'CWE-94',
    'XSS': 'CWE-79',
    'PATH_TRAVERSAL': 'CWE-22',
    'SSRF': 'CWE-918',
    'XXE': 'CWE-611',
    'DESERIALIZATION': 'CWE-502'
  };
  return mapping[type] || 'CWE-000';
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
  return deduplicateAndSort(findings)
    .filter((finding) => finding.confidence >= 0.6);
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
