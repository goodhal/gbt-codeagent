import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FrameworkScoutAgent } from "./src/agents/frameworkScoutAgent.js";
import { LocalRepoScoutAgent } from "./src/agents/localRepoScoutAgent.js";
import { GitUrlScoutAgent } from "./src/agents/gitUrlScoutAgent.js";
import { ZipUploadScoutAgent } from "./src/agents/zipUploadScoutAgent.js";
import { AuditAnalystAgent } from "./src/agents/auditAnalystAgent.js";
import { getAuditSkillCatalog } from "./src/config/auditSkills.js";
import { getProviderPreset, maskSecret, resolveLlmConfig } from "./src/config/llmProviders.js";
import { buildEnvironmentReport } from "./src/services/environmentReport.js";
import { DefensiveLlmReviewer } from "./src/services/llmReviewService.js";
import { createMemoryStore } from "./src/services/memoryStore.js";
import { createFingerprintService } from "./src/services/fingerprintService.js";
import { writeAuditHtmlReport } from "./src/services/reportWriter.js";
import { createSettingsStore } from "./src/services/settingsStore.js";
import { createTaskStore } from "./src/store/taskStore.js";
import { recordRequest, getPerformanceMetrics, getCache, setCache, withCache, measurePerformance } from "./src/core/performance.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, "public");
const downloadsDir = path.join(__dirname, "workspace", "downloads");
const reportsDir = path.join(__dirname, "workspace", "reports");
const memoryFile = path.join(__dirname, "workspace", "memory", "project-memory.json");
const settingsFile = path.join(__dirname, "workspace", "settings", "app-settings.json");

const settingsStore = createSettingsStore({ filePath: settingsFile });
const scoutAgent = new FrameworkScoutAgent({
  downloadsDir,
  getGithubConfig: async () => (await settingsStore.read()).github
});
const localScoutAgent = new LocalRepoScoutAgent({ downloadsDir });
const gitUrlScoutAgent = new GitUrlScoutAgent({ downloadsDir });
const zipUploadScoutAgent = new ZipUploadScoutAgent({ downloadsDir });
const llmReviewer = new DefensiveLlmReviewer();
const auditAgent = new AuditAnalystAgent({ llmReviewer });
const tasks = createTaskStore({ workspaceDir: path.join(__dirname, "workspace") });
const memoryStore = createMemoryStore({ filePath: memoryFile });
const fingerprintService = createFingerprintService({ downloadsDir });

await fs.mkdir(downloadsDir, { recursive: true });
await fs.mkdir(reportsDir, { recursive: true });

const server = http.createServer(async (req, res) => {
  const start = performance.now();
  const url = new URL(req.url, `http://${req.headers.host}`);
  try {
    console.log(`[请求] ${req.method} ${url.pathname}`);

    if (req.method === "GET" && url.pathname === "/api/health") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, { status: "ok", now: new Date().toISOString(), safeMode: true, environment });
    }

    if (req.method === "GET" && url.pathname === "/api/performance") {
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, getPerformanceMetrics());
    }

    if (req.method === "GET" && url.pathname === "/api/environment") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, environment);
    }

    if (req.method === "GET" && url.pathname === "/api/settings") {
      const result = sanitizeSettings(await settingsStore.read());
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" && url.pathname === "/api/audit-skills") {
      const skills = getAuditSkillCatalog();
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, skills);
    }

    if (req.method === "POST" && url.pathname === "/api/settings") {
      const body = await readJson(req);
      const current = await settingsStore.read();
      const updated = await settingsStore.write({
        llm: {
          providerId: body?.llm?.providerId || current.llm.providerId,
          baseUrl: body?.llm?.baseUrl ?? current.llm.baseUrl,
          model: body?.llm?.model ?? current.llm.model,
          apiKey: body?.llm?.apiKey ? body.llm.apiKey : current.llm.apiKey
        },
        github: {
          token: body?.github?.token ? body.github.token : current.github.token,
          ownerFilter: body?.github?.ownerFilter ?? current.github.ownerFilter,
          notes: body?.github?.notes ?? current.github.notes
        },
        fofa: {
          email: body?.fofa?.email ?? current.fofa.email,
          apiKey: body?.fofa?.apiKey ? body.fofa.apiKey : current.fofa.apiKey,
          notes: body?.fofa?.notes ?? current.fofa.notes
        }
      });
      return sendJson(res, 200, sanitizeSettings(updated));
    }

    if (req.method === "POST" && url.pathname === "/api/settings/clear-secrets") {
      const body = await readJson(req);
      return sendJson(res, 200, sanitizeSettings(await settingsStore.clearSecrets(Array.isArray(body?.targets) ? body.targets : [])));
    }

    if (req.method === "POST" && url.pathname === "/api/settings/test") {
      return sendJson(res, 200, await testConnections(await settingsStore.read()));
    }

    if (req.method === "GET" && url.pathname === "/api/memory") {
      return sendJson(res, 200, await memoryStore.read());
    }

    if (req.method === "GET" && url.pathname === "/api/fingerprint/projects") {
      return sendJson(res, 200, await fingerprintService.listProjects());
    }

    if (req.method === "POST" && url.pathname === "/api/fingerprint/analyze") {
      const body = await readJson(req);
      return sendJson(res, 200, await fingerprintService.analyzeProject(String(body?.projectId || "")));
    }

    if (req.method === "POST" && url.pathname === "/api/fingerprint/match") {
      const body = await readJson(req);
      return sendJson(res, 200, await fingerprintService.matchAssets({
        projectId: String(body?.projectId || ""),
        assetText: String(body?.assetText || "")
      }));
    }

    if (req.method === "DELETE" && /\/api\/fingerprint\/projects\/[^/]+$/.test(url.pathname)) {
      const [, , , , projectId] = url.pathname.split("/");
      if (!projectId) {
        return sendJson(res, 400, { error: "Project ID is required" });
      }
      
      const result = await fingerprintService.deleteProject(projectId);
      if (!result.success) {
        return sendJson(res, 400, { error: result.message });
      }
      
      return sendJson(res, 200, result);
    }

    if (req.method === "POST" && url.pathname === "/api/memory") {
      const body = await readJson(req);
      return sendJson(res, 200, await memoryStore.write({ preferences: body.preferences || {}, rules: Array.isArray(body.rules) ? body.rules : undefined }));
    }

    if (req.method === "POST" && url.pathname === "/api/tasks/upload") {
      console.log("[ZIP上传] 开始处理上传请求");
      try {
        const uploadResult = await parseMultipartForm(req);
        console.log("[ZIP上传] 解析完成，fields:", JSON.stringify(uploadResult.fields));
        console.log("[ZIP上传] 解析完成，文件数:", uploadResult.files.length);

        const selectedSkillIds = JSON.parse(uploadResult.fields.selectedSkillIds || "[]");
        const useMemory = uploadResult.fields.useMemory === "true";
        const useReAct = uploadResult.fields.useReAct === "true";
        const reactConfig = uploadResult.fields.reactConfig ? JSON.parse(uploadResult.fields.reactConfig) : {};

        const memory = await memoryStore.read();
        const taskData = {
          sourceType: "zip-upload",
          selectedSkillIds,
          useMemory,
          useReAct,
          reactConfig,
          zipFiles: uploadResult.files
        };

        const created = await tasks.createTask(taskData);
        console.log("[ZIP上传] 创建任务成功:", created.id);

        if (useMemory) {
          await tasks.updateTask(created.id, { memorySnapshot: buildMemorySnapshot(memory) });
        }

        runScout(created.id).catch((error) => {
          console.error("[ZIP上传] 运行scout失败:", error);
          tasks.failTask(created.id, error instanceof Error ? error.message : String(error));
        });

        const task = tasks.getTask(created.id);
        return sendJson(res, 202, task);
      } catch (uploadError) {
        console.error("[ZIP上传] 错误:", uploadError);
        return sendJson(res, 500, { error: "ZIP上传失败", detail: uploadError instanceof Error ? uploadError.message : String(uploadError) });
      }
    }

    if (req.method === "POST" && url.pathname === "/api/tasks") {
      console.log("[任务创建] 开始创建任务");
      const body = await readJson(req);
      console.log("[任务创建] 请求体:", JSON.stringify(body, null, 2));
      
      try {
        const memory = await memoryStore.read();
        console.log("[任务创建] 读取内存成功");
        
        const defaults = applyMemoryDefaults(body, memory);
        console.log("[任务创建] 应用默认值成功:", JSON.stringify(defaults, null, 2));
        
        const created = await tasks.createTask(defaults);
        console.log("[任务创建] 创建任务成功:", created.id);
        
        if (created.useMemory) {
          await tasks.updateTask(created.id, { memorySnapshot: buildMemorySnapshot(memory) });
          console.log("[任务创建] 更新内存快照成功");
        }
        
        runScout(created.id).catch((error) => {
          console.error("[任务创建] 运行scout失败:", error);
          tasks.failTask(created.id, error instanceof Error ? error.message : String(error));
        });
        
        const task = tasks.getTask(created.id);
        console.log("[任务创建] 返回任务:", task.id);
        return sendJson(res, 202, task);
      } catch (taskError) {
        console.error("[任务创建] 错误:", taskError);
        return sendJson(res, 500, { error: "任务创建失败", detail: taskError instanceof Error ? taskError.message : String(taskError), stack: taskError instanceof Error ? taskError.stack : undefined });
      }
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/audit$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const body = await readJson(req);
      const selectedProjectIds = Array.isArray(body?.selectedProjectIds) ? body.selectedProjectIds : [];
      const task = tasks.getTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      if (!task.scoutResult?.projects?.length) {
        return sendJson(res, 400, { error: "Targets are not ready yet" });
      }
      runAudit(taskId, selectedProjectIds).catch((error) => tasks.failTask(taskId, error instanceof Error ? error.message : String(error)));
      return sendJson(res, 202, tasks.getTask(taskId));
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/resume$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      console.log(`[恢复请求] 收到恢复任务请求: ${taskId}`);
      const task = await tasks.resumeTask(taskId);
      console.log(`[恢复请求] resumeTask 返回: ${task ? `status=${task.status}, phase=${task.phase}` : 'null'}`);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }

      // 根据当前阶段继续执行
      if (task.phase === "framework-scout" || task.phase === "scout") {
        runScout(taskId).catch((error) => tasks.failTask(taskId, error instanceof Error ? error.message : String(error)));
      } else if (task.phase === "audit" || task.phase === "audit-analyst") {
        console.log(`[恢复请求] 调用 runAudit，selectedProjectIds=${JSON.stringify(task.selectedProjectIds)}`);
        runAudit(taskId, task.selectedProjectIds).catch((error) => tasks.failTask(taskId, error instanceof Error ? error.message : String(error)));
      }

      return sendJson(res, 202, task);
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/restart$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const originalTask = tasks.getTask(taskId);
      if (!originalTask) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      if (originalTask.status !== "completed" && originalTask.status !== "failed" && originalTask.status !== "cancelled") {
        return sendJson(res, 400, { error: "Only completed/failed/cancelled tasks can be restarted" });
      }

      const restartData = {
        sourceType: originalTask.sourceType,
        selectedSkillIds: originalTask.selectedSkillIds || [],
        useMemory: originalTask.useMemory !== false,
        useReAct: originalTask.useReAct || false,
        reactConfig: originalTask.reactConfig || {}
      };

      const newTask = await tasks.createTask(restartData);
      tasks.updateTask(newTask.id, {
        scoutResult: originalTask.scoutResult,
        selectedProjectIds: originalTask.selectedProjectIds || [],
        memorySnapshot: originalTask.memorySnapshot,
        memorySummary: originalTask.memorySummary,
        phase: "audit",
        status: "queued",
        message: "重新审计任务已创建",
        progress: {
          stage: "audit",
          label: "等待开始",
          detail: "",
          percent: 0,
          current: 0,
          total: originalTask.selectedProjectIds?.length || 0
        }
      });

      runAudit(newTask.id, newTask.selectedProjectIds).catch((error) =>
        tasks.failTask(newTask.id, error instanceof Error ? error.message : String(error))
      );

      return sendJson(res, 202, tasks.getTask(newTask.id));
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/pause$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const task = await tasks.pauseTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found or cannot be paused" });
      }
      return sendJson(res, 200, task);
    }

    if (req.method === "POST" && /\/api\/tasks\/[^/]+\/stop$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const task = await tasks.stopTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found or already completed" });
      }
      return sendJson(res, 200, task);
    }

    if (req.method === "DELETE" && /\/api\/tasks\/[^/]+\/report$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const reportFile = path.join(reportsDir, `audit-report-${taskId}.html`);
      try {
        await fs.unlink(reportFile);
      } catch (error) {
        // 文件不存在时忽略
      }
      return sendJson(res, 200, { status: "ok", message: "Report deleted" });
    }

    if (req.method === "DELETE" && /\/api\/tasks\/[^/]+$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const task = tasks.getTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }

      // 从内存中移除任务
      tasks.deleteTask(taskId);

      // 清理任务文件
      const tasksDir = path.join(__dirname, "workspace", "tasks");
      try {
        const taskFile = path.join(tasksDir, `${taskId}.json`);
        await fs.unlink(taskFile);
      } catch (error) {
        // 文件不存在时忽略
      }

      // 清理关联的报告文件
      const reportFile = path.join(reportsDir, `audit-report-${taskId}.html`);
      try {
        await fs.unlink(reportFile);
      } catch (error) {
        // 文件不存在时忽略
      }

      return sendJson(res, 200, { status: "ok", message: "Task deleted" });
    }

    if (req.method === "GET" && url.pathname === "/api/tasks") {
      let result = tasks.listTasks();
      const statusFilter = url.searchParams.get("status");
      if (statusFilter) {
        const statuses = statusFilter.split(",");
        result = result.filter(t => statuses.includes(t.status));
      }
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, result);
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/tasks/")) {
      const id = url.pathname.split("/")[3];
      const task = tasks.getTask(id);
      if (!task) {
        recordRequest(url.pathname, performance.now() - start, false);
        return sendJson(res, 404, { error: "Task not found" });
      }
      recordRequest(url.pathname, performance.now() - start, true);
      return sendJson(res, 200, task);
    }

    if (req.method === "GET" && /\/api\/tasks\/[^/]+\/react-steps$/.test(url.pathname)) {
      const [, , , taskId] = url.pathname.split("/");
      const task = tasks.getTask(taskId);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      const projects = task.auditResult?.projects || [];
      const reactStepsData = projects.map(p => {
        const reactResult = p.reactAudit || p.reactResult;
        return {
          projectId: p.id,
          projectName: p.name,
          steps: reactResult?.steps || [],
          finalAnswer: reactResult?.finalAnswer || reactResult?.summary || "",
          issues: reactResult?.issues || []
        };
      });
      return sendJson(res, 200, { taskId, useReAct: task.useReAct, reactConfig: task.reactConfig, projects: reactStepsData });
    }

    if (req.method === "GET" && url.pathname.startsWith("/downloads/")) {
      return serveFile(res, path.join(downloadsDir, decodeURIComponent(url.pathname.replace("/downloads/", ""))));
    }

    if (req.method === "GET" && url.pathname.startsWith("/reports/")) {
      return serveFile(res, path.join(reportsDir, decodeURIComponent(url.pathname.replace("/reports/", ""))));
    }

    if (req.method === "GET") {
      const target = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      return serveFile(res, path.join(publicDir, target));
    }

    return sendJson(res, 404, { error: "Not found" });
  } catch (error) {
    console.error("[服务器错误]", error);
    return sendJson(res, 500, { 
      error: "Internal server error", 
      detail: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : undefined
    });
  }
});

async function runScout(taskId) {
  try {
    tasks.updateTask(taskId, {
      status: "running",
      phase: "framework-scout",
      message: "正在发现候选目标…",
      progress: {
        stage: "framework-scout",
        label: "正在发现候选目标",
        detail: "",
        percent: 12,
        current: 0,
        total: 0
      }
    });
    const task = tasks.getTask(taskId);

    let scoutResult;
    if (task.sourceType === "local") {
      scoutResult = await localScoutAgent.run({ localRepoPaths: task.localRepoPaths });
    } else if (task.sourceType === "git-url") {
      scoutResult = await gitUrlScoutAgent.cloneFromUrls(task.gitUrls, (progress) => {
        updateTaskProgress(taskId, progress);
      });
    } else if (task.sourceType === "zip-upload") {
      scoutResult = await zipUploadScoutAgent.processZipFiles(task.zipFiles, (progress) => {
        updateTaskProgress(taskId, progress);
      });
    } else {
      scoutResult = await scoutAgent.run({
        query: task.query,
        cmsType: task.cmsType,
        industry: task.industry,
        minAdoption: task.minAdoption
      });
    }

    const projectIds = scoutResult.projects?.map(p => p.id) || [];
    
    if (task.sourceType === "git-url" || task.sourceType === "local" || task.sourceType === "zip-upload") {
      // 直接导入类型，无需选择，直接开始审计
      if (projectIds.length > 0) {
        // 先保存 scoutResult 到任务中，供 runAudit 使用
        await tasks.updateTask(taskId, { scoutResult });
        runAudit(taskId, projectIds).catch((error) => tasks.failTask(taskId, error instanceof Error ? error.message : String(error)));
      } else {
        tasks.failTask(taskId, "没有找到可审计的项目");
      }
    } else {
      // GitHub 查询类型，需要用户选择
      tasks.updateTask(taskId, {
        status: "awaiting_selection",
        phase: "target-selection",
        message: scoutResult.summary || "请选择需要审计的目标。",
        scoutResult,
        progress: {
          stage: "target-selection",
          label: "请选择要审计的目标",
          detail: "",
          percent: 20,
          current: scoutResult.projects?.length || 0,
          total: scoutResult.projects?.length || 0
        }
      });
    }
  } catch (error) {
    console.error(`[任务失败] scout阶段失败 - 任务ID: ${taskId}`, error);
    tasks.failTask(taskId, {
      message: "发现候选目标时失败",
      detail: error instanceof Error ? error.message : String(error),
      stage: "framework-scout"
    });
  }
}

async function runAudit(taskId, selectedProjectIds) {
  try {
    const task = tasks.getTask(taskId);
    const selectedProjects = (task.scoutResult?.projects || []).filter((project) => selectedProjectIds.includes(project.id));
    if (!selectedProjects.length) {
      throw new Error("No targets selected for audit.");
    }

    // 检查是否已有审计结果（从暂停恢复的情况）
    const existingAuditResult = task.auditResult;
    console.log(`[审计流程] existingAuditResult:`, existingAuditResult ? `projects=${existingAuditResult.projects?.length}` : 'null');
    
    // 调试：打印 existingAuditResult 的详细结构
    if (existingAuditResult) {
      console.log(`[审计流程] existingAuditResult.projects 结构:`);
      existingAuditResult.projects?.forEach((p, i) => {
        console.log(`  [${i}] projectId=${p.projectId}, findings.length=${p.findings?.length || 0}, heuristicFindings.length=${p.heuristicFindings?.length || 0}`);
      });
    }
    
    const completedProjectIds = existingAuditResult?.projects?.map(p => p.projectId) || [];
    const remainingProjects = selectedProjects.filter(p => !completedProjectIds.includes(p.id));
    
    console.log(`[审计流程] 任务 ${taskId} - 已完成项目: ${completedProjectIds.length}, completedProjectIds=${JSON.stringify(completedProjectIds)}`);
    console.log(`[审计流程] 任务 ${taskId} - 剩余项目: ${remainingProjects.length}, remainingProjects=${JSON.stringify(remainingProjects.map(p => p.id))}`);

    // 如果是从暂停恢复，保持当前进度，只更新状态为 running
    if (existingAuditResult && completedProjectIds.length > 0) {
      console.log(`[审计流程] 任务 ${taskId} 从暂停点恢复，继续审计剩余项目`);
      tasks.updateTask(taskId, {
        status: "running",
        message: "正在继续审计..."
      });
    } else {
      // 完全从头开始
      tasks.updateTask(taskId, {
        status: "running",
        phase: "audit-analyst",
        message: "正在下载审计镜像并审计你选中的目标…",
        selectedProjectIds,
        progress: {
          stage: "mirror",
          label: "正在准备审计镜像",
          detail: "",
          percent: 24,
          current: 0,
          total: selectedProjects.length
        }
      });
    }

    // 只对剩余项目确保镜像
    for (const [projectIndex, project] of remainingProjects.entries()) {
      if (project.sourceType === "local" || project.sourceType === "git-url" || project.sourceType === "zip-upload") {
        updateTaskProgress(taskId, {
          stage: "mirror",
          label: `正在生成本地镜像：${project.name}`,
          detail: "",
          percent: calculateMirrorPercent(projectIndex + 1, remainingProjects.length, 1, 1),
          current: projectIndex + 1,
          total: remainingProjects.length
        });
        await localScoutAgent.ensureProjectMirror(project);
      } else {
        await scoutAgent.ensureProjectMirror(project, {
          onProgress: (detail) =>
            updateTaskProgress(taskId, {
              stage: "mirror",
              label: `正在下载审计镜像：${project.name}`,
              detail: detail.currentPath || "",
              percent: calculateMirrorPercent(projectIndex + 1, remainingProjects.length, detail.processed || 0, detail.total || 1),
              current: detail.processed || 0,
              total: detail.total || 0
            })
        });
      }
    }

    const settings = await settingsStore.read();
    const llmConfig = resolveLlmConfig(process.env, settings.llm);
    console.log(`[审计流程] LLM配置 - 提供商: ${llmConfig.providerId}, 模型: ${llmConfig.model}, 端点: ${llmConfig.baseUrl}, API Key配置: ${Boolean(llmConfig.apiKey)}`);
    console.log(`[审计流程] ReAct模式: ${task.useReAct ? '启用' : '禁用'}, 最大步数: ${task.reactConfig?.maxSteps || 15}`);
    
    let auditResult;
    if (remainingProjects.length > 0) {
      // 只对剩余项目进行审计
      const newAuditResult = await auditAgent.run({
        taskId,
        projects: remainingProjects,
        selectedSkillIds: task.selectedSkillIds,
        llmConfig,
        useReAct: task.useReAct || false,
        reactConfig: task.reactConfig || {},
        tasks,
        onProgress: (detail) => {
          // 调整进度，加入已完成的项目
          const adjustedDetail = {
            ...detail,
            current: (detail.current || 0) + completedProjectIds.length,
            total: selectedProjects.length,
            projectIndex: (detail.projectIndex || 0) + completedProjectIds.length
          };
          updateTaskProgress(taskId, buildAuditProgress(adjustedDetail, selectedProjects.length));
        },
        shouldCancel: () => {
          const currentTask = tasks.getTask(taskId);
          // 如果任务被暂停或取消，停止审计
          return currentTask?.status === 'cancelled' || currentTask?.status === 'paused';
        }
      });
      
      // 合并已有结果和新结果
      if (existingAuditResult) {
        auditResult = {
          ...existingAuditResult,
          projects: [
            ...(existingAuditResult.projects || []),
            ...newAuditResult.projects
          ]
        };
      } else {
        auditResult = newAuditResult;
      }

      // 立即检查任务状态，如果是暂停或取消，保存当前进度并停止
      const currentTaskAfterRun = tasks.getTask(taskId);
      if (currentTaskAfterRun?.status === 'paused' || currentTaskAfterRun?.status === 'cancelled') {
        console.log(`[审计流程] 任务 ${taskId} 被暂停/取消，保存当前进度并停止`);
        console.log(`[审计流程] 暂停时已有 ${auditResult?.projects?.length || 0} 个项目的结果`);
        tasks.updateTask(taskId, {
          auditResult,
          progress: {
            ...currentTaskAfterRun.progress,
            stage: currentTaskAfterRun.status === 'paused' ? "paused" : "cancelled",
            label: currentTaskAfterRun.status === 'paused' ? "审计已暂停" : "任务已取消"
          }
        });
        return;
      }
    } else {
      auditResult = existingAuditResult;
    }

    updateTaskProgress(taskId, {
      stage: "report",
      label: "正在生成审计报告",
      detail: "",
      percent: 98,
      current: selectedProjects.length,
      total: selectedProjects.length
    });
    const finalTaskSnapshot = {
      ...tasks.getTask(taskId),
      phase: "completed",
      message: "审计完成，可下载审计报告。",
      selectedProjectIds
    };
    
    // 生成 HTML 报告
    const htmlReport = await writeAuditHtmlReport({ reportsDir, task: finalTaskSnapshot, selectedProjects, auditResult });
    
    const memorySummary = buildMemorySummary(finalTaskSnapshot, { projects: selectedProjects }, auditResult);
    if (task.useMemory) {
      await memoryStore.appendRunSummary(memorySummary);
    }

    tasks.completeTask(taskId, {
      phase: "completed",
      message: "审计完成，可下载审计报告。",
      selectedProjectIds,
      auditResult,
      report: {
        html: htmlReport
      },
      memorySummary,
      progress: {
        stage: "completed",
        label: "审计完成",
        detail: "",
        percent: 100,
        current: selectedProjects.length,
        total: selectedProjects.length
      }
    });
  } catch (error) {
    console.error(`[任务失败] audit阶段失败 - 任务ID: ${taskId}`, error);
    tasks.failTask(taskId, {
      message: "审计过程中失败",
      detail: error instanceof Error ? error.message : String(error),
      stage: "audit-analyst"
    });
  }
}

function updateTaskProgress(taskId, progress) {
  const current = tasks.getTask(taskId);
  tasks.updateTask(taskId, {
    progress: {
      ...(current?.progress || {}),
      ...progress
    }
  });
}

function calculateMirrorPercent(projectIndex, totalProjects, processedFiles, totalFiles) {
  const safeProjects = Math.max(totalProjects || 1, 1);
  const safeTotalFiles = Math.max(totalFiles || 1, 1);
  const projectOffset = (projectIndex - 1) / safeProjects;
  const fileOffset = Math.min(processedFiles / safeTotalFiles, 1) / safeProjects;
  return Math.min(60, Math.max(24, Math.round(24 + (projectOffset + fileOffset) * 36)));
}

function buildAuditProgress(detail, totalProjects) {
  const safeProjects = Math.max(totalProjects || 1, 1);

  if (detail.stage === "heuristic") {
    return {
      stage: "heuristic",
      label: detail.label || `正在分析规则层：${detail.projectName || ""}`,
      detail: "",
      percent: Math.min(68, Math.round(60 + ((detail.projectIndex - 1) / safeProjects) * 8)),
      current: detail.projectIndex || 0,
      total: detail.totalProjects || safeProjects
    };
  }

  if (detail.stage === "llm-review") {
    const totalBatches = Math.max(detail.totalBatches || 1, 1);
    const batchProgress = detail.currentBatch ? Math.min(detail.currentBatch / totalBatches, 1) : 0;
    const projectOffset = (Math.max((detail.projectIndex || 1) - 1, 0) / safeProjects) * 24;
    return {
      stage: "llm-review",
      label: detail.label || `正在进行 LLM 复核：${detail.projectName || ""}`,
      detail: detail.currentPath || `${detail.reviewedFiles || 0} / ${detail.totalFiles || 0} 个文件`,
      percent: Math.min(95, Math.round(68 + projectOffset + batchProgress * (24 / safeProjects))),
      current: detail.currentBatch || detail.reviewedBatches || 0,
      total: detail.totalBatches || 0
    };
  }

  if (detail.stage === "llm-audit") {
    const totalBatches = Math.max(detail.totalBatches || 1, 1);
    const batchProgress = detail.currentBatch ? Math.min(detail.currentBatch / totalBatches, 1) : 0;
    const projectOffset = (Math.max((detail.projectIndex || 1) - 1, 0) / safeProjects) * 24;
    return {
      stage: "llm-audit",
      label: detail.label || `正在进行 LLM 独立审计：${detail.projectName || ""}`,
      detail: detail.currentPath || `${detail.auditedFiles || 0} / ${detail.totalFiles || 0} 个文件`,
      percent: Math.min(95, Math.round(68 + projectOffset + batchProgress * (24 / safeProjects))),
      current: detail.currentBatch || detail.auditedBatches || 0,
      total: detail.totalBatches || 0
    };
  }

  if (detail.stage === "react-audit") {
    if (detail.type === "react-start") {
      return {
        stage: "react-audit",
        label: detail.label || `正在启动 ReAct 推理审计：${detail.projectName || ""}`,
        detail: `${detail.totalFiles || 0} 个文件`,
        percent: 68,
        current: 0,
        total: 1
      };
    }
    if (detail.type === "react-batch" || detail.type === "react-step") {
      return {
        stage: "react-audit",
        label: detail.label || `正在进行 ReAct 推理审计：${detail.projectName || ""}`,
        detail: `推理步骤 ${detail.currentStep || 0} / ${detail.totalSteps || 0}`,
        percent: Math.min(92, Math.round(68 + ((detail.currentStep || 0) / Math.max(detail.totalSteps || 1, 1)) * 24)),
        current: detail.currentStep || 0,
        total: detail.totalSteps || 1
      };
    }
    if (detail.type === "react-complete") {
      return {
        stage: "react-complete",
        label: detail.label || `ReAct 推理审计完成：${detail.projectName || ""}`,
        detail: `推理步骤 ${detail.totalSteps || 0}，发现问题 ${detail.findingsCount || 0} 个`,
        percent: 95,
        current: 1,
        total: 1
      };
    }
    const projectOffset = (Math.max((detail.projectIndex || 1) - 1, 0) / safeProjects) * 24;
    return {
      stage: "react-audit",
      label: detail.label || `正在进行 ReAct 推理审计：${detail.projectName || ""}`,
      detail: detail.label || `推理审计中...`,
      percent: Math.min(92, Math.round(68 + projectOffset + 12)),
      current: detail.projectIndex || 0,
      total: safeProjects
    };
  }

  if (detail.stage === "project-complete") {
    return {
      stage: "project-complete",
      label: detail.label || `已完成：${detail.projectName || ""}`,
      detail: `规则层 ${detail.heuristicCount || 0} 条，LLM ${detail.llmCount || 0} 条${detail.useReAct ? ' (ReAct模式)' : ''}`,
      percent: Math.min(96, Math.round(68 + ((detail.projectIndex || 0) / safeProjects) * 27)),
      current: detail.projectIndex || 0,
      total: detail.totalProjects || safeProjects
    };
  }

  return {
    stage: detail.stage || "audit",
    label: detail.label || "正在审计",
    detail: detail.detail || "",
    percent: 70,
    current: detail.current || 0,
    total: detail.total || 0
  };
}

function sanitizeSettings(settings) {
  return {
    llm: {
      providerId: settings.llm.providerId,
      baseUrl: settings.llm.baseUrl,
      model: settings.llm.model,
      apiKeyConfigured: Boolean(settings.llm.apiKey),
      apiKeyMasked: maskSecret(settings.llm.apiKey),
      defaults: providerDefaults(settings.llm.providerId)
    },
    github: {
      tokenConfigured: Boolean(settings.github.token),
      tokenMasked: maskSecret(settings.github.token),
      ownerFilter: settings.github.ownerFilter,
      notes: settings.github.notes
    },
    fofa: {
      email: settings.fofa.email,
      apiKeyConfigured: Boolean(settings.fofa.apiKey),
      apiKeyMasked: maskSecret(settings.fofa.apiKey),
      notes: settings.fofa.notes,
      safeMode: "stored-only"
    },
    updatedAt: settings.updatedAt
  };
}

function providerDefaults(providerId) {
  const preset = getProviderPreset(providerId);
  return { baseUrl: preset.defaultBaseUrl, model: preset.defaultModel, compatibility: preset.compatibility, label: preset.label };
}

async function testConnections(settings) {
  const llm = resolveLlmConfig(process.env, settings.llm);
  const [llmTest, githubTest] = await Promise.all([testLlmConnection(llm), testGithubConnection(settings.github)]);
  return { testedAt: new Date().toISOString(), llm: llmTest, github: githubTest, overall: llmTest.ok && githubTest.ok ? "pass" : llmTest.ok || githubTest.ok ? "partial" : "warn" };
}

async function testGithubConnection(github) {
  if (!github.token) return { ok: false, status: "warn", message: "未配置 GitHub Token" };
  try {
    const response = await fetch("https://api.github.com/rate_limit", {
      headers: {
        "User-Agent": "safe-framework-audit-agents",
        "Accept": "application/vnd.github+json",
        "Authorization": `Bearer ${github.token}`
      }
    });

    if (response.ok) {
      return { ok: true, status: "pass", message: "GitHub Token 可用" };
    }

    if (response.status === 401) {
      const fallback = await fetch("https://api.github.com/rate_limit", {
        headers: {
          "User-Agent": "safe-framework-audit-agents",
          "Accept": "application/vnd.github+json"
        }
      });

      if (fallback.ok) {
        return { ok: true, status: "warn", message: "GitHub Token 无效，但公开仓库仍可匿名抓取" };
      }
    }

    return { ok: false, status: "warn", message: `GitHub 返回 ${response.status}` };
  } catch (error) {
    return { ok: false, status: "warn", message: error instanceof Error ? error.message : String(error) };
  }
}

async function testLlmConnection(llm) {
  if (!llm.apiKey) return { ok: false, status: "warn", message: "未配置 LLM API Key" };
  try {
    let url = llm.baseUrl;
    let options = { headers: {} };
    const compatibility = llm.compatibility || llm.defaults?.compatibility || "openai";
    if (compatibility === "openai") {
      url = `${stripTrailingSlash(llm.baseUrl)}/models`;
      options.headers = { Authorization: `Bearer ${llm.apiKey}` };
    } else if (compatibility === "gemini") {
      url = `${stripTrailingSlash(llm.baseUrl)}/v1beta/models?key=${encodeURIComponent(llm.apiKey)}`;
    } else if (compatibility === "anthropic") {
      url = `${stripTrailingSlash(llm.baseUrl)}/v1/models`;
      options.headers = { "x-api-key": llm.apiKey, "anthropic-version": "2023-06-01" };
    }
    const response = await fetch(url, options);
    const ok = response.ok || response.status === 404;
    return { ok, status: ok ? "pass" : "warn", message: ok ? `LLM 端点可达 (${response.status})` : `LLM 返回 ${response.status}` };
  } catch (error) {
    return { ok: false, status: "warn", message: error instanceof Error ? error.message : String(error) };
  }
}

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, "");
}

function applyMemoryDefaults(body, memory) {
  const useMemory = body.useMemory !== false;
  const sourceType = body.sourceType || "github";
  const useReAct = body.useReAct === true;
  const reactConfig = typeof body.reactConfig === 'object' && body.reactConfig !== null ? body.reactConfig : {};
  let selectedSkillIds = Array.isArray(body.selectedSkillIds) ? body.selectedSkillIds : [];
  
  // 如果提供了selectedSkills，将其转换为selectedSkillIds
  if (Array.isArray(body.selectedSkills)) {
    selectedSkillIds = body.selectedSkills;
  }
  
  let localRepoPaths = Array.isArray(body.localRepoPaths)
    ? body.localRepoPaths
    : String(body.localRepoPaths || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);

  if (sourceType === "local") {
    // 如果提供了localPath，将其添加到localRepoPaths中
    if (body.localPath) {
      localRepoPaths.push(body.localPath);
      // 去重
      localRepoPaths = [...new Set(localRepoPaths)];
    }
    
    return {
      ...body,
      sourceType,
      selectedSkillIds,
      localRepoPaths,
      useMemory,
      useReAct,
      reactConfig,
      query: "local repository import",
      cmsType: "all",
      industry: "all",
      minAdoption: 0
    };
  }

  function getDefaultQuery(sourceType, body, memory, useMemory) {
    if (body.query) {
      return body.query;
    }
    switch (sourceType) {
      case "git-url":
        return body.gitUrls?.join(", ") || "Git URL import";
      case "zip-upload":
        return "ZIP 代码包上传";
      case "github":
        if (useMemory) {
          return memory.preferences?.preferredQuery || 'topic:cms OR "headless cms" OR "content management system"';
        }
        return 'topic:cms OR "headless cms" OR "content management system"';
      default:
        if (useMemory) {
          return memory.preferences?.preferredQuery || 'topic:cms OR "headless cms" OR "content management system"';
        }
        return 'topic:cms OR "headless cms" OR "content management system"';
    }
  }

  const query = getDefaultQuery(sourceType, body, memory, useMemory);

  if (!useMemory) {
    return {
      ...body,
      sourceType,
      selectedSkillIds,
      localRepoPaths: [],
      useMemory: false,
      useReAct,
      reactConfig,
      query,
      cmsType: body.cmsType || "all",
      industry: body.industry || "all",
      minAdoption: Number(body.minAdoption || 100)
    };
  }
  return {
    ...body,
    sourceType,
    selectedSkillIds,
    localRepoPaths: [],
    useMemory,
    useReAct,
    reactConfig,
    query,
    cmsType: body.cmsType || "all",
    industry: body.industry || "all",
    minAdoption: Number(body.minAdoption || memory.preferences?.preferredMinAdoption || 100)
  };
}

function buildMemorySnapshot(memory) {
  return { rules: memory.rules, preferences: memory.preferences, learnedPatterns: memory.learnedPatterns.slice(0, 5) };
}

function buildMemorySummary(task, scoutResult, auditResult) {
  const topProjects = (scoutResult.projects || []).slice(0, 3).map((project) => project.sourceType === "local" ? project.localPath : `${project.owner}/${project.name}`);
  const findingTitles = auditResult.projects.flatMap((project) => project.findings.map((finding) => finding.title));
  return {
    createdAt: new Date().toISOString(),
    query: task.query,
    minAdoption: task.minAdoption,
    projectsReviewed: auditResult.projects.length,
    topProjects,
    findingsCount: auditResult.findingsCount,
    learnedPatterns: findingTitles.slice(0, 4)
  };
}

async function readJson(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

async function serveFile(res, filePath) {
  const start = performance.now();
  try {
    console.log(`Serving file: ${filePath}`);
    const content = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const type = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".md": "text/markdown; charset=utf-8" }[ext] || "application/octet-stream";
    const cacheControl = "no-store, max-age=0";
    res.writeHead(200, {
      "Content-Type": type,
      "Cache-Control": cacheControl
    });
    res.end(content);
    recordRequest("/static", performance.now() - start, true);
  } catch (error) {
    console.error(`File serve error: ${filePath}`, error.message);
    recordRequest("/static", performance.now() - start, false);
    sendJson(res, 404, { error: "File not found" });
  }
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store, max-age=0",
    Pragma: "no-cache",
    Expires: "0"
  });
  res.end(JSON.stringify(payload, null, 2));
}

async function parseMultipartForm(req) {
  const contentType = req.headers["content-type"] || "";
  const boundaryMatch = contentType.match(/boundary=(.+)$/);
  if (!boundaryMatch) {
    throw new Error("Invalid multipart form data");
  }

  let boundary = boundaryMatch[1];
  // 移除可能存在的引号
  boundary = boundary.replace(/^["']|["']$/g, "");
  boundary = "--" + boundary;
  console.log("[ZIP上传] boundary:", boundary);
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  const buffer = Buffer.concat(chunks);
  console.log("[ZIP上传] buffer长度:", buffer.length);

  const fields = {};
  const files = [];
  const binaryString = buffer.toString("binary");
  const parts = binaryString.split(boundary);
  console.log("[ZIP上传] parts数量:", parts.length);

  for (const part of parts) {
    if (!part || part === "--\r\n" || part === "--") continue;

    const headerEndIndex = part.indexOf("\r\n\r\n");
    if (headerEndIndex === -1) continue;

    const headerSection = part.substring(0, headerEndIndex);
    const bodySection = part.substring(headerEndIndex + 4, part.length - 2);

    const nameMatch = headerSection.match(/name="([^"]+)"/) || headerSection.match(/name=([^;\s]+)/);
    if (!nameMatch) continue;

    const fieldName = nameMatch[1].replace(/"/g, "");
    const filenameMatch = headerSection.match(/filename="([^"]+)"/) || headerSection.match(/filename=([^;\s]+)/);
    const actualFilename = filenameMatch ? filenameMatch[1].replace(/"/g, "") : null;
    console.log("[ZIP上传] 字段:", fieldName, "filename:", actualFilename);

    if (filenameMatch) {
      // 这是一个文件
      const filename = filenameMatch[1];
      const uploadDir = path.join(__dirname, "workspace", "uploads");
      await fs.mkdir(uploadDir, { recursive: true });

      const filepath = path.join(uploadDir, `${Date.now()}-${filename}`);
      await fs.writeFile(filepath, Buffer.from(bodySection, "binary"));

      const stat = await fs.stat(filepath);
      files.push({
        filename,
        filepath,
        size: stat.size
      });
    } else {
      // 这是一个普通字段
      fields[fieldName] = bodySection;
    }
  }

  return { fields, files };
}

const port = process.env.PORT || 3001;
server.listen(port, '0.0.0.0', () => console.log(`Safe audit agents listening on http://0.0.0.0:${port}`));

