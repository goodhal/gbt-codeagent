import http from "node:http";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { FrameworkScoutAgent } from "./src/agents/frameworkScoutAgent.js";
import { LocalRepoScoutAgent } from "./src/agents/localRepoScoutAgent.js";
import { AuditAnalystAgent } from "./src/agents/auditAnalystAgent.js";
import { getAuditSkillCatalog } from "./src/config/auditSkills.js";
import { getProviderPreset, maskSecret, resolveLlmConfig } from "./src/config/llmProviders.js";
import { buildEnvironmentReport } from "./src/services/environmentReport.js";
import { DefensiveLlmReviewer } from "./src/services/llmReviewService.js";
import { createMemoryStore } from "./src/services/memoryStore.js";
import { writeAuditHtmlReport } from "./src/services/reportWriter.js";
import { createSettingsStore } from "./src/services/settingsStore.js";
import { createTaskStore } from "./src/store/taskStore.js";

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
const llmReviewer = new DefensiveLlmReviewer();
const auditAgent = new AuditAnalystAgent({ llmReviewer });
const tasks = createTaskStore();
const memoryStore = createMemoryStore({ filePath: memoryFile });

await fs.mkdir(downloadsDir, { recursive: true });
await fs.mkdir(reportsDir, { recursive: true });

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    if (req.method === "GET" && url.pathname === "/api/health") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      return sendJson(res, 200, { status: "ok", now: new Date().toISOString(), safeMode: true, environment });
    }

    if (req.method === "GET" && url.pathname === "/api/environment") {
      const settings = await settingsStore.read();
      const environment = await buildEnvironmentReport({ rootDir: __dirname, downloadsDir, settings });
      return sendJson(res, 200, environment);
    }

    if (req.method === "GET" && url.pathname === "/api/settings") {
      return sendJson(res, 200, sanitizeSettings(await settingsStore.read()));
    }

    if (req.method === "GET" && url.pathname === "/api/audit-skills") {
      return sendJson(res, 200, getAuditSkillCatalog());
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

    if (req.method === "POST" && url.pathname === "/api/memory") {
      const body = await readJson(req);
      return sendJson(res, 200, await memoryStore.write({ preferences: body.preferences || {}, rules: Array.isArray(body.rules) ? body.rules : undefined }));
    }

    if (req.method === "POST" && url.pathname === "/api/tasks") {
      const body = await readJson(req);
      const memory = await memoryStore.read();
      const created = tasks.createTask(applyMemoryDefaults(body, memory));
      if (created.useMemory) {
        tasks.updateTask(created.id, { memorySnapshot: buildMemorySnapshot(memory) });
      }
      runScout(created.id).catch((error) => tasks.failTask(created.id, error instanceof Error ? error.message : String(error)));
      return sendJson(res, 202, tasks.getTask(created.id));
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

    if (req.method === "GET" && url.pathname === "/api/tasks") {
      return sendJson(res, 200, tasks.listTasks());
    }

    if (req.method === "GET" && url.pathname.startsWith("/api/tasks/")) {
      const id = url.pathname.split("/")[3];
      const task = tasks.getTask(id);
      if (!task) {
        return sendJson(res, 404, { error: "Task not found" });
      }
      return sendJson(res, 200, task);
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
    return sendJson(res, 500, { error: "Internal server error", detail: error instanceof Error ? error.message : String(error) });
  }
});

async function runScout(taskId) {
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
  const scoutResult = task.sourceType === "local"
    ? await localScoutAgent.run({ localRepoPaths: task.localRepoPaths })
    : await scoutAgent.run({ query: task.query });
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

async function runAudit(taskId, selectedProjectIds) {
  const task = tasks.getTask(taskId);
  const selectedProjects = (task.scoutResult?.projects || []).filter((project) => selectedProjectIds.includes(project.id));
  if (!selectedProjects.length) {
    throw new Error("No targets selected for audit.");
  }

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

  for (const [projectIndex, project] of selectedProjects.entries()) {
    if (project.sourceType === "local") {
      updateTaskProgress(taskId, {
        stage: "mirror",
        label: `正在生成本地镜像：${project.name}`,
        detail: "",
        percent: calculateMirrorPercent(projectIndex + 1, selectedProjects.length, 1, 1),
        current: projectIndex + 1,
        total: selectedProjects.length
      });
      await localScoutAgent.ensureProjectMirror(project);
    } else {
      await scoutAgent.ensureProjectMirror(project, {
        onProgress: (detail) =>
          updateTaskProgress(taskId, {
            stage: "mirror",
            label: `正在下载审计镜像：${project.name}`,
            detail: detail.currentPath || "",
            percent: calculateMirrorPercent(projectIndex + 1, selectedProjects.length, detail.processed || 0, detail.total || 1),
            current: detail.processed || 0,
            total: detail.total || 0
          })
      });
    }
  }

  const settings = await settingsStore.read();
  const llmConfig = resolveLlmConfig(process.env, settings.llm);
  const auditResult = await auditAgent.run({
    projects: selectedProjects,
    selectedSkillIds: task.selectedSkillIds,
    llmConfig,
    onProgress: (detail) => updateTaskProgress(taskId, buildAuditProgress(detail, selectedProjects.length))
  });
  updateTaskProgress(taskId, {
    stage: "report",
    label: "正在生成 HTML 报告",
    detail: "",
    percent: 98,
    current: selectedProjects.length,
    total: selectedProjects.length
  });
  const finalTaskSnapshot = {
    ...tasks.getTask(taskId),
    phase: "completed",
    message: "审计完成，可下载 HTML 报告。",
    selectedProjectIds
  };
  const report = await writeAuditHtmlReport({ reportsDir, task: finalTaskSnapshot, selectedProjects, auditResult });
  const memorySummary = buildMemorySummary(finalTaskSnapshot, { projects: selectedProjects }, auditResult);
  if (task.useMemory) {
    await memoryStore.appendRunSummary(memorySummary);
  }

  tasks.completeTask(taskId, {
    phase: "completed",
    message: "审计完成，可下载 HTML 报告。",
    selectedProjectIds,
    auditResult,
    report,
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

  if (detail.stage === "project-complete") {
    return {
      stage: "project-complete",
      label: detail.label || `已完成：${detail.projectName || ""}`,
      detail: `规则层 ${detail.heuristicCount || 0} 条，LLM ${detail.llmCount || 0} 条`,
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
    if (llm.compatibility === "openai") {
      url = `${stripTrailingSlash(llm.baseUrl)}/models`;
      options.headers = { Authorization: `Bearer ${llm.apiKey}` };
    } else if (llm.compatibility === "gemini") {
      url = `${stripTrailingSlash(llm.baseUrl)}/v1beta/models?key=${encodeURIComponent(llm.apiKey)}`;
    } else if (llm.compatibility === "anthropic") {
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
  const sourceType = body.sourceType === "local" ? "local" : "github";
  const selectedSkillIds = Array.isArray(body.selectedSkillIds) ? body.selectedSkillIds : [];
  const localRepoPaths = Array.isArray(body.localRepoPaths)
    ? body.localRepoPaths
    : String(body.localRepoPaths || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);

  if (sourceType === "local") {
    return {
      ...body,
      sourceType,
      selectedSkillIds,
      localRepoPaths,
      useMemory,
      query: "local repository import",
      minAdoption: 0
    };
  }

  if (!useMemory) {
    return {
      ...body,
      sourceType,
      selectedSkillIds,
      localRepoPaths: [],
      useMemory: false,
      query: body.query || 'topic:cms OR "headless cms" OR "content management system"',
      minAdoption: Number(body.minAdoption || 100)
    };
  }
  return {
    ...body,
    sourceType,
    selectedSkillIds,
    localRepoPaths: [],
    useMemory,
    query: body.query || memory.preferences.preferredQuery,
    minAdoption: Number(body.minAdoption || memory.preferences.preferredMinAdoption || 100)
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
  try {
    const content = await fs.readFile(filePath);
    const ext = path.extname(filePath).toLowerCase();
    const type = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".json": "application/json; charset=utf-8", ".md": "text/markdown; charset=utf-8" }[ext] || "application/octet-stream";
    res.writeHead(200, {
      "Content-Type": type,
      "Cache-Control": "no-store, max-age=0",
      Pragma: "no-cache",
      Expires: "0"
    });
    res.end(content);
  } catch {
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

const port = process.env.PORT || 3000;
server.listen(port, () => console.log(`Safe audit agents listening on http://localhost:${port}`));

