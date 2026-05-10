import { SimpleCharts } from './charts.js';

const page = document.body.dataset.page || "overview";
const charts = new SimpleCharts();
const toast = document.querySelector("#toast");
const selectionState = new Map();
const candidateState = new Map();
let selectedTaskId = null;
let latestSettings = null;
let latestMemory = null;
let auditSkills = [];
let availableProfiles = [];
let fingerprintProjects = [];
let selectedFingerprintProjectId = "";
let refreshTimer = null;
let currentTaskFilter = "all";

const STATUS_LABELS = { completed: "已完成", failed: "失败", running: "运行中", queued: "排队中", paused: "已暂停", cancelled: "已取消" };

let providerDefaultsMap = {};

markActiveNav();
initParticles();
void bootstrap();

async function bootstrap() {
  await Promise.all([loadQuickStatus(), loadAuditSkills()]);

  if (page === "overview") {
    await Promise.all([renderEnvironment(), renderOverviewTasks()]);
  }

  if (page === "discover") {
    initDiscoverPage();
  }

  if (page === "audit") {
    initAuditPage();
    await refreshAuditPage();
    startAuditPolling();
  }

  if (page === "fingerprints") {
    initFingerprintPage();
    await refreshFingerprintProjects();
  }

  if (page === "settings") {
    initSettingsPage();
    await Promise.all([refreshSettingsPage(), refreshMemoryPage()]);
  }
}

function startAuditPolling() {
  if (refreshTimer) return;
  refreshTimer = setInterval(refreshAuditPage, 1800);
}

function stopAuditPolling() {
  if (refreshTimer) {
    clearInterval(refreshTimer);
    refreshTimer = null;
  }
}

window.addEventListener("beforeunload", () => {
  stopAuditPolling();
});

function markActiveNav() {
  document.querySelectorAll("[data-nav]").forEach((link) => {
    if (new URL(link.href, location.origin).pathname === location.pathname) {
      link.classList.add("active");
    }
  });
}

async function loadQuickStatus() {
  try {
    const [settings, tasks] = await Promise.all([api("/api/settings"), api("/api/tasks")]);
    latestSettings = settings;
    renderQuickStatus(settings, tasks);
  } catch {
    const target = document.querySelector("#quick-status");
    if (target) {
      target.innerHTML = `<div class="empty-card">状态读取失败</div>`;
    }
  }
  try {
    const catalog = await api("/api/provider-defaults");
    providerDefaultsMap = {};
    for (const item of catalog) {
      providerDefaultsMap[item.id] = item;
    }
  } catch { /**/ }
}

function renderQuickStatus(settings, tasks = []) {
  const target = document.querySelector("#quick-status");
  if (!target) return;

  const running = tasks.filter((task) => task.status === "running").length;
  target.innerHTML = `
    <div class="status-card">
      <strong>LLM</strong>
      <span>${settings.llm.providerId || "未配置"} / ${settings.llm.model || "未配置"}</span>
    </div>
    <div class="status-card">
      <strong>GitHub</strong>
      <span>${settings.github.tokenConfigured ? "已配置" : "未配置"}</span>
    </div>
    <div class="status-card">
      <strong>FOFA</strong>
      <span>${settings.fofa?.apiKeyConfigured ? "已存档" : "未存档"}</span>
    </div>
    <div class="status-card">
      <strong>任务</strong>
      <span>${running} 个运行中</span>
    </div>
  `;
}

async function loadAuditSkills() {
  try {
    auditSkills = await api("/api/audit-skills");
    availableProfiles = await api("/api/profiles");
  } catch {
    auditSkills = [];
    availableProfiles = [];
  }
}

function initDiscoverPage() {
  const form = document.querySelector("#task-form");
  const skillPicker = document.querySelector("#skill-picker");
  const selectAllButton = document.querySelector("#select-all-skills-button");
  const clearButton = document.querySelector("#clear-skills-button");
  const githubFields = document.querySelector("#github-launch-fields");
  const gitUrlFields = document.querySelector("#git-url-fields");
  const zipUploadFields = document.querySelector("#zip-upload-fields");
  const localFields = document.querySelector("#local-launch-fields");

  renderSkillPicker(skillPicker);
  syncSourceMode(githubFields, gitUrlFields, zipUploadFields, localFields);

  document.querySelectorAll('input[name="sourceType"]').forEach((input) => {
    input.addEventListener("change", () => syncSourceMode(githubFields, gitUrlFields, zipUploadFields, localFields));
  });

  const useReActToggle = document.querySelector("#useReActToggle");
  const reactConfigDetails = document.querySelector("#react-config-details");
  useReActToggle?.addEventListener("change", () => {
    if (reactConfigDetails) {
      reactConfigDetails.classList.toggle("hidden-panel", !useReActToggle.checked);
    }
  });

  // 监听文件选择变化
  const zipFileInput = form?.elements.zipFiles;
  if (zipFileInput) {
    zipFileInput.addEventListener("change", () => {
      updateUploadPreview(zipFileInput.files);
    });
  }

  selectAllButton?.addEventListener("click", () => setAllSkills(true));
  clearButton?.addEventListener("click", () => setAllSkills(false));

  form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const selectedSkillIds = getSelectedSkillIds();
    if (!selectedSkillIds.length) {
      showToast("请至少选择一个审计 Skill。", "info");
      return;
    }

    const sourceType = getSourceType();

    if (sourceType === "zip-upload") {
      await handleZipUpload(form, selectedSkillIds);
      return;
    }

    const payload = {
      sourceType,
      selectedSkillIds,
      useMemory: form.elements.useMemory?.checked
    };

    const enableLlmAudit = form.elements.enableLlmAudit?.checked !== false;
    payload.enableLlmAudit = enableLlmAudit;

    const useReAct = form.elements.useReAct?.checked === true;
    if (useReAct) {
      payload.useReAct = true;
      payload.reactConfig = {
        maxSteps: Number(form.elements.reactMaxSteps?.value || 15),
        temperature: Number(form.elements.reactTemperature?.value || 0.1),
        maxRetries: Number(form.elements.reactMaxRetries?.value || 3),
        verbose: form.elements.reactVerbose?.checked === true
      };
    }

    if (sourceType === "local") {
      payload.localRepoPaths = String(form.elements.localRepoPaths.value || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (!payload.localRepoPaths.length) {
        showToast("请填写至少一个本地仓库路径。", "info");
        return;
      }
    } else if (sourceType === "git-url") {
      payload.gitUrls = String(form.elements.gitUrls.value || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (!payload.gitUrls.length) {
        showToast("请填写至少一个 Git 仓库地址。", "info");
        return;
      }
    } else {
      payload.query = form.elements.query.value;
      payload.minAdoption = Number(form.elements.minAdoption.value || 100);
      payload.cmsType = form.elements.cmsType.value;
      payload.industry = form.elements.industry.value;
    }

    await withBusy(form.querySelector("#task-submit-button"), async () => {
      const task = await api("/api/tasks", { method: "POST", body: payload });
      showToast(`任务已创建：${task.id.slice(0, 8)}`, "success");
      setTimeout(() => {
        location.href = `/audit.html?task=${encodeURIComponent(task.id)}`;
      }, 500);
    });
  });
}

function syncSourceMode(githubFields, gitUrlFields, zipUploadFields, localFields) {
  const sourceType = getSourceType();
  githubFields?.classList.toggle("hidden-panel", sourceType !== "github");
  gitUrlFields?.classList.toggle("hidden-panel", sourceType !== "git-url");
  zipUploadFields?.classList.toggle("hidden-panel", sourceType !== "zip-upload");
  localFields?.classList.toggle("hidden-panel", sourceType !== "local");
}

function renderSkillPicker(target) {
  if (!target) return;
  if (!auditSkills.length) {
    target.innerHTML = `<div class="empty-card">没有可用的审计 Skill。</div>`;
    return;
  }

  const profileOptions = availableProfiles.map(p =>
    `<option value="${escapeHtml(p.id)}">${escapeHtml(p.name)} - ${escapeHtml(p.description)}</option>`
  ).join("");

  const defaultProfile = availableProfiles[0]?.id || "default";

  target.innerHTML = `
    <div id="profile-selector-row" style="grid-column: 1 / -1; display: flex; align-items: center; gap: 12px; margin-bottom: 16px; padding: 8px 12px; background: #f0f5ff; border-radius: 8px;">
      <label style="font-weight: 600; margin: 0; min-width: 80px;">审计配置:</label>
      <select id="profile-selector" style="flex: 1; padding: 6px 12px; border-radius: 6px; border: 1px solid #bfdbfe; background: white;">
        ${profileOptions}
      </select>
    </div>
    ${auditSkills.map(
      (skill) => `
        <label class="skill-card" data-profiles="${(skill.profiles || []).join(",")}">
          <input class="skill-checkbox" type="checkbox" value="${escapeHtml(skill.id)}" checked />
          <div>
            <strong>${escapeHtml(skill.name)}</strong>
            <p>${escapeHtml(skill.description)}</p>
            ${skill.profiles ? `<p style="font-size: 11px; color: #667eea;">配置: ${skill.profiles.join(", ")} | 优先级: ${skill.priority || "normal"}</p>` : ""}
          </div>
        </label>
      `
    ).join("")}
  `;

  const profileSelector = document.getElementById("profile-selector");
  if (profileSelector) {
    profileSelector.value = defaultProfile;
    profileSelector.addEventListener("change", (e) => {
      const selectedProfile = e.target.value;
      filterSkillsByProfile(selectedProfile);
    });
  }
}

function filterSkillsByProfile(profile) {
  const skillCards = document.querySelectorAll("#skill-picker .skill-card");
  skillCards.forEach((card) => {
    const cardProfiles = (card.dataset.profiles || "").split(",").filter(p => p);
    if (cardProfiles.length === 0 || cardProfiles.includes(profile)) {
      card.style.display = "";
      const checkbox = card.querySelector(".skill-checkbox");
      if (checkbox) checkbox.checked = true;
    } else {
      card.style.display = "none";
      const checkbox = card.querySelector(".skill-checkbox");
      if (checkbox) checkbox.checked = false;
    }
  });
}

function getSelectedSkillIds() {
  return Array.from(document.querySelectorAll(".skill-checkbox:checked")).map((checkbox) => checkbox.value);
}

function setAllSkills(checked) {
  document.querySelectorAll(".skill-checkbox").forEach((checkbox) => {
    checkbox.checked = checked;
  });
}

function getSourceType() {
  return document.querySelector('input[name="sourceType"]:checked')?.value || "github";
}

async function renderEnvironment() {
  const target = document.querySelector("#env-report");
  if (!target) return;
  try {
    const environment = await api("/api/environment");
    target.innerHTML = `
      <div class="info-grid">
        <div class="info-item"><strong>Node</strong><span>${escapeHtml(environment.runtime.node)}</span></div>
        <div class="info-item"><strong>平台</strong><span>${escapeHtml(environment.runtime.platform)} / ${escapeHtml(environment.runtime.arch)}</span></div>
        <div class="info-item"><strong>工作区</strong><span>${escapeHtml(environment.workspace.rootDir)}</span></div>
        <div class="info-item"><strong>LLM</strong><span>${escapeHtml(environment.llm.active?.label || "未配置")} / ${escapeHtml(environment.llm.active?.model || "未配置")}</span></div>
        <div class="info-item"><strong>GitHub</strong><span>${environment.github.tokenConfigured ? "Token 已配置" : "未配置 Token"}</span></div>
        <div class="info-item"><strong>抓取模式</strong><span>${escapeHtml(environment.github.crawlMode)}</span></div>
      </div>
    `;
  } catch {
    target.innerHTML = `<div class="empty-card">环境信息读取失败。</div>`;
  }

  document.querySelector("#env-refresh-button")?.addEventListener("click", renderEnvironment);
}

async function renderOverviewTasks() {
  const target = document.querySelector("#overview-tasks");
  if (!target) return;
  const tasks = await api("/api/tasks");
  renderQuickStatus(latestSettings || (await api("/api/settings")), tasks);

  if (!tasks.length) {
    target.innerHTML = `<div class="empty-card">还没有任务。</div>`;
    return;
  }

  target.innerHTML = tasks
    .slice(0, 6)
    .map(
      (task) => {
        const rowClass = task.status === "completed" ? "status-completed" : task.status === "failed" ? "status-failed" : "";
        return `
          <a class="task-row ${rowClass}" href="/audit.html?task=${encodeURIComponent(task.id)}">
            <strong>${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : task.query)}</strong>
            <span>${escapeHtml(task.phase)} · ${escapeHtml(STATUS_LABELS[task.status] || task.status)} · ${escapeHtml(task.progress?.label || "")}</span>
          </a>
        `;
      }
    )
    .join("");
}

function initAuditPage() {
  document.querySelector("#refresh-button")?.addEventListener("click", refreshAuditPage);
  selectedTaskId = new URLSearchParams(location.search).get("task") || null;
  document.querySelectorAll("#task-filter-tabs .filter-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll("#task-filter-tabs .filter-tab").forEach(t => t.classList.remove("active"));
      tab.classList.add("active");
      currentTaskFilter = tab.dataset.filter;
      refreshAuditPage();
    });
  });
}

async function refreshAuditPage() {
  const filterParam = currentTaskFilter !== "all" ? `?status=${encodeURIComponent(currentTaskFilter)}` : "";
  const tasks = await api(`/api/tasks${filterParam}`);
  renderQuickStatus(latestSettings || (await api("/api/settings")), await api("/api/tasks"));
  renderTaskList(tasks);

  const selectedInFiltered = selectedTaskId && tasks.some(t => t.id === selectedTaskId);
  if (!selectedInFiltered) {
    selectedTaskId = tasks.length ? tasks[0].id : null;
  }
  if (!selectedTaskId) {
    setHtml("#task-detail", '<div class="empty-card">还没有任务。</div>');
    stopAuditPolling();
    return;
  }

  const task = await api(`/api/tasks/${selectedTaskId}`);
  renderTaskDetail(task);

  if (task.status === "running" || task.status === "queued") {
    startAuditPolling();
  } else {
    stopAuditPolling();
  }
}

function renderTaskList(tasks) {
  const target = document.querySelector("#task-list");
  if (!target) return;
  if (!tasks.length) {
    target.innerHTML = `<div class="empty-card">暂无任务。</div>`;
    return;
  }

  target.innerHTML = tasks
    .map((task) => {
      const active = task.id === selectedTaskId ? "active" : "";
      const statusClass = "status-" + task.status;
      const statusText = STATUS_LABELS[task.status] || task.status;
      const canPause = task.status === "running";
      const canResume = task.status === "paused";
      const canStop = task.status === "running" || task.status === "queued";
      const actionButtons = `
        ${canPause ? '<button class="task-pause-btn" data-pause-id="' + escapeHtml(task.id) + '" title="暂停任务">⏸</button>' : ''}
        ${canResume ? '<button class="task-resume-btn" data-resume-id="' + escapeHtml(task.id) + '" title="恢复任务">▶</button>' : ''}
        ${canStop ? '<button class="task-stop-btn" data-stop-id="' + escapeHtml(task.id) + '" title="取消任务">⏹</button>' : ''}
      `;
      return '<div class="task-card ' + active + ' ' + statusClass + '" data-task-id="' + escapeHtml(task.id) + '">' +
        '<div class="task-card-main">' +
          '<strong>' + escapeHtml(task.sourceType === "local" ? "本地仓库导入" : task.query) + '</strong>' +
          '<span>' + escapeHtml(task.phase) + ' · ' + escapeHtml(statusText) + '</span>' +
          '<small>' + escapeHtml(task.progress?.label || "") + ' ' + escapeHtml(String(task.progress?.percent || 0)) + '%</small>' +
        '</div>' +
        '<div class="task-card-actions">' + actionButtons + '</div>' +
        '<button class="task-delete-btn" data-delete-id="' + escapeHtml(task.id) + '" title="删除任务">✕</button>' +
      '</div>';
    })
    .join("");

  target.querySelectorAll("[data-task-id]").forEach((card) => {
    card.addEventListener("click", async (e) => {
      if (e.target.classList.contains("task-delete-btn") || e.target.classList.contains("task-pause-btn") ||
          e.target.classList.contains("task-resume-btn") || e.target.classList.contains("task-stop-btn")) return;
      selectedTaskId = card.dataset.taskId;
      await refreshAuditPage();
    });
  });

  target.querySelectorAll(".task-pause-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const taskId = btn.dataset.pauseId;
      if (taskId && confirm("确定要暂停这个任务吗？")) {
        await api("/api/tasks/" + taskId + "/pause", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".task-resume-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const taskId = btn.dataset.resumeId;
      if (taskId && confirm("确定要恢复这个任务吗？")) {
        await api("/api/tasks/" + taskId + "/resume", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".task-stop-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const taskId = btn.dataset.stopId;
      if (taskId && confirm("确定要取消这个任务吗？取消后无法恢复。")) {
        await api("/api/tasks/" + taskId + "/stop", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".task-delete-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const taskId = btn.dataset.deleteId;
      if (taskId && confirm("确定要删除这个任务吗？")) {
        await api("/api/tasks/" + taskId, { method: "DELETE" });
        if (selectedTaskId === taskId) selectedTaskId = null;
        await refreshAuditPage();
      }
    });
  });
}

function renderTaskDetail(task) {
  if (task.phase === "target-selection") {
    renderSelectionView(task);
    return;
  }

  const target = document.querySelector("#task-detail");
  if (!target) return;

  const projects = task.auditResult?.projects || [];
  const statusText = STATUS_LABELS[task.status] || task.status;
  const findingsCount = task.auditResult?.findingsCount || 0;
  const findingsTotalCount = task.auditResult?.findingsTotalCount || 0;
  // 使用验证前的原始数据，与卡片内统计保持一致
  const heuristicCount = projects.reduce((sum, p) => {
    return sum + (p.heuristicFindings?.length || 0);
  }, 0);
  const llmCount = projects.reduce((sum, p) => {
    return sum + (p.llmAudit?.findings?.length || 0);
  }, 0);
  const reactCount = projects.reduce((sum, p) => {
    return sum + (p.reactAudit?.issues?.length || 0);
  }, 0);
  const totalCount = heuristicCount + llmCount + reactCount;
  const useReAct = task.useReAct === true;
  const canPause = task.status === "running";
  const canResume = task.status === "paused";
  const canStop = task.status === "running" || task.status === "queued";
  const canRestart = task.status === "completed" || task.status === "failed";

  let html = "";
  html += '<div class="summary-grid">';
  html += '<div class="summary-card"><strong>状态</strong><span>' + escapeHtml(statusText) + '</span></div>';
  html += '<div class="summary-card"><strong>阶段</strong><span>' + escapeHtml(task.phase) + '</span></div>';
  html += '<div class="summary-card"><strong>来源</strong><span>' + escapeHtml(task.sourceType) + '</span></div>';
  html += '<div class="summary-card"><strong>结果</strong><span>' + escapeHtml(String(totalCount)) + '</span></div>';
  html += '</div>';

  if (canPause || canResume || canStop || canRestart) {
    html += '<div class="detail-block">';
    html += '<div class="task-action-buttons">';
    if (canPause) html += '<button class="btn-pause" data-pause-id="' + escapeHtml(task.id) + '">⏸ 暂停</button>';
    if (canResume) html += '<button class="btn-resume" data-resume-id="' + escapeHtml(task.id) + '">▶ 恢复</button>';
    if (canStop) html += '<button class="btn-stop" data-stop-id="' + escapeHtml(task.id) + '">⏹ 取消</button>';
    if (canRestart) html += '<button class="btn-restart" data-restart-id="' + escapeHtml(task.id) + '">🔄 重新审计</button>';
    html += '</div>';
    html += '</div>';
  }

  html += buildProgressCard(task.progress);

  html += '<div class="detail-block">';
  html += '<h3>任务说明</h3>';
  html += '<p>' + escapeHtml(task.message || "") + '</p>';
  html += '</div>';

  if (task.report?.html?.downloadPath || task.status === 'completed') {
    html += '<div class="detail-block">';
    html += '<h3>审计报告</h3>';
    html += '<div class="report-export-grid">';
    if (task.report?.html?.downloadPath) {
      html += '<a class="report-export-btn" href="' + escapeHtml(task.report.html.downloadPath) + '" target="_blank" rel="noreferrer">📄 HTML</a>';
    }
    html += '<button class="report-export-btn" id="export-sarif-btn" data-task-id="' + escapeHtml(task.id) + '">📋 SARIF</button>';
    html += '<button class="report-export-btn" id="export-json-btn" data-task-id="' + escapeHtml(task.id) + '">📊 JSON</button>';
    html += '<button class="report-export-btn" id="export-markdown-btn" data-task-id="' + escapeHtml(task.id) + '">📝 Markdown</button>';
    html += '</div>';
    html += '</div>';
  }

  html += renderAuditMetrics(task);

    html += '<div class="detail-block">';
    html += '<h3>审计结果</h3>';
    html += '<p>规则层 ' + escapeHtml(String(heuristicCount)) + ' 条，LLM 复核 ' + escapeHtml(String(llmCount)) + ' 条' + (useReAct ? '，ReAct推理 ' + escapeHtml(String(reactCount)) + ' 条' : '') + '。</p>';
    if (projects.length) {
      html += projects.map(renderProjectReview).join("");
    } else {
      html += '<div class="empty-card">任务还在进行中。</div>';
    }
    html += '</div>';

    target.innerHTML = html;

  target.querySelectorAll(".btn-pause").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.pauseId;
      if (taskId && confirm("确定要暂停这个任务吗？")) {
        await api("/api/tasks/" + taskId + "/pause", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".btn-resume").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.resumeId;
      if (taskId && confirm("确定要恢复这个任务吗？")) {
        await api("/api/tasks/" + taskId + "/resume", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".btn-stop").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.stopId;
      if (taskId && confirm("确定要取消这个任务吗？取消后无法恢复。")) {
        await api("/api/tasks/" + taskId + "/stop", { method: "POST" });
        await refreshAuditPage();
      }
    });
  });

  target.querySelectorAll(".btn-restart").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.restartId;
      if (taskId && confirm("确定要重新审计吗？这将创建一个新的审计任务。")) {
        try {
          const newTask = await api("/api/tasks/" + taskId + "/restart", { method: "POST" });
          showToast("重新审计任务已创建", "success");
          selectedTaskId = newTask.id;
          await refreshAuditPage();
        } catch (error) {
          showToast("创建重新审计任务失败: " + (error.message || "未知错误"), "error");
        }
      }
    });
  });

  target.querySelectorAll("#export-sarif-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.taskId;
      if (!taskId) return;
      btn.textContent = "正在导出...";
      btn.disabled = true;
      try {
        const result = await api("/api/export-sarif?taskId=" + encodeURIComponent(taskId));
        if (result.success) {
          showToast("SARIF 报告已生成: " + result.findingsCount + " 条发现", "success");
          window.open(result.downloadPath, "_blank");
        } else {
          showToast("导出失败: " + (result.error || "未知错误"), "error");
        }
      } catch (error) {
        showToast("导出失败: " + (error.message || "未知错误"), "error");
      } finally {
        btn.textContent = "📋 SARIF";
        btn.disabled = false;
      }
    });
  });

  target.querySelectorAll("#export-json-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.taskId;
      if (!taskId) return;
      btn.textContent = "正在导出...";
      btn.disabled = true;
      try {
        const result = await api("/api/export-json?taskId=" + encodeURIComponent(taskId));
        if (result.success) {
          showToast("JSON 报告已生成", "success");
          window.open(result.downloadPath, "_blank");
        } else {
          showToast("导出失败: " + (result.error || "未知错误"), "error");
        }
      } catch (error) {
        showToast("导出失败: " + (error.message || "未知错误"), "error");
      } finally {
        btn.textContent = "📊 JSON";
        btn.disabled = false;
      }
    });
  });

  target.querySelectorAll("#export-markdown-btn").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const taskId = btn.dataset.taskId;
      if (!taskId) return;
      btn.textContent = "正在导出...";
      btn.disabled = true;
      try {
        const result = await api("/api/export-markdown?taskId=" + encodeURIComponent(taskId));
        if (result.success) {
          showToast("Markdown 报告已生成", "success");
          window.open(result.downloadPath, "_blank");
        } else {
          showToast("导出失败: " + (result.error || "未知错误"), "error");
        }
      } catch (error) {
        showToast("导出失败: " + (error.message || "未知错误"), "error");
      } finally {
        btn.textContent = "📝 Markdown";
        btn.disabled = false;
      }
    });
  });

  target.querySelectorAll("[data-filter-all], [data-filter-owasp], [data-filter-gbt]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const projectName = btn.dataset.filterAll || btn.dataset.filterOwasp || btn.dataset.filterGbt;
      const filterType = btn.dataset.filterAll ? 'all' : btn.dataset.filterOwasp ? 'owasp' : 'gbt';
      
      target.querySelectorAll(`[data-filter-all="${projectName}"], [data-filter-owasp="${projectName}"], [data-filter-gbt="${projectName}"]`).forEach(t => t.classList.remove('active'));
      btn.classList.add('active');

      const findingLists = target.querySelectorAll('.finding-list');
      findingLists.forEach(list => {
        list.querySelectorAll('li').forEach(item => {
          if (filterType === 'all') {
            item.style.display = '';
          } else if (filterType === 'owasp' && item.querySelector('.badge-owasp')) {
            item.style.display = '';
          } else if (filterType === 'gbt' && item.querySelector('.badge-gbt')) {
            item.style.display = '';
          } else if (filterType !== 'all') {
            item.style.display = 'none';
          }
        });
      });
    });
  });
}

function renderSelectionView(task) {
  const target = document.querySelector("#task-detail");
  if (!target) return;

  const allProjects = task.scoutResult?.projects || [];
  const state = candidateState.get(task.id) || { keyword: "", page: 0 };
  const selected = selectionState.get(task.id) || new Set();
  const keyword = state.keyword.trim().toLowerCase();
  const filtered = allProjects.filter((project) => {
    const text = `${project.name} ${project.description || ""} ${project.cmsType || ""} ${(project.industries || []).join(" ")}`.toLowerCase();
    return !keyword || text.includes(keyword);
  });
  const pageSize = 10;
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const pageIndex = Math.min(state.page || 0, pageCount - 1);
  const pageItems = filtered.slice(pageIndex * pageSize, pageIndex * pageSize + pageSize);

  target.innerHTML = `
    <div class="detail-block">
      <div class="panel-head">
        <div>
          <h3>选择要审计的目标</h3>
          <p class="note">每页展示 10 个候选项目，你可以筛选后再勾选。</p>
        </div>
        <button id="start-audit-button" type="button">开始审计已选目标</button>
      </div>
      <div class="toolbar">
        <input id="candidate-keyword" value="${escapeHtml(state.keyword || "")}" placeholder="按名称、描述、类型或行业筛选" />
        <span class="note">已选 ${selected.size} 个</span>
      </div>
      <div class="stack">
        ${pageItems
          .map(
            (project) => `
              <label class="candidate-card">
                <input data-project-id="${escapeHtml(project.id)}" type="checkbox" ${selected.has(project.id) ? "checked" : ""} />
                <div>
                  <strong>${escapeHtml(project.name)}</strong>
                  <p>${escapeHtml(project.description || "暂无描述")}</p>
                  <span>${escapeHtml(project.cmsType || "generic")} · ${escapeHtml((project.industries || ["general"]).join(" / "))} · 存活量 ${
                    escapeHtml(String(project.adoptionSignals?.estimatedLiveUsage || 0))
                  }</span>
                </div>
              </label>
            `
          )
          .join("")}
      </div>
      <div class="button-row">
        <button id="page-prev" class="ghost" type="button" ${pageIndex <= 0 ? "disabled" : ""}>上一页</button>
        <span class="note">第 ${pageIndex + 1} / ${pageCount} 页</span>
        <button id="page-next" class="ghost" type="button" ${pageIndex >= pageCount - 1 ? "disabled" : ""}>下一页</button>
      </div>
    </div>
  `;

  target.querySelectorAll("[data-project-id]").forEach((input) => {
    input.addEventListener("change", () => {
      const set = selectionState.get(task.id) || new Set();
      if (input.checked) set.add(input.dataset.projectId);
      else set.delete(input.dataset.projectId);
      selectionState.set(task.id, set);
      renderSelectionView(task);
    });
  });

  target.querySelector("#candidate-keyword")?.addEventListener("input", (event) => {
    candidateState.set(task.id, { keyword: event.target.value, page: 0 });
    renderSelectionView(task);
  });

  target.querySelector("#page-prev")?.addEventListener("click", () => {
    candidateState.set(task.id, { ...state, page: Math.max(0, pageIndex - 1) });
    renderSelectionView(task);
  });

  target.querySelector("#page-next")?.addEventListener("click", () => {
    candidateState.set(task.id, { ...state, page: Math.min(pageCount - 1, pageIndex + 1) });
    renderSelectionView(task);
  });

  target.querySelector("#start-audit-button")?.addEventListener("click", async () => {
    const selectedIds = Array.from(selectionState.get(task.id) || []);
    if (!selectedIds.length) {
      showToast("请先选择至少一个目标。", "info");
      return;
    }
    await api(`/api/tasks/${task.id}/audit`, { method: "POST", body: { selectedProjectIds: selectedIds } });
    showToast("审计已启动。", "success");
    await refreshAuditPage();
  });
}

function renderProjectReview(project) {
  const heuristicFindings = project.heuristicFindings || [];
  const llmFindings = project.llmAudit?.findings || [];
  const reactFindings = project.reactAudit?.issues || [];
  const allFindings = [...heuristicFindings, ...llmFindings, ...reactFindings];
  const severityStats = {
    critical: allFindings.filter(f => f.severity === 'critical' || f.severity === 'CRITICAL').length,
    high: allFindings.filter(f => f.severity === 'high' || f.severity === 'HIGH').length,
    medium: allFindings.filter(f => f.severity === 'medium' || f.severity === 'MEDIUM').length,
    low: allFindings.filter(f => f.severity === 'low' || f.severity === 'LOW').length
  };

  const typeStats = {};
  allFindings.forEach(f => {
    const type = f.type || f.vulnType || '其他';
    typeStats[type] = (typeStats[type] || 0) + 1;
  });

  const total = severityStats.critical + severityStats.high + severityStats.medium + severityStats.low;
  const projectNameClean = project.projectName.replace(/[^a-zA-Z0-9]/g, '-');

  function renderCharts() {
    const severityChartContainer = document.querySelector('#severity-pie-' + projectNameClean);
    const typeChartContainer = document.querySelector('#type-bar-' + projectNameClean);

    if (severityChartContainer) {
      charts.pieChart('#severity-pie-' + projectNameClean, [
        { label: '严重', value: severityStats.critical, color: '#ef4444' },
        { label: '高危', value: severityStats.high, color: '#f97316' },
        { label: '中危', value: severityStats.medium, color: '#f59e0b' },
        { label: '低危', value: severityStats.low, color: '#10b981' }
      ]);
    }

    const vulnTypeLabels = {
      HARD_CODED_SECRET: "硬编码密钥", COMMAND_INJECTION: "命令注入", SQL_INJECTION: "SQL注入",
      CODE_INJECTION: "代码注入", DESERIALIZATION: "反序列化", AUTH_BYPASS: "认证绕过",
      SSRF: "SSRF", XSS: "XSS", PATH_TRAVERSAL: "路径穿越", SESSION_FIXATION: "会话固定",
      WEAK_CRYPTO: "弱加密", INFO_LEAK: "信息泄露", FILE_UPLOAD: "文件上传",
      OPEN_REDIRECT: "开放重定向", XXE: "XXE", CSRF: "CSRF", IDOR: "越权访问"
    };
    const typeData = Object.entries(typeStats).map(([type, value], idx) => ({
      label: vulnTypeLabels[type] || type,
      value,
      color: charts.getColor(idx)
    }));

    if (typeChartContainer) {
      charts.barChart('#type-bar-' + projectNameClean, typeData);
    }
  }

  setTimeout(renderCharts, 100);
  
  requestAnimationFrame(() => {
    setTimeout(renderCharts, 50);
  });

  return `
    <article class="review-card-block">
      <div class="review-head">
        <div>
          <h4>${escapeHtml(project.projectName)}</h4>
          ${
            project.repoUrl
              ? `<p><a href="${escapeHtml(project.repoUrl)}" target="_blank" rel="noreferrer">${escapeHtml(project.repoUrl)}</a></p>`
              : ""
          }
          ${
            project.localPath
              ? `<p>审计镜像：${escapeHtml(project.localPath)}</p>`
              : ""
          }
        </div>
        <div class="summary-badge">
          <span class="total-count">共 ${total} 个问题</span>
        </div>
      </div>

      <div class="stats-grid">
        <section class="chart-section">
          <h5>按问题严重等级统计</h5>
          <div class="chart-container" id="severity-pie-${projectNameClean}"></div>
          <div class="chart-legend">
            <span class="legend-item"><span class="legend-dot" style="background:#ef4444"></span> 严重 ${severityStats.critical}</span>
            <span class="legend-item"><span class="legend-dot" style="background:#f97316"></span> 高危 ${severityStats.high}</span>
            <span class="legend-item"><span class="legend-dot" style="background:#f59e0b"></span> 中危 ${severityStats.medium}</span>
            <span class="legend-item"><span class="legend-dot" style="background:#10b981"></span> 低危 ${severityStats.low}</span>
          </div>
        </section>

        <section class="chart-section">
          <h5>按问题类型统计</h5>
          <div class="chart-container bar-chart" id="type-bar-${projectNameClean}"></div>
        </section>
      </div>

      <div class="stats-grid" style="grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); margin-top: 12px;">
        <div class="summary-card"><strong>规则层</strong><span>${heuristicFindings.length}</span></div>
        <div class="summary-card"><strong>LLM 复核</strong><span>${llmFindings.length}</span></div>
        <div class="summary-card"><strong>LLM 状态</strong><span>${escapeHtml(project.llmAudit?.status || 'N/A')}</span></div>
        <div class="summary-card"><strong>调用</strong><span>${project.llmAudit?.called ? '是' : '否'}</span></div>
      </div>
      ${project.llmAudit?.summary ? `<p class="note" style="margin-top: 8px;">${escapeHtml(project.llmAudit.summary)}</p>` : ''}
    </article>
  `;
}

function renderAuditMetrics(task) {
  const metrics = task.metrics || {};
  const auditPhases = task.auditPhases || [];
  
  if (!Object.keys(metrics).length && !auditPhases.length) {
    return '';
  }

  let html = '<div class="detail-block">';
  html += '<h3>📊 审计统计</h3>';
  
  if (auditPhases.length) {
    html += '<div class="audit-phases">';
    html += '<div class="phases-header">审计阶段</div>';
    html += '<div class="phases-timeline">';
    auditPhases.forEach((phase, idx) => {
      const isCompleted = phase.status === 'completed';
      const isCurrent = phase.status === 'running';
      html += `
        <div class="phase-item ${isCompleted ? 'completed' : ''} ${isCurrent ? 'current' : ''}">
          <div class="phase-dot"></div>
          <div class="phase-info">
            <span class="phase-name">${escapeHtml(phase.name)}</span>
            <span class="phase-status">${isCompleted ? '✓ 完成' : isCurrent ? '⏳ 进行中' : '待执行'}</span>
          </div>
          ${phase.duration ? `<span class="phase-duration">${escapeHtml(phase.duration)}s</span>` : ''}
        </div>
      `;
    });
    html += '</div>';
    html += '</div>';
  }

  if (Object.keys(metrics).length) {
    html += '<div class="metrics-grid">';
    
    const metricItems = [
      { key: 'totalDuration', label: '总耗时', value: metrics.totalDuration ? `${metrics.totalDuration}s` : '-', icon: '⏱️' },
      { key: 'llmCalls', label: 'LLM调用', value: metrics.llmCalls || '-', icon: '🤖' },
      { key: 'averageConfidence', label: '平均置信度', value: metrics.averageConfidence ? `${Math.round(metrics.averageConfidence * 100)}%` : '-', icon: '📈' },
      { key: 'truePositiveRate', label: '准确率', value: metrics.truePositiveRate ? `${Math.round(metrics.truePositiveRate * 100)}%` : '-', icon: '✅' },
      { key: 'filesScanned', label: '扫描文件', value: metrics.filesScanned || '-', icon: '📁' },
      { key: 'linesAnalyzed', label: '分析行数', value: metrics.linesAnalyzed?.toLocaleString() || '-', icon: '📝' },
    ];

    metricItems.forEach(item => {
      html += `
        <div class="metric-card">
          <span class="metric-icon">${item.icon}</span>
          <div class="metric-content">
            <span class="metric-label">${item.label}</span>
            <span class="metric-value">${item.value}</span>
          </div>
        </div>
      `;
    });
    
    html += '</div>';
  }
  
  html += '</div>';
  return html;
}

function renderFindingList(findings, emptyMessage) {
  if (!findings?.length) {
    return '<div class="empty-card">' + escapeHtml(emptyMessage) + '</div>';
  }

  const getConfidenceClass = (confidence) => {
    if (!confidence) return 'medium';
    if (confidence >= 0.7) return 'high';
    if (confidence >= 0.4) return 'medium';
    return 'low';
  };

  const getConfidenceLabel = (confidence) => {
    if (!confidence) return '中';
    if (confidence >= 0.8) return '高';
    if (confidence >= 0.5) return '中';
    return '低';
  };

  const getStandardBadge = (finding) => {
    const badges = [];
    if (finding.gbtMapping?.includes('GB/T')) {
      badges.push('<span class="badge badge-gbt">国标</span>');
    }
    if (finding.owasp || finding.owaspId || (finding.gbtMapping && finding.gbtMapping.includes('OWASP'))) {
      badges.push('<span class="badge badge-owasp">OWASP</span>');
    }
    return badges.join('');
  };

  const renderKnowledgeCard = (finding) => {
    const items = [];
    if (finding.cwe) {
      items.push(`<div class="knowledge-item"><span class="knowledge-label">CWE</span><span class="knowledge-value">${escapeHtml(finding.cwe)}</span></div>`);
    }
    if (finding.owasp) {
      items.push(`<div class="knowledge-item"><span class="knowledge-label">OWASP</span><span class="knowledge-value">${escapeHtml(finding.owasp)}</span></div>`);
    }
    if (finding.gbtMapping) {
      items.push(`<div class="knowledge-item"><span class="knowledge-label">GB/T</span><span class="knowledge-value">${escapeHtml(finding.gbtMapping)}</span></div>`);
    }
    if (finding.vulnType) {
      items.push(`<div class="knowledge-item"><span class="knowledge-label">类型</span><span class="knowledge-value">${escapeHtml(finding.vulnType)}</span></div>`);
    }
    if (items.length === 0) return '';
    
    return `
      <div class="knowledge-card">
        <div class="knowledge-header">📚 参考标准</div>
        <div class="knowledge-content">${items.join('')}</div>
      </div>
    `;
  };

  const renderDetailSection = (finding) => {
    const details = [];
    if (finding.description) {
      const desc = finding.description.length > 150 ? finding.description.substring(0, 150) + '...' : finding.description;
      details.push(`<p class="finding-description">${escapeHtml(desc)}</p>`);
    }
    if (finding.remediation) {
      details.push(`<p class="finding-remediation"><strong>修复建议:</strong> ${escapeHtml(finding.remediation.substring(0, 100) + '...')}</p>`);
    }
    return details.join('');
  };

  return '<ul class="finding-list">' +
    findings.map(f => {
      const severityLabels = { critical: "严重", CRITICAL: "严重", high: "高危", HIGH: "高危", medium: "中危", MEDIUM: "中危", low: "低危", LOW: "低危" };
      const sev = severityLabels[f.severity] || f.severity || "info";
      const confidence = f.confidence !== undefined ? f.confidence : 0.75;
      const confidencePercent = Math.round(confidence * 100);
      const confidenceClass = getConfidenceClass(confidence);
      const confidenceLabel = getConfidenceLabel(confidence);
      const clusterInfo = f.clusterId ? `<span class="cluster-tag">🗂️ 聚类 ${f.clusterSize || 1}</span>` : '';
      const standardBadge = getStandardBadge(f);
      const verdictBadge = f.verdict ? (() => {
        if (f.verdict === 'confirmed') return '<span class="badge badge-success">✓ 已确认</span>';
        if (f.verdict === 'false_positive') return '<span class="badge badge-danger">✗ 误报</span>';
        if (f.verdict === 'downgraded') return '<span class="badge badge-warning">↓ 已降级</span>';
        if (f.verdict === 'needs_review') return '<span class="badge badge-info">? 待复核</span>';
        return '';
      })() : '';
      const knowledgeCard = renderKnowledgeCard(f);
      const detailSection = renderDetailSection(f);

      return '<li class="finding-item expanded' + (f.verdict === 'false_positive' ? ' finding-fp' : '') + '">' +
        '<div class="finding-head">' +
          '<strong>' + escapeHtml(f.title) + '</strong>' +
          '<span>' +
            '<span class="badge badge-' + (f.severity || 'info') + '">' + escapeHtml(sev) + '</span>' +
            '<span class="badge badge-confidence badge-confidence-' + confidenceClass + '">置信度 ' + confidenceLabel + '</span>' +
            standardBadge +
            verdictBadge +
            clusterInfo +
          '</span>' +
        '</div>' +
        (f.verificationReason ? '<p class="note">验证说明：' + escapeHtml(f.verificationReason) + '</p>' : '') +
        '<span class="finding-location">📍 ' + escapeHtml(f.location || "n/a") + '</span>' +
        '<div class="confidence-bar">' +
          '<div class="confidence-info">' +
            '<span class="confidence-label">置信度</span>' +
            '<span class="confidence-value">' + confidencePercent + '%</span>' +
          '</div>' +
          '<div class="confidence-track">' +
            '<div class="confidence-fill ' + confidenceClass + '" style="width:' + confidencePercent + '%"></div>' +
          '</div>' +
          '<div class="confidence-marks">' +
            '<span>0%</span>' +
            '<span>50%</span>' +
            '<span>100%</span>' +
          '</div>' +
        '</div>' +
        knowledgeCard +
        detailSection +
      '</li>';
    }).join("") +
  '</ul>';
}

function renderReActSteps(steps) {
  if (!steps?.length) return "";

  const toolLabels = {
    'local_file_content': '读取文件',
    'local_file_info': '文件信息',
    'local_search_code': '搜索代码',
    'local_list_directory': '列出目录',
    'local_context_analysis': '上下文分析',
    'local_glob_search': '全局搜索',
    'local_trace_calls': '追踪调用',
    'local_check_dependency': '检查依赖',
    'local_analyze_data_flow': '分析数据流'
  };

  return '<div class="react-steps">' +
    steps.map((step, idx) => {
      const toolLabel = toolLabels[step.action] || step.action || '思考';
      const thoughtPreview = step.thought?.length > 100 ? step.thought.substring(0, 100) + '...' : step.thought;
      const obsPreview = step.observation?.length > 150 ? step.observation.substring(0, 150) + '...' : step.observation;
      return '<div class="react-step">' +
        '<div class="react-step-header">' +
          '<span class="react-step-num">步骤 ' + (idx + 1) + '</span>' +
          '<span class="react-step-tool">' + escapeHtml(toolLabel) + '</span>' +
        '</div>' +
        '<div class="react-step-thought"><strong>推理:</strong> ' + escapeHtml(thoughtPreview || "") + '</div>' +
        (step.actionArgs ? '<div class="react-step-args"><strong>参数:</strong> ' + escapeHtml(JSON.stringify(step.actionArgs)) + '</div>' : '') +
        (step.observation ? '<div class="react-step-obs"><strong>结果:</strong> ' + escapeHtml(obsPreview) + '</div>' : '') +
      '</div>';
    }).join("") +
  '</div>';
}

function buildProgressCard(progress) {
  const percent = Math.max(0, Math.min(100, Number(progress?.percent || 0)));
  return `
    <div class="detail-block progress-card">
      <div class="panel-head">
        <h3>${escapeHtml(progress?.label || "处理中")}</h3>
        <span>${escapeHtml(String(percent))}%</span>
      </div>
      <div class="progress-track"><div class="progress-fill" style="width:${percent}%"></div></div>
      <p class="note">${escapeHtml([progress?.current, progress?.total].every((value) => value !== undefined) ? `${progress?.current || 0} / ${progress?.total || 0}` : "")}${
        progress?.detail ? ` · ${escapeHtml(progress.detail)}` : ""
      }</p>
    </div>
  `;
}

function initFingerprintPage() {
  document.querySelector("#fingerprint-refresh-button")?.addEventListener("click", refreshFingerprintProjects);
  document.querySelector("#asset-match-button")?.addEventListener("click", matchAssetsForSelectedProject);
}

async function refreshFingerprintProjects() {
  const target = document.querySelector("#fingerprint-projects");
  if (!target) return;

  fingerprintProjects = await api("/api/fingerprint/projects");
  if (!fingerprintProjects.length) {
    target.innerHTML = '<div class="empty-card">还没有本地镜像项目。请先在审计中心完成一次镜像下载。</div>';
    setHtml("#fingerprint-detail", '<div class="empty-card">暂无可分析项目。</div>');
    return;
  }

  if (!selectedFingerprintProjectId) {
    selectedFingerprintProjectId = fingerprintProjects[0].id;
  }

  target.innerHTML = fingerprintProjects
    .map((project) => {
      const active = project.id === selectedFingerprintProjectId ? "active" : "";
      return '<div class="task-card ' + active + '" data-fingerprint-project="' + escapeHtml(project.id) + '">' +
        '<div class="task-card-main">' +
          '<strong>' + escapeHtml(project.name) + '</strong>' +
          '<span>' + escapeHtml(project.localPath) + '</span>' +
          '<small>' + escapeHtml(String(project.fileCount)) + ' 个文件</small>' +
        '</div>' +
        '<button class="task-delete-btn" data-delete-fp="' + escapeHtml(project.id) + '" title="删除镜像">✕</button>' +
      '</div>';
    })
    .join("");

  target.querySelectorAll("[data-fingerprint-project]").forEach((card) => {
    card.addEventListener("click", async (e) => {
      if (e.target.classList.contains("task-delete-btn")) return;
      selectedFingerprintProjectId = card.dataset.fingerprintProject;
      await refreshFingerprintProjects();
    });
  });

  target.querySelectorAll(".task-delete-btn").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const projectId = btn.dataset.deleteFp;
      if (projectId && confirm("确定要删除这个镜像项目吗？")) {
        const result = await api("/api/fingerprint/projects/" + projectId, { method: "DELETE" });
        if (result.success) {
          if (selectedFingerprintProjectId === projectId) {
            selectedFingerprintProjectId = null;
            setHtml("#fingerprint-detail", '<div class="empty-card">请选择一个本地镜像项目进行分析。</div>');
          }
          showToast("镜像已删除。", "success");
          await refreshFingerprintProjects();
        } else {
          showToast(result.message || "删除失败。", "error");
        }
      }
    });
  });

  await renderFingerprintDetail(selectedFingerprintProjectId);
}

async function renderFingerprintDetail(projectId) {
  const target = document.querySelector("#fingerprint-detail");
  if (!target || !projectId) return;

  const analysis = await api("/api/fingerprint/analyze", {
    method: "POST",
    body: { projectId }
  });

  target.innerHTML = `
    <div class="summary-grid">
      <div class="summary-card"><strong>文件数</strong><span>${escapeHtml(String(analysis.fileCount))}</span></div>
      <div class="summary-card"><strong>CMS</strong><span>${escapeHtml(analysis.cms.map((item) => item.label).join("、") || "未识别")}</span></div>
      <div class="summary-card"><strong>技术栈</strong><span>${escapeHtml(analysis.technologies.map((item) => item.label).join("、") || "未识别")}</span></div>
      <div class="summary-card"><strong>语言</strong><span>${escapeHtml(analysis.languages.join("、") || "未识别")}</span></div>
    </div>
    <div class="detail-block">
      <h3>后台路径特征</h3>
      <p>${escapeHtml(analysis.adminPaths.join("、") || "暂无明显后台路径特征。")}</p>
      <h3>接口路径特征</h3>
      <p>${escapeHtml(analysis.apiPaths.join("、") || "暂无明显接口路径特征。")}</p>
      <h3>本地匹配建议</h3>
      <ul class="plain-list">${analysis.safeSearchHints.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </div>
  `;
}

async function matchAssetsForSelectedProject() {
  if (!selectedFingerprintProjectId) {
    showToast("请先选择一个本地镜像项目。", "info");
    return;
  }
  const assetText = document.querySelector("#asset-input")?.value || "";
  const result = await api("/api/fingerprint/match", {
    method: "POST",
    body: { projectId: selectedFingerprintProjectId, assetText }
  });
  setHtml(
    "#asset-match-result",
    `
      <div class="summary-grid">
        <div class="summary-card"><strong>总资产</strong><span>${escapeHtml(String(result.totalAssets))}</span></div>
        <div class="summary-card"><strong>匹配到</strong><span>${escapeHtml(String(result.matchedAssets))}</span></div>
      </div>
      <p>${escapeHtml(result.safeSummary)}</p>
      ${
        result.matches?.length
          ? `<ul class="plain-list">${result.matches
              .map((item) => `<li>${escapeHtml(item.asset)} · 命中：${escapeHtml(item.hitTokens.join("、"))}</li>`)
              .join("")}</ul>`
          : ""
      }
    `
  );
}

function initSettingsPage() {
  const settingsForm = document.querySelector("#settings-form");
  const memoryForm = document.querySelector("#memory-form");
  const providerSelect = settingsForm?.elements.providerId;

  providerSelect?.addEventListener("change", () => applyProviderDefaults(settingsForm));
  document.querySelector("#settings-refresh-button")?.addEventListener("click", refreshSettingsPage);
  document.querySelector("#settings-test-button")?.addEventListener("click", testConnections);
  document.querySelector("#clear-llm-button")?.addEventListener("click", () => clearSecrets(["llm"]));
  document.querySelector("#clear-github-button")?.addEventListener("click", () => clearSecrets(["github"]));
  document.querySelector("#clear-fofa-button")?.addEventListener("click", () => clearSecrets(["fofa"]));
  document.querySelector("#memory-refresh-button")?.addEventListener("click", refreshMemoryPage);

  settingsForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/settings", {
      method: "POST",
      body: {
        llm: {
          providerId: settingsForm.elements.providerId.value,
          baseUrl: settingsForm.elements.baseUrl.value,
          model: settingsForm.elements.model.value,
          apiKey: settingsForm.elements.apiKey.value
        },
        github: {
          token: settingsForm.elements.githubToken.value,
          ownerFilter: settingsForm.elements.ownerFilter.value,
          notes: settingsForm.elements.githubNotes.value
        },
        fofa: {
          email: settingsForm.elements.fofaEmail.value,
          apiKey: settingsForm.elements.fofaApiKey.value,
          notes: settingsForm.elements.fofaNotes.value
        }
      }
    });
    settingsForm.elements.apiKey.value = "";
    settingsForm.elements.githubToken.value = "";
    settingsForm.elements.fofaApiKey.value = "";
    showToast("设置已保存。", "success");
    await Promise.all([refreshSettingsPage(), loadQuickStatus()]);
  });

  memoryForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/memory", {
      method: "POST",
      body: {
        preferences: {
          preferredQuery: memoryForm.elements.preferredQuery.value,
          preferredMinAdoption: Number(memoryForm.elements.preferredMinAdoption.value || 100),
          autoUseMemory: true
        },
        rules: String(memoryForm.elements.rules.value || "")
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean)
      }
    });
    showToast("项目记忆已更新。", "success");
    await refreshMemoryPage();
  });
}

async function refreshSettingsPage() {
  const settings = await api("/api/settings");
  latestSettings = settings;
  const form = document.querySelector("#settings-form");
  if (!form) return;

  form.elements.providerId.value = settings.llm.providerId;
  form.elements.baseUrl.value = settings.llm.baseUrl;
  form.elements.model.value = settings.llm.model;
  form.elements.ownerFilter.value = settings.github.ownerFilter;
  form.elements.githubNotes.value = settings.github.notes || "";
  form.elements.fofaEmail.value = settings.fofa?.email || "";
  form.elements.fofaNotes.value = settings.fofa?.notes || "";

  setText(
    "#settings-summary",
    `当前模型：${settings.llm.providerId} / ${settings.llm.model || "未配置"}，GitHub：${
      settings.github.tokenConfigured ? settings.github.tokenMasked : "未配置"
    }，FOFA：${settings.fofa?.apiKeyConfigured ? settings.fofa.apiKeyMasked : "未存档"}`
  );
}

async function refreshMemoryPage() {
  latestMemory = await api("/api/memory");
  setHtml(
    "#memory-view",
    `
      <p>默认查询：${escapeHtml(latestMemory.preferences?.preferredQuery || "未设置")}</p>
      <p>默认阈值：${escapeHtml(String(latestMemory.preferences?.preferredMinAdoption || 100))}</p>
      <p>已学习模式：${escapeHtml((latestMemory.learnedPatterns || []).slice(0, 5).join("、") || "暂无")}</p>
    `
  );
  const form = document.querySelector("#memory-form");
  if (!form) return;
  form.elements.preferredQuery.value = latestMemory.preferences?.preferredQuery || 'topic:cms OR "headless cms" OR "content management system"';
  form.elements.preferredMinAdoption.value = latestMemory.preferences?.preferredMinAdoption || 100;
  form.elements.rules.value = (latestMemory.rules || []).join("\n");
}

async function testConnections() {
  const result = await api("/api/settings/test", { method: "POST" });
  setHtml(
    "#connection-test-result",
    `
      <div class="info-grid">
        <div class="info-item"><strong>整体</strong><span>${escapeHtml(result.overall)}</span></div>
        <div class="info-item"><strong>LLM</strong><span>${escapeHtml(result.llm.message)}</span></div>
        <div class="info-item"><strong>GitHub</strong><span>${escapeHtml(result.github.message)}</span></div>
      </div>
    `
  );
}

async function clearSecrets(targets) {
  await api("/api/settings/clear-secrets", { method: "POST", body: { targets } });
  showToast("密钥已清空。", "success");
  await Promise.all([refreshSettingsPage(), loadQuickStatus()]);
}

function applyProviderDefaults(form) {
  const providerId = form.elements.providerId.value;
  const defaults = providerDefaultsMap[providerId];
  if (!defaults) return;
  form.elements.baseUrl.value = defaults.defaultBaseUrl;
  form.elements.model.value = defaults.defaultModel;
}

async function api(url, options = {}) {
  const response = await fetch(url, {
    method: options.method || "GET",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.detail || data.error || "Request failed");
  }
  return data;
}

async function withBusy(button, fn) {
  if (!button) {
    return fn();
  }
  const previous = button.textContent;
  button.disabled = true;
  try {
    await fn();
  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    button.disabled = false;
    button.textContent = previous;
  }
}

function setText(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.textContent = value;
}

function setHtml(selector, value) {
  const node = document.querySelector(selector);
  if (node) node.innerHTML = value;
}

function showToast(message, kind = "info") {
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast ${kind}`;
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => {
    toast.className = "toast hidden";
  }, 2200);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function initParticles() {
  const canvas = document.querySelector("#particle-field");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const particles = Array.from({ length: 26 }, () => ({
    x: Math.random(),
    y: Math.random(),
    r: 1 + Math.random() * 3,
    dx: (Math.random() - 0.5) * 0.0008,
    dy: (Math.random() - 0.5) * 0.0008
  }));

  function resize() {
    canvas.width = window.innerWidth * devicePixelRatio;
    canvas.height = window.innerHeight * devicePixelRatio;
    ctx.setTransform(devicePixelRatio, 0, 0, devicePixelRatio, 0, 0);
  }

  function tick() {
    ctx.clearRect(0, 0, window.innerWidth, window.innerHeight);
    particles.forEach((particle) => {
      particle.x += particle.dx;
      particle.y += particle.dy;
      if (particle.x <= 0 || particle.x >= 1) particle.dx *= -1;
      if (particle.y <= 0 || particle.y >= 1) particle.dy *= -1;
      const x = particle.x * window.innerWidth;
      const y = particle.y * window.innerHeight;
      const gradient = ctx.createRadialGradient(x, y, 0, x, y, particle.r * 8);
      gradient.addColorStop(0, "rgba(15,118,110,0.22)");
      gradient.addColorStop(1, "rgba(15,118,110,0)");
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(x, y, particle.r * 8, 0, Math.PI * 2);
      ctx.fill();
    });
    requestAnimationFrame(tick);
  }

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(tick);
}

// ZIP 上传相关函数
function updateUploadPreview(files) {
  const preview = document.querySelector("#upload-preview");
  if (!preview) return;

  if (!files || files.length === 0) {
    preview.innerHTML = "";
    return;
  }

  const fileList = Array.from(files).map((file) => {
    const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
    return `<div class="upload-file-item">
      <strong>${escapeHtml(file.name)}</strong>
      <span>${sizeMB} MB</span>
    </div>`;
  }).join("");

  preview.innerHTML = `<div class="upload-file-list">${fileList}</div>`;
}

async function handleZipUpload(form, selectedSkillIds) {
  const zipFileInput = form.elements.zipFiles;
  const files = zipFileInput?.files;

  if (!files || files.length === 0) {
    showToast("请选择至少一个 ZIP 文件。", "info");
    return;
  }

  // 检查文件大小
  const maxSize = 100 * 1024 * 1024; // 100MB
  for (const file of files) {
    if (file.size > maxSize) {
      showToast(`文件 ${file.name} 超过 100MB 限制。`, "error");
      return;
    }
  }

  const submitButton = form.querySelector("#task-submit-button");
  const previousText = submitButton?.textContent;

  try {
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = "上传中...";
    }

    // 使用 FormData 上传文件
    const formData = new FormData();
    formData.append("sourceType", "zip-upload");
    formData.append("selectedSkillIds", JSON.stringify(selectedSkillIds));
    formData.append("useMemory", form.elements.useMemory?.checked || false);

    const enableLlmAudit = form.elements.enableLlmAudit?.checked !== false;
    formData.append("enableLlmAudit", enableLlmAudit);

    const useReAct = form.elements.useReAct?.checked === true;
    if (useReAct) {
      formData.append("useReAct", "true");
      const reactConfig = {
        maxSteps: Number(form.elements.reactMaxSteps?.value || 15),
        temperature: Number(form.elements.reactTemperature?.value || 0.1),
        maxRetries: Number(form.elements.reactMaxRetries?.value || 3),
        verbose: form.elements.reactVerbose?.checked === true
      };
      formData.append("reactConfig", JSON.stringify(reactConfig));
    }

    for (const file of files) {
      formData.append("zipFiles", file);
    }

    const response = await fetch("/api/tasks/upload", {
      method: "POST",
      body: formData
    });

    const task = await response.json();

    if (!response.ok) {
      throw new Error(task.detail || task.error || "上传失败");
    }

    showToast(`任务已创建：${task.id.slice(0, 8)}`, "success");
    setTimeout(() => {
      location.href = `/audit.html?task=${encodeURIComponent(task.id)}`;
    }, 500);

  } catch (error) {
    showToast(error instanceof Error ? error.message : String(error), "error");
  } finally {
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = previousText;
    }
  }
}

