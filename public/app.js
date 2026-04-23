const page = document.body.dataset.page || "overview";
const toast = document.querySelector("#toast");
const selectionState = new Map();
const candidateState = new Map();
let selectedTaskId = null;
let latestSettings = null;
let latestMemory = null;
let auditSkills = [];
let fingerprintProjects = [];
let selectedFingerprintProjectId = "";
let fingerprintAnalysisCache = new Map();
let refreshTimer = null;

const providerDefaultsMap = {
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  compatible: { baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  anthropic: { baseUrl: "https://api.anthropic.com", model: "claude-3-7-sonnet-latest" },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com", model: "gemini-2.5-pro" },
  deepseek: { baseUrl: "https://api.deepseek.com", model: "deepseek-chat" },
  qwen: { baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-max" }
};

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
    refreshTimer = setInterval(refreshAuditPage, 1800);
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

window.addEventListener("beforeunload", () => {
  if (refreshTimer) {
    clearInterval(refreshTimer);
  }
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
  } catch {
    auditSkills = [];
  }
}

function initDiscoverPage() {
  const form = document.querySelector("#task-form");
  const skillPicker = document.querySelector("#skill-picker");
  const selectAllButton = document.querySelector("#select-all-skills-button");
  const clearButton = document.querySelector("#clear-skills-button");
  const githubFields = document.querySelector("#github-launch-fields");
  const localFields = document.querySelector("#local-launch-fields");

  renderSkillPicker(skillPicker);
  syncSourceMode(githubFields, localFields);

  document.querySelectorAll('input[name="sourceType"]').forEach((input) => {
    input.addEventListener("change", () => syncSourceMode(githubFields, localFields));
  });

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
    const payload = {
      sourceType,
      selectedSkillIds,
      useMemory: form.elements.useMemory?.checked
    };

    if (sourceType === "local") {
      payload.localRepoPaths = String(form.elements.localRepoPaths.value || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);
      if (!payload.localRepoPaths.length) {
        showToast("请填写至少一个本地仓库路径。", "info");
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

function syncSourceMode(githubFields, localFields) {
  const sourceType = getSourceType();
  githubFields?.classList.toggle("hidden-panel", sourceType !== "github");
  localFields?.classList.toggle("hidden-panel", sourceType !== "local");
}

function renderSkillPicker(target) {
  if (!target) return;
  if (!auditSkills.length) {
    target.innerHTML = `<div class="empty-card">没有可用的审计 Skill。</div>`;
    return;
  }

  target.innerHTML = auditSkills
    .map(
      (skill) => `
        <label class="skill-card">
          <input class="skill-checkbox" type="checkbox" value="${escapeHtml(skill.id)}" checked />
          <div>
            <strong>${escapeHtml(skill.name)}</strong>
            <p>${escapeHtml(skill.description)}</p>
          </div>
        </label>
      `
    )
    .join("");
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
  return document.querySelector('input[name="sourceType"]:checked')?.value === "local" ? "local" : "github";
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
      (task) => `
        <a class="task-row" href="/audit.html?task=${encodeURIComponent(task.id)}">
          <strong>${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : task.query)}</strong>
          <span>${escapeHtml(task.phase)} · ${escapeHtml(task.status)} · ${escapeHtml(task.progress?.label || "")}</span>
        </a>
      `
    )
    .join("");
}

function initAuditPage() {
  document.querySelector("#refresh-button")?.addEventListener("click", refreshAuditPage);
  selectedTaskId = new URLSearchParams(location.search).get("task") || null;
}

async function refreshAuditPage() {
  const tasks = await api("/api/tasks");
  renderQuickStatus(latestSettings || (await api("/api/settings")), tasks);
  renderTaskList(tasks);

  if (!selectedTaskId && tasks.length) {
    selectedTaskId = tasks[0].id;
  }
  if (!selectedTaskId) {
    setHtml("#task-detail", `<div class="empty-card">还没有任务。</div>`);
    return;
  }

  const task = await api(`/api/tasks/${selectedTaskId}`);
  renderTaskDetail(task);
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
      return `
        <button class="task-card ${active}" data-task-id="${escapeHtml(task.id)}" type="button">
          <strong>${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : task.query)}</strong>
          <span>${escapeHtml(task.phase)} · ${escapeHtml(task.status)}</span>
          <small>${escapeHtml(task.progress?.label || "")} ${escapeHtml(String(task.progress?.percent || 0))}%</small>
        </button>
      `;
    })
    .join("");

  target.querySelectorAll("[data-task-id]").forEach((button) => {
    button.addEventListener("click", async () => {
      selectedTaskId = button.dataset.taskId;
      await refreshAuditPage();
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
  target.innerHTML = `
    <div class="summary-grid">
      <div class="summary-card"><strong>状态</strong><span>${escapeHtml(task.status)}</span></div>
      <div class="summary-card"><strong>阶段</strong><span>${escapeHtml(task.phase)}</span></div>
      <div class="summary-card"><strong>来源</strong><span>${escapeHtml(task.sourceType)}</span></div>
      <div class="summary-card"><strong>结果</strong><span>${escapeHtml(String(task.auditResult?.findingsCount || 0))}</span></div>
    </div>

    ${buildProgressCard(task.progress)}

    <div class="detail-block">
      <h3>任务说明</h3>
      <p>${escapeHtml(task.message || "")}</p>
      ${
        task.report
          ? `<p><a class="download-link" href="${escapeHtml(task.report.downloadPath)}" target="_blank" rel="noreferrer">下载 HTML 报告</a></p>`
          : ""
      }
    </div>

    <div class="detail-block">
      <h3>审计结果</h3>
      <p>规则层 ${escapeHtml(String(task.auditResult?.heuristicFindingsCount || 0))} 条，LLM 复核 ${escapeHtml(
        String(task.auditResult?.llmFindingsCount || 0)
      )} 条。</p>
      ${projects.length ? projects.map(renderProjectReview).join("") : `<div class="empty-card">任务还在进行中。</div>`}
    </div>
  `;
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
      </div>
      <div class="review-columns">
        <section class="review-pane">
          <h5>规则层</h5>
          ${renderFindingList(project.heuristicFindings, "规则层暂未保留高置信度结果。")}
        </section>
        <section class="review-pane">
          <h5>LLM 复核</h5>
          <p>${escapeHtml(project.llmReview?.summary || "暂无 LLM 复核结果。")}</p>
          ${renderFindingList(project.llmReview?.findings || [], "LLM 本次没有额外保留高置信度结果。")}
        </section>
      </div>
    </article>
  `;
}

function renderFindingList(findings, emptyMessage) {
  if (!findings?.length) {
    return `<div class="empty-card">${escapeHtml(emptyMessage)}</div>`;
  }

  return `
    <ul class="finding-list">
      ${findings
        .map(
          (finding) => `
            <li>
              <div class="finding-head">
                <strong>${escapeHtml(finding.title)}</strong>
                <span class="badge">${escapeHtml(finding.severity || "info")}</span>
              </div>
              <p><strong>位置：</strong>${escapeHtml(finding.location || "n/a")}</p>
              <p><strong>影响：</strong>${escapeHtml(finding.impact || "")}</p>
              <p><strong>证据：</strong>${escapeHtml(finding.evidence || "")}</p>
              ${finding.remediation ? `<p><strong>修复建议：</strong>${escapeHtml(finding.remediation)}</p>` : ""}
              ${finding.safeValidation ? `<p><strong>安全验证建议：</strong>${escapeHtml(finding.safeValidation)}</p>` : ""}
            </li>
          `
        )
        .join("")}
    </ul>
  `;
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
    target.innerHTML = `<div class="empty-card">还没有本地镜像项目。请先在审计中心完成一次镜像下载。</div>`;
    setHtml("#fingerprint-detail", `<div class="empty-card">暂无可分析项目。</div>`);
    return;
  }

  if (!selectedFingerprintProjectId) {
    selectedFingerprintProjectId = fingerprintProjects[0].id;
  }

  target.innerHTML = fingerprintProjects
    .map(
      (project) => `
        <button class="task-card ${project.id === selectedFingerprintProjectId ? "active" : ""}" data-fingerprint-project="${escapeHtml(project.id)}" type="button">
          <strong>${escapeHtml(project.name)}</strong>
          <span>${escapeHtml(project.localPath)}</span>
          <small>${escapeHtml(String(project.fileCount))} 个文件</small>
        </button>
      `
    )
    .join("");

  target.querySelectorAll("[data-fingerprint-project]").forEach((button) => {
    button.addEventListener("click", async () => {
      selectedFingerprintProjectId = button.dataset.fingerprintProject;
      await refreshFingerprintProjects();
    });
  });

  await renderFingerprintDetail(selectedFingerprintProjectId);
}

async function renderFingerprintDetail(projectId) {
  const target = document.querySelector("#fingerprint-detail");
  if (!target || !projectId) return;

  const analysis = fingerprintAnalysisCache.get(projectId) || await api("/api/fingerprint/analyze", {
    method: "POST",
    body: { projectId }
  });
  fingerprintAnalysisCache.set(projectId, analysis);

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
  form.elements.baseUrl.value = defaults.baseUrl;
  form.elements.model.value = defaults.model;
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
