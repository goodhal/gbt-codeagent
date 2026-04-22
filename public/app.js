const taskForm = document.querySelector("#task-form");
const memoryForm = document.querySelector("#memory-form");
const settingsForm = document.querySelector("#settings-form");
const taskList = document.querySelector("#task-list");
const taskDetail = document.querySelector("#task-detail");
const refreshButton = document.querySelector("#refresh-button");
const envRefreshButton = document.querySelector("#env-refresh-button");
const memoryRefreshButton = document.querySelector("#memory-refresh-button");
const settingsRefreshButton = document.querySelector("#settings-refresh-button");
const settingsTestButton = document.querySelector("#settings-test-button");
const clearLlmButton = document.querySelector("#clear-llm-button");
const clearGithubButton = document.querySelector("#clear-github-button");
const taskSubmitButton = document.querySelector("#task-submit-button");
const envReport = document.querySelector("#env-report");
const memoryView = document.querySelector("#memory-view");
const settingsSummary = document.querySelector("#settings-summary");
const connectionTestResult = document.querySelector("#connection-test-result");
const quickStatus = document.querySelector("#quick-status");
const toast = document.querySelector("#toast");
const providerSelect = settingsForm.elements.providerId;
const chipButtons = Array.from(document.querySelectorAll(".chip"));
const particleCanvas = document.querySelector("#particle-field");
const githubLaunchFields = document.querySelector("#github-launch-fields");
const localLaunchFields = document.querySelector("#local-launch-fields");
const skillPicker = document.querySelector("#skill-picker");
const selectAllSkillsButton = document.querySelector("#select-all-skills-button");
const clearSkillsButton = document.querySelector("#clear-skills-button");

let selectedTaskId = null;
let latestMemory = null;
let latestSettings = null;
let auditSkills = [];
let toastTimer = null;
const selectionState = new Map();
const pageState = new Map();
const candidateViewState = new Map();

const providerDefaultsMap = {
  openai: { baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  compatible: { baseUrl: "https://api.openai.com/v1", model: "gpt-4.1-mini" },
  anthropic: { baseUrl: "https://api.anthropic.com", model: "claude-3-7-sonnet-latest" },
  gemini: { baseUrl: "https://generativelanguage.googleapis.com", model: "gemini-2.5-pro" },
  deepseek: { baseUrl: "https://api.deepseek.com", model: "deepseek-chat" },
  qwen: { baseUrl: "https://dashscope.aliyuncs.com/compatible-mode/v1", model: "qwen-max" }
};

taskForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  await withBusy(taskSubmitButton, async () => {
    const sourceType = getSourceType();
    const selectedSkillIds = getSelectedSkillIds();

    if (!selectedSkillIds.length) {
      showToast("请至少选择一个审计 Skill。", "info");
      return;
    }

    const payload = {
      sourceType,
      selectedSkillIds,
      useMemory: taskForm.elements.useMemory.checked
    };

    if (sourceType === "local") {
      const localRepoPaths = String(taskForm.elements.localRepoPaths.value || "")
        .split(/\r?\n|,/)
        .map((item) => item.trim())
        .filter(Boolean);

      if (!localRepoPaths.length) {
        showToast("请先填写至少一个本地仓库路径。", "info");
        return;
      }

      payload.localRepoPaths = localRepoPaths;
      payload.useMemory = false;
    } else {
      payload.query = taskForm.elements.query.value;
      payload.minAdoption = Number(taskForm.elements.minAdoption.value || 100);
    }

    const response = await fetch("/api/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const task = await response.json();

    selectedTaskId = task.id;
    selectionState.set(task.id, new Set());
    pageState.set(task.id, 0);
    candidateViewState.set(task.id, { keyword: "", minLive: "0", selectedOnly: false });

    showToast(
      sourceType === "local" ? "本地仓库导入任务已启动。" : "候选目标发现任务已启动。",
      "success"
    );

    await refreshTasks();
  });
});

memoryForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetch("/api/memory", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      preferences: {
        preferredQuery: memoryForm.elements.preferredQuery.value,
        preferredMinAdoption: Number(memoryForm.elements.preferredMinAdoption.value || 100),
        autoUseMemory: true
      },
      rules: String(memoryForm.elements.rules.value || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
    })
  });
  showToast("项目记忆已更新。", "success");
  await refreshMemory();
});

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  await saveSettings();
});

providerSelect.addEventListener("change", () => applyProviderDefaults(true));
refreshButton.addEventListener("click", () => refreshTasks());
envRefreshButton.addEventListener("click", () => refreshEnvironment());
memoryRefreshButton.addEventListener("click", () => refreshMemory());
settingsRefreshButton.addEventListener("click", () => refreshSettings());
settingsTestButton.addEventListener("click", () => testConnections());
clearLlmButton.addEventListener("click", () => clearSecrets(["llm"]));
clearGithubButton.addEventListener("click", () => clearSecrets(["github"]));
selectAllSkillsButton.addEventListener("click", () => setAllSkills(true));
clearSkillsButton.addEventListener("click", () => setAllSkills(false));

chipButtons.forEach((button) =>
  button.addEventListener("click", () => {
    taskForm.elements.query.value = button.dataset.query || "";
    showToast("已填入快捷查询。", "info");
  })
);

document.querySelectorAll('input[name="sourceType"]').forEach((radio) =>
  radio.addEventListener("change", () => {
    updateSourceModeUI();
  })
);

async function saveSettings() {
  await fetch("/api/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
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
      }
    })
  });

  settingsForm.elements.apiKey.value = "";
  settingsForm.elements.githubToken.value = "";
  showToast("连接设置已保存。", "success");
  await refreshSettings();
  await refreshEnvironment();
}

async function testConnections() {
  await withBusy(settingsTestButton, async () => {
    connectionTestResult.textContent = "正在测试连接，请稍候…";
    const response = await fetch("/api/settings/test", { method: "POST" });
    const result = await response.json();

    connectionTestResult.innerHTML = `
      <div class="detail-block">
        <h3>连接测试</h3>
        <p>整体状态：<span class="sev sev-${result.overall === "pass" ? "low" : "medium"}">${escapeHtml(result.overall)}</span></p>
        <p>LLM：${escapeHtml(result.llm.message)}</p>
        <p>GitHub：${escapeHtml(result.github.message)}</p>
      </div>
    `;

    showToast(
      result.overall === "pass" ? "连接测试通过。" : "连接测试已完成，请查看详情。",
      result.overall === "pass" ? "success" : "info"
    );
  });
}

async function clearSecrets(targets) {
  await fetch("/api/settings/clear-secrets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targets })
  });

  settingsForm.elements.apiKey.value = "";
  settingsForm.elements.githubToken.value = "";
  showToast("密钥已清空。", "success");
  await refreshSettings();
  await refreshEnvironment();
}

async function loadAuditSkills() {
  auditSkills = await (await fetch("/api/audit-skills")).json();
  renderSkillPicker();
}

function renderSkillPicker() {
  if (!auditSkills.length) {
    skillPicker.innerHTML = `<div class="empty-card">没有可用的审计 Skill。</div>`;
    return;
  }

  const currentSelection = new Set(getSelectedSkillIds());
  const defaultSelectAll = currentSelection.size === 0;

  skillPicker.innerHTML = auditSkills
    .map(
      (skill) => `
        <label class="skill-card">
          <input class="skill-checkbox" type="checkbox" value="${escapeHtml(skill.id)}" ${
            defaultSelectAll || currentSelection.has(skill.id) ? "checked" : ""
          } />
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
  showToast(checked ? "已全选审计 Skill。" : "已清空审计 Skill。", "info");
}

function getSourceType() {
  return document.querySelector('input[name="sourceType"]:checked')?.value === "local" ? "local" : "github";
}

function updateSourceModeUI() {
  const sourceType = getSourceType();
  githubLaunchFields.classList.toggle("hidden-panel", sourceType !== "github");
  localLaunchFields.classList.toggle("hidden-panel", sourceType !== "local");
  taskSubmitButton.textContent = sourceType === "local" ? "导入本地仓库" : "发现候选目标";
  taskForm.elements.useMemory.disabled = sourceType === "local";

  if (sourceType === "local") {
    taskForm.elements.useMemory.checked = false;
  } else if (latestMemory?.preferences?.autoUseMemory) {
    taskForm.elements.useMemory.checked = true;
  }
}

async function refreshTasks() {
  const response = await fetch("/api/tasks");
  const tasks = await response.json();
  renderTaskList(tasks);

  if (selectedTaskId && !tasks.find((task) => task.id === selectedTaskId)) {
    selectedTaskId = null;
  }
  if (!selectedTaskId && tasks.length) {
    selectedTaskId = tasks[0].id;
  }

  if (selectedTaskId) {
    const detail = await (await fetch(`/api/tasks/${selectedTaskId}`)).json();
    renderTaskDetail(detail);
  } else {
    taskDetail.textContent = "还没有任务。";
  }
}

function renderTaskList(tasks) {
  taskList.innerHTML = "";

  if (!tasks.length) {
    taskList.innerHTML = `<div class="empty">暂无任务</div>`;
    return;
  }

  for (const task of tasks) {
    const button = document.createElement("button");
    button.className = `task-card ${task.id === selectedTaskId ? "active" : ""}`;
    const selectedCount = task.selectedProjectIds?.length || 0;
    const findingCount = task.auditResult?.findingsCount || 0;
    const llmCalls = task.auditResult?.llmCallCount || 0;
    const progressLabel = task.progress?.label ? ` · ${task.progress.label} ${task.progress.percent || 0}%` : "";

    button.innerHTML = `
      <strong>${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : task.query)}</strong>
      <span>${escapeHtml(task.status)} · ${escapeHtml(task.phase)} · ${
        task.sourceType === "local" ? "local" : "github"
      } · ${task.useMemory ? "memory" : "incognito"}</span>
      <small>已选 ${selectedCount} · 结果 ${findingCount} · LLM 调用 ${llmCalls}${escapeHtml(progressLabel)} · ${escapeHtml(
        formatDateTime(task.createdAt)
      )}</small>
    `;

    button.addEventListener("click", async () => {
      selectedTaskId = task.id;
      renderTaskList(tasks);
      renderTaskDetail(await (await fetch(`/api/tasks/${task.id}`)).json());
    });

    taskList.appendChild(button);
  }
}

function renderTaskDetail(task) {
  if (!task || task.error) {
    taskDetail.innerHTML = `<div class="empty">${escapeHtml(task?.error || "任务详情不可用")}</div>`;
    return;
  }

  if (task.phase === "target-selection" && task.scoutResult?.projects?.length) {
    renderSelectionView(task);
    return;
  }

  const projects = task.scoutResult?.projects || [];
  const audited = task.auditResult?.projects || [];
  const selectedSkills = resolveSkillNames(task.selectedSkillIds);
  const llmCallCount = task.auditResult?.llmCallCount || 0;
  const llmSkippedCount = task.auditResult?.llmSkippedCount || 0;

  taskDetail.innerHTML = `
    <div class="detail-block summary-block">
      <div>
        <h3>任务概览</h3>
        <p>状态：${escapeHtml(task.status)}</p>
        <p>阶段：${escapeHtml(task.phase)}</p>
        <p>来源：${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : "GitHub 候选发现")}</p>
        <p>已启用 Skill：${escapeHtml(selectedSkills || "默认全部")}</p>
        <p>${escapeHtml(task.message || "")}</p>
      </div>
      <div class="mini-metrics">
        <div class="mini-stat"><strong>${projects.length}</strong><span>候选目标</span></div>
        <div class="mini-stat"><strong>${task.selectedProjectIds?.length || 0}</strong><span>已选目标</span></div>
        <div class="mini-stat"><strong>${task.auditResult?.findingsCount || 0}</strong><span>总结果</span></div>
      </div>
    </div>

    ${buildTaskProgress(task)}

    ${buildTaskLlmCallout(task)}

    ${
      task.report
        ? `<div class="detail-block"><h3>下载报告</h3><p><a class="download-link" href="${escapeHtml(
            task.report.downloadPath
          )}" target="_blank" rel="noreferrer">下载 HTML 报告</a></p></div>`
        : ""
    }

    <div class="detail-block">
      <h3>审计结果</h3>
      <p>规则层 ${escapeHtml(String(task.auditResult?.heuristicFindingsCount || 0))} 条，LLM 复核 ${escapeHtml(
        String(task.auditResult?.llmFindingsCount || 0)
      )} 条，LLM 已调用 ${escapeHtml(String(llmCallCount))} 个目标，跳过 ${escapeHtml(String(llmSkippedCount))} 个目标。</p>
      ${audited.length ? audited.map((item) => renderProjectReview(item)).join("") : `<p class="empty">尚未完成审计。</p>`}
    </div>
  `;
}

function buildTaskProgress(task) {
  const progress = task.progress;
  if (!progress) {
    return "";
  }

  const percent = Math.max(0, Math.min(100, Number(progress.percent || 0)));
  const meta = [];
  if (progress.current || progress.total) {
    meta.push(`${progress.current || 0} / ${progress.total || 0}`);
  }
  if (progress.detail) {
    meta.push(progress.detail);
  }

  return `
    <div class="detail-block progress-card">
      <div class="progress-head">
        <strong>${escapeHtml(progress.label || "处理中")}</strong>
        <span>${escapeHtml(String(percent))}%</span>
      </div>
      <div class="progress-track" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${escapeHtml(String(percent))}">
        <div class="progress-fill" style="width:${escapeHtml(String(percent))}%"></div>
      </div>
      <p class="progress-meta">${escapeHtml(meta.join(" · ") || progress.stage || "")}</p>
    </div>
  `;
}

function renderProjectReview(item) {
  const locationParts = [];
  if (item.repoUrl) {
    locationParts.push(`<p><a href="${escapeHtml(item.repoUrl)}" target="_blank" rel="noreferrer">${escapeHtml(item.repoUrl)}</a></p>`);
  }
  if (item.localPath) {
    locationParts.push(`<p><strong>审计镜像：</strong>${escapeHtml(item.localPath)}</p>`);
  }
  const locationLine = locationParts.join("");

  const llmState = describeLlmReview(item.llmReview);
  const llmWarnings = (item.llmReview?.warnings || [])
    .map((warning) => `<li>${escapeHtml(warning)}</li>`)
    .join("");

  return `
    <article class="finding-group project-review">
      <h4>${escapeHtml(item.projectName)}</h4>
      ${locationLine}

      <div class="review-columns">
        <section class="review-card">
          <h5>规则层</h5>
          <p>保留 ${item.heuristicFindings.length} 条结果</p>
          ${renderFindingList(item.heuristicFindings, "规则层暂未保留到高置信度结果。")}
        </section>

        <section class="review-card">
          <h5>LLM 复核</h5>
          <div class="review-status">
            <span class="sev sev-status">${escapeHtml(llmState.statusText)}</span>
            <span class="sev sev-${escapeHtml(llmState.badgeClass)}">${escapeHtml(llmState.callText)}</span>
          </div>
          <p>${escapeHtml(llmState.summary)}</p>
          ${llmState.meta ? `<p class="review-meta">${escapeHtml(llmState.meta)}</p>` : ""}
          ${llmWarnings ? `<ul class="warning-list">${llmWarnings}</ul>` : ""}
          ${renderFindingList(item.llmReview?.findings || [], llmState.emptyMessage)}
        </section>
      </div>
    </article>
  `;
}

function renderFindingList(findings, emptyMessage) {
  if (!findings?.length) {
    return `<p class="empty">${escapeHtml(emptyMessage)}</p>`;
  }

  return `
    <ul class="finding-list">
      ${findings
        .map(
          (finding) => `
            <li>
              <strong>${escapeHtml(finding.title)}</strong>
              <span class="sev sev-${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
              <span class="sev sev-source">${escapeHtml(finding.source || "rule")}</span>
              <p><strong>位置：</strong>${escapeHtml(finding.location || "n/a")}</p>
              <p><strong>影响：</strong>${escapeHtml(finding.impact || "")}</p>
              <p><strong>证据：</strong>${escapeHtml(finding.evidence || "")}</p>
              ${
                finding.remediation
                  ? `<p><strong>修复建议：</strong>${escapeHtml(finding.remediation)}</p>`
                  : ""
              }
              ${
                finding.safeValidation
                  ? `<p><strong>安全验证建议：</strong>${escapeHtml(finding.safeValidation)}</p>`
                  : ""
              }
            </li>
          `
        )
        .join("")}
    </ul>
  `;
}

function renderSelectionView(task) {
  const allProjects = [...task.scoutResult.projects];
  const isGithubTask = task.sourceType !== "local";

  if (!selectionState.has(task.id)) {
    const preselected = task.selectedProjectIds?.length
      ? task.selectedProjectIds
      : task.sourceType === "local"
        ? allProjects.map((project) => project.id)
        : [];
    selectionState.set(task.id, new Set(preselected));
  }

  if (!candidateViewState.has(task.id)) {
    candidateViewState.set(task.id, { keyword: "", minLive: "0", selectedOnly: false });
  }

  const selectedSet = selectionState.get(task.id);
  const viewState = candidateViewState.get(task.id);
  const filteredProjects = filterProjects(allProjects, selectedSet, viewState, isGithubTask);
  const perPage = 10;
  const totalPages = Math.max(1, Math.ceil(filteredProjects.length / perPage));
  const currentPage = Math.min(pageState.get(task.id) || 0, totalPages - 1);
  const pageProjects = filteredProjects.slice(currentPage * perPage, currentPage * perPage + perPage);
  pageState.set(task.id, currentPage);

  taskDetail.innerHTML = `
    <div class="detail-block summary-block">
      <div>
        <h3>选择需要审计的目标</h3>
        <p>${
          task.sourceType === "local"
            ? "这些是你刚导入的本地仓库。勾选后会先生成本地镜像，再执行规则层和 LLM 复核。"
            : "先看候选列表，再勾选真正要审计的目标。这里每页固定展示 10 个，方便你逐页挑选。"
        }</p>
        <p>${escapeHtml(task.scoutResult?.summary || task.message || "")}</p>
      </div>
      <div class="mini-metrics">
        <div class="mini-stat"><strong>${allProjects.length}</strong><span>候选目标</span></div>
        <div class="mini-stat"><strong>${filteredProjects.length}</strong><span>筛选后</span></div>
        <div class="mini-stat"><strong>${selectedSet.size}</strong><span>已选目标</span></div>
      </div>
    </div>

    <div class="result-callout">
      <strong>${isGithubTask ? "当前不会调用大模型" : "当前会调用大模型"}</strong>
        <span>${
        isGithubTask
          ? "GitHub 在发现阶段不会直接调用大模型。开始审计选中目标后，系统会先下载本地审计镜像，再执行规则层和 LLM 复核。"
          : "本地仓库导入模式会在规则层之后执行 LLM 二次复核。报告里会明确写出每个目标是否真的调用了模型。"
      }</span>
      </div>

    ${
      task.scoutResult?.skippedPaths?.length
        ? `
          <div class="detail-block">
            <h3>导入时跳过的路径</h3>
            <ul class="warning-list">
              ${task.scoutResult.skippedPaths
                .map((item) => `<li>${escapeHtml(item.path)} · ${escapeHtml(item.reason)}</li>`)
                .join("")}
            </ul>
          </div>
        `
        : ""
    }

    <div class="selection-toolbar ${isGithubTask ? "" : "selection-toolbar-local"}">
      <label class="toolbar-field">
        关键词筛选
        <input
          id="candidate-search-input"
          type="text"
          value="${escapeHtml(viewState.keyword)}"
          placeholder="${task.sourceType === "local" ? "例如 cms、admin、D:\\projects" : "例如 strapi、directus、headless"}"
        />
      </label>

      ${
        isGithubTask
          ? `
            <label class="toolbar-field">
              最低存活量
              <select id="candidate-min-live">
                ${renderAdoptionOptions(viewState.minLive)}
              </select>
            </label>
          `
          : ""
      }

      <label class="checkbox-row compact-check toolbar-check">
        <input id="candidate-selected-only" type="checkbox" ${viewState.selectedOnly ? "checked" : ""} />
        只看已选
      </label>
    </div>

    <div class="selection-actions">
      <div class="button-row">
        <button id="select-page-button" class="ghost" type="button">全选本页</button>
        <button id="clear-page-button" class="ghost" type="button">清空本页</button>
        <button id="clear-all-button" class="ghost danger" type="button">清空全部</button>
      </div>
      <div class="button-row">
        <span class="page-label">第 ${currentPage + 1} / ${totalPages} 页</span>
        <button id="prev-page-button" class="ghost" type="button" ${currentPage === 0 ? "disabled" : ""}>上一页</button>
        <button id="next-page-button" class="ghost" type="button" ${
          currentPage >= totalPages - 1 ? "disabled" : ""
        }>下一页</button>
        <button id="start-audit-button" type="button">开始审计选中目标</button>
      </div>
    </div>

    <div class="candidate-list">
      ${
        pageProjects.length
          ? pageProjects.map((project) => renderCandidateCard(project, selectedSet)).join("")
          : `<div class="empty-card">当前筛选条件下没有候选目标。</div>`
      }
    </div>
  `;

  taskDetail.querySelectorAll(".candidate-checkbox").forEach((checkbox) => {
    checkbox.addEventListener("change", (event) => {
      const projectId = event.target.dataset.projectId;
      if (event.target.checked) {
        selectedSet.add(projectId);
      } else {
        selectedSet.delete(projectId);
      }
      renderSelectionView(task);
    });
  });

  taskDetail.querySelector("#candidate-search-input")?.addEventListener("input", (event) => {
    viewState.keyword = event.target.value;
    pageState.set(task.id, 0);
    renderSelectionView(task);
  });

  taskDetail.querySelector("#candidate-min-live")?.addEventListener("change", (event) => {
    viewState.minLive = event.target.value;
    pageState.set(task.id, 0);
    renderSelectionView(task);
  });

  taskDetail.querySelector("#candidate-selected-only")?.addEventListener("change", (event) => {
    viewState.selectedOnly = event.target.checked;
    pageState.set(task.id, 0);
    renderSelectionView(task);
  });

  taskDetail.querySelector("#select-page-button")?.addEventListener("click", () => {
    pageProjects.forEach((project) => selectedSet.add(project.id));
    renderSelectionView(task);
  });

  taskDetail.querySelector("#clear-page-button")?.addEventListener("click", () => {
    pageProjects.forEach((project) => selectedSet.delete(project.id));
    renderSelectionView(task);
  });

  taskDetail.querySelector("#clear-all-button")?.addEventListener("click", () => {
    selectedSet.clear();
    renderSelectionView(task);
  });

  taskDetail.querySelector("#prev-page-button")?.addEventListener("click", () => {
    pageState.set(task.id, Math.max(0, currentPage - 1));
    renderSelectionView(task);
  });

  taskDetail.querySelector("#next-page-button")?.addEventListener("click", () => {
    pageState.set(task.id, Math.min(totalPages - 1, currentPage + 1));
    renderSelectionView(task);
  });

  taskDetail.querySelector("#start-audit-button")?.addEventListener("click", async (event) => {
    const selectedProjectIds = Array.from(selectedSet);
    if (!selectedProjectIds.length) {
      showToast("请至少选择一个目标。", "info");
      return;
    }

    const button = event.currentTarget;
    button.disabled = true;
    button.textContent = "审计中…";

    await fetch(`/api/tasks/${task.id}/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ selectedProjectIds })
    });

    showToast("已开始审计选中的目标。", "success");
    await refreshTasks();
  });
}

function renderCandidateCard(project, selectedSet) {
  const usage = project.adoptionSignals?.estimatedLiveUsage || 0;
  const stars = project.adoptionSignals?.stars || 0;
  const forks = project.adoptionSignals?.forks || 0;
  const updatedAt = project.pushedAt || project.updatedAt;
  const sourceMeta =
    project.sourceType === "local"
      ? `<p class="candidate-path"><strong>路径：</strong>${escapeHtml(project.localPath || "n/a")}</p>`
      : `<p><a href="${escapeHtml(project.repoUrl)}" target="_blank" rel="noreferrer">打开仓库</a></p>`;

  return `
    <label class="candidate-card ${selectedSet.has(project.id) ? "selected" : ""}">
      <input class="candidate-checkbox" type="checkbox" data-project-id="${escapeHtml(project.id)}" ${
        selectedSet.has(project.id) ? "checked" : ""
      } />
      <div class="candidate-body">
        <div class="candidate-head">
          <div>
            <strong>${escapeHtml(project.sourceType === "local" ? project.name : `${project.owner}/${project.name}`)}</strong>
            <p>${escapeHtml(project.description || "暂无描述")}</p>
          </div>
          <span class="usage-pill">${project.sourceType === "local" ? "本地导入" : `存活量 ${usage}`}</span>
        </div>
        <div class="candidate-meta">
          ${
            project.sourceType === "local"
              ? `<span>${escapeHtml(project.language || "Unknown")}</span><span>${escapeHtml(
                  formatDate(updatedAt)
                )}</span><span>完整仓库待镜像</span>`
              : `<span>Stars ${stars}</span><span>Forks ${forks}</span><span>${escapeHtml(
                  project.language || "Unknown"
                )}</span><span>${escapeHtml(formatDate(updatedAt))}</span>`
          }
        </div>
        ${sourceMeta}
      </div>
    </label>
  `;
}

function resolveSkillNames(selectedSkillIds) {
  if (!Array.isArray(selectedSkillIds) || !selectedSkillIds.length) {
    return "";
  }
  const selected = new Set(selectedSkillIds);
  return auditSkills
    .filter((skill) => selected.has(skill.id))
    .map((skill) => skill.name)
    .join("、");
}

function filterProjects(projects, selectedSet, viewState, isGithubTask) {
  const keyword = String(viewState.keyword || "").trim().toLowerCase();
  const minLive = Number(viewState.minLive || 0);

  return projects.filter((project) => {
    const haystack = `${project.owner || ""}/${project.name || ""} ${project.description || ""} ${
      project.language || ""
    } ${project.localPath || ""}`.toLowerCase();
    const usage = Number(project.adoptionSignals?.estimatedLiveUsage || 0);

    if (keyword && !haystack.includes(keyword)) {
      return false;
    }
    if (isGithubTask && usage < minLive) {
      return false;
    }
    if (viewState.selectedOnly && !selectedSet.has(project.id)) {
      return false;
    }
    return true;
  });
}

function renderAdoptionOptions(selected) {
  const options = [
    ["0", "全部"],
    ["100", "100+"],
    ["300", "300+"],
    ["800", "800+"],
    ["1500", "1500+"]
  ];
  return options
    .map(([value, label]) => `<option value="${value}" ${String(selected) === value ? "selected" : ""}>${label}</option>`)
    .join("");
}

async function refreshEnvironment() {
  const report = await (await fetch("/api/environment")).json();
  envReport.innerHTML = `
    <div class="detail-block">
      <h3>运行时</h3>
      <p>Node.js：${escapeHtml(report.runtime.node)}</p>
      <p>平台：${escapeHtml(report.runtime.platform)} / ${escapeHtml(report.runtime.arch)}</p>
      <p>工作目录：${escapeHtml(report.runtime.cwd)}</p>
    </div>
    <div class="detail-block">
      <h3>大模型配置</h3>
      <p>当前提供商：${escapeHtml(report.llm.active.label)}</p>
      <p>模型：${escapeHtml(report.llm.active.model)}</p>
      <p>Base URL：${escapeHtml(report.llm.active.baseUrl)}</p>
      <p>API Key：${report.llm.active.apiKeyConfigured ? escapeHtml(report.llm.active.apiKeyMasked) : "未配置"}</p>
    </div>
    <div class="detail-block">
      <h3>GitHub 抓取</h3>
      <p>方式：${escapeHtml(report.github.crawlMode)}</p>
      <p>Token：${report.github.tokenConfigured ? escapeHtml(report.github.tokenMasked) : "未配置"}</p>
      <p>Owner 过滤：${escapeHtml(report.github.ownerFilter || "未设置")}</p>
    </div>
  `;
}

async function refreshMemory() {
  latestMemory = await (await fetch("/api/memory")).json();
  memoryView.innerHTML = `
    <div class="detail-block">
      <h3>偏好</h3>
      <p>默认查询：${escapeHtml(latestMemory.preferences.preferredQuery)}</p>
      <p>默认阈值：${escapeHtml(String(latestMemory.preferences.preferredMinAdoption))}</p>
      <p>自动记忆：${latestMemory.preferences.autoUseMemory ? "开启" : "关闭"}</p>
    </div>
    <div class="detail-block">
      <h3>最近摘要</h3>
      <ul>
        ${
          (
            latestMemory.recentSummaries.length
              ? latestMemory.recentSummaries
              : [{ query: "暂无历史", findingsCount: 0, projectsReviewed: 0 }]
          )
            .map(
              (item) => `
                <li>
                  <strong>${escapeHtml(item.query)}</strong>
                  <p>项目 ${escapeHtml(String(item.projectsReviewed || 0))} · 发现 ${escapeHtml(
                    String(item.findingsCount || 0)
                  )}</p>
                </li>
              `
            )
            .join("")
        }
      </ul>
    </div>
  `;

  memoryForm.elements.preferredQuery.value = latestMemory.preferences.preferredQuery;
  memoryForm.elements.preferredMinAdoption.value = latestMemory.preferences.preferredMinAdoption;
  memoryForm.elements.rules.value = latestMemory.rules.join("\n");
  taskForm.elements.query.value = latestMemory.preferences.preferredQuery;
  taskForm.elements.minAdoption.value = latestMemory.preferences.preferredMinAdoption;
  taskForm.elements.useMemory.checked = latestMemory.preferences.autoUseMemory;
  renderQuickStatus();
}

async function refreshSettings() {
  latestSettings = await (await fetch("/api/settings")).json();
  settingsSummary.textContent = `当前模型：${latestSettings.llm.providerId} / ${
    latestSettings.llm.model || latestSettings.llm.defaults?.model || "默认"
  }，GitHub Token：${latestSettings.github.tokenConfigured ? latestSettings.github.tokenMasked : "未配置"}`;

  settingsForm.elements.providerId.value = latestSettings.llm.providerId || "openai";
  settingsForm.elements.baseUrl.value = latestSettings.llm.baseUrl || latestSettings.llm.defaults?.baseUrl || "";
  settingsForm.elements.model.value = latestSettings.llm.model || latestSettings.llm.defaults?.model || "";
  settingsForm.elements.ownerFilter.value = latestSettings.github.ownerFilter || "";
  settingsForm.elements.githubNotes.value = latestSettings.github.notes || "";
  renderQuickStatus();
}

function applyProviderDefaults(force = false) {
  const selected = providerSelect.value;
  const defaults = providerDefaultsMap[selected] || {};
  if (force || !settingsForm.elements.baseUrl.value) {
    settingsForm.elements.baseUrl.value = defaults.baseUrl || "";
  }
  if (force || !settingsForm.elements.model.value) {
    settingsForm.elements.model.value = defaults.model || "";
  }
}

function renderQuickStatus() {
  const llmStatus = latestSettings?.llm?.apiKeyConfigured ? "已配置" : "未配置";
  const githubStatus = latestSettings?.github?.tokenConfigured ? "已配置" : "未配置";
  const memoryStatus = latestMemory?.preferences?.autoUseMemory ? "开启" : "关闭";

  quickStatus.innerHTML = `
    <div class="status-card"><strong>LLM</strong><span>${llmStatus}</span></div>
    <div class="status-card"><strong>GitHub</strong><span>${githubStatus}</span></div>
    <div class="status-card"><strong>记忆</strong><span>${memoryStatus}</span></div>
  `;
}

function buildTaskLlmCallout(task) {
  const llmCallCount = task.auditResult?.llmCallCount || 0;
  const llmSkippedCount = task.auditResult?.llmSkippedCount || 0;

  if (task.progress?.stage === "mirror") {
    return `
      <div class="detail-block result-callout">
        <strong>正在下载本地审计镜像</strong>
        <span>当前目标会先下载到本地镜像目录，再进入规则层和 LLM 复核阶段。</span>
        <p class="review-meta">${escapeHtml(task.progress.detail || `已处理 ${task.progress.current || 0} / ${task.progress.total || 0}`)}</p>
      </div>
    `;
  }

  if (task.progress?.stage === "llm-review") {
    return `
      <div class="detail-block result-callout">
        <strong>正在实时调用大模型</strong>
        <span>系统已经进入 LLM 复核阶段，正在按批次读取本地镜像文件并提交给模型分析。</span>
        <p class="review-meta">当前批次 ${escapeHtml(String(task.progress.current || 0))} / ${escapeHtml(String(task.progress.total || 0))}${
          task.progress.detail ? ` · ${escapeHtml(task.progress.detail)}` : ""
        }</p>
      </div>
    `;
  }

  if (llmCallCount > 0) {
    return `
      <div class="detail-block result-callout">
        <strong>这次已经实际调用大模型</strong>
        <span>LLM 已复核 ${escapeHtml(String(llmCallCount))} 个目标，另有 ${escapeHtml(String(llmSkippedCount))} 个目标被跳过。你可以在下面的项目卡片里查看每个目标的调用状态、模型名和复核摘要。</span>
      </div>
    `;
  }

  return `
    <div class="detail-block result-callout">
      <strong>这次没有实际调用大模型</strong>
      <span>${task.sourceType === "github"
        ? "当前任务已经进入 GitHub 审计阶段，但 LLM 没有真正执行。通常是 API Key 未配置，或者目标镜像没有成功生成。"
        : "当前任务虽然是本地导入模式，但 LLM 没有真正执行。请检查 API Key、本地镜像是否生成成功，或查看各项目卡片中的“未调用原因”。"}</span>
    </div>
  `;
}

function describeLlmReview(llmReview) {
  if (!llmReview?.called) {
    const reason = getLlmSkipReasonLabel(llmReview?.skipReason);
    return {
      statusText: "未调用",
      callText: reason.short,
      badgeClass: "skipped",
      summary: llmReview?.summary || reason.long,
      meta: "",
      emptyMessage: reason.empty
    };
  }

  const status = llmReview.status || "completed";
  const statusText =
    status === "failed" ? "调用失败" : status === "partial" ? "部分完成" : "已完成";
  const metaParts = [];

  if (llmReview.providerId || llmReview.model) {
    metaParts.push(`模型：${llmReview.providerId || "unknown"} / ${llmReview.model || "unknown"}`);
  }
  if (Number.isFinite(Number(llmReview.reviewedFiles)) || Number.isFinite(Number(llmReview.reviewedBatches))) {
    metaParts.push(
      `复核文件 ${Number(llmReview.reviewedFiles || 0)} 个，批次 ${Number(llmReview.reviewedBatches || 0)} 个`
    );
  }

  return {
    statusText,
    callText: "已调用",
    badgeClass: status === "failed" ? "failed" : "called",
    summary: llmReview.summary || "LLM 已完成复核。",
    meta: metaParts.join(" · "),
    emptyMessage: "LLM 本次没有额外保留到高置信度结果。"
  };
}

function getLlmSkipReasonLabel(reason) {
  switch (reason) {
    case "missing-api-key":
      return {
        short: "缺少 API Key",
        long: "当前未配置可用的 LLM API Key，所以 LLM 没有被调用。",
        empty: "未配置 API Key，LLM 未调用。"
      };
    case "no-local-files":
      return {
        short: "无本地镜像",
        long: "本地镜像中没有可供 LLM 复核的源码文件，所以没有实际调用模型。",
        empty: "本地镜像为空，LLM 未调用。"
      };
    case "reviewer-unavailable":
      return {
        short: "复核器未启用",
        long: "当前没有可用的 LLM 复核器，所以没有执行模型复核。",
        empty: "LLM 复核器未启用。"
      };
    default:
      return {
        short: "已跳过",
        long: "本项目的 LLM 复核被跳过。",
        empty: "本项目的 LLM 复核被跳过。"
      };
  }
}

async function withBusy(button, action) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "处理中…";
  try {
    await action();
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function showToast(message, kind = "info") {
  toast.textContent = message;
  toast.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.className = "toast hidden";
  }, 2200);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatDateTime(value) {
  if (!value) {
    return "-";
  }
  return new Date(value).toLocaleString();
}

function formatDate(value) {
  if (!value) {
    return "未知时间";
  }
  return new Date(value).toLocaleDateString();
}

function initParticleField() {
  if (!particleCanvas) {
    return;
  }

  const ctx = particleCanvas.getContext("2d");
  if (!ctx) {
    return;
  }

  const motionMedia = window.matchMedia("(prefers-reduced-motion: reduce)");
  let particles = [];
  let rafId = null;
  let cssWidth = window.innerWidth;
  let cssHeight = window.innerHeight;

  const drawScene = (staticOnly = false) => {
    ctx.clearRect(0, 0, cssWidth, cssHeight);

    for (let i = 0; i < particles.length; i += 1) {
      const particle = particles[i];
      ctx.beginPath();
      ctx.fillStyle = `rgba(${particle.color}, ${particle.alpha})`;
      ctx.arc(particle.x, particle.y, particle.radius, 0, Math.PI * 2);
      ctx.fill();

      for (let j = i + 1; j < particles.length; j += 1) {
        const other = particles[j];
        const dx = other.x - particle.x;
        const dy = other.y - particle.y;
        const distance = Math.hypot(dx, dy);
        if (distance > 130) {
          continue;
        }
        ctx.beginPath();
        ctx.strokeStyle = `rgba(140, 112, 82, ${0.04 * (1 - distance / 130)})`;
        ctx.lineWidth = 1;
        ctx.moveTo(particle.x, particle.y);
        ctx.lineTo(other.x, other.y);
        ctx.stroke();
      }
    }

    if (staticOnly) {
      return;
    }

    particles = particles.map((particle) => ({
      ...particle,
      x: wrapValue(particle.x + particle.speedX, cssWidth),
      y: wrapValue(particle.y + particle.speedY, cssHeight)
    }));
  };

  const seedParticles = () => {
    const area = cssWidth * cssHeight;
    const count = Math.max(20, Math.min(54, Math.round(area / 28000)));
    particles = Array.from({ length: count }, () => ({
      x: Math.random() * cssWidth,
      y: Math.random() * cssHeight,
      radius: 1 + Math.random() * 3.2,
      alpha: 0.08 + Math.random() * 0.16,
      speedX: (Math.random() - 0.5) * 0.14,
      speedY: (Math.random() - 0.5) * 0.1,
      color: pickParticleColor()
    }));
  };

  const resize = () => {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    cssWidth = window.innerWidth;
    cssHeight = window.innerHeight;
    particleCanvas.width = Math.floor(cssWidth * dpr);
    particleCanvas.height = Math.floor(cssHeight * dpr);
    particleCanvas.style.width = `${cssWidth}px`;
    particleCanvas.style.height = `${cssHeight}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    seedParticles();
    drawScene(true);
  };

  const stop = () => {
    if (rafId) {
      cancelAnimationFrame(rafId);
    }
    rafId = null;
  };

  const loop = () => {
    drawScene();
    rafId = requestAnimationFrame(loop);
  };

  const syncMotion = () => {
    stop();
    if (motionMedia.matches) {
      drawScene(true);
      return;
    }
    loop();
  };

  resize();
  syncMotion();
  window.addEventListener("resize", resize);

  if (typeof motionMedia.addEventListener === "function") {
    motionMedia.addEventListener("change", syncMotion);
  } else if (typeof motionMedia.addListener === "function") {
    motionMedia.addListener(syncMotion);
  }
}

function pickParticleColor() {
  const palette = ["15, 118, 110", "194, 65, 12", "170, 138, 92", "92, 74, 53"];
  return palette[Math.floor(Math.random() * palette.length)];
}

function wrapValue(value, max) {
  if (value < -12) {
    return max + 12;
  }
  if (value > max + 12) {
    return -12;
  }
  return value;
}

initParticleField();
updateSourceModeUI();
loadAuditSkills();
refreshTasks();
refreshEnvironment();
refreshMemory();
refreshSettings();
setInterval(refreshTasks, 1500);
