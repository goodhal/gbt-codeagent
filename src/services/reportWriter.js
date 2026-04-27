import { promises as fs } from "node:fs";
import path from "node:path";

export async function writeAuditHtmlReport({ reportsDir, task, selectedProjects, auditResult }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const fileName = `audit-report-${task.id}.html`;
  const filePath = path.join(reportsDir, fileName);
  const html = buildHtml({ task, selectedProjects, auditResult });
  await fs.writeFile(filePath, html, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

function buildHtml({ task, selectedProjects, auditResult }) {
  const selectedMap = new Map(selectedProjects.map((project) => [project.id, project]));
  const skillTags = (auditResult.skillsUsed || [])
    .map((skill) => `<span class="tag">${escapeHtml(skill.name)}</span>`)
    .join("");
  const skippedPaths = task.scoutResult?.skippedPaths || [];

  const projectSections = (auditResult.projects || [])
    .map((projectResult) => {
      const project = selectedMap.get(projectResult.projectId);
      const llmState = describeLlmReview(projectResult.llmReview);
      const heuristicFindings = renderFindings(projectResult.heuristicFindings, "规则层本次没有保留到高置信度结果。");
      const llmFindings = renderFindings(projectResult.llmReview?.findings || [], llmState.emptyMessage);
      const llmWarnings = (projectResult.llmReview?.warnings || [])
        .map((warning) => `<li>${escapeHtml(warning)}</li>`)
        .join("");

      return `
        <section class="project card">
          <div class="project-head">
            <div>
              <h3>${escapeHtml(projectResult.projectName)}</h3>
              <p class="muted">${escapeHtml(project?.description || "暂无描述")}</p>
            </div>
            <div class="project-meta">
              <p><strong>来源</strong><br/>${escapeHtml(project?.sourceType === "local" ? "本地仓库" : "GitHub")}</p>
              <p><strong>语言</strong><br/>${escapeHtml(project?.language || "Unknown")}</p>
            </div>
          </div>

          ${
            project?.sourceType === "local"
              ? `<p><strong>本地路径：</strong>${escapeHtml(project.localPath || "n/a")}</p>`
              : `<p><strong>仓库：</strong><a href="${escapeHtml(projectResult.repoUrl)}">${escapeHtml(projectResult.repoUrl)}</a></p>
                 ${project?.localPath ? `<p><strong>审计镜像：</strong>${escapeHtml(project.localPath)}</p>` : ""}`
          }

          <div class="sub-card">
            <h4>规则层摘要</h4>
            <p>保留 ${escapeHtml(String(projectResult.heuristicFindings.length))} 条结果。</p>
            ${heuristicFindings}
          </div>

          <div class="sub-card">
            <h4>LLM 复核摘要</h4>
            <div class="status-row">
              <span class="badge status">${escapeHtml(llmState.statusText)}</span>
              <span class="badge ${escapeHtml(llmState.badgeClass)}">${escapeHtml(llmState.callText)}</span>
            </div>
            <p>${escapeHtml(llmState.summary)}</p>
            ${llmState.meta ? `<p class="muted">${escapeHtml(llmState.meta)}</p>` : ""}
            ${llmWarnings ? `<ul class="warning-list">${llmWarnings}</ul>` : ""}
            ${llmFindings}
          </div>
        </section>
      `;
    })
    .join("");

  const llmOverview = buildLlmOverview(task, auditResult);

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Audit Report ${escapeHtml(task.id)}</title>
  <style>
    body{font-family:Segoe UI,PingFang SC,sans-serif;margin:0;background:#f6f1e8;color:#1f1c17}
    main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}
    .card{background:#fff;border:1px solid #e7ddd0;border-radius:24px;padding:22px;box-shadow:0 18px 40px rgba(0,0,0,.06);margin-bottom:20px}
    .hero{background:linear-gradient(135deg,#fff8ef,#f4ede2)}
    .hero h1,.project h3,.finding h4,.sub-card h4{font-family:Georgia,Noto Serif SC,serif}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:18px}
    .metric{padding:14px;border-radius:16px;background:#fbf7f1;border:1px solid #eee1d3}
    .project-head,.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
    .project-meta{display:flex;gap:18px;text-align:right}
    .sub-card{margin-top:16px;padding:16px;border-radius:18px;background:#fbf7f1;border:1px solid #eee1d3}
    .finding{border-top:1px solid #eee2d4;padding-top:14px;margin-top:14px}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#efe7db}
    .badge.low{background:#d7efe9}
    .badge.medium{background:#f6decf}
    .badge.high{background:#f7cdcd}
    .badge.rule{background:#ece7f8}
    .badge.llm{background:#dce9ff}
    .badge.status{background:#efe7db}
    .badge.called{background:#d7efe9}
    .badge.skipped{background:#f6decf}
    .badge.failed{background:#f7cdcd}
    .tag{display:inline-block;margin:0 8px 8px 0;padding:6px 10px;border-radius:999px;background:#efe7db}
    .muted{color:#746c61}
    .warning-list{color:#8a5b22}
    .status-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
    .callout{padding:14px 16px;border-radius:18px;border:1px solid #eadbc8;background:#fffaf4;margin-top:18px}
    a{color:#0f766e}
    @media (max-width: 900px){.grid{grid-template-columns:1fr}.project-meta{display:grid;grid-template-columns:1fr 1fr;text-align:left}.project-head,.finding-head{display:block}}
  </style>
</head>
<body>
  <main>
    <section class="card hero">
      <h1>防御性代码审计报告</h1>
      <p class="muted">报告分为两层：规则型静态审计，以及对已进入审计阶段并完成本地镜像的目标执行的 LLM 二次复核。全程不包含利用方式或攻击载荷。</p>
      <div class="grid">
        <div class="metric"><strong>任务 ID</strong><br/>${escapeHtml(task.id)}</div>
        <div class="metric"><strong>来源模式</strong><br/>${escapeHtml(task.sourceType === "local" ? "本地仓库导入" : "GitHub 候选发现")}</div>
        <div class="metric"><strong>选中目标</strong><br/>${escapeHtml(String(selectedProjects.length))}</div>
        <div class="metric"><strong>总保留结果</strong><br/>${escapeHtml(String(auditResult.findingsCount || 0))}</div>
      </div>
      <div class="grid">
        <div class="metric"><strong>规则层结果</strong><br/>${escapeHtml(String(auditResult.heuristicFindingsCount || 0))}</div>
        <div class="metric"><strong>LLM 复核结果</strong><br/>${escapeHtml(String(auditResult.llmFindingsCount || 0))}</div>
        <div class="metric"><strong>LLM 已调用目标</strong><br/>${escapeHtml(String(auditResult.llmCallCount || 0))}</div>
        <div class="metric"><strong>LLM 跳过目标</strong><br/>${escapeHtml(String(auditResult.llmSkippedCount || 0))}</div>
      </div>
      <div class="grid">
        <div class="metric"><strong>查询 / 导入</strong><br/>${escapeHtml(task.sourceType === "local" ? "local repository import" : task.query)}</div>
        <div class="metric"><strong>生成时间</strong><br/>${escapeHtml(auditResult.reviewedAt || "")}</div>
        <div class="metric"><strong>记忆模式</strong><br/>${escapeHtml(task.useMemory ? "memory" : "incognito")}</div>
        <div class="metric"><strong>任务阶段</strong><br/>${escapeHtml(task.phase || "")}</div>
      </div>
      <div class="callout">
        <strong>${escapeHtml(llmOverview.title)}</strong>
        <div>${escapeHtml(llmOverview.body)}</div>
      </div>
      <div style="margin-top:16px;">
        ${skillTags || '<span class="muted">未指定 Skill，已使用默认审计集合。</span>'}
      </div>
    </section>

    <section class="card">
      <h2>执行摘要</h2>
      <p>${escapeHtml(task.message || "")}</p>
      <p>本次共对 ${escapeHtml(String(auditResult.projects?.length || 0))} 个目标进行了防御性静态审计。规则层保留 ${escapeHtml(String(auditResult.heuristicFindingsCount || 0))} 条结果，LLM 复核保留 ${escapeHtml(String(auditResult.llmFindingsCount || 0))} 条结果。</p>
      <p class="muted">如果某个目标在某一层没有结果，不代表绝对安全，只表示当前镜像、规则和模型复核下没有保留到足够高置信度的问题。</p>
    </section>

    ${
      skippedPaths.length
        ? `
          <section class="card">
            <h2>导入时跳过的路径</h2>
            <ul class="warning-list">
              ${skippedPaths.map((item) => `<li>${escapeHtml(item.path)} · ${escapeHtml(item.reason)}</li>`).join("")}
            </ul>
          </section>
        `
        : ""
    }

    ${projectSections}
  </main>
</body>
</html>`;
}

function buildLlmOverview(task, auditResult) {
  if (task.sourceType === "github") {
    return {
      title: "GitHub 目标也支持大模型复核",
      body: (auditResult.llmCallCount || 0) > 0
        ? `本次 GitHub 审计阶段已经对 ${auditResult.llmCallCount || 0} 个选中目标调用了大模型，并基于下载到本地的审计镜像执行了复核。`
        : "GitHub 模式在发现阶段不会调用大模型；只有当你选中目标并进入审计阶段后，系统才会下载本地审计镜像并尝试执行 LLM 复核。当前这次没有实际调用成功。"
    };
  }

  if ((auditResult.llmCallCount || 0) > 0) {
    return {
      title: "本次已经实际调用大模型",
      body: `LLM 已复核 ${auditResult.llmCallCount || 0} 个目标，另有 ${auditResult.llmSkippedCount || 0} 个目标被跳过。下方每个项目卡片都会继续写明调用状态、模型信息和复核摘要。`
    };
  }

  return {
    title: "本次没有实际调用大模型",
    body: "当前任务虽然是本地导入模式，但 LLM 没有真正执行。常见原因包括未配置 API Key、本地镜像为空，或该目标在复核前被跳过。"
  };
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
  const statusText = status === "failed" ? "调用失败" : status === "partial" ? "部分完成" : "已完成";
  const metaParts = [];

  if (llmReview.providerId || llmReview.model) {
    metaParts.push(`模型：${llmReview.providerId || "unknown"} / ${llmReview.model || "unknown"}`);
  }
  if (Number.isFinite(Number(llmReview.reviewedFiles)) || Number.isFinite(Number(llmReview.reviewedBatches))) {
    metaParts.push(`复核文件 ${Number(llmReview.reviewedFiles || 0)} 个，批次 ${Number(llmReview.reviewedBatches || 0)} 个`);
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

function renderFindings(findings, emptyMessage) {
  if (!findings?.length) {
    return `<p class="muted">${escapeHtml(emptyMessage)}</p>`;
  }

  return `
    <div class="finding-list">
      ${findings
        .map(
          (finding) => {
            const isGbtFinding = finding.skillId === "gbt-code-audit";
            const extraInfo = isGbtFinding ? `
              <p><strong>漏洞类型：</strong>${escapeHtml(finding.vulnType || "UNKNOWN")}</p>
              <p><strong>CWE：</strong>${escapeHtml(finding.cwe || "CWE-000")}</p>
              <p><strong>国标映射：</strong>${escapeHtml(finding.gbtMapping || "GB/T39412-2020 通用基线")}</p>
              <p><strong>CVSS 评分：</strong>${escapeHtml(String(finding.cvssScore || 0.0))}</p>
              <p><strong>编程语言：</strong>${escapeHtml(finding.language || "unknown")}</p>
            ` : "";
            
            return `
            <div class="finding">
              <div class="finding-head">
                <h4>${escapeHtml(finding.title)}</h4>
                <div>
                  <span class="badge ${escapeHtml(finding.severity)}">${escapeHtml(finding.severity)}</span>
                  <span class="badge ${escapeHtml(finding.source || "rule")}">${escapeHtml(finding.source || "rule")}</span>
                </div>
              </div>
              ${extraInfo}
              <p><strong>位置：</strong>${escapeHtml(finding.location || "n/a")}</p>
              <p><strong>影响：</strong>${escapeHtml(finding.impact || "")}</p>
              <p><strong>证据：</strong>${escapeHtml(finding.evidence || "")}</p>
              <p><strong>修复建议：</strong>${escapeHtml(finding.remediation || "")}</p>
              <p><strong>安全验证建议：</strong>${escapeHtml(finding.safeValidation || "")}</p>
            </div>
          `;
          }
        )
        .join("")}
    </div>
  `;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
