import { promises as fs } from "node:fs";
import path from "node:path";
import { OWASP_NAMES } from "../config/owaspMapping.js";
import { validationChecklist } from "./validationChecklist.js";

export async function writeAuditHtmlReport({ reportsDir, task, selectedProjects, auditResult, architectureAnalysis }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const fileName = `audit-report-${task.id}.html`;
  const filePath = path.join(reportsDir, fileName);
  const html = buildHtml({ task, selectedProjects, auditResult, architectureAnalysis });
  await fs.writeFile(filePath, html, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

function buildHtml({ task, selectedProjects, auditResult, architectureAnalysis }) {
  const selectedMap = new Map(selectedProjects.map((project) => [project.id, project]));
  const skillTags = (auditResult.skillsUsed || [])
    .map((skill) => `<span class="tag">${escapeHtml(skill.name)}</span>`)
    .join("");
  const skippedPaths = task.scoutResult?.skippedPaths || [];

  const projectSections = (auditResult.projects || [])
    .map((projectResult) => {
      const project = selectedMap.get(projectResult.projectId);
      const llmResult = projectResult.llmAudit;
      const llmState = describeLlmAudit(llmResult);
      const verdictMap = buildVerdictMap(projectResult.findings || []);
      const heuristicSource = (projectResult.heuristicFindings || []).length > 0
        ? (projectResult.heuristicFindings || [])
        : (projectResult.findings || []).filter(f => ['quick_scan', 'taint', 'rule', 'pattern'].includes(f.source) || !f.source);
      const llmSource = (llmResult?.findings || []).length > 0
        ? (llmResult?.findings || [])
        : (projectResult.findings || []).filter(f => f.source === 'llm');
      const heuristicFindings = renderFindings(heuristicSource, "规则层本次没有保留到高置信度结果。", verdictMap);
      const llmFindings = renderFindings(llmSource, llmState.emptyMessage, verdictMap);
      const llmWarnings = (llmResult?.warnings || [])
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
            <p>保留 ${escapeHtml(String(heuristicSource.length))} 条结果。</p>
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
    body{font-family:Segoe UI,PingFang SC,sans-serif;margin:0;background:#f0f5ff;color:#1a1a1a}
    main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}
    .card{background:#fff;border:1px solid #dbeafe;border-radius:24px;padding:22px;box-shadow:0 18px 40px rgba(59,130,246,.12);margin-bottom:20px}
    .hero{background:linear-gradient(135deg,#eff6ff,#dbeafe)}
    .hero h1,.project h3,.finding h4,.sub-card h4{font-family:Georgia,Noto Serif SC,serif}
    .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:18px}
    .metric{padding:14px;border-radius:16px;background:#f0f5ff;border:1px solid #bfdbfe}
    .project-head,.finding-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
    .project-meta{display:flex;gap:18px;text-align:right}
    .sub-card{margin-top:16px;padding:16px;border-radius:18px;background:#f0f5ff;border:1px solid #bfdbfe}
    .finding{border-top:1px solid #dbeafe;padding-top:14px;margin-top:14px}
    .finding-fp{opacity:0.6;border-left:3px solid #fca5a5;padding-left:10px}
    .badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;background:#dbeafe}
    .badge.critical{background:#fecaca}
    .badge.low{background:#dbeafe}
    .badge.medium{background:#bfdbfe}
    .badge.high{background:#fecaca}
    .badge.rule{background:#e0e7ff}
    .badge.llm{background:#dbeafe}
    .badge.status{background:#dbeafe}
    .badge.called{background:#d1fae5}
    .badge.skipped{background:#fed7aa}
    .badge.failed{background:#fecaca}
    .tag{display:inline-block;margin:0 8px 8px 0;padding:6px 10px;border-radius:999px;background:#dbeafe}
    .muted{color:#667eea}
    .warning-list{color:#b45309}
    .ast-context{margin-top:12px;padding:12px;border-radius:12px;background:#f0fdf4;border:1px solid #86efac;font-size:13px}
    .ast-context p{margin:4px 0}
    .code-context{margin:8px 0;padding:10px;border-radius:8px;background:#1a1a1a;color:#10b981;font-size:12px;overflow-x:auto;white-space:pre}
    .status-row{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
    .callout{padding:14px 16px;border-radius:18px;border:1px solid #bfdbfe;background:#eff6ff;margin-top:18px}
    a{color:#2563eb}
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
        <div class="metric"><strong>确认结果</strong><br/>${escapeHtml(String(auditResult.findingsCount || 0))}</div>
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

    ${architectureAnalysis ? buildArchitectureSection(architectureAnalysis) : ""}

    ${buildValidationChecklist(auditResult)}
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

function describeLlmAudit(llmAudit) {
  if (!llmAudit?.called) {
    const reason = getLlmSkipReasonLabel(llmAudit?.skipReason);
    return {
      statusText: "未调用",
      callText: reason.short,
      badgeClass: "skipped",
      summary: llmAudit?.summary || reason.long,
      meta: "",
      emptyMessage: reason.empty
    };
  }

  const status = llmAudit.status || "completed";
  const statusText = status === "failed" ? "调用失败" : status === "partial" ? "部分完成" : "已完成";
  const metaParts = [];

  if (llmAudit.providerId || llmAudit.model) {
    metaParts.push(`模型：${llmAudit.providerId || "unknown"} / ${llmAudit.model || "unknown"}`);
  }
  const auditedFiles = llmAudit.auditedFiles;
  const auditedBatches = llmAudit.auditedBatches;
  if (Number.isFinite(Number(auditedFiles)) || Number.isFinite(Number(auditedBatches))) {
    metaParts.push(`复核文件 ${Number(auditedFiles || 0)} 个，批次 ${Number(auditedBatches || 0)} 个`);
  }

  return {
    statusText,
    callText: "已调用",
    badgeClass: status === "failed" ? "failed" : "called",
    summary: llmAudit.summary || "LLM 已完成复核。",
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

function buildVerdictMap(validatedFindings) {
  const map = new Map();
  for (const f of validatedFindings) {
    if (f.location) {
      map.set(f.location, { verdict: f.verdict, verificationReason: f.verificationReason, adjustedSeverity: f.adjustedSeverity });
    }
  }
  return map;
}

function renderFindings(findings, emptyMessage, verdictMap) {
  if (!findings?.length) {
    return `<p class="muted">${escapeHtml(emptyMessage)}</p>`;
  }

  return `
    <div class="finding-list">
      ${findings
        .map(
          (finding, index) => {
            const isGbtFinding = finding.skillId === "gbt-code-audit";
            // 处理OWASP映射，添加中文名称
            let owaspDisplay = "无";
            if (finding.owasp) {
              const owaspIds = finding.owasp.split(", ");
              owaspDisplay = owaspIds.map(id => `${id} ${OWASP_NAMES[id] || ""}`).join(", ");
            } else if (finding.owaspIds) {
              owaspDisplay = finding.owaspIds.map(id => `${id} ${OWASP_NAMES[id] || ""}`).join(", ");
            }

            const extraInfo = isGbtFinding ? `
              <p><strong>漏洞类型：</strong>${escapeHtml(finding.vulnType || "UNKNOWN")}</p>
              <p><strong>CWE：</strong>${escapeHtml(finding.cwe || "CWE-000")}</p>
              <p><strong>国标映射：</strong>${escapeHtml(finding.gbtMapping || "GB/T39412-2020 通用基线")}</p>
              <p><strong>OWASP 映射：</strong>${escapeHtml(owaspDisplay)}</p>
              <p><strong>CVSS 评分：</strong>${escapeHtml(String(finding.cvssScore || 0.0))}</p>
              <p><strong>编程语言：</strong>${escapeHtml(finding.language || "unknown")}</p>
            ` : "";

            const confidenceInfo = finding.confidence ? `
              <p><strong>置信度：</strong>${escapeHtml(String((finding.confidence * 100).toFixed(0)))}%</p>
            ` : "";

            const astContextInfo = finding.astContext ? `
              <div class="ast-context">
                <p><strong>--- AST 深度分析 ---</strong></p>
                <p><strong>危险sink：</strong>${escapeHtml(finding.astContext.sink || "n/a")} (${escapeHtml(finding.astContext.sinkSeverity || "n/a")})</p>
                <p><strong>风险描述：</strong>${escapeHtml(finding.astContext.sinkDesc || "n/a")}</p>
                <p><strong>用户输入检测：</strong>${finding.astContext.hasUserInput ? "✓ 有" : "✗ 无"}</p>
                <p><strong>输入验证：</strong>${finding.astContext.hasValidation ? "✓ 有" : "✗ 无"}</p>
                <p><strong>编码处理：</strong>${finding.astContext.hasEncoding ? "✓ 有" : "✗ 无"}</p>
                ${finding.astContext.contextLines ? `
                  <p><strong>代码上下文：</strong></p>
                  <pre class="code-context">${finding.astContext.contextLines.map(l => `${String(l.lineNum).padStart(4)} | ${escapeHtml(l.content)}`).join('\n')}</pre>
                ` : ""}
                ${finding.astContext.recommendation ? `<p><strong>深度建议：</strong>${escapeHtml(finding.astContext.recommendation)}</p>` : ""}
              </div>
            ` : "";

            const verdictInfo = verdictMap?.get(finding.location);
            const verdictBadge = verdictInfo ? (() => {
              const v = verdictInfo.verdict;
              if (v === 'confirmed') return '<span class="badge called">✓ 已确认</span>';
              if (v === 'false_positive') return '<span class="badge failed">✗ 误报</span>';
              if (v === 'downgraded') return '<span class="badge skipped">↓ 已降级</span>';
              if (v === 'needs_review') return '<span class="badge status">? 待复核</span>';
              return '';
            })() : '';

            return `
            <div class="finding${verdictInfo?.verdict === 'false_positive' ? ' finding-fp' : ''}">
              <div class="finding-head">
                <h4>${index + 1}. ${escapeHtml(finding.title)}</h4>
                <div>
                  <span class="badge ${escapeHtml(severityClass(finding.severity))}">${escapeHtml(severityLabel(finding.severity))}</span>
                  <span class="badge ${escapeHtml(finding.source || "rule")}">${escapeHtml(finding.source || "rule")}</span>
                  ${verdictBadge}
                </div>
              </div>
              ${verdictInfo?.verificationReason ? `<p class="muted">验证说明：${escapeHtml(verdictInfo.verificationReason)}</p>` : ''}
              ${extraInfo}
              ${confidenceInfo}
              <p><strong>位置：</strong>${escapeHtml(finding.location || "n/a")}</p>
              <p><strong>影响：</strong>${escapeHtml(finding.impact || "")}</p>
              <p><strong>证据：</strong>${escapeHtml(finding.evidence || "")}</p>
              <p><strong>修复建议：</strong>${escapeHtml(finding.remediation || "")}</p>
              <p><strong>安全验证建议：</strong>${escapeHtml(finding.safeValidation || "")}</p>
              ${astContextInfo}
            </div>
          `;
          }
        )
        .join("")}
    </div>
  `;
}

function severityClass(severity) {
  const normalized = (severity || "medium").toLowerCase();
  const mapping = { critical: "critical", high: "high", medium: "medium", low: "low" };
  return mapping[normalized] || "medium";
}

function severityLabel(severity) {
  const normalized = (severity || "medium").toLowerCase();
  const mapping = { critical: "严重", high: "高危", medium: "中危", low: "低危" };
  return mapping[normalized] || "中危";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function buildValidationChecklist(auditResult) {
  const hasDotnetSkills = auditResult.skillsUsed?.some(skill => 
    skill.id === 'dotnet-route-audit' || skill.id === 'dotnet-auth-audit'
  );
  const checklistType = hasDotnetSkills ? 'dotnet' : 'general';
  const checklistReport = validationChecklist.generateChecklistReport(checklistType, auditResult);
  
  if (checklistReport.summary.status === 'complete') {
    return "";
  }
  
  const sectionsHtml = checklistReport.sections.map(section => {
    const itemsHtml = section.items.map(item => {
      const statusClass = {
        'pass': 'check-pass',
        'fail': 'check-fail',
        'skip': 'check-skip'
      }[item.status];
      
      const icon = {
        'pass': '✓',
        'fail': '✗',
        'skip': '○'
      }[item.status];
      
      return `
        <div class="check-item ${statusClass}">
          <span class="check-icon">${icon}</span>
          <span class="check-label">${escapeHtml(item.label)}</span>
          ${item.required ? '<span class="check-required">必需</span>' : ''}
        </div>
      `;
    }).join('');
    
    return `
      <div class="check-section">
        <h4>${escapeHtml(section.name)}</h4>
        <div class="check-items">${itemsHtml}</div>
      </div>
    `;
  }).join('');
  
  const statusBadge = checklistReport.summary.status === 'complete' 
    ? '<span class="badge success">✓ 完整</span>' 
    : '<span class="badge warning">! 部分完成</span>';
  
  return `
    <section class="card">
      <h2>验证清单 ${statusBadge}</h2>
      <div class="check-summary">
        <div class="summary-item">
          <span class="summary-value">${checklistReport.summary.completeness}%</span>
          <span class="summary-label">完整性</span>
        </div>
        <div class="summary-item">
          <span class="summary-value">${checklistReport.summary.passRate}%</span>
          <span class="summary-label">必需项通过率</span>
        </div>
        <div class="summary-item">
          <span class="summary-value">${checklistReport.summary.checkedRequired}/${checklistReport.summary.requiredItems}</span>
          <span class="summary-label">必需项完成</span>
        </div>
      </div>
      ${sectionsHtml}
      <style>
        .check-summary {
          display: grid;
          grid-template-columns: repeat(3, 1fr);
          gap: 14px;
          margin-bottom: 20px;
        }
        .summary-item {
          padding: 12px;
          border-radius: 12px;
          background: #f0f5ff;
          text-align: center;
        }
        .summary-value {
          display: block;
          font-size: 24px;
          font-weight: bold;
          color: #1e40af;
        }
        .summary-label {
          font-size: 12px;
          color: #667eea;
        }
        .check-section {
          margin-bottom: 16px;
          padding-bottom: 16px;
          border-bottom: 1px solid #dbeafe;
        }
        .check-section:last-child {
          border-bottom: none;
          margin-bottom: 0;
          padding-bottom: 0;
        }
        .check-items {
          display: grid;
          grid-template-columns: repeat(2, 1fr);
          gap: 8px;
          margin-top: 8px;
        }
        .check-item {
          display: flex;
          align-items: center;
          gap: 8px;
          padding: 6px 10px;
          border-radius: 8px;
          font-size: 13px;
        }
        .check-pass {
          background: #d1fae5;
          color: #065f46;
        }
        .check-fail {
          background: #fee2e2;
          color: #991b1b;
        }
        .check-skip {
          background: #f3f4f6;
          color: #6b7280;
        }
        .check-icon {
          font-weight: bold;
        }
        .check-required {
          margin-left: auto;
          font-size: 10px;
          padding: 2px 6px;
          border-radius: 4px;
          background: #f59e0b;
          color: white;
        }
        .badge.success {
          background: #d1fae5;
          color: #065f46;
        }
        .badge.warning {
          background: #fee2e2;
          color: #991b1b;
        }
        @media (max-width: 600px) {
          .check-summary {
            grid-template-columns: 1fr;
          }
          .check-items {
            grid-template-columns: 1fr;
          }
        }
      </style>
    </section>
  `;
}

function buildArchitectureSection(architectureAnalysis) {
  if (!architectureAnalysis) return "";

  const { overview, criticalPaths, hotspots, knowledgeGaps, recommendations } = architectureAnalysis;

  const riskScore = overview?.riskScore || 0;
  const riskLevel = riskScore >= 70 ? 'high' : riskScore >= 40 ? 'medium' : 'low';
  const riskLabel = { high: '高风险', medium: '中风险', low: '低风险' }[riskLevel];
  const riskColor = { high: '#ef4444', medium: '#f59e0b', low: '#10b981' }[riskLevel];

  return `
    <section class="card">
      <h2>架构分析报告</h2>
      
      <div class="grid">
        <div class="metric">
          <strong>总节点数</strong><br/>${escapeHtml(String(overview?.totalNodes || 0))}
        </div>
        <div class="metric">
          <strong>总边数</strong><br/>${escapeHtml(String(overview?.totalEdges || 0))}
        </div>
        <div class="metric">
          <strong>模块数量</strong><br/>${escapeHtml(String(overview?.communities || 0))}
        </div>
        <div class="metric" style="background: ${riskColor}20; border-color: ${riskColor}40;">
          <strong>架构风险</strong><br/>
          <span style="color: ${riskColor}; font-weight: bold;">${riskLabel} (${riskScore})</span>
        </div>
      </div>

      ${overview?.warnings?.length > 0 ? `
        <div class="sub-card" style="margin-top: 16px;">
          <h4>架构警告</h4>
          <ul>
            ${overview.warnings.map(w => `
              <li class="warning-item ${w.severity}">
                <span class="severity-badge ${w.severity}">${w.severity === 'high' ? '高危' : w.severity === 'medium' ? '中危' : '低危'}</span>
                ${escapeHtml(w.message)}
              </li>
            `).join('')}
          </ul>
        </div>
      ` : ''}

      ${criticalPaths?.length > 0 ? `
        <div class="sub-card" style="margin-top: 16px;">
          <h4>关键执行路径</h4>
          <div style="display: grid; gap: 12px;">
            ${criticalPaths.slice(0, 5).map((path, idx) => `
              <div style="padding: 10px; background: #fff; border-radius: 8px; border: 1px solid #dbeafe;">
                <div style="display: flex; justify-content: space-between;">
                  <span><strong>${escapeHtml(path.entryPoint?.name || `路径 ${idx + 1}`)}</strong></span>
                  <span class="badge ${path.criticality >= 70 ? 'high' : path.criticality >= 40 ? 'medium' : 'low'}">
                    关键度: ${path.criticality}%
                  </span>
                </div>
                <div style="font-size: 13px; color: #667eea; margin-top: 4px;">
                  ${path.nodeCount} 个节点 · ${path.edgeCount} 条边 · 深度 ${path.depth}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      ${hotspots?.length > 0 ? `
        <div class="sub-card" style="margin-top: 16px;">
          <h4>热点节点（高连接度）</h4>
          <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px;">
            ${hotspots.slice(0, 10).map(hotspot => `
              <div style="padding: 8px; background: #fff; border-radius: 8px; border: 1px solid #dbeafe;">
                <div style="font-size: 14px; font-weight: bold;">${escapeHtml(hotspot.name)}</div>
                <div style="font-size: 12px; color: #667eea;">
                  连接度: ${hotspot.degree} · ${escapeHtml(hotspot.community)}
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      ${knowledgeGaps?.isolatedNodes?.length > 0 || knowledgeGaps?.untestedHotspots?.length > 0 ? `
        <div class="sub-card" style="margin-top: 16px;">
          <h4>知识缺口分析</h4>
          <div style="display: grid; gap: 8px;">
            ${knowledgeGaps.isolatedNodes?.length > 0 ? `
              <div>
                <strong>孤立节点：</strong>${knowledgeGaps.isolatedNodes.length} 个
                <span style="font-size: 12px; color: #667eea;">（可能是死代码）</span>
              </div>
            ` : ''}
            ${knowledgeGaps.untestedHotspots?.length > 0 ? `
              <div>
                <strong>未测试热点：</strong>${knowledgeGaps.untestedHotspots.length} 个
                <span style="font-size: 12px; color: #f59e0b;">（建议添加测试）</span>
              </div>
            ` : ''}
            ${knowledgeGaps.orphanFiles?.length > 0 ? `
              <div>
                <strong>孤立文件：</strong>${knowledgeGaps.orphanFiles.length} 个
              </div>
            ` : ''}
          </div>
        </div>
      ` : ''}

      ${recommendations?.length > 0 ? `
        <div class="sub-card" style="margin-top: 16px;">
          <h4>架构优化建议</h4>
          <ol>
            ${recommendations.slice(0, 5).map((rec, idx) => `
              <li style="margin-bottom: 8px;">
                <span class="badge ${rec.severity}">${rec.severity === 'high' ? '重要' : rec.severity === 'medium' ? '建议' : '参考'}</span>
                <strong>${escapeHtml(rec.message)}</strong>
                <p style="font-size: 13px; color: #667eea; margin: 4px 0 0 0;">${escapeHtml(rec.suggestion)}</p>
              </li>
            `).join('')}
          </ol>
        </div>
      ` : ''}

      <style>
        .warning-item {
          padding: 8px;
          border-radius: 8px;
          margin-bottom: 8px;
          list-style: none;
        }
        .warning-item.high {
          background: #fee2e2;
          border: 1px solid #fecaca;
        }
        .warning-item.medium {
          background: #fef3c7;
          border: 1px solid #fde68a;
        }
        .warning-item.low {
          background: #dbeafe;
          border: 1px solid #bfdbfe;
        }
        .severity-badge {
          display: inline-block;
          padding: 2px 6px;
          border-radius: 4px;
          font-size: 11px;
          margin-right: 8px;
          color: white;
        }
        .severity-badge.high { background: #ef4444; }
        .severity-badge.medium { background: #f59e0b; }
        .severity-badge.low { background: #3b82f6; }
      </style>
    </section>
  `;
}

const SARIF_SEVERITY = {
  'CRITICAL': 'error',
  'HIGH': 'error',
  'MEDIUM': 'warning',
  'LOW': 'note',
  'INFO': 'note'
};

const SARIF_LEVEL = {
  'CRITICAL': 'error',
  'HIGH': 'error',
  'MEDIUM': 'warning',
  'LOW': 'note',
  'INFO': 'note'
};

function convertToSarif(findings, options = {}) {
  const {
    toolName = 'GBT CodeAgent',
    toolVersion = '1.0.0',
    toolInformationUri = 'https://gbt-codeagent.com'
  } = options;

  const sarif = {
    version: '2.1.0',
    '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: []
  };

  const run = {
    tool: {
      driver: {
        name: toolName,
        version: toolVersion,
        informationUri: toolInformationUri,
        rules: []
      }
    },
    results: []
  };

  const ruleIdMap = new Map();

  for (const finding of findings) {
    const ruleId = finding.vulnType || finding.id || 'UNKNOWN';

    if (!ruleIdMap.has(ruleId)) {
      const rule = {
        id: ruleId,
        name: finding.title || ruleId,
        shortDescription: {
          text: finding.title || ruleId
        },
        fullDescription: {
          text: finding.description || finding.title || ''
        },
        help: {
          text: finding.remediation || '',
          markdown: finding.remediation || ''
        },
        properties: {
          tags: [
            finding.category || 'security',
            finding.severity || 'medium'
          ],
          precision: finding.confidence ? 'high' : 'medium'
        }
      };

      if (finding.severity) {
        rule.defaultConfiguration = {
          level: SARIF_LEVEL[finding.severity.toUpperCase()] || 'warning'
        };
        rule.properties.severity = finding.severity;
      }

      if (finding.cwe) {
        rule.properties.cwe = Array.isArray(finding.cwe) ? finding.cwe : [finding.cwe];
      }

      if (finding.owasp) {
        rule.properties.owasp = Array.isArray(finding.owasp) ? finding.owasp : [finding.owasp];
      }

      if (finding.gbt) {
        rule.properties.gbt = Array.isArray(finding.gbt) ? finding.gbt : [finding.gbt];
      }

      if (finding.doc_url) {
        rule.helpUri = finding.doc_url;
      }

      run.tool.driver.rules.push(rule);
      ruleIdMap.set(ruleId, rule);
    }

    const result = {
      ruleId: ruleId,
      ruleIndex: run.tool.driver.rules.findIndex(r => r.id === ruleId),
      level: SARIF_LEVEL[finding.severity?.toUpperCase()] || 'warning',
      message: {
        text: finding.impact || finding.title || 'Security issue detected'
      },
      locations: []
    };

    if (finding.location) {
      const locationParts = finding.location.split(':');
      const filePath = locationParts[0] || '';
      const lineNumber = locationParts[1] ? parseInt(locationParts[1], 10) : 1;

      const physicalLocation = {
        artifactLocation: {
          uri: filePath,
          uriBaseId: '%SRCROOT%'
        }
      };

      if (lineNumber) {
        physicalLocation.region = {
          startLine: lineNumber,
          startColumn: 1
        };

        if (locationParts[2]) {
          physicalLocation.region.startColumn = parseInt(locationParts[2], 10);
        }
      }

      if (finding.evidence) {
        physicalLocation.region = physicalLocation.region || {};
        physicalLocation.region.snippet = {
          text: finding.evidence
        };
      }

      result.locations.push({
        physicalLocation
      });
    }

    if (finding.suppressionComment) {
      result.suppressions = [
        {
          kind: 'inSource',
          justification: finding.suppressionComment
        }
      ];
    }

    if (finding.astContext) {
      result.properties = {
        astContext: {
          sink: finding.astContext.sink,
          sinkSeverity: finding.astContext.sinkSeverity,
          hasUserInput: finding.astContext.hasUserInput,
          hasValidation: finding.astContext.hasValidation,
          hasEncoding: finding.astContext.hasEncoding
        }
      };
    }

    run.results.push(result);
  }

  sarif.runs.push(run);
  return sarif;
}

async function writeSarifReport(findings, outputPath, options = {}) {
  const sarif = convertToSarif(findings, options);
  const jsonContent = JSON.stringify(sarif, null, 2);
  await fs.writeFile(outputPath, jsonContent, 'utf-8');

  return {
    filePath: outputPath,
    findingsCount: findings.length,
    rulesCount: sarif.runs[0]?.tool?.driver?.rules?.length || 0,
    generatedAt: new Date().toISOString()
  };
}

async function writeSarifReportStream(findings, outputStream, options = {}) {
  const sarif = convertToSarif(findings, options);
  const jsonContent = JSON.stringify(sarif, null, 2);

  return new Promise((resolve, reject) => {
    outputStream.write(jsonContent, 'utf-8', (err) => {
      if (err) {
        reject(err);
      } else {
        resolve({
          findingsCount: findings.length,
          rulesCount:sarif.runs[0]?.tool?.driver?.rules?.length || 0,
          generatedAt: new Date().toISOString()
        });
      }
    });
  });
}

function getSarifSummary(sarif) {
  const summary = {
    version: sarif.version,
    runs: sarif.runs.length,
    totalResults: 0,
    resultsBySeverity: {},
    resultsByRule: {},
    rulesCount: 0
  };

  for (const run of sarif.runs) {
    summary.rulesCount += run.tool?.driver?.rules?.length || 0;
    summary.totalResults += run.results?.length || 0;

    for (const result of run.results || []) {
      const severity = result.level || 'warning';
      summary.resultsBySeverity[severity] = (summary.resultsBySeverity[severity] || 0) + 1;

      if (result.ruleId) {
        summary.resultsByRule[result.ruleId] = (summary.resultsByRule[result.ruleId] || 0) + 1;
      }
    }
  }

  return summary;
}

export {
  writeSarifReport,
  writeSarifReportStream,
  convertToSarif,
  getSarifSummary,
  SARIF_SEVERITY,
  SARIF_LEVEL
};
