import { promises as fs } from "node:fs";
import path from "node:path";

export async function writeAuditMarkdownReport({ reportsDir, task, selectedProjects, auditResult }) {
  await fs.mkdir(reportsDir, { recursive: true });
  const fileName = `audit_report_${new Date().toISOString().slice(0, 10).replace(/-/g, "")}_${new Date().toTimeString().slice(0, 8).replace(/:/g, "")}.md`;
  const filePath = path.join(reportsDir, fileName);
  const markdown = buildMarkdown({ task, selectedProjects, auditResult });
  await fs.writeFile(filePath, markdown, "utf8");

  return {
    fileName,
    filePath,
    downloadPath: `/reports/${fileName}`,
    generatedAt: new Date().toISOString()
  };
}

function buildMarkdown({ task, selectedProjects, auditResult }) {
  const projectName = selectedProjects[0]?.name || "unknown";
  const language = detectLanguageFromFindings(auditResult.findings || []);
  const standards = getStandardsFromFindings(auditResult.findings || []);

  const stats = calculateStatistics(auditResult.findings || []);
  const gbtStats = calculateGbtStatistics(auditResult.findings || []);

  let markdown = `# ${projectName} 代码安全审计报告

## 封面

**项目**: ${projectName}
**语言**: ${language}
**适用标准**: ${standards}
**日期**: ${new Date().toISOString().slice(0, 10)}
**审计人**: Agent

---

## 审计汇总

本次审计共发现 **${stats.total}** 个安全问题，其中：

### 问题汇总

| 严重等级 | 数量 | 快速扫描 | LLM 审计 | 说明 |
|:--------:|:----:|:--------:|:--------:|:-----:|
| 🔴 严重 | ${stats.critical} | ${stats.quickScanCritical} | ${stats.llmCritical} | 可直接导致系统被入侵 |
| 🟠 高危 | ${stats.high} | ${stats.quickScanHigh} | ${stats.llmHigh} | 可导致数据泄露或权限提升 |
| 🟡 中危 | ${stats.medium} | ${stats.quickScanMedium} | ${stats.llmMedium} | 可能被利用但需要特定条件 |
| 🟢 低危 | ${stats.low} | ${stats.quickScanLow} | ${stats.llmLow} | 存在安全隐患但影响较小 |
| **总计** | **${stats.total}** | **${stats.quickScanTotal}** | **${stats.llmTotal}** | |

### 按国标分类统计

> ⚠️ **注意**：以下统计仅包含能明确对应到国标规则的安全问题

`;

  for (const [standard, rules] of Object.entries(gbtStats)) {
    markdown += `#### ${standard} - ${rules.total} 个\n\n`;
    markdown += `| 规则 | 问题数 |\n|------|--------|\n`;
    for (const [rule, count] of Object.entries(rules.details)) {
      markdown += `| ${rule} | ${count} |\n`;
    }
    markdown += "\n";
  }

  markdown += `## 详细发现\n\n`;

  const findings = auditResult.findings || [];
  findings.forEach((finding, index) => {
    markdown += renderFindingMarkdown(finding, index + 1);
  });

  return markdown;
}

function renderFindingMarkdown(finding, index) {
  const severityEmoji = {
    "high": "🔴",
    "medium": "🟠",
    "low": "🟡"
  };
  const emoji = severityEmoji[finding.severity] || "🟢";
  const severityLabel = finding.severityLabel || (finding.severity === "high" ? "严重" : finding.severity === "medium" ? "中危" : "低危");

  let markdown = `### #${index} ${emoji} ${finding.vulnType || "UNKNOWN"}

**来源**: ${finding.source || "quick_scan"}
**严重性**: ${severityLabel}
**文件**: ${finding.file || finding.location}

**漏洞编号**: ${finding.vulnId || `C-VULN-${String(index).padStart(3, "0")}`}

**CVSS 评分**: ${finding.cvssScore || 0.0} (${severityLabel})

**评分明细**: ${finding.cvssBreakdown || "5/5/5"} (原始分: ${finding.cvssOriginalBase || 5.0})

**CWE**: ${finding.cwe || "CWE-000"}

**国标映射**: ${finding.gbtMapping || "GB/T39412-2020 通用基线"}

**语言**: ${finding.language || "unknown"}

**问题代码**:
\`\`\`${finding.language || "java"}
${finding.codeSnippet || "无代码片段"}
\`\`\`

**问题描述**: ${finding.evidence || "发现安全漏洞"}

---

`;
  return markdown;
}

function calculateStatistics(findings) {
  const stats = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    quickScanTotal: 0,
    quickScanCritical: 0,
    quickScanHigh: 0,
    quickScanMedium: 0,
    quickScanLow: 0,
    llmTotal: 0,
    llmCritical: 0,
    llmHigh: 0,
    llmMedium: 0,
    llmLow: 0
  };

  for (const finding of findings) {
    const severity = finding.severity || "medium";
    const severityLabel = finding.severityLabel || "";
    const isQuickScan = finding.source === "quick_scan" || finding.source === "quick-scan";

    if (severity === "high" || severityLabel === "严重") {
      stats.critical++;
      if (isQuickScan) {
        stats.quickScanCritical++;
        stats.quickScanTotal++;
      } else {
        stats.llmCritical++;
        stats.llmTotal++;
      }
    } else if (severity === "high" || severityLabel === "高危") {
      stats.high++;
      if (isQuickScan) {
        stats.quickScanHigh++;
        stats.quickScanTotal++;
      } else {
        stats.llmHigh++;
        stats.llmTotal++;
      }
    } else if (severity === "medium" || severityLabel === "中危") {
      stats.medium++;
      if (isQuickScan) {
        stats.quickScanMedium++;
        stats.quickScanTotal++;
      } else {
        stats.llmMedium++;
        stats.llmTotal++;
      }
    } else {
      stats.low++;
      if (isQuickScan) {
        stats.quickScanLow++;
        stats.quickScanTotal++;
      } else {
        stats.llmLow++;
        stats.llmTotal++;
      }
    }
  }

  return stats;
}

function calculateGbtStatistics(findings) {
  const gbtStats = {};

  for (const finding of findings) {
    const gbtMapping = finding.gbtMapping || "";
    if (!gbtMapping) continue;

    const mappings = gbtMapping.split("；");
    for (const mapping of mappings) {
      const match = mapping.match(/GB\/T(\d+)-([\d.]+)/);
      if (!match) continue;

      const standard = `GB/T ${match[1]}-${match[2].includes(".") ? match[2].split(".")[0] : match[2]}`;
      const rule = mapping.trim();

      if (!gbtStats[standard]) {
        gbtStats[standard] = { total: 0, details: {} };
      }
      gbtStats[standard].total++;
      if (!gbtStats[standard].details[rule]) {
        gbtStats[standard].details[rule] = 0;
      }
      gbtStats[standard].details[rule]++;
    }
  }

  return gbtStats;
}

function detectLanguageFromFindings(findings) {
  const languages = {};
  for (const finding of findings) {
    const lang = finding.language || "unknown";
    languages[lang] = (languages[lang] || 0) + 1;
  }
  const sorted = Object.entries(languages).sort((a, b) => b[1] - a[1]);
  return sorted[0]?.[0] || "Unknown";
}

function getStandardsFromFindings(findings) {
  const standards = new Set();
  for (const finding of findings) {
    const gbtMapping = finding.gbtMapping || "";
    const match = gbtMapping.match(/GB\/T\d+/g);
    if (match) {
      match.forEach(s => standards.add(s));
    }
  }
  return Array.from(standards).join(", ") || "GB/T 39412-2020";
}