/**
 * GapfillService — 覆盖率驱动的审查循环
 * 参考: E:\code\audit\audit\stages\gapfill.py
 *
 * 分析已完成审查的覆盖率，识别子系统×攻击类别组合中的盲区，
 * 生成新的定向审查任务。
 */

import { callLLM, parseJsonResponse } from "./llmFactory.js";
import { GAPFILL_COVERAGE_PROMPT, GAPFILL_USER_PROMPT } from "../config/llmPrompts.js";

/**
 * @param {object} llmConfig - LLM配置
 * @param {object[]} allFindings - 当前所有发现
 * @param {object[]} completedTasks - 已完成的任务描述 [{ taskId, attackClass, subsystem, findingsCount, gapsObserved }]
 * @param {object} [options]
 * @param {number} [options.maxNewTasks=8] - 最大新任务数
 * @returns {Promise<object>} { newTasks, coverageAnalysis }
 */
export async function analyzeCoverageGap(llmConfig, allFindings, completedTasks, options = {}) {
  const { maxNewTasks = 8 } = options;

  if (!llmConfig?.apiKey || !completedTasks?.length) {
    return { newTasks: [], coverageAnalysis: null };
  }

  console.log(`[Gapfill] 分析 ${completedTasks.length} 个已完成任务的覆盖率`);

  try {
    // 本地构建覆盖率矩阵辅助信息（减少 LLM 工作量）
    const matrix = buildCoverageMatrix(allFindings, completedTasks);
    const findingsDistro = summarizeFindingsDistribution(allFindings);

    const userPrompt = GAPFILL_USER_PROMPT
      .replace("{completed_tasks_json}", JSON.stringify(completedTasks, null, 2))
      .replace("{findings_distribution}", findingsDistro)
      .replace("{max_new_tasks}", String(maxNewTasks));

    const responseText = await callLLM(llmConfig, GAPFILL_COVERAGE_PROMPT, userPrompt);
    const parsed = parseJsonResponse(responseText);

    const newTasks = (parsed.new_tasks || parsed.newTasks || [])
      .map(t => ({
        ...t,
        task_id: t.task_id || `t_gf_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
        source: "gapfill",
      }))
      .slice(0, maxNewTasks);

    console.log(`[Gapfill] 生成了 ${newTasks.length} 个新审查任务`);
    return {
      newTasks,
      coverageAnalysis: {
        matrix,
        gapsIdentified: parsed.coverage_analysis || parsed.missing_areas || [],
        rawResponse: parsed,
      },
    };
  } catch (error) {
    console.warn(`[Gapfill] 覆盖率分析失败: ${error.message}`);
    return { newTasks: [], coverageAnalysis: null };
  }
}

function buildCoverageMatrix(findings, tasks) {
  // 提取子系统和攻击类别
  const subsystems = new Set();
  const attackClasses = new Set();

  for (const f of findings) {
    const sub = extractSubsystem(f) || "unknown";
    subsystems.add(sub);
    attackClasses.add(f.vulnType || f.vuln_class || "unknown");
  }

  for (const t of tasks) {
    subsystems.add(t.subsystem || extractSubsystem(t) || "unknown");
    attackClasses.add(t.attackClass || t.attack_class || "unknown");
  }

  // 计算覆盖状态
  const matrix = [];
  for (const sub of subsystems) {
    for (const ac of attackClasses) {
      const coveredByTask = tasks.some(t =>
        (t.subsystem === sub || extractSubsystem(t) === sub) &&
        (t.attackClass === ac || t.attack_class === ac)
      );
      const hasFindings = findings.some(f =>
        (extractSubsystem(f) === sub) && (f.vulnType === ac || f.vuln_class === ac)
      );

      if (!coveredByTask) {
        matrix.push({ subsystem: sub, attack_class: ac, covered: coveredByTask, found: hasFindings });
      }
    }
  }

  return matrix.slice(0, 30);
}

function extractSubsystem(finding) {
  const loc = finding.location || finding.file || "";
  const parts = loc.replaceAll("\\", "/").split("/");
  // 取前2层目录作为子系统标识
  const meaningful = parts.filter(p => p && !p.includes(".") && !["src", "main", "java", "python", "lib", "app", "api"].includes(p.toLowerCase()));
  return meaningful.slice(0, 2).join("/") || parts[0] || "unknown";
}

function summarizeFindingsDistribution(findings) {
  const distro = {};
  for (const f of findings) {
    const key = `${f.vulnType || "unknown"}|${f.severity || "unknown"}`;
    distro[key] = (distro[key] || 0) + 1;
  }
  const sorted = Object.entries(distro).sort((a, b) => b[1] - a[1]);
  return sorted.map(([k, v]) => `${k}: ${v}`).join("\n");
}

