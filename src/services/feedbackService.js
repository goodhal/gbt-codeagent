/**
 * FeedbackService — 从已确认漏洞发现同类问题
 * 参考: E:\code\audit\audit\stages\feedback.py
 *
 * 从已确认可达的漏洞发现中提取可迁移模式，
 * 在代码库中搜索结构相似的位置，生成新的定向审查任务。
 */

import { promises as fs } from "node:fs";
import path from "path";
import { callLLM, parseJsonResponse } from "./llmFactory.js";
import { FEEDBACK_SIBLING_PROMPT, FEEDBACK_USER_PROMPT } from "../config/llmPrompts.js";

/**
 * @param {object} llmConfig - LLM配置
 * @param {string} repoPath - 项目根目录
 * @param {object[]} reachableFindings - 已确认可达的发现（含 _traceReachable=true 的发现）
 * @param {Set<string> | string[]} completedTaskIds - 已完成任务的ID集合
 * @param {object} [options]
 * @param {number} [options.maxNewTasks=10] - 最大新任务数
 * @param {Function} [options.onProgress] - 进度回调
 * @returns {Promise<object>} { newTasks, patternsExtracted }
 */
export async function discoverSiblingVulnerabilities(llmConfig, repoPath, reachableFindings, completedTaskIds, options = {}) {
  const { maxNewTasks = 10, onProgress } = options;

  if (!llmConfig?.apiKey || !reachableFindings?.length) {
    return { newTasks: [], patternsExtracted: [] };
  }

  console.log(`[Feedback] 从 ${reachableFindings.length} 条可达发现中提取模式`);

  // 本地预提取可迁移模式（减少 LLM 工作量）
  const patterns = extractTransferablePatterns(reachableFindings);

  try {
    onProgress?.({
      stage: "feedback",
      label: `反馈循环: 分析 ${reachableFindings.length} 条可达发现的迁移模式`,
    });

    const completedIds = Array.isArray(completedTaskIds) ? completedTaskIds : Array.from(completedTaskIds || []);

    const userPrompt = FEEDBACK_USER_PROMPT
      .replace("{reachable_findings_json}", JSON.stringify(
        reachableFindings.map(f => ({
          finding_id: f.finding_id || f.title,
          vuln_class: f.vulnType || f.vuln_class,
          file: f.location || f.file,
          severity: f.severity,
          sink_pattern: f._sinkPattern || "unknown",
          reachable: f._traceReachable || false,
          pre_extracted_patterns: patterns.filter(p => p.sourceFindingId === (f.finding_id || f.title)),
        })),
        null, 2
      ))
      .replace("{completed_task_ids}", JSON.stringify(completedIds))
      .replace("{max_new_tasks}", String(maxNewTasks));

    const responseText = await callLLM(llmConfig, FEEDBACK_SIBLING_PROMPT, userPrompt);
    const parsed = parseJsonResponse(responseText);

    const newTasks = (parsed.new_hunt_tasks || parsed.newHuntTasks || [])
      .map(t => ({
        ...t,
        task_id: t.task_id || `t_fb_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
        source: "feedback",
      }));

    // 本地搜索补充：对每个提取的模式，用 grep 找相似调用点
    const localTasks = await localSiblingSearch(repoPath, patterns, reachableFindings, completedIds, maxNewTasks);

    const allTasks = [...localTasks, ...newTasks].slice(0, maxNewTasks);

    console.log(`[Feedback] 生成了 ${allTasks.length} 个同类发现审查任务 (LLM: ${newTasks.length}, 本地: ${localTasks.length})`);
    return {
      newTasks: allTasks,
      patternsExtracted: patterns,
    };
  } catch (error) {
    console.warn(`[Feedback] 同类发现失败: ${error.message}`);

    // 回退：仅使用本地搜索
    const completedIds = Array.isArray(completedTaskIds) ? completedTaskIds : Array.from(completedTaskIds || []);
    const localTasks = await localSiblingSearch(repoPath, patterns, reachableFindings, completedIds, maxNewTasks);
    return { newTasks: localTasks, patternsExtracted: patterns };
  }
}

function extractTransferablePatterns(findings) {
  const patterns = [];

  for (const f of findings) {
    const vulnType = f.vulnType || f.vuln_class || "";
    const evidence = f.evidence || f.description || "";
    const sink = f.sink || "";

    // 提取危险函数名
    const funcPatterns = [
      /(?:execute|exec|query|eval|system|popen|subprocess\.(?:run|call|Popen)|os\.system|shell_exec)\s*\(/gi,
      /(?:\.readFile|\.writeFile|\.open|FileInputStream|FileOutputStream|Files\.(?:read|write|copy|move|delete))\s*\(/gi,
      /(?:statement\.execute|\.executeQuery|\.executeUpdate|\.createQuery|\.createNativeQuery)\s*\(/gi,
      /(?:RestTemplate\.|HttpClient\.|WebClient\.|\.getForObject|\.postForEntity|\.exchange)\s*\(/gi,
      /(?:\.innerHTML|\.outerHTML|dangerouslySetInnerHTML|document\.write)\s*[=(]/gi,
      /(?:parseObject|readObject|readValue|fromJson|unmarshal|Deserializer)\s*\(/gi,
    ];

    for (const fp of funcPatterns) {
      let m;
      fp.lastIndex = 0;
      while ((m = fp.exec(evidence)) !== null) {
        patterns.push({
          sourceFindingId: f.finding_id || f.title,
          sinkFunction: m[0].replace(/[=()<>]/g, "").trim(),
          vulnType,
          sourceFile: f.location || f.file || "",
          severity: f.severity || "",
          approach: "sink-driven",
        });
      }
    }

    // 如果找不到函数名，使用漏洞类型作为模式
    if (patterns.filter(p => p.sourceFindingId === (f.finding_id || f.title)).length === 0) {
      patterns.push({
        sourceFindingId: f.finding_id || f.title,
        vulnType,
        sourceFile: f.location || f.file || "",
        severity: f.severity || "",
        approach: "vuln-class-driven",
      });
    }
  }

  return patterns;
}

async function localSiblingSearch(repoPath, patterns, reachableFindings, completedTaskIds, maxTasks) {
  const tasks = [];
  const seenFiles = new Set(reachableFindings.map(f => f.location || f.file).filter(Boolean));

  // 对每个可迁移的 sink 函数，搜索代码库中其他调用点
  for (const pattern of patterns) {
    if (tasks.length >= maxTasks) break;
    if (!pattern.sinkFunction) continue;

    try {
      const matches = await grepCodebase(repoPath, pattern.sinkFunction);
      for (const match of matches) {
        if (tasks.length >= maxTasks) break;
        const relative = path.relative(repoPath, match.file).replaceAll("\\", "/");

        // 跳过已审查过的文件
        if (seenFiles.has(relative)) continue;
        seenFiles.add(relative);

        tasks.push({
          task_id: `t_fb_local_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
          source: "feedback",
          attack_class: pattern.vulnType,
          attackClass: pattern.vulnType,
          scope_hint: `来自反馈循环：模式 ${pattern.sinkFunction} 与 ${pattern.sourceFindingId} 结构相似`,
          scopeHint: `来自反馈循环：模式 ${pattern.sinkFunction} 与 ${pattern.sourceFindingId} 结构相似`,
          target_files: [relative],
          targetFiles: [relative],
          rationale: `在 ${relative}:${match.line} 发现与已确认漏洞相同的危险函数 ${pattern.sinkFunction}`,
          priority: 2,
        });
      }
    } catch { /* skip */ }
  }

  return tasks;
}

async function grepCodebase(repoPath, pattern) {
  const results = [];
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  await walkAndGrep(repoPath, repoPath, new RegExp(escaped, "i"), results, 15);
  return results;
}

async function walkAndGrep(root, current, regex, results, max) {
  if (results.length >= max) return;
  try {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (results.length >= max) return;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        const skipDirs = [".git", "node_modules", "target", "__pycache__", "test", "spec", ".idea", "build", "dist"];
        if (skipDirs.includes(entry.name) || entry.name.startsWith(".")) continue;
        await walkAndGrep(root, full, regex, results, max);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        const codeExts = [".java", ".py", ".js", ".ts", ".go", ".php", ".rb", ".cs", ".cpp", ".c", ".rs", ".kt", ".swift"];
        if (!codeExts.includes(ext)) continue;
        try {
          const content = await fs.readFile(full, "utf8");
          const lines = content.split("\n");
          for (let i = 0; i < lines.length; i++) {
            if (results.length >= max) break;
            if (regex.test(lines[i]) && !lines[i].trim().startsWith("//") && !lines[i].trim().startsWith("#") && !lines[i].trim().startsWith("*")) {
              const relative = path.relative(root, full).replaceAll("\\", "/");
              results.push({ file: full, relative, line: i + 1, content: lines[i].trim() });
            }
          }
        } catch { /* skip */ }
      }
    }
  } catch { /* skip */ }
}

