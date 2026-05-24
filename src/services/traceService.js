/**
 * TraceService — 可达性追踪门禁
 * 参考: E:\code\audit\audit\stages\trace.py
 *
 * 对已确认的漏洞发现进行 LLM 驱动的反向追踪：
 * 从 sink 逐函数向上追踪调用方，直到外部入口点或阻断因素。
 * 无法从入口点到达的发现不应出现在最终报告中。
 */

import { promises as fs } from "node:fs";
import path from "path";
import { callLLM, parseJsonResponse, clampNumber } from "./llmFactory.js";
import {
  TRACE_REACHABILITY_PROMPT,
  TRACE_USER_PROMPT,
} from "../config/llmPrompts.js";

/**
 * @param {object} llmConfig - LLM配置
 * @param {string} repoPath - 项目根目录
 * @param {object[]} findings - 待追踪的发现列表
 * @param {object} [options]
 * @param {number} [options.maxFindings=20] - 最大追踪发现数
 * @param {Function} [options.onProgress] - 进度回调
 * @returns {Promise<object[]>} 附带可达性判定（_traceReachable, _traceCallChain, _traceBlockers）的发现列表
 */
export async function traceReachability(llmConfig, repoPath, findings, options = {}) {
  const { maxFindings = 20, onProgress } = options;

  if (!llmConfig?.apiKey || !findings?.length) {
    return findings.map(f => ({ ...f, _traceStatus: "skipped", _traceReason: "no-llm-or-findings" }));
  }

  // 仅追踪严重性较高的确认发现
  const candidates = findings
    .filter(f => (f.verdict === "confirmed" || f.verdict === undefined) &&
                 (f.severity === "critical" || f.severity === "high" || f.severity === "medium"))
    .slice(0, maxFindings);

  if (candidates.length === 0) {
    console.log("[Trace] 无可追踪候选发现");
    return findings;
  }

  console.log(`[Trace] 开始追踪 ${candidates.length}/${findings.length} 条发现`);

  let completed = 0;
  const results = new Map();

  for (const finding of candidates) {
    try {
      onProgress?.({
        stage: "trace",
        current: completed + 1,
        total: candidates.length,
        findingId: finding.finding_id || finding.title,
        label: `可达性追踪: ${completed + 1}/${candidates.length}`
      });

      const traceResult = await traceOneFinding(llmConfig, repoPath, finding);
      results.set(finding.finding_id || finding.title, traceResult);
      completed++;

      console.log(`[Trace] ${finding.finding_id || finding.title}: reachable=${traceResult.reachable} confidence=${traceResult.confidence}`);
    } catch (error) {
      console.warn(`[Trace] 追踪失败 ${finding.finding_id || finding.title}: ${error.message}`);
      results.set(finding.finding_id || finding.title, {
        reachable: false,
        confidence: 0,
        rationale: `追踪器失败: ${error.message}`,
        callChain: [],
        blockers: [{ kind: "other", location: "tracer", description: "agent 未能生成有效追踪结果" }],
      });
      completed++;
    }
  }

  // 将追踪结果合并回原始发现
  return findings.map(f => {
    const key = f.finding_id || f.title;
    const trace = results.get(key);
    if (!trace) return f;
    return {
      ...f,
      _traceReachable: trace.reachable,
      _traceConfidence: trace.confidence,
      _traceRationale: trace.rationale || "",
      _traceCallChain: trace.callChain || [],
      _traceEntryPoints: trace.entryPoints || [],
      _traceBlockers: trace.blockers || [],
      _traceStatus: "completed",
    };
  });
}

async function traceOneFinding(llmConfig, repoPath, finding) {
  const entryPointsInfo = await collectEntryPoints(repoPath);

  const userPrompt = TRACE_USER_PROMPT
    .replace("{finding_id}", finding.finding_id || finding.title || "unknown")
    .replace(/\{file\}/g, finding.location || finding.file || "unknown")
    .replace("{line_start}", finding.line_start || "0")
    .replace("{line_end}", finding.line_end || "0")
    .replace("{vuln_class}", finding.vulnType || finding.vuln_class || "unknown")
    .replace("{severity}", finding.severity || "unknown")
    .replace("{description}", (finding.description || finding.evidence || "").substring(0, 500))
    .replace("{evidence_snippet}", (finding.evidence || "").substring(0, 2000))
    .replace("{entry_points_info}", entryPointsInfo)
    .replace("{repo_path}", repoPath);

  const systemPrompt = TRACE_REACHABILITY_PROMPT;

  const responseText = await callLLM(llmConfig, systemPrompt, userPrompt);
  const parsed = parseJsonResponse(responseText);

  return {
    reachable: !!parsed.reachable,
    confidence: clampNumber(parsed.confidence, 0, 1),
    rationale: parsed.rationale || "",
    callChain: Array.isArray(parsed.call_chain) ? parsed.call_chain : [],
    entryPoints: Array.isArray(parsed.entry_points) ? parsed.entry_points : [],
    blockers: Array.isArray(parsed.blockers) ? parsed.blockers : [],
    externalInputs: Array.isArray(parsed.external_inputs) ? parsed.external_inputs : [],
  };
}

async function collectEntryPoints(repoPath) {
  try {
    const info = [];
    // 收集常见的入口点文件
    const patterns = [
      { glob: "**/Controller*.java", label: "Java Controller" },
      { glob: "**/*Controller.java", label: "Java Controller" },
      { glob: "**/*Resource.java", label: "Java REST Resource" },
      { glob: "**/routes/**/*.js", label: "JS Route" },
      { glob: "**/routes/**/*.ts", label: "TS Route" },
      { glob: "**/views/**/*.py", label: "Python View" },
      { glob: "**/*.go", label: "Go Handler", filter: (f) => /func\s+\w+\s*\(.*http\./.test(f) },
    ];

    for (const { glob, label } of patterns) {
      // 简单收集：列出匹配的文件路径
      try {
        const files = await collectMatchingFiles(repoPath, glob);
        for (const f of files.slice(0, 10)) {
          const relative = path.relative(repoPath, f).replaceAll("\\", "/");
          info.push(`- ${label}: ${relative}`);
        }
      } catch { /* skip */ }
    }

    if (info.length === 0) {
      info.push("- 未自动检测到入口点。请根据代码结构自行识别HTTP路由、CLI入口、消息处理器等。");
    }

    return info.join("\n");
  } catch {
    return "- 入口点收集失败。请手动搜索路由定义和入口函数。";
  }
}

async function collectMatchingFiles(root, pattern) {
  const results = [];
  // 简化版 glob
  const { globSync } = await import("glob");
  try {
    const matches = globSync(pattern, { cwd: root, absolute: true, nodir: true, ignore: ["node_modules/**", ".git/**", "**/test/**", "**/target/**"] });
    results.push(...matches.slice(0, 10));
  } catch {
    // fallback: manual search
    const ext = path.extname(pattern);
    if (ext) {
      await walkForExt(root, root, ext, results, 10);
    }
  }
  return results;
}

async function walkForExt(root, current, ext, results, max) {
  if (results.length >= max) return;
  try {
    const entries = await fs.readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      if (results.length >= max) return;
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith(".") || entry.name === "node_modules" || entry.name === "test" || entry.name === "target") continue;
        await walkForExt(root, full, ext, results, max);
      } else if (entry.isFile() && full.endsWith(ext)) {
        results.push(full);
      }
    }
  } catch { /* skip */ }
}

