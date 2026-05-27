/**
 * CoverageService — 审计覆盖率追踪 + 增强版 Gapfill
 *
 * 1. 追踪：记录哪些文件被审查、哪些攻击类型被检查
 * 2. 产出：覆盖率报告 — 未审查文件、未检查攻击类型
 * 3. Gapfill：基于覆盖盲区生成定向审查任务
 */

import { promises as fs } from "node:fs";
import path from "path";
import { extractSubsystem } from "../utils/fileUtils.js";

/**
 * 构建覆盖率追踪器
 * @param {string} repoPath - 项目根目录
 * @param {object[]} allFiles - 所有项目文件列表 [{relativePath, fullPath, language}]
 */
export function createCoverageTracker(repoPath, allFiles) {
  const reviewedFiles = new Set();
  const fileAttackClasses = new Map(); // filePath → Set<attackClass>
  // 统一转为仓库相对路径，确保与 markFromFindings 的 location 路径格式匹配
  const toRelative = (p) => {
    if (typeof p === 'object' && p.relativePath) return normalizePath(p.relativePath);
    const str = String(p || '');
    // 如果是绝对路径，截取 repoPath 后的部分
    const absRepo = normalizePath(String(repoPath || ''));
    const absFile = normalizePath(str);
    if (absFile.startsWith(absRepo)) return absFile.slice(absRepo.length).replace(/^\//, '');
    return absFile.split('/').slice(-4).join('/'); // fallback: 最后4级作为唯一标识
  };
  const allFilePaths = new Set(allFiles.map(f => toRelative(f)));

  return {
    /** 标记文件已被审查 */
    markReviewed(filePath, attackClass) {
      const key = normalizePath(filePath);
      reviewedFiles.add(key);
      if (attackClass) {
        if (!fileAttackClasses.has(key)) fileAttackClasses.set(key, new Set());
        fileAttackClasses.get(key).add(attackClass);
      }
    },

    /** 从发现列表批量标记 */
    markFromFindings(findings) {
      for (const f of findings) {
        const file = f.location || f.file || "";
        const vulnClass = f.vulnType || f.vuln_class || "";
        this.markReviewed(file, vulnClass);
      }
    },

    /** 生成覆盖率报告 */
    generateReport() {
      const reviewedCount = reviewedFiles.size;
      const totalFiles = allFilePaths.size;
      const unreviewedFiles = [...allFilePaths].filter(f => !reviewedFiles.has(normalizePath(f)));
      const unreviewedCodeFiles = unreviewedFiles.filter(f => isCodeFile(f));

      // 提取所有已审查的攻击类型
      const allAttackClasses = new Set();
      for (const classes of fileAttackClasses.values()) {
        for (const c of classes) allAttackClasses.add(c);
      }

      // 按子系统分组统计
      const subsystemCoverage = {};
      for (const f of allFilePaths) {
        const sub = extractSubsystem(f);
        if (!subsystemCoverage[sub]) subsystemCoverage[sub] = { total: 0, reviewed: 0 };
        subsystemCoverage[sub].total++;
        if (reviewedFiles.has(normalizePath(f))) subsystemCoverage[sub].reviewed++;
      }

      // 识别未覆盖的高优先级文件
      const highPriorityUnreviewed = unreviewedCodeFiles
        .filter(f => isHighSignalFile(f))
        .slice(0, 20);

      return {
        summary: {
          totalFiles,
          reviewedFiles: reviewedCount,
          unreviewedFiles: unreviewedCodeFiles.length,
          coveragePercent: totalFiles > 0 ? Math.round((reviewedCount / totalFiles) * 100) : 0,
          attackClassesFound: allAttackClasses.size,
        },
        subsystemCoverage,
        unreviewedHighPriority: highPriorityUnreviewed,
        unreviewedAll: unreviewedCodeFiles.slice(0, 50),
        reviewedFiles: [...reviewedFiles],
        fileAttackClasses: Object.fromEntries(
          [...fileAttackClasses].map(([k, v]) => [k, [...v]])
        ),
      };
    },

    /**
     * 获取需要补充审计的高信号文件列表
     * 返回 LLM 审查后仍未覆盖的 T1/T2 文件
     */
    getGapfillTargets(findings = []) {
      this.markFromFindings(findings);
      const report = this.generateReport();
      const allAttackClasses = new Set();
      for (const classes of fileAttackClasses.values()) {
        for (const c of classes) allAttackClasses.add(c);
      }

      // 找出完全没有被 LLM 产出发现的文件
      const allReviewed = new Set();
      for (const f of findings) {
        const loc = f.location || f.file || '';
        const m = loc.match(/^(.+?):/);
        if (m) allReviewed.add(normalizePath(m[1]));
      }

      const unreviewed = [...allFilePaths]
        .filter(f => !allReviewed.has(normalizePath(f)))
        .filter(f => isCodeFile(f));

      // 按 Tier 分类遗漏文件
      const gapByTier = { T1: [], T2: [], T3: [] };
      for (const f of unreviewed) {
        const tier = smartFileFilter.getTier(f);
        if (gapByTier[tier]) gapByTier[tier].push(f);
      }

      return {
        totalUnreviewed: unreviewed.length,
        missedT1: gapByTier.T1,
        missedT2: gapByTier.T2,
        missedT3: gapByTier.T3,
        // 高优先级遗漏（需要立即补充审计的）
        critical: gapByTier.T1.length > 0 ? gapByTier.T1 : gapByTier.T2.slice(0, 10),
        needsGapfill: gapByTier.T1.length > 0 || gapByTier.T2.length > 0,
        summary: gapByTier.T1.length > 0 || gapByTier.T2.length > 0
          ? `${gapByTier.T1.length} 个 Controller/Filter/Interceptor 未被 LLM 覆盖`
          : gapByTier.T2.length > 0
            ? `${gapByTier.T2.length} 个 Service/Util/Config 未被 LLM 覆盖`
            : '所有高优先级文件已覆盖',
      };
    },
  };
}

// smartFileFilter 引用（延迟加载，避免循环依赖）
let _smartFileFilter = null;
function getSmartFileFilter() {
  if (!_smartFileFilter) {
    // 内联 getTier 逻辑避免循环 import
    return {
      getTier(filePath) {
        const basename = (filePath || '').toLowerCase().split('/').pop() || '';
        const dirname = (filePath || '').toLowerCase();
        const T1 = [/controller/i, /filter/i, /interceptor/i, /gateway/i, /securityconfig/i, /webconfig/i, /route/i, /router/i];
        const T2 = [/service/i, /dao/i, /mapper/i, /repository/i, /util/i, /helper/i, /manager/i, /handler/i, /config/i, /properties/i, /business/i, /core/i, /common/i];
        const T3 = [/entity/i, /dto/i, /vo/i, /pojo/i, /model/i, /domain/i, /bean/i, /object/i];
        for (const p of T1) if (p.test(basename) || p.test(dirname)) return 'T1';
        for (const p of T2) if (p.test(basename) || p.test(dirname)) return 'T2';
        for (const p of T3) if (p.test(basename) || p.test(dirname)) return 'T3';
        return 'T2';
      }
    };
  }
  return _smartFileFilter;
}
const smartFileFilter = getSmartFileFilter();

/**
 * 增强版 Gapfill：基于覆盖率数据生成定向审查任务
 * @param {object} llmConfig
 * @param {object} coverageReport - createCoverageTracker.generateReport() 的输出
 * @param {object[]} allFindings - 当前所有发现
 * @param {string} repoPath
 * @param {object} [options]
 */
export async function enhancedGapfill(llmConfig, coverageReport, allFindings, repoPath, options = {}) {
  const { maxNewTasks = 10 } = options;

  if (!llmConfig?.apiKey) {
    return { newTasks: [], gapsIdentified: [] };
  }

  // 本地计算盲区：哪些 subsystem × attack_class 从未被检查
  const blindSpots = computeBlindSpots(coverageReport, allFindings);

  // 本地搜索未审查文件中的潜在 sink —— 路径统一使用 repo-relative 格式
  const localTasks = await localBlindSpotSearch(repoPath, coverageReport.unreviewedHighPriority, blindSpots, maxNewTasks);

  // LLM 补充分析（仅在发现数较多时启用）
  if (blindSpots.length > 0 && localTasks.length < maxNewTasks) {
    try {
      const llmTasks = await llmGapfillTasks(llmConfig, coverageReport, blindSpots, maxNewTasks - localTasks.length);
      const allTasks = [...localTasks, ...llmTasks].slice(0, maxNewTasks);
      console.log(`[Gapfill] 本地发现 ${localTasks.length} 个盲区任务, LLM补充 ${llmTasks.length} 个`);
      return { newTasks: allTasks, gapsIdentified: blindSpots };
    } catch (error) {
      console.warn(`[Gapfill] LLM补充失败: ${error.message}`);
      return { newTasks: localTasks, gapsIdentified: blindSpots };
    }
  }

  console.log(`[Gapfill] 本地发现 ${localTasks.length} 个盲区任务`);
  return { newTasks: localTasks, gapsIdentified: blindSpots };
}

// ========== 内部辅助函数 ==========

function computeBlindSpots(coverageReport, allFindings) {
  const spots = [];
  let reviewedSubsystems = Object.keys(coverageReport.subsystemCoverage);

  // 如果覆盖率追踪未生效（如路径未匹配），从发现中直接提取已覆盖的子系统
  if (reviewedSubsystems.length === 0 || coverageReport.summary.coveragePercent === 0) {
    const foundSubs = new Set();
    for (const f of allFindings) {
      foundSubs.add(extractSubsystem(f.location || f.file || ""));
    }
    reviewedSubsystems = [...foundSubs];
  }

  // 已知的攻击类型清单
  const allAttackClasses = [
    "SQL_INJECTION", "COMMAND_INJECTION", "CODE_INJECTION", "DESERIALIZATION",
    "XSS", "SSRF", "XXE", "PATH_TRAVERSAL", "AUTH_BYPASS", "IDOR",
    "HARDCODED_CREDENTIALS", "WEAK_CRYPTO", "INFO_LEAK", "FILE_UPLOAD",
    "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "SESSION_FIXATION",
    "CORS_MISCONFIG", "OPEN_REDIRECT", "LOG_INJECTION", "REDOS",
  ];

  // 对每个子系统，找从未检查的攻击类型
  for (const sub of reviewedSubsystems) {
    const checkedClasses = new Set();
    for (const f of allFindings) {
      const fSub = extractSubsystem(f.location || f.file || "");
      if (fSub === sub && f.vulnType) {
        checkedClasses.add(f.vulnType);
      }
    }

    for (const ac of allAttackClasses) {
      if (!checkedClasses.has(ac)) {
        spots.push({ subsystem: sub, attackClass: ac, reason: "never_checked" });
      }
    }
  }

  // 对完全未审查的文件找可能适用的攻击类型
  for (const file of (coverageReport.unreviewedHighPriority || []).slice(0, 5)) {
    const sub = extractSubsystem(file);
    const ext = path.extname(file).toLowerCase();
    const relevantClasses = attackClassesForExtension(ext);
    for (const ac of relevantClasses) {
      spots.push({ subsystem: sub, attackClass: ac, targetFile: file, reason: "unreviewed_file" });
    }
  }

  return [...new Map(spots.map(s => `${s.subsystem}|${s.attackClass}`)).keys()]
    .map(k => spots.find(s => `${s.subsystem}|${s.attackClass}` === k))
    .slice(0, 20);
}

async function localBlindSpotSearch(repoPath, unreviewedFiles, blindSpots, maxTasks) {
  const tasks = [];
  const sinkKeywords = {
    SQL_INJECTION: ["executeQuery", "executeUpdate", "createQuery", "Statement", "PreparedStatement", "JdbcTemplate", "query("],
    COMMAND_INJECTION: ["Runtime.getRuntime", "ProcessBuilder", "exec(", "ProcessImpl"],
    DESERIALIZATION: ["readObject", "ObjectInputStream", "Yaml.load", "parseObject", "readValue", "fromJson"],
    PATH_TRAVERSAL: ["FileInputStream", "FileOutputStream", "File(", "Files.read", "Paths.get"],
    SSRF: ["HttpClient", "RestTemplate", "URL.openConnection", "fetch(", "WebClient"],
    SSTI: ["Thymeleaf", "templateEngine", "process(", "FreeMarker", "Velocity"],
    JNDI_INJECTION: ["InitialContext", "lookup(", "JNDI"],
  };

  for (const spot of blindSpots.slice(0, maxTasks)) {
    const keywords = sinkKeywords[spot.attackClass];
    if (!keywords) continue;

    const targetFiles = spot.targetFile
      ? [spot.targetFile]
      : (unreviewedFiles || []).slice(0, 10);

    for (const file of targetFiles) {
      const fullPath = path.join(repoPath, file);
      try {
        const content = await fs.readFile(fullPath, "utf8");
        for (const kw of keywords) {
          if (content.includes(kw)) {
            const lines = content.split("\n");
            const lineIdx = lines.findIndex(l => l.includes(kw));
            tasks.push({
              task_id: `t_gf_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
              source: "gapfill",
              attack_class: spot.attackClass,
              attackClass: spot.attackClass,
              scope_hint: `盲区: ${spot.subsystem} 的 ${spot.attackClass} 从未被审查。发现潜在sink: ${kw}`,
              scopeHint: `盲区: ${spot.subsystem} 的 ${spot.attackClass} 从未被审查。发现潜在sink: ${kw}`,
              target_files: [file],
              targetFiles: [file],
              rationale: `覆盖盲区发现: 文件 ${file}:${lineIdx >= 0 ? lineIdx + 1 : '?'} 含有关键字 "${kw}"，但 ${spot.attackClass} 攻击类型尚未在此子系统中被审查`,
              priority: 2,
            });
            break; // 每个文件每个攻击类型只生成一个任务
          }
        }
      } catch { /* skip */ }
      if (tasks.length >= maxTasks) break;
    }
    if (tasks.length >= maxTasks) break;
  }

  return tasks.slice(0, maxTasks);
}

async function llmGapfillTasks(llmConfig, coverageReport, blindSpots, maxTasks) {
  const SYSTEM_PROMPT = `你是覆盖率分析员。以下是审计覆盖率数据和盲区识别结果。请根据盲区生成精准的审查任务。

# 输出格式
{
  "new_tasks": [
    {"task_id": "t_gf_xxx", "attack_class": "SQL_INJECTION", "target_files": ["path/to/File.java"], "scope_hint": "具体说明查什么", "rationale": "为什么这个盲区值得审查"}
  ]
}

# 约束
- 每个任务一个攻击类型
- target_files 必须是真实可能存在的文件路径（基于子系统路径推断）
- 只生成最多 ${maxTasks} 个任务`;

  const userPrompt = `盲区列表：
${JSON.stringify(blindSpots.slice(0, 15), null, 2)}

覆盖率摘要：
${JSON.stringify(coverageReport.summary, null, 2)}

请生成最多 ${maxTasks} 个定向审查任务。`;

  const responseText = await callLLM(llmConfig, SYSTEM_PROMPT, userPrompt);
  const parsed = parseJsonResponse(responseText);
  return (parsed.new_tasks || []).map(t => ({
    ...t,
    task_id: t.task_id || `t_gf_llm_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    source: "gapfill",
    attackClass: t.attack_class || t.attackClass,
    targetFiles: t.target_files || t.targetFiles || [],
  })).slice(0, maxTasks);
}

// enhancedGapfill / computeBlindSpots / localBlindSpotSearch / llmGapfillTasks 已移除（从未被调用）

// ========== 文件/语言工具 ==========

function normalizePath(p) {
  return (p || "").replaceAll("\\", "/").split(":")[0].trim();
}

function isCodeFile(filePath) {
  const codeExts = [".java", ".py", ".js", ".ts", ".go", ".php", ".rb", ".cs", ".cpp", ".c", ".rs", ".kt", ".swift", ".scala"];
  const ext = path.extname(filePath).toLowerCase();
  return codeExts.includes(ext);
}

function isHighSignalFile(filePath) {
  const lower = filePath.toLowerCase();
  return /(controller|service|dao|repository|handler|route|auth|security|admin|api|endpoint|upload|file|config|util)/.test(lower);
}

function attackClassesForExtension(ext) {
  const map = {
    ".java": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "SSRF", "XXE", "AUTH_BYPASS", "SSTI", "SPEL_INJECTION", "JNDI_INJECTION", "IDOR"],
    ".py": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "PATH_TRAVERSAL", "SSRF", "SSTI", "CODE_INJECTION"],
    ".js": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION", "PROTOTYPE_POLLUTION"],
    ".ts": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION"],
    ".go": ["SQL_INJECTION", "COMMAND_INJECTION", "PATH_TRAVERSAL", "SSRF", "CODE_INJECTION"],
    ".php": ["SQL_INJECTION", "COMMAND_INJECTION", "XSS", "PATH_TRAVERSAL", "FILE_UPLOAD", "DESERIALIZATION"],
    ".cs": ["SQL_INJECTION", "COMMAND_INJECTION", "DESERIALIZATION", "XSS", "AUTH_BYPASS"],
    ".cpp": ["COMMAND_INJECTION", "BUFFER_OVERFLOW", "PATH_TRAVERSAL", "CODE_INJECTION"],
  };
  return map[ext] || ["COMMAND_INJECTION", "SQL_INJECTION", "PATH_TRAVERSAL"];
}
