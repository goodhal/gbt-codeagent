/**
 * 统一漏洞评分与编号模块
 * 参考: java-audit-skills/skills/java-shared/SEVERITY_RATING.md
 *
 * 评分公式: Score = R × 0.40 + I × 0.35 + C × 0.25
 * CVSS 3.1 映射: CVSS = Score / 3.0 × 10.0
 * 漏洞编号: {C/H/M/L}-{TYPE}-{NNN}
 *
 * 三维: Reachability(可达性) × Impact(影响范围) × Complexity(利用复杂度)
 */

// === 三维评分定义 ===

export const REACHABILITY_LEVELS = {
  3: { label: "高", desc: "无需认证，HTTP直接可达" },
  2: { label: "中", desc: "需要普通用户认证" },
  1: { label: "低", desc: "需要管理员权限或内网访问" },
  0: { label: "无", desc: "代码不可达/死代码" }
};

export const IMPACT_LEVELS = {
  3: { label: "高", desc: "RCE/任意文件写入/完全数据泄露/系统沦陷" },
  2: { label: "中", desc: "敏感数据泄露/越权操作/部分文件读取" },
  1: { label: "低", desc: "有限信息泄露/低影响配置读取" },
  0: { label: "无", desc: "无实际安全影响" }
};

export const COMPLEXITY_LEVELS = {
  3: { label: "低复杂度", desc: "单次请求即可利用，无前置条件" },
  2: { label: "中复杂度", desc: "需要构造特殊payload或多步操作" },
  1: { label: "高复杂度", desc: "需要特定环境/竞态条件/链式利用" },
  0: { label: "不可利用", desc: "有效防护，无法绕过" }
};

// === 严重等级映射 ===

export const SEVERITY_LEVELS = [
  { prefix: "C", label: "Critical", minScore: 2.70, maxScore: 3.00, cvssMin: 9.0, cvssMax: 10.0, icon: "🔴", desc: "可直接导致系统沦陷" },
  { prefix: "H", label: "High",     minScore: 2.10, maxScore: 2.69, cvssMin: 7.0, cvssMax: 8.9,  icon: "🟠", desc: "可造成重大损害" },
  { prefix: "M", label: "Medium",   minScore: 1.20, maxScore: 2.09, cvssMin: 4.0, cvssMax: 6.9,  icon: "🟡", desc: "可造成一定损害" },
  { prefix: "L", label: "Low",      minScore: 0.10, maxScore: 1.19, cvssMin: 0.1, cvssMax: 3.9,  icon: "🔵", desc: "安全加固建议" }
];

// === 漏洞类型代码 ===

export const VULN_TYPE_CODES = {
  "COMMAND_INJECTION": "CMD",
  "SQL_INJECTION": "SQL",
  "SQL_INJECTION_MYBATIS": "SQL",
  "SQL_INJECTION_ORDERBY": "SQL",
  "SQL_INJECTION_GROUPBY": "SQL",
  "SQL_INJECTION_HQL": "SQL",
  "CODE_INJECTION": "CODE",
  "SPEL_INJECTION": "SPEL",
  "SSTI": "SSTI",
  "PATH_TRAVERSAL": "PATH",
  "FILE_UPLOAD": "UPLOAD",
  "FILE_READ": "READ",
  "HARD_CODE_PASSWORD": "PASS",
  "PLAINTEXT_PASSWORD": "PASS",
  "WEAK_CRYPTO": "CRYPTO",
  "WEAK_HASH": "HASH",
  "PREDICTABLE_RANDOM": "RAND",
  "DESERIALIZATION": "DES",
  "SSRF": "SSRF",
  "XXE": "XXE",
  "AUTH_BYPASS": "AUTH",
  "AUTH_BYPASS_URI": "AUTH",
  "AUTH_BYPASS_SUFFIX": "AUTH",
  "AUTH_BYPASS_SPRING": "AUTH",
  "AUTH_CSRF_DISABLED": "CSRF",
  "AUTH_INFO_EXPOSURE": "AUTH",
  "IDOR": "IDOR",
  "INFO_LEAK": "INFO",
  "LOG_INJECTION": "LOG",
  "SESSION_FIXATION": "SESS",
  "COOKIE_MANIPULATION": "COOKIE",
  "XSS": "XSS",
  "XPATH_INJECTION": "XPATH",
  "BUFFER_OVERFLOW": "BUF",
  "FORMAT_STRING": "FMT",
  "INTEGER_OVERFLOW": "INT",
  "PROCESS_CONTROL": "PROC",
  "OPEN_REDIRECT": "REDIR",
  "CORS_MISCONFIGURATION": "CORS",
  "CSRF": "CSRF",
  "RACE_CONDITION": "RACE",
  "UNCONTROLLED_MEMORY": "MEM",
  "IMPROPER_EXCEPTION_HANDLING": "EXC",
  "INFINITE_LOOP": "LOOP",
  "WEAK_PASSWORD_POLICY": "POL",
  "PLAINTEXT_TRANSMISSION": "TRANS",
  "COMPONENT_VULNERABILITY": "CMP",
  "STRUTS_WILDCARD": "CONFIG",
  "AUTH_SERVLETPATH_SAFE": "INFO",
  "UNKNOWN": "VULN"
};

// === 典型漏洞评分参考（来自SEVERITY_RATING.md） ===

export const TYPICAL_SCORES = {
  // SQL注入
  "SQL_INJECTION:3:3:3": { score: 3.00, cvss: 10.0, level: "C", example: "SQL注入+无认证+String拼接" },
  "SQL_INJECTION:3:3:2": { score: 2.75, cvss: 9.2, level: "C", example: "SQL注入+无认证+预编译绕过" },
  "SQL_INJECTION:2:3:2": { score: 2.35, cvss: 7.8, level: "H", example: "SQL注入+需认证+条件利用" },
  "SQL_INJECTION:1:2:1": { score: 1.35, cvss: 4.5, level: "M", example: "ORDER BY注入+环境依赖(Oracle-only)" },
  // XXE
  "XXE:3:3:3": { score: 3.00, cvss: 10.0, level: "C", example: "XXE有回显+无认证" },
  "XXE:2:3:3": { score: 2.60, cvss: 8.7, level: "H", example: "XXE有回显+需认证" },
  "XXE:2:2:2": { score: 2.00, cvss: 6.7, level: "M", example: "XXE无回显+需认证" },
  // 文件上传
  "FILE_UPLOAD:3:3:2": { score: 2.75, cvss: 9.2, level: "C", example: "任意文件上传+无类型校验+Web目录" },
  "FILE_UPLOAD:3:2:2": { score: 2.40, cvss: 8.0, level: "H", example: "文件上传+路径穿越+类型绕过" },
  // 文件读取
  "FILE_READ:3:2:2": { score: 2.40, cvss: 8.0, level: "H", example: "任意文件读取+无路径校验" },
  "FILE_READ:2:2:2": { score: 2.00, cvss: 6.7, level: "M", example: "文件读取+基础路径限制+需认证" },
  // 鉴权绕过
  "AUTH_BYPASS:3:2:2": { score: 2.40, cvss: 8.0, level: "H", example: "鉴权绕过+分号绕过+管理接口" },
  "AUTH_BYPASS:3:3:2": { score: 2.75, cvss: 9.2, level: "C", example: "完全鉴权绕过+Manager接口" },
  // 其他
  "COMMAND_INJECTION:3:3:3": { score: 3.00, cvss: 10.0, level: "C", example: "命令注入+无认证+直接利用" },
  "DESERIALIZATION:3:3:2": { score: 2.75, cvss: 9.2, level: "C", example: "反序列化RCE+Fastjson+无认证" },
  "SSRF:3:2:2": { score: 2.40, cvss: 8.0, level: "H", example: "SSRF+可访问内网+无认证" },
  "COMPONENT_VULNERABILITY:3:3:1": { score: 2.50, cvss: 8.3, level: "H", example: "Log4Shell+无认证+可RCE" }
};

// === 可利用性标注对评级的影响 ===

export const EXPLOITABILITY_IMPACT = {
  "✅ 已确认可利用": { R: 1.0, C: 1.0, desc: "已验证可利用" },
  "⚠️ 待验证":        { R: 1.0, C: 0.67, desc: "未验证，降低复杂度分值" },
  "❌ 不可利用":      { R: 0,   C: 0,   desc: "不可利用" },
  "🔍 环境依赖":      { R: 0.67, C: 0.67, desc: "降低可达性和复杂度" }
};

// === 核心评分函数 ===

export function scoreVulnerability(reachability, impact, complexity, exploitability = null) {
  const R = Number(reachability) || 2;
  const I = Number(impact) || 2;
  const C = Number(complexity) || 2;

  let adjustedR = R;
  let adjustedC = C;

  if (exploitability && EXPLOITABILITY_IMPACT[exploitability]) {
    const factor = EXPLOITABILITY_IMPACT[exploitability];
    adjustedR = R * factor.R;
    adjustedC = C * factor.C;
  }

  const rawScore = adjustedR * 0.40 + adjustedI() + adjustedC * 0.25;
  function adjustedI() { return I * 0.35; }

  const score = Math.round(rawScore * 100) / 100;
  const cvss = Math.round(score / 3.0 * 10.0 * 10) / 10;

  let level = SEVERITY_LEVELS[3]; // Low default
  for (const lvl of SEVERITY_LEVELS) {
    if (score >= lvl.minScore && score <= lvl.maxScore) {
      level = lvl;
      break;
    }
  }

  return {
    score,
    cvss,
    level: level.prefix,
    levelLabel: level.label,
    levelIcon: level.icon,
    levelDesc: level.desc,
    breakdown: `${adjustedR}/${I}/${adjustedC}`,
    rawR: R,
    rawI: I,
    rawC: C,
    adjustedR,
    adjustedI: I,
    adjustedC,
    reachabilityDesc: REACHABILITY_LEVELS[R]?.desc || "未知",
    impactDesc: IMPACT_LEVELS[I]?.desc || "未知",
    complexityDesc: COMPLEXITY_LEVELS[C]?.desc || "未知",
    exploitability: exploitability || null
  };
}

/**
 * 从典型评分表快速评分
 * 如果 vulnType 和 R/I/C 匹配典型值，直接返回预设分数
 */
export function scoreFromReference(vulnType, reachability, impact, complexity) {
  const key = `${vulnType}:${reachability}:${impact}:${complexity}`;
  if (TYPICAL_SCORES[key]) {
    return {
      ...TYPICAL_SCORES[key],
      breakdown: `${reachability}/${impact}/${complexity}`,
      reachabilityDesc: REACHABILITY_LEVELS[reachability]?.desc || "未知",
      impactDesc: IMPACT_LEVELS[impact]?.desc || "未知",
      complexityDesc: COMPLEXITY_LEVELS[complexity]?.desc || "未知"
    };
  }
  return scoreVulnerability(reachability, impact, complexity);
}

// === 统一漏洞编号生成器 ===

export class VulnIdGenerator {
  constructor() {
    this.counter = {};
  }

  /**
   * 生成统一漏洞编号: {C/H/M/L}-{TYPE}-{NNN}
   */
  generate(vulnType, severity) {
    const severityMap = {
      "严重": "C", "critical": "C",
      "高危": "H", "high": "H",
      "中危": "M", "medium": "M",
      "低危": "L", "low": "L"
    };

    const prefix = severityMap[severity] || "L";
    const typeCode = VULN_TYPE_CODES[vulnType] || "VULN";

    if (!this.counter[prefix]) this.counter[prefix] = {};
    if (!this.counter[prefix][typeCode]) this.counter[prefix][typeCode] = 0;
    this.counter[prefix][typeCode]++;

    return `${prefix}-${typeCode}-${String(this.counter[prefix][typeCode]).padStart(3, "0")}`;
  }

  /** 获取当前计数 */
  getCounts() {
    const result = {};
    for (const [prefix, codes] of Object.entries(this.counter)) {
      result[prefix] = {};
      for (const [code, count] of Object.entries(codes)) {
        result[prefix][code] = count;
      }
    }
    return result;
  }

  /** 重置计数器 */
  reset() {
    this.counter = {};
  }

  /** 按等级统计漏洞数量 */
  countByLevel() {
    return {
      C: Object.values(this.counter.C || {}).reduce((a, b) => a + b, 0),
      H: Object.values(this.counter.H || {}).reduce((a, b) => a + b, 0),
      M: Object.values(this.counter.M || {}).reduce((a, b) => a + b, 0),
      L: Object.values(this.counter.L || {}).reduce((a, b) => a + b, 0)
    };
  }
}

// 导出单例
export const vulnIdGenerator = new VulnIdGenerator();

// === 报告统计格式生成（来自 SEVERITY_RATING.md 7.1/7.3） ===

export function generateVulnStatsTable(findings) {
  const counts = { C: 0, H: 0, M: 0, L: 0 };
  for (const f of findings) {
    const id = f.vulnId || "";
    if (id.startsWith("C-")) counts.C++;
    else if (id.startsWith("H-")) counts.H++;
    else if (id.startsWith("M-")) counts.M++;
    else if (id.startsWith("L-")) counts.L++;
  }

  const total = counts.C + counts.H + counts.M + counts.L;
  return {
    counts,
    total,
    markdown: [
      "## 漏洞统计",
      "",
      "| 严重等级 | CVSS | 数量 | 说明 |",
      "|----------|------|------|------|",
      `| 🔴 C (Critical) | 9.0-10.0 | ${counts.C} | 可直接导致系统沦陷 |`,
      `| 🟠 H (High) | 7.0-8.9 | ${counts.H} | 可造成重大损害 |`,
      `| 🟡 M (Medium) | 4.0-6.9 | ${counts.M} | 可造成一定损害 |`,
      `| 🔵 L (Low) | 0.1-3.9 | ${counts.L} | 安全加固建议 |`,
      "",
      "## 审计结论",
      "",
      "| 统计项 | 数量 |",
      "|--------|------|",
      `| 总检测点 | ${total} |`,
      `| 🔴 Critical | ${counts.C} |`,
      `| 🟠 High | ${counts.H} |`,
      `| 🟡 Medium | ${counts.M} |`,
      `| 🔵 Low | ${counts.L} |`
    ].join("\n")
  };
}

/**
 * 从漏洞类型的通用描述生成可达性/影响/复杂度默认值
 */
export function getVulnTypeDefaults(vulnType) {
  const defaults = {
    "COMMAND_INJECTION": { R: 3, I: 3, C: 3 },
    "SQL_INJECTION": { R: 3, I: 3, C: 3 },
    "CODE_INJECTION": { R: 3, I: 3, C: 3 },
    "SPEL_INJECTION": { R: 3, I: 3, C: 3 },
    "SSTI": { R: 3, I: 3, C: 3 },
    "DESERIALIZATION": { R: 3, I: 3, C: 2 },
    "SSRF": { R: 3, I: 2, C: 2 },
    "XXE": { R: 3, I: 3, C: 2 },
    "PATH_TRAVERSAL": { R: 3, I: 2, C: 2 },
    "FILE_UPLOAD": { R: 3, I: 3, C: 2 },
    "FILE_READ": { R: 3, I: 2, C: 2 },
    "AUTH_BYPASS": { R: 3, I: 3, C: 2 },
    "AUTH_BYPASS_URI": { R: 3, I: 3, C: 2 },
    "AUTH_BYPASS_SUFFIX": { R: 3, I: 3, C: 2 },
    "HARD_CODE_PASSWORD": { R: 3, I: 2, C: 3 },
    "XSS": { R: 3, I: 2, C: 2 },
    "IDOR": { R: 3, I: 2, C: 2 },
    "WEAK_CRYPTO": { R: 2, I: 2, C: 1 },
    "WEAK_HASH": { R: 2, I: 2, C: 1 },
    "PREDICTABLE_RANDOM": { R: 2, I: 2, C: 2 },
    "COMPONENT_VULNERABILITY": { R: 3, I: 3, C: 1 },
    "OPEN_REDIRECT": { R: 2, I: 1, C: 3 }
  };
  return defaults[vulnType] || { R: 2, I: 2, C: 2 };
}
