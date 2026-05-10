/**
 * 统一审计配置模块
 * 集中管理语言映射、漏洞类型、证据点等配置
 */

/**
 * 文件扩展名到语言的映射
 */
export const FILE_EXTENSION_MAP = {
  '.java': 'java',
  '.py': 'python',
  '.pyw': 'python',
  '.js': 'javascript',
  '.jsx': 'javascript',
  '.mjs': 'javascript',
  '.cjs': 'javascript',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.go': 'go',
  '.cpp': 'cpp',
  '.cc': 'cpp',
  '.cxx': 'cpp',
  '.c': 'cpp',
  '.h': 'cpp',
  '.hpp': 'cpp',
  '.cs': 'csharp',
  '.php': 'php',
  '.phtml': 'php',
  '.php3': 'php',
  '.php4': 'php',
  '.php5': 'php',
  '.rb': 'ruby',
  '.rbw': 'ruby',
  '.rs': 'rust',
  '.kt': 'kotlin',
  '.kts': 'kotlin',
  '.swift': 'swift',
  '.scala': 'scala',
  '.sc': 'scala',
  '.pl': 'perl',
  '.pm': 'perl',
  '.t': 'perl',
  '.lua': 'lua',
  '.sh': 'shell',
  '.bash': 'shell',
  '.zsh': 'shell',
  '.yml': 'yaml',
  '.yaml': 'yaml',
  '.xml': 'xml',
  '.html': 'html',
  '.sql': 'sql'
};

/**
 * 语言到扩展名的映射（反向映射）
 */
export const LANGUAGE_EXTENSIONS = {};
for (const [ext, lang] of Object.entries(FILE_EXTENSION_MAP)) {
  if (!LANGUAGE_EXTENSIONS[lang]) {
    LANGUAGE_EXTENSIONS[lang] = [];
  }
  LANGUAGE_EXTENSIONS[lang].push(ext);
}

/**
 * 语言到 GB/T 标准文件的映射
 */
export const LANGUAGE_GBT_MAP = {
  'java': 'GBT_34944-2017.md',
  'python': 'GBT_39412-2020.md',
  'javascript': 'GBT_39412-2020.md',
  'typescript': 'GBT_39412-2020.md',
  'go': 'GBT_39412-2020.md',
  'ruby': 'GBT_39412-2020.md',
  'rust': 'GBT_39412-2020.md',
  'php': 'GBT_39412-2020.md',
  'cpp': 'GBT_34943-2017.md',
  'c': 'GBT_34943-2017.md',
  'csharp': 'GBT_34946-2017.md',
  'c#': 'GBT_34946-2017.md'
};

/**
 * 语言支持的漏洞类型映射
 */
export const LANGUAGE_VULN_MAP = {
  java: ['COMMAND_INJECTION', 'SQL_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'XSS', 'XXE', 'DESERIALIZATION', 'SSRF', 'AUTH_BYPASS', 'WEAK_CRYPTO'],
  python: ['COMMAND_INJECTION', 'SQL_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'DESERIALIZATION', 'SSRF', 'WEAK_CRYPTO', 'HARD_CODE_PASSWORD'],
  javascript: ['COMMAND_INJECTION', 'SQL_INJECTION', 'XSS', 'SSRF', 'OPEN_REDIRECT', 'CSRF', 'PATH_TRAVERSAL'],
  typescript: ['COMMAND_INJECTION', 'SQL_INJECTION', 'XSS', 'SSRF', 'OPEN_REDIRECT', 'CSRF', 'PATH_TRAVERSAL'],
  go: ['COMMAND_INJECTION', 'SQL_INJECTION', 'PATH_TRAVERSAL', 'SSRF', 'WEAK_CRYPTO'],
  cpp: ['COMMAND_INJECTION', 'SQL_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'BUFFER_OVERFLOW', 'FORMAT_STRING', 'INTEGER_OVERFLOW'],
  csharp: ['COMMAND_INJECTION', 'SQL_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'DESERIALIZATION', 'XSS', 'SSRF'],
  php: ['COMMAND_INJECTION', 'SQL_INJECTION', 'XSS', 'PATH_TRAVERSAL', 'SSRF', 'CODE_INJECTION'],
  ruby: ['COMMAND_INJECTION', 'SQL_INJECTION', 'CODE_INJECTION', 'PATH_TRAVERSAL', 'SSRF'],
  rust: ['COMMAND_INJECTION', 'SQL_INJECTION', 'PATH_TRAVERSAL', 'SSRF']
};

/**
 * 漏洞类型编码映射（用于生成漏洞ID）
 */
export const VULN_TYPE_CODES = {
  SQL_INJECTION: "SQL", SQLI: "SQL", SQL: "SQL",
  COMMAND_INJECTION: "CMD", CMD_INJECTION: "CMD", CMD: "CMD",
  CODE_INJECTION: "CODE", CODE: "CODE",
  PATH_TRAVERSAL: "FILE", PATH_TRAV: "FILE", FILE: "FILE",
  FILE_READ: "READ", FILE_WRITE: "WRITE", UPLOAD: "UPLOAD",
  XSS: "XSS", STORED_XSS: "XSS", REFLECTED_XSS: "XSS",
  SSRF: "SSRF", CSRF: "CSRF",
  XXE: "XXE", DESERIALIZATION: "DESER", DESER: "DESER",
  AUTH_BYPASS: "AUTH", IDOR: "IDOR", AUTH: "AUTH",
  OPEN_REDIRECT: "REDIR", REDIR: "REDIR",
  CRLF_INJECTION: "CRLF", CRLF: "CRLF",
  WEAK_CRYPTO: "CRYPTO", WEAK_HASH: "CRYPTO",
  SESSION_FIXATION: "SESS", SESS: "SESS",
  HARD_CODE_PASSWORD: "SECRET", SECRET: "SECRET",
  LOGIC_FLAW: "LOGIC", LOGIC: "LOGIC",
  NOSQL_INJECTION: "NOSQL", NOSQL: "NOSQL"
};

/**
 * 漏洞类型到沙箱类型的映射
 */
export const VULN_TYPE_TO_SANDBOX = {
  'COMMAND_INJECTION': 'COMMAND_INJECTION',
  'CODE_INJECTION': 'COMMAND_INJECTION',
  'SQL_INJECTION': 'SQL_INJECTION',
  'PATH_TRAVERSAL': 'PATH_TRAVERSAL',
  'PATH_TRAV': 'PATH_TRAVERSAL'
};

/**
 * 严重程度前缀映射
 */
export const SEVERITY_PREFIX = {
  critical: "C", 严重: "C",
  high: "H", 高危: "H",
  medium: "M", 中危: "M",
  low: "L", 低危: "L"
};

/**
 * 严重程度排序优先级
 */
export const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };

/**
 * 漏洞类型到 CWE 的映射
 */
export const VULN_CWE_MAP = {
  COMMAND_INJECTION: "CWE-78",
  CODE_INJECTION: "CWE-94",
  SQL_INJECTION: "CWE-89",
  NOSQL_INJECTION: "CWE-89",
  XPATH_INJECTION: "CWE-643",
  PATH_TRAVERSAL: "CWE-22",
  XSS: "CWE-79",
  SSRF: "CWE-918",
  CSRF: "CWE-352",
  XXE: "CWE-611",
  DESERIALIZATION: "CWE-502",
  AUTH_BYPASS: "CWE-287",
  IDOR: "CWE-639",
  OPEN_REDIRECT: "CWE-601",
  HARD_CODE_PASSWORD: "CWE-259",
  PLAINTEXT_PASSWORD: "CWE-256",
  WEAK_CRYPTO: "CWE-327",
  WEAK_HASH: "CWE-328",
  PREDICTABLE_RANDOM: "CWE-338",
  WEAK_RANDOM: "CWE-338",
  BUFFER_OVERFLOW: "CWE-120",
  FORMAT_STRING: "CWE-134",
  INTEGER_OVERFLOW: "CWE-190",
  PROCESS_CONTROL: "CWE-114",
  SESSION_FIXATION: "CWE-384",
  COOKIE_MANIPULATION: "CWE-565",
  REFERER_AUTH_BYPASS: "CWE-293",
  AUTH_INFO_EXPOSURE: "CWE-204",
  UNCINTROLLED_MEMORY: "CWE-770",
  IMPROPER_EXCEPTION_HANDLING: "CWE-703",
  WEAK_PASSWORD_POLICY: "CWE-521",
  PLAINTEXT_TRANSMISSION: "CWE-319",
  CORS_MISCONFIGURATION: "CWE-942",
  LOG_INJECTION: "CWE-93",
  SPEL_INJECTION: "CWE-94",
  SSTI: "CWE-94",
  RACE_CONDITION: "CWE-362",
  INFINITE_LOOP: "CWE-835"
};

/**
 * 标准证据点定义
 */
export const EVIDENCE_POINTS = {
  CMD: ["EVID_CMD_EXEC_POINT", "EVID_CMD_COMMAND_STRING_CONSTRUCTION", "EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT"],
  SQL: ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION", "EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT"],
  NOSQL: ["EVID_NOSQL_QUERY_CONSTRUCTION", "EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE", "EVID_NOSQL_OPERATOR_INJECTION_FIELDS"],
  LDAP: ["EVID_LDAP_EXEC_POINT", "EVID_LDAP_FILTER_STRING_CONSTRUCTION", "EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT"],
  EXPR: ["EVID_EXPR_EVAL_ENTRY", "EVID_EXPR_EXPR_CONTROL", "EVID_EXPR_EXEC_CHAIN_ENTRY"],
  FILE: ["EVID_FILE_WRAPPER_PREFIX", "EVID_FILE_RESOLVED_TARGET", "EVID_FILE_INCLUDE_REQUIRE_EXEC_BOUNDARY"],
  WRITE: ["EVID_WRITE_WRITE_CALLSITE", "EVID_WRITE_DESTPATH_JOIN_AND_NORMALIZATION", "EVID_WRITE_DESTPATH_RESOLVED_TARGET", "EVID_WRITE_CONTENT_SOURCE_INTO_WRITE", "EVID_WRITE_TRUNCATE_OR_OVERWRITE_MODE", "EVID_WRITE_EXECUTION_ACCESSIBILITY_PROOF"],
  UPLOAD: ["EVID_UPLOAD_DESTPATH", "EVID_UPLOAD_FILENAME_EXTENSION_PARSING_SANITIZE", "EVID_UPLOAD_ACCESSIBILITY_PROOF", "EVID_UPLOAD_EXEC_DISABLE_STRATEGY"],
  ARCHIVE: ["EVID_ARCHIVE_EXTRACT_CALLSITE", "EVID_ARCHIVE_ENTRY_NAME_SOURCE", "EVID_ARCHIVE_ENTRY_SANITIZATION", "EVID_ARCHIVE_EXTRACT_BASE_DIR", "EVID_ARCHIVE_FINAL_TARGET"],
  SSRF: ["EVID_SSRF_URL_NORMALIZATION", "EVID_SSRF_FINAL_URL_HOST_PORT", "EVID_SSRF_FINAL_REDIRECT_URL", "EVID_SSRF_DNSIP_AND_INNER_BLOCK"],
  XSS: ["EVID_XSS_OUTPUT_POINT", "EVID_XSS_USER_INPUT_INTO_OUTPUT", "EVID_XSS_ESCAPE_OR_RAW_CONTROL"],
  REDIR: ["EVID_REDIR_OUTPUT_POINT", "EVID_REDIR_DEST_SOURCE_MAPPING", "EVID_REDIR_DEST_VALIDATION_NORMALIZATION"],
  CRLF: ["EVID_CRLF_OUTPUT_POINT", "EVID_CRLF_USER_INPUT_INTO_HEADER_COOKIE", "EVID_CRLF_CONTROL_CHAR_FILTERING_ENCODING"],
  XXE: ["EVID_XXE_PARSER_CALL", "EVID_XXE_INPUT_SOURCE", "EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO"],
  DESER: ["EVID_DESER_CALLSITE", "EVID_DESER_INPUT_SOURCE", "EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN"],
  TPL: ["EVID_TPL_ENGINE_RENDER_OR_PARSE_ENTRY", "EVID_TPL_TEMPLATE_OR_EXPR_CONTROL", "EVID_TPL_EXEC_CHAIN_ENTRY"],
  AUTH: ["EVID_AUTH_PATH_PROTECTED_MATCH", "EVID_AUTH_TOKEN_DECODE_JUDGMENT", "EVID_AUTH_PERMISSION_CHECK_EXEC", "EVID_AUTH_IDOR_OWNERSHIP_CONDITION"],
  CSRF: ["EVID_CSRF_STATE_CHANGE_HANDLER_EXEC", "EVID_CSRF_TOKEN_SOURCE", "EVID_CSRF_TOKEN_RECEIVE", "EVID_CSRF_TOKEN_VERIFY", "EVID_CSRF_BYPASS_BRANCH"],
  SESS: ["EVID_SESS_SESSION_INIT_REGEN", "EVID_SESS_COOKIE_FLAGS", "EVID_SESS_JWT_VERIFY_CLAIMS", "EVID_SESS_LOGOUT_CLEAR"],
  CFG: ["EVID_CFG_CONFIG_LOCATION", "EVID_CFG_RUNTIME_SETTING_CODE", "EVID_CFG_IMPACT_ASSOCIATION", "EVID_CFG_SECURITY_SWITCH_EVIDENCE"]
};

/**
 * GB/T 标准定义
 */
export const GBT_STANDARDS = {
  "GB/T34943-2017": "C/C++ 语言源代码漏洞测试规范",
  "GB/T34944-2017": "Java 语言源代码漏洞测试规范",
  "GB/T34946-2017": "C# 语言源代码漏洞测试规范",
  "GB/T39412-2020": "网络安全技术 源代码漏洞检测规则"
};

/**
 * 漏洞类型到 GB/T 条款的映射
 */
export const VULN_GBT_MAP = {
  COMMAND_INJECTION: "GB/T34944-6.1.1.6",
  SQL_INJECTION: "GB/T34944-6.1.2.1",
  CODE_INJECTION: "GB/T34944-6.1.1.7",
  PATH_TRAVERSAL: "GB/T34944-6.2.1.3",
  HARD_CODE_PASSWORD: "GB/T34944-6.3.2.1",
  WEAK_CRYPTO: "GB/T34944-6.3.3.1",
  WEAK_HASH: "GB/T34944-6.3.3.1",
  DESERIALIZATION: "GB/T34944-6.1.3.2",
  SSRF: "GB/T39412-6.4",
  XXE: "GB/T39412-6.5",
  AUTH_BYPASS: "GB/T34944-6.3.1.2",
  XSS: "GB/T39412-6.3",
  CSRF: "GB/T39412-6.2",
  BUFFER_OVERFLOW: "GB/T34943-5.1",
  FORMAT_STRING: "GB/T34943-5.2",
  INTEGER_OVERFLOW: "GB/T34943-5.3"
};

/**
 * DKTSS 基础评分表
 */
export const DKTSS_BASE_SCORES = {
  'COMMAND_INJECTION': 10, 'CODE_INJECTION': 10, 'DESERIALIZATION': 10,
  'SQL_INJECTION': { 'write': 8, 'read': 6, 'default': 7 },
  'SSRF': { 'internal': 7, 'http_only': 4, 'default': 5 },
  'AUTH_BYPASS': 8, 'IDOR': 7,
  'XSS': { 'stored': 6, 'reflected': 5, 'default': 5 },
  'XXE': 6, 'PATH_TRAVERSAL': 6, 'FILE_UPLOAD': 6,
  'WEAK_CRYPTO': 5, 'WEAK_HASH': 4,
  'HARD_CODE_PASSWORD': 7, 'LOG_INJECTION': 4,
  'default': 5
};

/**
 * DKTSS 摩擦系数
 */
export const DKTSS_FRICTION = {
  accessPath: { internet: 0, intranet: -2, physical: -4 },
  authRequired: { none: 0, lowPrivilege: -1, highPrivilege: -3 },
  interaction: { none: 0, weak: -1, strong: -3 }
};

/**
 * DKTSS 武器化程度
 */
export const DKTSS_WEAPON = {
  matureExp: 1,
  pocOnly: 0,
  theoretical: -2
};

/**
 * 验证裁定结果
 */
export const VERDICT = {
  CONFIRMED: 'confirmed',
  FALSE_POSITIVE: 'false_positive',
  DOWNGRADED: 'downgraded',
  NEEDS_REVIEW: 'needs_review',
  HYPOTHESIS: 'hypothesis'
};

/**
 * 净化函数模式
 */
export const SANITIZER_PATTERNS = {
  sql: [
    /PreparedStatement/,
    /prepareStatement/,
    /JdbcTemplate\./,
    /@Param/,
    /namedParameter/,
    /queryForObject/,
    /queryForList/
  ],
  xss: [
    /HtmlUtils\.escape/,
    /StringEscapeUtils\.escapeHtml/,
    /ESAPI\.encoder\./,
    /encodeForHTML/,
    /sanitize/,
    /cleanInput/
  ],
  cmd: [
    /ProcessBuilder/,
    /Runtime\.getRuntime\(\)\.exec/,
    /sanitizeCommand/,
    /validateCommand/
  ],
  path: [
    /Path\.normalize/,
    /File\.getCanonicalPath/,
    /sanitizePath/,
    /validatePath/,
    /PathMatcher/
  ],
  general: [
    /Integer\.parseInt/,
    /Long\.parseLong/,
    /Double\.parseDouble/,
    /parseInt/,
    /parseLong/,
    /UUID\.fromString/,
    /Pattern\.matches/,
    /validateInput/,
    /checkArgument/
  ]
};

/**
 * 抑制规则模式
 */
export const SUPPRESSION_PATTERNS = [
  /gbt:\s*disable\s+([\w\-]+)/i,
  /gbt-disable:\s*([\w\-]+)/i,
  /gbt:\s*ignore\s+([\w\-]+)/i,
  /ignore:\s*([\w\-]+)/i,
  /eslint-disable-next-line\s+([\w\-]+)/i,
  /eslint-disable-line\s+([\w\-]+)/i,
  /tslint:disable-next-line\s+([\w\-]+)/i,
  /tslint:disable\s+([\w\-]+)/i,
  /pylint:\s*disable\s*=\s*([\w\-]+)/i,
  /noinspection\s+([\w\-]+)/i
];

/**
 * 注释模式
 */
export const COMMENT_PATTERNS = {
  singleLine: {
    '//': /^(\/\/)(.*)$/,
    '#': /^(\#)(.*)$/,
    ';': /^(\;)(.*)$/
  },
  multiLine: {
    '/* */': {
      start: /\/\*/,
      end: /\*\//
    },
    '<!-- -->': {
      start: /<!--/,
      end: /-->/
    }
  }
};

/**
 * 根据文件路径检测语言
 */
export function detectLanguage(filePath) {
  const path = require('path');
  const ext = path.extname(filePath).toLowerCase();
  return FILE_EXTENSION_MAP[ext] || null;
}

/**
 * 判断漏洞类型是否与语言匹配
 */
export function isVulnerabilitySupported(vulnType, language) {
  if (!vulnType || !language) return true;
  
  const supportedVulns = LANGUAGE_VULN_MAP[language];
  if (!supportedVulns) return true;
  
  const upperVulnType = vulnType.toUpperCase();
  return supportedVulns.some(v => v === upperVulnType || upperVulnType.includes(v));
}

/**
 * 获取漏洞类型编码
 */
export function getVulnTypeCode(vulnType) {
  if (!vulnType) return "LOGIC";
  const upper = vulnType.toUpperCase();
  for (const [key, code] of Object.entries(VULN_TYPE_CODES)) {
    if (upper === key.toUpperCase() || upper.includes(key.toUpperCase())) {
      return code;
    }
  }
  return "LOGIC";
}

/**
 * 获取严重程度前缀
 */
export function getSeverityPrefix(severity) {
  return SEVERITY_PREFIX[severity?.toLowerCase()] || SEVERITY_PREFIX[severity] || "L";
}

/**
 * 生成漏洞唯一编号
 */
export function generateVulnId(finding, existingFindings = []) {
  const severity = getSeverityPrefix(finding.severity);
  const typeCode = getVulnTypeCode(finding.type);
  const count = existingFindings.filter(f =>
    getSeverityPrefix(f.severity) === severity &&
    getVulnTypeCode(f.type) === typeCode
  ).length + 1;
  return `${severity}-${typeCode}-${count.toString().padStart(3, '0')}`;
}

/**
 * 计算 DKTSS 评分
 */
export function calculateDKTSS(finding) {
  const vulnType = finding.type || finding.vulnType || '';
  let baseScore = DKTSS_BASE_SCORES[vulnType] || DKTSS_BASE_SCORES.default;

  if (typeof baseScore === 'object') {
    const detail = finding.detail || '';
    if (detail.includes('脱库') || detail.includes('写文件')) baseScore = baseScore.write;
    else if (detail.includes('读') || detail.includes('limited')) baseScore = baseScore.read;
    else if (vulnType === 'SSRF') baseScore = baseScore.internal;
    else baseScore = baseScore.default;
  }

  const accessPath = finding.accessPath || 'internet';
  const authLevel = finding.authRequired || 'none';
  const interaction = finding.interaction || 'none';
  const friction = (DKTSS_FRICTION.accessPath[accessPath] || 0)
    + (DKTSS_FRICTION.authRequired[authLevel] || 0)
    + (DKTSS_FRICTION.interaction[interaction] || 0);

  const weapon = DKTSS_WEAPON[finding.weaponLevel || 'pocOnly'] || 0;
  const ver = finding.versionPatched ? 0 : 0;

  const finalScore = Math.max(0, Math.min(10, baseScore - friction + weapon + ver));
  return Math.round(finalScore * 10) / 10;
}

/**
 * 获取 DKTSS 严重程度
 */
export function getDktssSeverity(dktssScore) {
  if (dktssScore >= 7) return 'critical';
  if (dktssScore >= 5) return 'high';
  if (dktssScore >= 3) return 'medium';
  return 'low';
}

/**
 * Java 组件版本漏洞检测规则
 * 整合自 java-audit-skills 工程
 */
export const COMPONENT_VULN_RULES = {
  critical: [
    // ==================== Log4j 漏洞 ====================
    {
      name: "Log4j2 RCE漏洞 (CVE-2021-44228)",
      function: "log4j-core:2.0-2.14.1",
      description: "Log4j2 远程代码执行漏洞（Log4Shell），影响版本 2.0-2.14.1，建议升级到 2.17.1+",
      pattern: /log4j-core["']?\s*[:_-]\s*["']?2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\./
    },
    {
      name: "Log4j 1.x SocketServer 反序列化漏洞 (CVE-2019-17571)",
      function: "log4j:1.2.0-1.2.17",
      description: "Log4j 1.x SocketServer 反序列化 RCE 漏洞，影响所有 1.2.x 版本，Log4j 1.x 已 EOL，建议迁移到 Log4j 2.17.1+",
      pattern: /log4j["']?\s*[:_-]\s*["']?1\.2\./
    },
    {
      name: "Log4j2 RCE漏洞 (CVE-2021-45046)",
      function: "log4j-core:2.15.0",
      description: "Log4j2 远程代码执行漏洞，影响版本 2.15.0，建议升级到 2.17.1+",
      pattern: /log4j-core["']?\s*[:_-]\s*["']?2\.15\.0/
    },
    // ==================== Fastjson 漏洞 ====================
    {
      name: "Fastjson 反序列化漏洞 (CVE-2022-25845)",
      function: "fastjson:1.2.0-1.2.80",
      description: "Fastjson 反序列化远程代码执行漏洞，影响版本 ≤1.2.80，建议升级到 1.2.83+ 或使用 Fastjson2",
      pattern: /fastjson["']?\s*[:_-]\s*["']?1\.2\.([0-7][0-9]|80)["']?/
    },
    // ==================== Spring Framework 漏洞 ====================
    {
      name: "Spring Framework RCE漏洞 (CVE-2022-22965 Spring4Shell)",
      function: "spring-beans:5.3.0-5.3.17 或 5.2.0-5.2.19",
      description: "Spring Framework 远程代码执行漏洞（Spring4Shell），影响 5.3.0-5.3.17 和 5.2.0-5.2.19，建议升级到 5.3.18+ 或 5.2.20+",
      pattern: /spring-(beans|core|context|web)["']?\s*[:_-]\s*["']?5\.(3\.(0|1|2|3|4|5|6|7|8|9|1[0-7])|2\.(0|1|2|3|4|5|6|7|8|9|1[0-9]))/
    },
    // ==================== Struts2 漏洞 ====================
    {
      name: "Struts2 RCE漏洞 (S2-061 CVE-2020-17530)",
      function: "struts2-core:2.0.0-2.5.25",
      description: "Struts2 OGNL表达式注入漏洞，影响版本 ≤2.5.25，建议升级到 2.5.26+",
      pattern: /struts2-core["']?\s*[:_-]\s*["']?2\.[0-5]\.(0|1|2|3|4|5|6|7|8|9|1[0-9]|2[0-5])["']?/
    },
    // ==================== Jackson 漏洞 ====================
    {
      name: "Jackson 反序列化漏洞 (CVE-2020-36518)",
      function: "jackson-databind:2.0.0-2.12.6.1",
      description: "Jackson 反序列化漏洞，影响版本 ≤2.12.6.1，建议升级到 2.12.7+ 或 2.13.3+",
      pattern: /jackson-databind["']?\s*[:_-]\s*["']?2\.(0|1|2|3|4|5|6|7|8|9|10|11|12)\./
    },
    // ==================== Apache Commons 漏洞 ====================
    {
      name: "Commons Collections 反序列化漏洞",
      function: "commons-collections:3.0-3.2.1",
      description: "Apache Commons Collections 反序列化漏洞，影响版本 3.0-3.2.1，建议升级到 3.2.2+ 或使用 4.x",
      pattern: /commons-collections["']?\s*[:_-]\s*["']?3\.(0|1|2\.[01])["']?/
    },
    // ==================== Shiro 漏洞 ====================
    {
      name: "Apache Shiro 认证绕过漏洞 (CVE-2020-13933)",
      function: "shiro-core:1.0.0-1.5.3",
      description: "Apache Shiro 认证绕过漏洞，影响版本 ≤1.5.3，建议升级到 1.7.1+",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-5]\./
    },
    {
      name: "Apache Shiro 反序列化漏洞 (CVE-2016-4437 SHIRO-550)",
      function: "shiro-core:1.0.0-1.2.4",
      description: "Apache Shiro RememberMe 反序列化漏洞（SHIRO-550），影响版本 ≤1.2.4，建议升级到 1.7.1+",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-2]\./
    }
  ],
  high: [
    // ==================== Spring Boot 漏洞 ====================
    {
      name: "Spring Boot Actuator 未授权访问",
      function: "spring-boot-starter-actuator:1.x",
      description: "Spring Boot 1.x Actuator 默认未授权访问，建议升级到 2.x 并配置安全策略",
      pattern: /spring-boot-starter-actuator["']?\s*[:_-]\s*["']?1\./
    },
    {
      name: "Spring Boot RCE漏洞 (CVE-2022-22963)",
      function: "spring-cloud-function-context:3.0.0-3.2.2",
      description: "Spring Cloud Function SpEL 表达式注入漏洞，影响版本 3.0.0-3.2.2，建议升级到 3.2.3+",
      pattern: /spring-cloud-function-context["']?\s*[:_-]\s*["']?3\.[0-2]\./
    },
    // ==================== XStream 漏洞 ====================
    {
      name: "XStream 反序列化漏洞 (CVE-2021-39139)",
      function: "xstream:1.0.0-1.4.17",
      description: "XStream 反序列化远程代码执行漏洞，影响版本 ≤1.4.17，建议升级到 1.4.18+",
      pattern: /xstream["']?[-_:]\s*["']?1\.[0-4]\.([0-9]|1[0-7])["']?/
    },
    {
      name: "XStream 反序列化漏洞 (CVE-2022-40151)",
      function: "xstream:1.0.0-1.4.19",
      description: "XStream 反序列化栈溢出漏洞，影响版本 ≤1.4.19，建议升级到 1.4.20+",
      pattern: /xstream["']?[-_:]\s*["']?1\.[0-4]\.([0-9]|1[0-9])["']?/
    },
    // ==================== SnakeYAML 漏洞 ====================
    {
      name: "SnakeYAML 反序列化漏洞 (CVE-2022-1471)",
      function: "snakeyaml:1.0-1.32",
      description: "SnakeYAML 反序列化远程代码执行漏洞，影响版本 ≤1.32，建议升级到 2.0+",
      pattern: /snakeyaml["']?\s*[:_-]\s*["']?1\.(0|[1-2][0-9]|3[0-2])["']?/
    },
    // ==================== Apache Commons Text 漏洞 ====================
    {
      name: "Apache Commons Text RCE漏洞 (CVE-2022-42889 Text4Shell)",
      function: "commons-text:1.5-1.9",
      description: "Apache Commons Text 远程代码执行漏洞（Text4Shell），影响版本 1.5-1.9，建议升级到 1.10.0+",
      pattern: /commons-text["']?\s*[:_-]\s*["']?1\.[5-9]["']?/
    },
    // ==================== Apache ActiveMQ 漏洞 ====================
    {
      name: "Apache ActiveMQ 反序列化漏洞 (CVE-2023-46604)",
      function: "activemq-client:5.0.0-5.18.2",
      description: "Apache ActiveMQ OpenWire 协议反序列化远程代码执行漏洞，影响版本 ≤5.18.2，建议升级到 5.18.3+",
      pattern: /activemq-client["']?\s*[:_-]\s*["']?5\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18)\./
    },
    {
      name: "Apache ActiveMQ 未授权访问漏洞 (CVE-2024-32114)",
      function: "activemq-all:6.0.0-6.0.1",
      description: "Apache ActiveMQ Jolokia 和 REST API 未授权访问漏洞，影响版本 6.0.0-6.0.1，建议升级到 6.1.0+",
      pattern: /activemq-all["']?\s*[:_-]\s*["']?6\.0\.[0-1]["']?/
    },
    // ==================== Apache RocketMQ 漏洞 ====================
    {
      name: "Apache RocketMQ RCE漏洞 (CVE-2023-33246)",
      function: "rocketmq-client:4.0.0-5.1.0",
      description: "Apache RocketMQ 远程命令执行漏洞 (CVSS 9.8)，5.x 影响 ≤5.1.0，4.x 影响 ≤4.9.5，建议升级到 5.1.1+ 或 4.9.6+",
      pattern: /rocketmq-client["']?\s*[:_-]\s*["']?(5\.[0-1]\.|4\.[0-9]\.)["']?/
    },
    // ==================== Nacos 漏洞 ====================
    {
      name: "Nacos 认证绕过漏洞 (CVE-2021-29441)",
      function: "nacos-client:1.0.0-1.4.0",
      description: "Nacos AuthFilter 认证绕过漏洞，攻击者可伪造 User-Agent 绕过认证，影响 <1.4.1，建议升级到 1.4.1+",
      pattern: /nacos-client["']?\s*[:_-]\s*["']?1\.[0-3]\./
    },
    // ==================== Logback 漏洞 ====================
    {
      name: "Logback 反序列化漏洞 (CVE-2023-6378)",
      function: "logback-core:1.3.0-1.3.13 或 1.4.0-1.4.13",
      description: "Logback 反序列化拒绝服务漏洞，影响版本 1.3.0-1.3.13 和 1.4.0-1.4.13，建议升级到 1.3.14+ 或 1.4.14+",
      pattern: /logback-core["']?\s*[:_-]\s*["']?1\.(3\.(0|1|2|3|4|5|6|7|8|9|1[0-3])|4\.(0|1|2|3|4|5|6|7|8|9|1[0-3]))/
    },
    // ==================== Apache CXF 漏洞 ====================
    {
      name: "Apache CXF SSRF漏洞 (CVE-2024-28752)",
      function: "cxf-core:3.0.0-3.6.3 或 4.0.0-4.0.4",
      description: "Apache CXF SSRF 漏洞，影响版本 3.0.0-3.6.3 和 4.0.0-4.0.4，建议升级到 3.6.4+ 或 4.0.5+",
      pattern: /cxf-core["']?\s*[:_-]\s*["']?(3\.[0-6]\.[0-3]|4\.0\.[0-4])["']?/
    }
  ],
  medium: [
    // ==================== Guava 漏洞 ====================
    {
      name: "Guava 临时目录劫持漏洞 (CVE-2020-8908)",
      function: "guava:10.0-29.0",
      description: "Guava 临时目录劫持漏洞，影响版本 10.0-29.0，建议升级到 30.0+",
      pattern: /guava["']?\s*[:_-]\s*["']?(1[0-9]|2[0-9])\./
    },
    // ==================== Gson 漏洞 ====================
    {
      name: "Gson 反序列化漏洞 (CVE-2022-25647)",
      function: "gson:2.0.0-2.8.8",
      description: "Gson 反序列化不可信数据漏洞，影响版本 ≤2.8.8，建议升级到 2.8.9+",
      pattern: /gson["']?\s*[:_-]\s*["']?2\.[0-8]\.[0-8]["']?/
    },
    // ==================== MySQL Connector 漏洞 ====================
    {
      name: "MySQL Connector 客户端文件读取漏洞 (CVE-2023-22102)",
      function: "mysql-connector-java:8.0.0-8.0.34",
      description: "MySQL Connector/J 客户端任意文件读取漏洞，影响版本 ≤8.0.34，建议升级到 8.0.35+",
      pattern: /mysql-connector-java["']?[-_:]\s*["']?8\.0\.([0-9]|[1-2][0-9]|3[0-4])["']?/
    },
    // ==================== PostgreSQL JDBC 漏洞 ====================
    {
      name: "PostgreSQL JDBC 代码执行漏洞 (CVE-2024-1597)",
      function: "postgresql:42.0.0-42.7.1",
      description: "PostgreSQL JDBC SQL注入漏洞，影响版本 ≤42.7.1，建议升级到 42.7.2+",
      pattern: /postgresql["']?\s*[:_-]\s*["']?42\.[0-7]\.[0-1]["']?/
    },
    // ==================== H2 Database 漏洞 ====================
    {
      name: "H2 Database RCE漏洞 (CVE-2022-23221)",
      function: "h2:1.0.0-2.0.206",
      description: "H2 Database 远程代码执行漏洞，影响版本 ≤2.0.206，建议升级到 2.1.210+",
      pattern: /h2["']?\s*[:_-]\s*["']?[12]\.(0|1)\./
    },
    // ==================== Hutool 漏洞 ====================
    {
      name: "Hutool XXE漏洞 (CVE-2023-33695)",
      function: "hutool-all:5.0.0-5.8.15",
      description: "Hutool XXE 漏洞，影响版本 ≤5.8.15，建议升级到 5.8.16+",
      pattern: /hutool-all["']?[-_:]\s*["']?5\.[0-8]\.([0-9]|1[0-5])["']?/
    },
    // ==================== Apache Commons Compress 漏洞 ====================
    {
      name: "Apache Commons Compress DOS漏洞 (CVE-2024-25710)",
      function: "commons-compress:1.3-1.25",
      description: "Apache Commons Compress 无限循环拒绝服务漏洞，影响版本 1.3-1.25，建议升级到 1.26.0+",
      pattern: /commons-compress["']?\s*[:_-]\s*["']?1\.(3|4|5|6|7|8|9|1[0-9]|2[0-5])["']?/
    },
    // ==================== Bouncy Castle 漏洞 ====================
    {
      name: "Bouncy Castle LDAP注入漏洞 (CVE-2024-30171)",
      function: "bcprov-jdk15on:1.0-1.73",
      description: "Bouncy Castle LDAP 注入漏洞，影响版本 ≤1.73，建议升级到 1.74+",
      pattern: /bcprov-jdk[0-9]+on["']?\s*[:_-]\s*["']?1\.(0|[1-6][0-9]|7[0-3])["']?/
    },
    // ==================== Spring Security 漏洞 ====================
    {
      name: "Spring Security 授权绕过漏洞 (CVE-2023-34035)",
      function: "spring-security-core:5.7.0-5.7.9 或 5.8.0-5.8.4 或 6.0.0-6.0.3",
      description: "Spring Security 授权绕过漏洞，影响版本 5.7.0-5.7.9、5.8.0-5.8.4、6.0.0-6.0.3，建议升级到 5.7.10+、5.8.5+ 或 6.0.4+",
      pattern: /spring-security-core["']?\s*[:_-]\s*["']?(5\.7\.[0-9]|5\.8\.[0-4]|6\.0\.[0-3])["']?/
    },
    // ==================== Apache Avro 漏洞 ====================
    {
      name: "Apache Avro 任意代码执行漏洞 (CVE-2024-47561)",
      function: "avro:1.0.0-1.11.3",
      description: "Apache Avro 任意代码执行漏洞，影响版本 ≤1.11.3，建议升级到 1.11.4+",
      pattern: /avro["']?\s*[:_-]\s*["']?1\.(0|1|2|3|4|5|6|7|8|9|10|11)\./
    },
    // ==================== Apache Solr 漏洞 ====================
    {
      name: "Apache Solr 认证绕过漏洞 (CVE-2024-45216)",
      function: "solr-core:6.0.0-9.6.1",
      description: "Apache Solr 认证绕过漏洞，影响版本 6.0.0-9.6.1，建议升级到 9.7.0+",
      pattern: /solr-core["']?\s*[:_-]\s*["']?[6-9]\.[0-6]\./
    }
  ],
  low: [
    // ==================== OkHttp 漏洞 ====================
    {
      name: "OkHttp 证书验证绕过",
      function: "okhttp:3.0.0-3.12.0",
      description: "OkHttp 旧版本可能存在证书验证问题，建议升级到 4.x+",
      pattern: /okhttp["']?\s*[:_-]\s*["']?3\.(0|1|2|3|4|5|6|7|8|9|10|11|12)\./
    }
  ]
};

/**
 * 扫描组件依赖，检测已知漏洞版本
 * @param {string} dependencyContent - 依赖文件内容（pom.xml 或 build.gradle）
 * @returns {Array} 检测到的漏洞列表
 */
export function scanComponentVulnerabilities(dependencyContent) {
  const findings = [];
  
  for (const [severity, rules] of Object.entries(COMPONENT_VULN_RULES)) {
    for (const rule of rules) {
      if (rule.pattern.test(dependencyContent)) {
        findings.push({
          type: 'COMPONENT_VULNERABILITY',
          severity: severity,
          name: rule.name,
          component: rule.function.split(':')[0],
          affectedVersion: rule.function.split(':')[1],
          description: rule.description,
          cve: rule.name.match(/CVE-\d+-\d+/g)?.[0] || null,
          pattern: rule.pattern.toString()
        });
      }
    }
  }
  
  return findings;
}