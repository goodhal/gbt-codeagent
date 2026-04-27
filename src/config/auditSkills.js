const AUDIT_SKILLS = [
  {
    id: "access-control",
    name: "访问控制",
    description: "关注对象级授权、公共角色、插件路由和后台访问边界。",
    reviewPrompt: "重点检查对象级访问控制、公共角色权限、管理接口与插件路由是否存在过宽暴露。"
  },
  {
    id: "bootstrap-config",
    name: "初始化与配置",
    description: "关注初始化管理员、开发开关、默认凭据和危险默认值。",
    reviewPrompt: "重点检查初始化管理员、开发开关、默认凭据、演示密钥和 fail-open 配置。"
  },
  {
    id: "upload-storage",
    name: "上传与存储",
    description: "关注上传链路、路径约束、公开目录和文件托管边界。",
    reviewPrompt: "重点检查上传处理、文件落盘、公开访问目录、文件类型和路径规范化控制。"
  },
  {
    id: "query-safety",
    name: "查询与注入",
    description: "关注原始查询、模板拼接、动态筛选和持久层输入约束。",
    reviewPrompt: "重点检查原始查询、动态筛选、模板插值和持久层输入拼接风险。"
  },
  {
    id: "secret-exposure",
    name: "敏感信息",
    description: "关注公开前端变量、配置文件中的密钥和占位凭据。",
    reviewPrompt: "重点检查公开变量、配置文件、环境变量和初始化脚本里的敏感信息暴露。"
  },
  {
    id: "gbt-code-audit",
    name: "GB/T 国标代码安全审计",
    description: "基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计，支持 Java、C/C++、C#、Python 多语言漏洞检测。",
    reviewPrompt: "基于 GB/T 国标进行深度代码安全审计，重点关注命令注入、SQL注入、代码注入、路径遍历、硬编码密钥、弱加密算法、反序列化、SSRF、认证绕过、权限缺失等安全漏洞。审计时需遵循国标规则，提供准确的国标映射、CVSS评分和修复建议。",
    gbtStandards: {
      "GB/T34943-2017": "C/C++ 语言源代码漏洞测试规范",
      "GB/T34944-2017": "Java 语言源代码漏洞测试规范",
      "GB/T34946-2017": "C# 语言源代码漏洞测试规范",
      "GB/T39412-2020": "网络安全技术 源代码漏洞检测规则"
    },
    supportedLanguages: ["java", "python", "cpp", "csharp", "go", "javascript", "typescript", "php", "ruby", "rust"],
    vulnCategories: [
      "COMMAND_INJECTION",
      "SQL_INJECTION", 
      "CODE_INJECTION",
      "PATH_TRAVERSAL",
      "XSS",
      "XXE",
      "DESERIALIZATION",
      "SSRF",
      "HARD_CODE_PASSWORD",
      "HARD_CODE_SECRET",
      "WEAK_CRYPTO",
      "WEAK_HASH",
      "PREDICTABLE_RANDOM",
      "AUTH_BYPASS",
      "INFO_LEAK",
      "BUFFER_OVERFLOW",
      "FORMAT_STRING",
      "INTEGER_OVERFLOW",
      "PROCESS_CONTROL",
      "SESSION_FIXATION",
      "COOKIE_MANIPULATION",
      "MISSING_ACCESS_CONTROL",
      "IMPROPER_EXCEPTION_HANDLING",
      "WEAK_PASSWORD_POLICY",
      "PLAINTEXT_TRANSMISSION"
    ]
  }
];

export function getAuditSkillCatalog() {
  return AUDIT_SKILLS.map((skill) => ({ ...skill }));
}

export function resolveAuditSkills(selectedIds = []) {
  if (!Array.isArray(selectedIds) || !selectedIds.length) {
    return getAuditSkillCatalog();
  }

  const selected = new Set(selectedIds);
  const resolved = AUDIT_SKILLS.filter((skill) => selected.has(skill.id));
  return resolved.length ? resolved.map((skill) => ({ ...skill })) : getAuditSkillCatalog();
}