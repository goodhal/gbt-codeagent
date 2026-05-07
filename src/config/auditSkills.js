const AUDIT_SKILLS = [
  {
    id: "access-control",
    name: "访问控制",
    description: "关注对象级授权、公共角色、插件路由和后台访问边界。",
    reviewPrompt: `重点检查对象级访问控制(OWASP Top 10 A01)、公共角色权限、管理接口与插件路由是否存在过宽暴露。

【漏洞模式】
- 直接对象引用：用户可直接访问其他用户的资源
- 水平越权：同级别用户可访问他人数据
- 垂直越权：低权限用户可执行高权限操作
- 缺少角色检查：关键接口无 @Roles 或权限注解
- 插件路由暴露：管理路由未鉴权

【检测要点】
1. 检查用户ID是否可被篡改（如URL参数、请求体）
2. 检查是否存在无需鉴权的管理接口
3. 检查JWT/session中是否包含权限信息
4. 检查数据库查询是否包含用户ID过滤`,
    profiles: ["security", "default", "sensitive"],
    priority: "high"
  },
  {
    id: "bootstrap-config",
    name: "初始化与配置",
    description: "关注初始化管理员、开发开关、默认凭据和危险默认值。",
    reviewPrompt: `重点检查初始化管理员(OWASP Top 10 A05:2021)、开发开关、默认凭据、演示密钥和 fail-open 配置。

【危险模式】
- 调试/开发模式在生产环境开启
- 默认密码或硬编码凭证未修改
- fail-open 错误处理导致安全绕过
- CORS配置允许任意来源

【检测要点】
1. 检查是否存在 setup/init/install 管理路由
2. 检查是否存在硬编码的管理员账户
3. 检查是否使用生产禁用函数如 eval()
4. 检查错误处理是否泄露敏感信息
5. 检查是否有测试数据残留`,
    profiles: ["security", "default", "sensitive"],
    priority: "high"
  },
  {
    id: "upload-storage",
    name: "上传与存储",
    description: "关注上传链路、路径约束、公开目录和文件托管边界。",
    reviewPrompt: `重点检查文件上传(OWASP Top 10 A03:2021)、路径约束、公开访问目录、文件类型和路径规范化控制。

【高危场景】
- 任意文件上传：无文件类型验证或仅客户端验证
- 路径遍历：上传文件名包含 ../ 绕过目录限制
- 文件包含：上传文件被当作脚本执行
- 存储XSS：上传HTML/SVG可被浏览器执行

【检测要点】
1. 检查是否验证文件扩展名和MIME类型
2. 检查是否使用白名单而非黑名单
3. 检查上传目录是否可通过URL直接访问
4. 检查是否重命名文件而非使用原始文件名
5. 检查是否限制文件大小`,
    profiles: ["security", "default"],
    priority: "medium"
  },
  {
    id: "query-safety",
    name: "查询与注入",
    description: "关注原始查询、模板拼接、动态筛选和持久层输入约束。",
    reviewPrompt: `重点检查注入漏洞(OWASP Top 10 A03:2021)：SQL注入、NoSQL注入、命令注入、模板注入、LDAP注入、XPath注入。

【注入类型检测】
1. SQL注入：字符串拼接构建查询
   - 危险: "SELECT * FROM users WHERE id=" + userId
   - 安全: 使用参数化查询

2. 命令注入：用户输入进入系统命令
   - 危险: os.system("ping " + userInput)
   - 安全: 使用 subprocess.run with args=[]

3. 模板注入：用户输入进入模板渲染
   - 危险: render_template_string(user_input)
   - 安全: 模板中不包含用户输入

4. NoSQL注入：MongoDB/Redis查询中的注入
   - 危险: db.users.find({"name": userInput})
   - 安全: 使用参数化或验证输入

【检测要点】
1. 检查数据库查询是否使用参数化
2. 检查命令执行是否使用安全API
3. 检查模板渲染是否隔离用户输入
4. 检查是否对特殊字符进行转义`,
    profiles: ["security", "default", "sensitive", "extreme"],
    priority: "critical"
  },
  {
    id: "secret-exposure",
    name: "敏感信息",
    description: "关注公开前端变量、配置文件中的密钥和占位凭据。",
    reviewPrompt: `重点检查敏感数据泄露(OWASP Top 10 A02:2021)：硬编码密钥、API密钥泄露、日志中的敏感信息、客户端存储的敏感数据。

【敏感信息类型】
- 密码/密钥：password, secret, token, api_key, private_key
- 个人信息：身份证、银行卡、手机号、邮箱
- 认证凭据：session, jwt, credential
- 配置信息：数据库连接串、加密盐

【检测要点】
1. 检查是否将敏感信息硬编码在代码中
2. 检查日志记录是否包含敏感数据
3. 检查前端localStorage/sessionStorage存储敏感信息
4. 检查错误响应是否泄露敏感信息
5. 检查Git历史中是否曾提交过密钥`,
    profiles: ["security", "default", "sensitive"],
    priority: "high"
  },
  {
    id: "gbt-code-audit",
    name: "GB/T 国标代码安全审计",
    description: "基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计，支持 Java、C/C++、C#、Python 多语言漏洞检测。",
    reviewPrompt: `基于 GB/T 国标进行深度代码安全审计，遵循 GB/T 34943-2017(C/C++)、GB/T 34944-2017(Java)、GB/T 34946-2017(C#)、GB/T 39412-2020 标准。

【必须检测的漏洞类型】
1. 命令注入 (GB/T34944-6.1.1.6)：os.system, subprocess.Popen, exec(), eval()
2. SQL注入 (GB/T34944-6.1.2.1)：字符串拼接查询, raw SQL
3. 代码注入 (GB/T34944-6.1.1.7)：eval, exec, pickle.loads
4. 路径遍历 (GB/T34944-6.2.1.3)：文件路径拼接用户输入
5. 硬编码密钥 (GB/T34944-6.3.2.1)：密码、密钥在代码中明文存储
6. 弱加密算法 (GB/T34944-6.3.3.1)：MD5, SHA1, DES
7. 反序列化 (GB/T34944-6.1.3.2)：pickle.loads, yaml.load, ObjectInputStream
8. SSRF (GB/T39412-6.4)：用户输入进入HTTP请求URL
9. XXE (GB/T39412-6.5)：XML解析未禁用外部实体
10. 认证绕过 (GB/T34944-6.3.1.2)：绕过登录验证逻辑

【输出要求】
1. 每个漏洞必须包含：
   - gbtMapping: 对应GB/T条款，如 "GB/T34944-6.1.1.6 命令注入"
   - cvssScore: 0.0-10.0 的CVSS评分
   - confidence: 0.0-1.0 的置信度

2. 修复建议必须包含：
   - 具体代码示例（安全版本）
   - 使用的安全API/库名称
   - 验证方法（如何确认已修复）

【置信度评级】
- 0.9-1.0: 明显的漏洞模式，无误报可能
- 0.7-0.9: 典型漏洞模式，需人工确认
- 0.5-0.7: 可能的漏洞，需更多上下文
- <0.5: 低置信度，建议忽略`,
    profiles: ["security", "default", "sensitive", "extreme", "portability"],
    priority: "critical",
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
      "PLAINTEXT_TRANSMISSION",
      "OPEN_REDIRECT",
      "CSRF",
      "REGEX_DOS",
      "INSECURE_RANDOM",
      "JWT_VULNERABILITY"
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

export function getSkillsByProfile(profile) {
  if (!profile) {
    return getAuditSkillCatalog();
  }

  const lowerProfile = profile.toLowerCase();
  return AUDIT_SKILLS
    .filter((skill) => skill.profiles?.includes(lowerProfile))
    .map((skill) => ({ ...skill }));
}

export function getProfileConfig(profileName) {
  const profiles = {
    default: {
      id: "default",
      name: "默认配置",
      description: "高质量标准检查，低误报率",
      severityThreshold: "MEDIUM",
      enabledSkills: getSkillsByProfile("default").map(s => s.id)
    },
    security: {
      id: "security",
      name: "安全配置",
      description: "针对潜在漏洞代码的检查，包含所有安全规则",
      severityThreshold: "LOW",
      enabledSkills: getSkillsByProfile("security").map(s => s.id)
    },
    sensitive: {
      id: "sensitive",
      name: "敏感配置",
      description: "默认检查 + 更全面的检查，低误报率",
      severityThreshold: "LOW",
      enabledSkills: getSkillsByProfile("sensitive").map(s => s.id)
    },
    portability: {
      id: "portability",
      name: "可移植性配置",
      description: "检测平台差异带来的代码问题（如32位和64位架构）",
      severityThreshold: "MEDIUM",
      enabledSkills: getSkillsByProfile("portability").map(s => s.id)
    },
    extreme: {
      id: "extreme",
      name: "极致配置",
      description: "敏感检查 + 更全面的检查，可接受的误报率",
      severityThreshold: "INFO",
      enabledSkills: getSkillsByProfile("extreme").map(s => s.id)
    }
  };

  return profiles[profileName.toLowerCase()] || profiles.default;
}


export function getAllProfiles() {
  return [
    {
      id: "default",
      name: "默认配置",
      description: "高质量标准检查，低误报率",
      severityThreshold: "MEDIUM",
      enabledSkills: getSkillsByProfile("default").map(s => s.id)
    },
    {
      id: "security",
      name: "安全配置",
      description: "针对潜在漏洞代码的检查，包含所有安全规则",
      severityThreshold: "LOW",
      enabledSkills: getSkillsByProfile("security").map(s => s.id)
    },
    {
      id: "sensitive",
      name: "敏感配置",
      description: "默认检查 + 更全面的检查，低误报率",
      severityThreshold: "LOW",
      enabledSkills: getSkillsByProfile("sensitive").map(s => s.id)
    },
    {
      id: "portability",
      name: "可移植性配置",
      description: "检测平台差异带来的代码问题（如32位和64位架构）",
      severityThreshold: "MEDIUM",
      enabledSkills: getSkillsByProfile("portability").map(s => s.id)
    },
    {
      id: "extreme",
      name: "极致配置",
      description: "敏感检查 + 更全面的检查，可接受的误报率",
      severityThreshold: "INFO",
      enabledSkills: getSkillsByProfile("extreme").map(s => s.id)
    }
  ];
}
