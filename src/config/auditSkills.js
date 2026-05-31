const AUDIT_SKILLS = [
  {
    id: "access-control",
    name: "访问控制",
    description: "关注对象级授权、公共角色、插件路由和后台访问边界。",
    version: "1.0.0",
    tags: ["security", "authorization", "owasp-a01"],
    triggers: ["越权", "权限", "访问控制", "authorization", "permission", "role", "admin"],
    reviewPrompt: `## 访问控制审查清单
- [ ] 用户/资源 ID 是否来自请求参数（非 session 绑定）→ IDOR 风险
- [ ] 管理/特权端点是否有鉴权注解/中间件（@Roles, @PreAuthorize, middleware）
- [ ] 数据库查询是否按当前用户过滤（WHERE user_id = ?），而非仅靠 URL 参数
- [ ] 水平越权：同角色用户能否通过修改 ID 访问他人数据
- [ ] 垂直越权：低权限用户能否访问管理功能

## 不报告的情况
- 框架全局鉴权拦截器已覆盖（如 Spring Security filter chain 无例外）
- 端点明确设计为公开（如登录、注册、公开 API）
- 使用了成熟的鉴权框架且配置正确（如 Spring Security, Passport.js）`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    integrations: ["gbt-code-audit", "secret-exposure"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "bootstrap-config",
    name: "初始化与配置",
    description: "关注初始化管理员、开发开关、默认凭据和危险默认值。",
    version: "1.0.0",
    tags: ["security", "configuration", "owasp-a05", "hardcoded"],
    triggers: ["配置", "初始化", "setup", "init", "config", "secret", "cors"],
    reviewPrompt: `## 初始化与配置审查清单
- [ ] DEBUG / DEV 模式是否在生产环境开启
- [ ] 是否存在硬编码默认密码或初始管理员凭据
- [ ] CORS 是否允许 '*' 且 allowCredentials: true
- [ ] 是否存在未清理的 setup/init/install 端点
- [ ] 错误处理是否 fail-open（异常时放行而非拒绝）
- [ ] 错误响应是否泄露堆栈/路径/DB 信息

## 不报告的情况
- DEBUG 从环境变量读取且生产环境未设置
- 默认凭据来自配置文件且有文档说明需要修改
- CORS 配置通过白名单管理且测试时临时放开`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    integrations: ["secret-exposure", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "upload-storage",
    name: "上传与存储",
    description: "关注上传链路、路径约束、公开目录和文件托管边界。",
    version: "1.0.0",
    tags: ["security", "file-upload", "owasp-a03", "path-traversal"],
    triggers: ["上传", "文件", "upload", "storage", "file", "path"],
    reviewPrompt: `## 上传与存储审查清单
- [ ] 文件类型验证是否仅客户端（可绕过）→ 需服务端 MIME + 魔数验证
- [ ] 文件名是否直接使用用户输入（含 '../' 可路径穿越）
- [ ] 上传目录是否可通过 URL 直接访问（需在 Web 根外或禁用执行权限）
- [ ] 是否限制文件大小（防止 DoS）
- [ ] 上传 HTML/SVG 是否会导致存储型 XSS
- [ ] 是否重命名为 UUID/随机名（防止覆盖和猜测）

## 不报告的情况
- 使用白名单验证扩展名 + MIME type（双重验证）
- 上传目录配置了禁止脚本执行（.htaccess / nginx 配置）
- 文件重命名为服务端生成的随机名
- 上传到对象存储（S3/OSS）且不通过应用服务器`,
    profiles: ["security", "default"],
    priority: "medium",
    integrations: ["query-safety", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "query-safety",
    name: "查询与注入",
    description: "关注原始查询、模板拼接、动态筛选和持久层输入约束。",
    version: "1.0.0",
    tags: ["security", "injection", "owasp-a03", "sql", "command"],
    triggers: ["注入", "SQL", "命令执行", "query", "execute", "eval", "nosql"],
    evidencePoints: {
      SQL: ["EVID_SQL_EXEC_POINT", "EVID_SQL_STRING_CONSTRUCTION", "EVID_SQL_USER_PARAM_TO_SQL_FRAGMENT"],
      CMD: ["EVID_CMD_EXEC_POINT", "EVID_CMD_COMMAND_STRING_CONSTRUCTION", "EVID_CMD_USER_PARAM_TO_CMD_FRAGMENT"],
      NOSQL: ["EVID_NOSQL_QUERY_CONSTRUCTION", "EVID_NOSQL_USER_INPUT_INTO_QUERY_STRUCTURE", "EVID_NOSQL_OPERATOR_INJECTION_FIELDS"],
      LDAP: ["EVID_LDAP_EXEC_POINT", "EVID_LDAP_FILTER_STRING_CONSTRUCTION", "EVID_LDAP_USER_PARAM_TO_FILTER_FRAGMENT"],
      EXPR: ["EVID_EXPR_EVAL_ENTRY", "EVID_EXPR_EXPR_CONTROL", "EVID_EXPR_EXEC_CHAIN_ENTRY"]
    },
    reviewPrompt: `## 注入漏洞审查清单
- [ ] SQL/NoSQL：用户输入是否直接拼接进查询字符串（非参数化）
- [ ] 命令注入：用户输入是否进入 exec() / os.system() / subprocess(shell=True) / Runtime.exec()
- [ ] 模板注入：用户输入是否进入模板引擎渲染上下文（非数据上下文）
- [ ] LDAP/XPATH：用户输入是否进入查询过滤器字符串
- [ ] 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记

## 不报告的情况
- 使用参数化查询（JDBC PreparedStatement / ORM 安全方法 / Mongoose schema validation）
- 使用 subprocess.run([...]) 参数数组（非 shell 字符串）
- 使用白名单 + 类型强校验过滤用户输入
- 框架自带的自动转义已生效（如 Django ORM, Hibernate HQL parameter binding）`,
    profiles: ["security", "default", "sensitive", "extreme"],
    priority: "critical",
    integrations: ["gbt-code-audit", "upload-storage"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "cwe", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "secret-exposure",
    name: "敏感信息",
    description: "关注公开前端变量、配置文件中的密钥和占位凭据。",
    version: "1.0.0",
    tags: ["security", "secrets", "owasp-a02", "data-leak"],
    triggers: ["密钥", "密码", "敏感", "secret", "password", "token", "api"],
    reviewPrompt: `## 敏感信息审查清单
- [ ] 硬编码密钥：password / api_key / secret / token / private_key 在源文件中
- [ ] 日志输出：是否打印 token、密码、请求体全量 JSON
- [ ] 前端存储：localStorage/sessionStorage 是否存储 token 或敏感数据
- [ ] 错误响应：是否泄露堆栈路径、DB 结构、内部 IP
- [ ] 数据库连接串是否含明文密码

## 不报告的情况
- 值从环境变量/密钥管理服务读取（process.env.SECRET, os.getenv()）
- 明显的占位符/示例值（YOUR_API_KEY, changeme, test_）
- 代码中的公钥、client_id（这些天然公开）
- 仅变量名为 secret/token 但值来自外部配置`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    integrations: ["bootstrap-config", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "business-logic",
    name: "业务逻辑",
    description: "关注竞态条件、Mass Assignment、状态机验证、多租户隔离等业务逻辑漏洞。",
    version: "1.0.0",
    tags: ["security", "business-logic", "owasp-a07"],
    triggers: ["业务逻辑", "竞态", "状态机", "mass assignment", "race condition", "并发"],
    reviewPrompt: `## 业务逻辑审查清单
- [ ] 竞态条件：余额/库存/优惠券操作是否缺乏原子性（无锁、无 SELECT FOR UPDATE）
- [ ] Mass Assignment：请求体是否可批量绑定敏感字段（如 role, isAdmin, balance）
- [ ] 状态机：订单/支付/审批状态跳转是否校验了前置状态合法性
- [ ] 多租户：跨租户数据访问是否仅靠 URL 参数过滤（无 session 绑定校验）
- [ ] 幂等性：支付/扣款接口是否有防重复提交机制

## 不报告的情况
- 使用乐观锁（@Version / version 字段）或悲观锁（SELECT FOR UPDATE）
- DTO 显式声明允许字段（@JsonProperty(access=READ_ONLY) / 白名单绑定）
- 状态机使用枚举 + 合法转换表校验
- 租户 ID 从 JWT/session 中提取（非请求参数）`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    integrations: ["access-control", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "config-audit",
    name: "配置审计",
    description: "关注配置文件中的安全基线、认证配置、加密配置和安全开关。",
    version: "1.0.0",
    tags: ["security", "configuration", "owasp-a05", "secure-config"],
    triggers: ["配置", "config", "application", "settings", "properties", "yml", "yaml"],
    reviewPrompt: `## 配置文件审查清单
- [ ] 明文密码/密钥在配置文件中
- [ ] DEBUG=True / debug:true / NODE_ENV=development 在生产配置中
- [ ] CORS allowOrigins:* 且 allowCredentials:true
- [ ] CSRF 保护被显式禁用
- [ ] Session cookie 缺少 Secure / HttpOnly / SameSite 标志
- [ ] 日志级别设为 DEBUG/TRACE（泄露敏感信息）
- [ ] TLS 版本 < 1.2 / 弱密码套件

## 不报告的情况
- 值从 $ENV_VAR 或环境变量引用（非字面量）
- 开发/测试配置文件（application-dev.yml, .env.example）
- 已使用配置加密方案（Spring Cloud Config 加密 / Vault）`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    integrations: ["secret-exposure", "bootstrap-config", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "supply-chain",
    name: "供应链安全",
    description: "关注第三方依赖库的已知漏洞、版本更新和安全配置。",
    version: "1.0.0",
    tags: ["security", "supply-chain", "dependencies", "cve", "owasp-a06"],
    triggers: ["依赖", "package", "npm", "maven", "pip", "cve", "漏洞", "版本"],
    reviewPrompt: `## 供应链安全审查清单
- [ ] 依赖是否有已知 CVE（检查版本号是否在受影响范围内）
- [ ] 是否依赖已废弃/不再维护的包
- [ ] 是否有版本锁定文件（package-lock.json / go.sum / Pipfile.lock）
- [ ] 是否有未审核的第三方脚本/SDK 直接引入

## 不报告的情况
- 版本号已包含安全补丁（需确认 CVE 的 fixed version）
- 依赖仅用于开发/测试（devDependencies / test scope）
- 使用内部私有包且有安全审计流程`,
    profiles: ["security", "default", "sensitive"],
    priority: "medium",
    integrations: ["secret-exposure", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "cve", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "crypto-audit",
    name: "加密审计",
    description: "关注密钥管理、密码算法强度、随机数生成和TLS配置。",
    version: "1.0.0",
    tags: ["security", "cryptography", "encryption", "owasp-a02", "secure-crypto"],
    triggers: ["加密", "密钥", "crypto", "hash", "aes", "rsa", "ssl", "tls"],
    reviewPrompt: `## 加密安全审查清单
- [ ] 弱哈希：MD5 / SHA1 用于密码存储或完整性校验
- [ ] 弱加密：DES / 3DES / RC4 / ECB 模式
- [ ] 密钥长度不足：AES < 256, RSA < 2048, EC < 256
- [ ] 非加密安全随机：Math.random() / Random() / rand() 用于 token/密钥生成
- [ ] 密钥硬编码在源代码或配置文件中
- [ ] TLS < 1.2 / 自签名证书 / 弱密码套件

## 不报告的情况
- MD5/SHA1 用于非安全场景（如文件去重 hash、缓存 key）
- 加密密钥从 KMS/Vault/HSM 获取
- 使用 crypto.randomBytes() / SecureRandom / secrets 模块
- 密码使用 bcrypt/scrypt/argon2 哈希`,
    profiles: ["security", "sensitive", "extreme"],
    priority: "high",
    integrations: ["secret-exposure", "config-audit", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "dotnet-route-audit",
    name: ".NET 路由审计",
    description: "针对 ASP.NET 项目的路由提取与参数映射分析，支持 MVC、Core、Web Forms、Web API 等框架。",
    version: "1.0.0",
    tags: ["security", "dotnet", "aspnet", "route", "api", "csharp"],
    triggers: ["路由", "ASP.NET", ".NET", "API", "Controller", "endpoint"],
    reviewPrompt: `## .NET 路由审查清单
- [ ] 识别所有 HTTP 端点（Controller/Action/Minimal API/Page）
- [ ] 检查参数来源（Query/Form/Body/Path/Header/Cookie）
- [ ] 鉴权标注：[Authorize] vs [AllowAnonymous] — 敏感端点是否缺鉴权
- [ ] 路由参数是否直接用于数据库查询/命令执行

## 不报告的情况
- 端点有全局 [Authorize] filter 覆盖
- 路由参数仅用于查询且使用参数化
- [AllowAnonymous] 仅用于公开端点（login/register/health）`,
    profiles: ["security", "default", "sensitive"],
    priority: "high",
    gbtStandards: {
      "GB/T34946-2017": "C# 语言源代码漏洞测试规范"
    },
    supportedLanguages: ["csharp"],
    integrations: ["access-control", "query-safety", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "skillId", "vulnType", "cwe", "gbtMapping", "cvssScore", "language", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "dotnet-auth-audit",
    name: ".NET 鉴权审计",
    description: "审计 ASP.NET 鉴权机制，包括 Forms Auth、JWT、Identity、自定义中间件。",
    version: "1.0.0",
    tags: ["security", "dotnet", "aspnet", "authentication", "authorization", "identity", "jwt"],
    triggers: ["鉴权", "认证", "登录", "JWT", "Identity", "Cookie", "token"],
    reviewPrompt: `## .NET 鉴权审查清单
- [ ] 登录流程：密码是否哈希存储（Identity 默认 BCrypt，非明文）
- [ ] JWT：密钥是否硬编码？是否验证签名+过期+issuer
- [ ] [Authorize] 是否覆盖所有非公开端点（检查 Controller/Page 级别）
- [ ] Cookie：Secure / HttpOnly / SameSite 标志是否设置
- [ ] 密码策略：最小长度、锁定机制、重置流程是否安全
- [ ] 默认账户（admin/administrator）是否已删除或修改

## 不报告的情况
- 使用 ASP.NET Identity 默认配置（密码哈希+锁定已内置）
- JWT 密钥来自 appsettings.json 且已加密 / 来自 Key Vault
- Cookie 策略由 CookiePolicyMiddleware 统一配置`,
    profiles: ["security", "sensitive"],
    priority: "high",
    gbtStandards: {
      "GB/T34946-2017": "C# 语言源代码漏洞测试规范"
    },
    supportedLanguages: ["csharp"],
    integrations: ["access-control", "secret-exposure", "config-audit", "gbt-code-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "skillId", "vulnType", "cwe", "gbtMapping", "cvssScore", "language", "evidence", "impact", "remediation", "safeValidation"]
    }
  },
  {
    id: "gbt-code-audit",
    name: "GB/T 国标代码安全审计",
    description: "基于中国国家标准（GB/T 34943/34944/34946/39412）的代码安全审计，支持 Java、C/C++、C#、Python 多语言漏洞检测。",
    version: "1.0.0",
    tags: ["security", "gbt", "national-standard", "multi-language", "compliance"],
    triggers: ["国标", "GB/T", "合规", "安全审计", "代码审计", "漏洞检测", "security audit"],
    evidencePoints: {
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
    },
    reviewPrompt: `## GB/T 国标代码安全审计清单
标准依据：GB/T 34943(C/C++) / GB/T 34944(Java) / GB/T 34946(C#) / GB/T 39412-2020

### 必须检测（按标准条款）
- [ ] 命令注入 (GB/T34944-6.1.1.6)：用户输入进入 exec/system/popen
- [ ] SQL注入 (GB/T34944-6.1.2.1)：字符串拼接构建查询
- [ ] 代码注入 (GB/T34944-6.1.1.7)：eval/exec/pickle/yaml.load 接收用户数据
- [ ] 路径遍历 (GB/T34944-6.2.1.3)：文件路径含用户可控输入
- [ ] 硬编码密钥 (GB/T34944-6.3.2.1)：password/secret/key 明文
- [ ] 弱加密 (GB/T34944-6.3.3.1)：MD5/SHA1/DES/3DES/RC4
- [ ] 反序列化 (GB/T34944-6.1.3.2)：不可信数据反序列化
- [ ] SSRF (GB/T39412-6.4)：用户输入进入 HTTP 请求 URL
- [ ] XXE (GB/T39412-6.5)：XML 解析未禁用外部实体
- [ ] 认证绕过 (GB/T34944-6.3.1.2)
- [ ] XSS (GB/T39412-6.1.1.3)
- [ ] CSRF (GB/T39412-6.1.2.3)
- [ ] CORS 缺陷 (GB/T39412-6.3.2.2)
- [ ] 信息泄露 (GB/T39412-6.3.2.1)

### 关键判定规则
- 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记
- 输出要求：每个发现必须包含 gbtMapping, cvssScore, confidence, evidenceLabel (CONFIRMED/SUSPICIOUS)

### 不报告的情况
- 使用框架安全 API 且配置正确（参数化查询、安全反序列化器、标准认证中间件）
- 安全测试用例 / 示例代码 / 文档中的代码片段`,
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
    ],
    integrations: ["access-control", "query-safety", "secret-exposure", "upload-storage", "bootstrap-config", "business-logic", "config-audit", "supply-chain", "crypto-audit"],
    outputFormat: {
      fields: ["title", "severity", "confidence", "location", "skillId", "vulnType", "cwe", "gbtMapping", "cvssScore", "language", "evidence", "impact", "remediation", "safeValidation"]
    },
    usageFlow: [
      { phase: "提案阶段", description: "明确审计目标和范围，确认目标代码库" },
      { phase: "设计阶段", description: "确定扫描策略和工具组合" },
      { phase: "规格阶段", description: "定义具体的扫描参数和规则" },
      { phase: "任务阶段", description: "分解为可执行的子任务" },
      { phase: "验证阶段", description: "结果分析和误报过滤" }
    ],
    contextCheck: [
      "当前目录是否为代码仓库",
      "是否检测到支持的语言文件",
      "必要的工具是否已安装"
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
