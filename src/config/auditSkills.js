const AUDIT_SKILLS = [
  {
    id: "access-control",
    name: "访问控制",
    description: "关注对象级授权、公共角色、插件路由和后台访问边界。",
    version: "1.0.0",
    tags: ["security", "authorization", "owasp-a01"],
    triggers: ["越权", "权限", "访问控制", "authorization", "permission", "role", "admin"],
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
    reviewPrompt: `重点检查业务逻辑漏洞(OWASP Top 10 A07:2021)：竞态条件、Mass Assignment、状态机验证、多租户隔离、IDOR。

【漏洞模式】
- 竞态条件：余额扣减、库存更新、优惠券发放等并发场景
- Mass Assignment：对象属性过度暴露导致未授权修改
- 状态机漏洞：订单状态非法跳转、支付流程绕过
- 多租户隔离：不同租户数据未正确隔离
- IDOR：水平越权访问他人资源

【检测要点】
1. 检查是否有 @Transactional 或并发控制机制
2. 检查DTO是否限制可修改字段（@JsonIgnore、@JsonProperty(access=READ_ONLY)）
3. 检查状态转换是否有完整校验
4. 检查敏感操作是否验证资源归属
5. 检查是否使用乐观锁或悲观锁`,
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
    reviewPrompt: `重点检查配置文件的安全基线(OWASP Top 10 A05:2021)：认证配置、加密配置、安全开关、调试模式。

【配置文件类型】
- application.yml/application.properties (Java)
- config.py/settings.py (Python)
- web.config (C#)
- .env (Node.js)
- package.json (Node.js)
- pom.xml (Maven)

【危险配置模式】
- 认证配置：JWT密钥硬编码、密码策略过弱、会话超时过长
- 加密配置：TLS版本过低、证书配置错误、弱加密算法
- 安全开关：CORS允许任意来源、CSRF防护禁用、调试模式开启
- 数据库配置：明文密码、允许远程访问、测试账户未删除

【检测要点】
1. 检查是否存在明文密码或密钥
2. 检查CORS配置是否允许任意来源
3. 检查是否启用调试模式
4. 检查会话超时配置是否合理
5. 检查是否禁用了敏感HTTP头
6. 检查日志级别是否过高`,
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
    reviewPrompt: `重点检查供应链安全(OWASP Top 10 A06:2021)：第三方依赖库的已知CVE漏洞、过时版本、恶意包风险。

【依赖文件类型】
- package.json / package-lock.json (Node.js)
- requirements.txt / Pipfile (Python)
- pom.xml / dependency-reduced-pom.xml (Maven)
- go.mod / go.sum (Go)
- Cargo.toml / Cargo.lock (Rust)
- composer.json / composer.lock (PHP)

【危险模式】
- 使用已知漏洞的库版本（如Log4j、Spring框架漏洞）
- 使用过时的库版本（超过2年未更新）
- 使用未验证的第三方包
- 使用带已知安全风险的包（如event-stream事件攻击）

【检测要点】
1. 检查是否存在已知CVE漏洞的依赖
2. 检查依赖版本是否过时
3. 检查是否使用了有安全风险的包
4. 检查是否启用了依赖安全检查工具
5. 检查是否有依赖锁定文件`,
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
    reviewPrompt: `重点检查加密安全(OWASP Top 10 A02:2021)：密钥管理、密码算法强度、随机数生成、TLS配置。

【加密安全维度】
- 密钥管理：密钥存储、密钥轮换、密钥派生函数(KDF)
- 算法选择：对称加密、非对称加密、哈希算法
- 随机数：密码学安全随机数生成
- TLS配置：协议版本、证书、密码套件

【危险模式】
- 使用弱加密算法：MD5、SHA1、DES、3DES
- 使用弱密钥长度：小于256位的AES、小于2048位的RSA
- 使用不安全的随机数生成器：Math.random()、Random类
- 密钥硬编码或明文存储
- TLS版本过低：SSLv3、TLS 1.0、TLS 1.1

【检测要点】
1. 检查是否使用弱加密算法（MD5、SHA1、DES）
2. 检查密钥长度是否足够（AES至少256位，RSA至少2048位）
3. 检查是否使用密码学安全的随机数生成器
4. 检查密钥是否安全存储（不硬编码、使用密钥管理服务）
5. 检查TLS配置是否符合安全标准`,
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
    reviewPrompt: `重点审计 ASP.NET 路由配置(OWASP Top 10 A01:2021)：

【支持的框架】
- ASP.NET MVC 5：MapRoute 约定路由 + 属性路由
- ASP.NET Core：最小 API + 控制器路由 + 属性路由
- Web Forms：物理文件路径 + MapPageRoute
- Web API 2：MapHttpRoute + RoutePrefix

【检测要点】
1. 识别所有 HTTP 端点（Controller/Action/页面）
2. 分析参数来源（Query/Form/Body/Path/Header/Cookie）
3. 检查鉴权标注（[Authorize]/[AllowAnonymous]）
4. 识别未授权的管理接口
5. 检查路由参数是否存在注入风险
6. 检查敏感操作是否需要身份验证

【危险模式】
- 未授权的管理接口暴露
- 路由参数直接用于数据库查询
- 缺少 [Authorize] 属性的敏感端点
- 路由配置错误导致资源暴露

【输出要求】
1. 路由清单：URL、HTTP方法、控制器/动作、授权状态
2. 参数清单：参数名、类型、来源
3. 安全问题：未授权端点、潜在注入风险`,
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
    reviewPrompt: `重点检查 ASP.NET 认证授权机制(OWASP Top 10 A01:2021)：

【鉴权机制类型】
- Forms Authentication：传统表单认证
- ASP.NET Identity：现代身份管理系统
- JWT Bearer Authentication：无状态令牌认证
- Cookie Authentication：Cookie会话管理
- OpenID Connect/OAuth2：第三方身份提供者

【检测要点】
1. 登录认证流程是否安全
   - 密码复杂度验证
   - 多因素认证支持
   - 登录失败锁定机制
   - 密码重置流程

2. 权限验证是否完整
   - [Authorize] 属性是否正确使用
   - 角色检查是否完整
   - 策略授权是否正确配置

3. 是否存在认证绕过漏洞
   - 调试模式是否禁用
   - 默认账户是否删除
   - 测试账户是否清理

4. Session 管理是否安全
   - Session 超时配置
   - Cookie Secure/HttpOnly 标志
   - Session 固定攻击防护

5. 密码策略是否合理
   - 最小长度要求
   - 复杂度要求
   - 过期策略
   - 历史密码检查

【危险模式】
- 缺少 [Authorize] 属性的敏感操作
- 密码以明文或弱哈希存储
- JWT 密钥硬编码
- Cookie 缺少 Secure/HttpOnly 标志
- Session 超时时间过长

【输出要求】
1. 鉴权配置评估
2. 安全问题清单
3. 修复建议`,
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
