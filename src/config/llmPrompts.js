import { promises as fs } from "node:fs";
import path from "path";
import { withRetryWithFallback } from "../core/index.js";
import { ragService } from "../services/ragService.js";
import { buildFullLanguageContext } from "./languageAdapterLoader.js";

export const REVIEW_PRIORITY_LAYERS = `
【审查规则优先级分层 - 必须严格遵守】

🔴 安全问题（优先级最高）- 必须检测：
- SQL注入：用户输入直接拼接SQL语句
- 命令注入：执行系统命令时使用用户可控数据
- XSS漏洞：用户输入未经过滤直接输出到页面
- 敏感信息硬编码：密码、密钥、API密钥明文存储
- 不安全的反序列化：使用不可信数据进行反序列化
- 认证绕过：身份验证逻辑缺陷
- 权限控制缺失：水平越权、垂直越权
- SSRF：服务器端请求伪造
- 路径遍历：文件路径包含用户可控输入
- 文件上传漏洞：文件类型验证不足
- CSRF：缺少CSRF令牌校验的写操作端点
- 日志注入：用户输入未过滤写入日志
- 开放重定向：重定向目标来自用户可控参数
- XXE：XML解析未禁用外部实体
- CORS配置缺陷：反射Origin且允许凭据
- 不安全组件：使用已知有漏洞的第三方组件(如Fastjson Log4j Shiro)

🟠 性能问题（优先级次之）- 重点检测：
- 循环中的数据库查询：N+1查询问题
- 大对象的频繁创建：内存占用过高
- 未关闭的资源：数据库连接、文件流泄漏
- 重复计算：相同计算多次执行
- 低效算法：时间复杂度较高的实现

🟡 代码规范（优先级较低）- 参考检测：
- 命名规范：变量、函数命名不规范
- 注释缺失：关键逻辑缺少注释说明
- 方法过长：单方法超过50行
- 复杂度过高：圈复杂度超过15
- 魔法数字：未定义常量的硬编码数值`;

export const CORE_SECURITY_PRINCIPLES = `
【核心安全分析原则】

1. 深度分析优于广度扫描
   - 深入分析少数真实漏洞比报告大量误报更有价值
   - 每个发现都需要上下文验证
   - 理解业务逻辑后才能判断安全影响

2. 数据流追踪
   - 从用户输入（Source）到危险函数（Sink）
   - 识别所有数据处理和验证节点
   - 评估过滤和编码的有效性

3. 上下文感知分析
   - 不要孤立看待代码片段
   - 理解函数调用链和模块依赖
   - 考虑运行时环境和配置

4. 质量优先
   - 高置信度发现优于低置信度猜测
   - 提供明确的证据和复现步骤
   - 给出实际可行的修复建议

5. 自检原则
   - 每报一个 critical 或 high，先问自己："我能描述这个漏洞会导致的精确用户事故吗？"
   - 如果答案模糊（"可能导致安全问题"），降级到 medium
   - 如果答案明确且可复现（"攻击者可通过 /api/user?id=xxx 读取任意用户数据"），保留级别
   - 如果你自己都不确定能不能被攻击，就不要报为 critical`;

export const RUNTIME_CONTEXT_AWARENESS = `
【运行时环境感知 - 同问题不同环境不同级别】

同一类问题在不同运行时环境的影响完全不同，必须区分：

服务端（Node.js/Deno/Python/Go/Java）：
- 未处理异常 → 可能导致进程崩溃 → 🔴 critical
- 资源泄漏（连接/文件句柄）→ 累积耗尽 → 🔴 critical
- try-catch 空吞异常 → 静默故障，难以排查 → 🟠 high

浏览器端（React/Vue/Angular）：
- 未处理异常 → ErrorBoundary/全局 handler 兜底 → 最多 🟡 medium
- 渲染 undefined → 框架渲染空，不崩溃 → 不算漏洞
- 事件监听器未移除 → 内存增长 → 🟠 high

后端 API 端点：
- 缺少认证 → 数据泄露 → 🔴 critical
- 缺少授权检查 → 越权访问 → 🔴 critical

前端管理页面：
- 缺少前端路由守卫 → 但后端已有全局拦截 → 最多 🟡 medium
- loading/error 状态缺失 → 体验问题 → 🟢 low`;

export const SEVERITY_CLASSIFICATION_GUIDE = `
【严重级别判定标准 - 必须严格区分】

🔴 critical（严重）- 仅以下情况：
- 可直接通过网络远程利用，无需认证
- 可导致远程代码执行(RCE)、系统完全控制
- 可导致任意文件读取/写入
- 可绕过身份认证直接访问核心功能
- 明确的命令注入、SQL注入且用户输入未经任何过滤直接到达危险函数
- 硬编码的生产环境密钥/凭证
- ⚠️ critical 只能用于最严重的问题，不能滥用

🟠 high（高危）- 以下情况：
- 需要普通用户认证后可利用
- 可导致重要数据泄露（用户密码、个人信息）
- CSRF 可导致关键操作（修改密码、转账）
- 反序列化漏洞（有实际风险）
- SSRF 可访问内网
- 权限控制缺失导致越权
- 会话固定、敏感信息在日志中泄露

🟡 medium（中危）- 以下情况：
- 需要特定条件才能利用（如需要管理员权限）
- 信息泄露但影响范围有限（如版本号、路径泄露）
- 配置不当但不直接导致安全漏洞
- 弱加密算法但仍需要其他条件才能利用
- 输入验证不足但已有部分防护
- 仅测试/开发环境风险
- 竞争条件但利用难度大

🟢 low（低危）- 以下情况：
- 几乎无法实际利用
- 仅理论风险，缺乏实际攻击路径
- 代码风格问题不直接导致安全漏洞
- 已废弃但未删除的调试代码（不影响生产）
- 框架已默认防护的潜在风险
- low 用于信息性发现，置信度应设为 0.3-0.5

⚠️ 判定原则：
- 不确定时应降级而非升级：有疑问时选较低级别
- 需要认证或特定条件才能利用的，不应评为 critical
- 仅理论风险无实际攻击路径的，评为 low
- 如果所有发现都是同一级别，说明判定标准有问题，请重新审视

## 统计预期（校准用）
- 一个正常项目的审计结果中，critical 应为 0-2 个，high 应为 0-5 个
- 如果 critical 超过 5 个或 high 超过 15 个，说明严重度判定过于宽松，请重新审视并降级
- 如果所有发现都是 medium，说明你可能漏掉了真正的严重问题
- 如果所有发现都是 low，说明你过度保守，请提高对真实风险的认识

### 🚫 明确不算漏洞的情况（必须遵守）

以下情况绝对不能报为漏洞，即使看起来有问题：
- JS/TS 渲染中访问可能为 undefined 的属性（框架渲染空值，不会崩溃）
- "可以加可选链"但当前代码逻辑已经保证安全的场景
- 纯理论风险，缺少真实输入能触发的路径
- 仅代码风格 / 命名 / 重复代码问题（这些不是安全漏洞）
- 测试代码 / 演示代码 / 示例代码 / mock 文件中的"漏洞"
- 已被框架默认防护的潜在风险（如 Spring Security 已启用的 CSRF、框架自带的 XSS 过滤）
- CSS 工具类的数值（如 Tailwind text-[11px]、mt-3）、hex 颜色、CSS 单位
- 仅 import 语句但无实际调用的情况
- 非安全相关的代码规范建议（如"变量命名不够语义化"）`;

export const FILE_VALIDATION_RULES = `
【文件路径验证规则 - 防止幻觉】

⚠️ 严禁行为：
- 禁止报告不存在的文件路径
- 禁止凭记忆或推测编造代码片段
- 禁止假设特定文件存在（如 config/database.py、"Python项目通常有config.py"）
- 禁止报告注释行代码作为漏洞
- 禁止报告导入语句但无实际调用的代码
- 禁止基于"典型项目结构"猜测文件路径
- 禁止使用知识库示例代码作为项目实际代码

✅ 正确做法：
- 先 Glob 发现文件 → 再 Read 读取内容 → 再分析 → 再报告
- 只报告提供代码片段中确实存在的漏洞
- 引用实际代码时使用提供的 snippet（直接复制，保持格式和缩进）
- 行号必须在文件实际行数范围内，不确定时重新确认
- 漏洞类型必须与项目技术栈一致（不在 Rust 项目中报 Python 漏洞）

🔴 验证清单（每个发现前自检）：
□ 文件路径确认存在
□ 代码片段来自实际读取
□ 行号在文件行数范围内
□ 漏洞类型与技术栈一致
□ 不是从知识库示例推测的

⚠️ 知识库隔离原则：知识库示例用于理解漏洞概念和检测方法，≠ 项目代码。必须在实际代码中找到对应模式。

🔥 宁可漏报，不可误报。质量优于数量。`;

export const EVIDENCE_CONTRACT_GUIDE = `
【证据契约要求 - 每个漏洞必须提供标准证据】

🔴 核心原则：漏洞发现必须附带标准化证据点（EVID_*），用于后续验证和追溯。

【常见漏洞类型对应证据点】
| 漏洞类型 | 必须证据点 |
|---------|-----------|
| SQL注入 | EVID_SQL_EXEC_POINT, EVID_SQL_STRING_CONSTRUCTION, EVID_SQL_USER_PARAM_MAPPING |
| 命令注入 | EVID_CMD_EXEC_POINT, EVID_CMD_STRING_CONSTRUCTION, EVID_CMD_USER_PARAM_MAPPING |
| 文件操作 | EVID_FILE_READ_SINK, EVID_FILE_PATH_CONSTRUCTION, EVID_FILE_USER_PARAM_MAPPING |
| SSRF | EVID_SSRF_URL_CONSTRUCTION, EVID_SSRF_USER_PARAM_MAPPING, EVID_SSRF_DNSIP_AND_INNER_BLOCK |
| XXE | EVID_XXE_PARSER_CALL, EVID_XXE_INPUT_SOURCE, EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO |
| 反序列化 | EVID_DESER_CALLSITE, EVID_DESER_INPUT_SOURCE, EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN |
| XSS | EVID_XSS_OUTPUT_POINT, EVID_XSS_USER_INPUT_INTO_OUTPUT, EVID_XSS_ESCAPE_OR_RAW_CONTROL |
| 认证绕过 | EVID_AUTH_CHECK_BYPASS, EVID_AUTH_TOKEN_DECODE_JUDGMENT, EVID_AUTH_PERMISSION_CHECK_EXEC |

【证据点输出格式】
每个漏洞发现中必须包含 evidencePoints 数组，列出该漏洞涉及的所有证据点ID。

【证据完整性判定】
- ✅ COMPLETE: 所有关键证据点都存在
- ⚠️ PARTIAL: 部分证据点缺失，需人工复核
- ❌ UNRESOLVED: 关键证据点缺失，标记为待验证

⚠️ 注意：如果无法提供完整的证据链，必须将漏洞标记为"待验证"，不得直接标记为"已确认可利用"。`;

export const DE_DUPLICATION_RULES = `
【去重规则 - 必须遵守】

LLM 最常见的问题是同一个模式在多个文件中被重复报告为独立漏洞。以下规则强制避免：

✅ 应该合并的情况（同一根因）：
- 同一文件、同一函数、同一行号、同一漏洞类型 → 合并为一条
- 如果某个模式要报 10 个文件以上，说明这是系统性的代码风格，合为一条典型说明

❌ 不应该合并的情况（不同攻击面）：
- 不同 Controller/端点/参数的同类漏洞 → 分别报告
  - 例如 ProcessBuilder 命令注入 ≠ Runtime.exec 命令注入 ≠ ProcessImplVul 命令注入
  - 三个不同端点的 "命令注入" 是三个独立的攻击面，必须分别报告
- 不同文件、不同 sink 函数的同类漏洞 → 分别报告
- 不同利用前提（如一个需认证、一个无需认证）→ 分别报告

判定标准：如果合并后 attackVector 无法精确描述每个端点的攻击方式，则不应合并。

- 同一文件中相同类型且相同函数调用的问题合并为一条`;

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

export const VULNERABILITY_FILES = {
  'sql_injection': 'sql_injection.md',
  'command_injection': 'command_injection.md',
  'code_injection': 'code_injection.md',
  'deserialization': 'deserialization.md',
  'hardcoded_credentials': 'hardcoded_credentials.md',
  'path_traversal': 'path_traversal.md',
  'weak_crypto': 'weak_crypto.md'
};

/**
 * 借鉴 AiCodeAudit：语言级安全审计规则
 * 为每种语言精确定义输入源、危险点、安全信号的识别模式
 * 使 LLM 审计时能更准确地判定漏洞上下文中是否存在真实风险链路
 */
export const LANGUAGE_AUDIT_RULES = {
  ".py": `
[Python 审计规则]
1. 输入源识别：request.args, request.form, request.json, request.values, request.files, input(), sys.argv, os.environ, getenv, 上传文件对象, URL/path 参数
2. 危险点识别：eval(), exec(), pickle.load/loads, yaml.load (非 safe_load), subprocess.run/Popen/call (shell=True), os.system, SQL 字符串拼接, open/Path.open/read_text/write_text (用户可控路径), 模板直出 (Jinja2 未转义)
3. 安全信号：yaml.safe_load, html.escape/MarkupSafe.escape, pathlib.Path.resolve(), subprocess 列表参数 (非 shell 模式), 参数化查询 (sqlite3 ?, psycopg2 %s, sqlalchemy bind), pydantic/marshmallow 校验
4. 判定指引：看到 request 输入进入 SQL/命令/文件/URL/模板 → 优先确认风险；若有 safe_load/参数化/白名单 → 降低级别；仅 import 没有调用 → 不报`,

  ".js": `
[JavaScript 审计规则]
1. 输入源识别：req.query, req.body, req.params, req.headers, req.files, process.env, window.location, document.location, 上传文件对象, URL 参数
2. 危险点识别：child_process.exec/spawn/execSync, eval(), new Function(), vm.runInNewContext, 字符串拼接 SQL (mysql.query/seqlize.query 拼接), fs.readFile/writeFile/createReadStream/createWriteStream (用户可控路径), fetch/axios URL 拼接, dynamic require/import, innerHTML/dangerouslySetInnerHTML/document.write
3. 安全信号：path.normalize/join/resolve, prepared statement/参数化查询 (mysql2.execute, sequelize bind), DOMPurify, zod/joi/yup/express-validator, helmet
4. 判定指引：看到 req.query/body/params 进入 SQL/命令/文件/URL → 优先确认风险；若有 path.resolve+约束/参数化/DOMPurify → 降低级别；前端渲染 undefined → 不算漏洞`,

  ".ts": `
[TypeScript 审计规则]
1. 输入源识别：req.query, req.body, req.params, req.headers, process.env, 上传文件, URL/path 参数
2. 危险点识别：child_process.exec/spawn/execSync, eval(), new Function(), SQL 字符串拼接, fs.readFile/writeFile (用户可控), fetch/axios URL 拼接, dynamic import
3. 安全信号：path.normalize/join/resolve, prepared statement/参数化查询, zod/joi/class-validator/nestjs 校验, helmet, TypeScript 类型约束（不视为安全信号）
4. 判定指引：TypeScript 类型注解不是安全防护，仍需检查运行时输入；其余同 JS`,

  ".java": `
[Java 审计规则]
1. 输入源识别：request.getParameter(), @RequestParam, @PathVariable, @RequestBody, System.getenv, MultipartFile, 上传文件名, URL 参数, Cookie
2. 危险点识别：Runtime.exec(), ProcessBuilder, JDBC Statement.execute/executeQuery/executeUpdate (字符串拼接), Hibernate HQL 拼接, JdbcTemplate 拼接, FileInputStream/FileOutputStream (用户可控路径), HttpURLConnection/RestTemplate/WebClient URL 拼接, ObjectInputStream (反序列化), XMLDecoder, XStream, ScriptEngine.eval, GroovyShell
3. 安全信号：PreparedStatement (参数绑定), @PreAuthorize/@RolesAllowed/hasRole, Paths.get/toRealPath/normalize, @Valid + BindingResult, Spring Security 全局配置
4. 判定指引：看到 request.getParameter/@RequestParam 进入 SQL/命令/文件/URL → 优先确认风险；有 PreparedStatement/参数绑定 → 降低级别；Spring Security 全局 CSRF → 不报 CSRF`,

  ".go": `
[Go 审计规则]
1. 输入源识别：r.URL.Query(), r.FormValue(), r.PostFormValue(), c.Param()/c.Query()/c.PostForm() (gin), ShouldBindJSON/BindJSON, os.Getenv, 上传文件, URL/path 参数
2. 危险点识别：exec.Command (配合 sh -c 或用户可控参数), database/sql db.Query/db.Exec (拼接 SQL), os.Open/os.Create (用户可控路径), http.Get/http.Post (用户可控 URL), template.HTML (text/template 无转义)
3. 安全信号：html/template (自动转义), Query/Exec 占位符 (?/$1), PreparedStatement, filepath.Clean/Join, validator 绑定, ShouldBind 校验, r.Context()
4. 判定指引：看到 Query/FormValue/BindJSON 进入 SQL/命令/文件/URL → 优先确认风险；html/template 自动转义, 参数化 → 降低级别`,

  ".php": `
[PHP 审计规则]
1. 输入源识别：$_GET, $_POST, $_REQUEST, $_FILES, $_COOKIE, $_SERVER, $_ENV, file_get_contents('php://input'), URL 参数, 路径参数
2. 危险点识别：system/exec/shell_exec/passthru/proc_open, mysqli_query/mysql_query (拼接 SQL), PDO::query (拼接 SQL), include/require/include_once/require_once (动态路径), file_get_contents/fopen/fwrite (用户可控路径), unserialize, eval, preg_replace /e, create_function
3. 安全信号：PDO::prepare + bindValue/bindParam, filter_input/filter_var, htmlspecialchars, realpath/basename, password_hash/password_verify, CSRF token 校验
4. 判定指引：看到 $_GET/$_POST 进入 SQL/include/system/文件 → 优先确认风险；PDO prepare + bind → 降低级别`,

  ".c": `
[C 审计规则]
1. 输入源识别：argv, getenv, recv/read/fgets/scanf, socket 输入, 文件名/路径参数
2. 危险点识别：system/popen/execl/execv, sprintf/strcpy/strcat/gets (无边界), fopen/open (用户可控路径), 动态加载 dlopen, 认证逻辑绕过
3. 安全信号：snprintf/strncpy (有边界), realpath, strlen/sizeof 结合边界检查, strncmp/memcmp
4. 判定指引：仅凭 malloc/free/strdup/xstrdup 不报漏洞；需要可控输入+危险操作+缺失边界才报`,

  ".cpp": `
[C++ 审计规则]
1. 输入源识别：argv, getenv, recv/read/gets/scanf, std::cin, 文件名/路径参数
2. 危险点识别：system/popen, sprintf/strcpy/strcat, std::ifstream/ofstream/fstream (用户可控路径), 命令执行, 认证绕过
3. 安全信号：snprintf, std::filesystem::canonical, std::array, std::regex 校验, std::clamp, size()
4. 判定指引：仅凭内存分配/释放/字符串复制不报漏洞；需要可控输入+危险操作+缺失防护`,

  ".cs": `
[C# 审计规则]
1. 输入源识别：Request.Query, Request.Form, Request.Body, Request.Headers, IFormFile, Environment.GetEnvironmentVariable, URL/path 参数
2. 危险点识别：Process.Start, SqlCommand.ExecuteReader/ExecuteNonQuery (拼接 SQL), File.ReadAllText/WriteAllText/OpenRead/OpenWrite (用户可控路径), HttpClient.GetAsync/PostAsync (用户可控 URL), BinaryFormatter/SoapFormatter (反序列化), XPathNavigator/XPathExpression
3. 安全信号：SqlParameter/SqlCommand 参数化, Path.GetFullPath/Path.Combine, [Authorize]/[AllowAnonymous], ModelState.IsValid, DataAnnotations/FluentValidation, AntiForgeryToken (CSRF)
4. 判定指引：看到 Request 输入进入 SQL/Process/文件/URL → 优先确认风险；参数化查询/SqlParameter → 降低级别；[Authorize] 全局启用 → 不报认证绕过`,
};

/**
 * 借鉴 AiCodeAudit：双层判定体系 + 反误报负面示例
 * 将原本单一的 severity 判定扩展为 "确认风险" / "可疑风险" 双层判定
 * 使 LLM 能表达不确定性，同时用具体反例抑制常见误报模式
 */
export const DUAL_VERDICT_SYSTEM = `
【漏洞判定双轨体系 - 确认风险 vs 可疑风险】

你必须对每个发现的漏洞使用以下判定体系，而不是仅报告严重度：

🔴 确认风险 — 同时满足以下条件：
  - 明确看到用户可控输入进入危险操作
  - 代码中缺少有效的校验/转义/鉴权防护
  - 能清晰描述完整的攻击链路和后果
  - 示例：request.args["id"] 直接进入 SQL 拼接且无 PreparedStatement

🟡 可疑风险 — 满足以下情况之一：
  - 看到明显的输入源和危险点，但缺少完整调用链证据
  - 看到危险点和明显缺失防护，但输入可控性不确定
  - 上下文不足以完全闭合利用链，但风险信号很强
  - 必须在攻击向量中明确写出"当前缺少哪些证据"
  - 等级上限为中危

⚪ 审计通过 — 以下情况：
  - 没有输入源 + 危险点的有效组合
  - 代码本身是安全封装/校验/日志/资源释放逻辑
  - 已有充分的参数化/白名单/鉴权/转义措施

【具体反误报负面示例 - 以下绝对不能报为漏洞】

错误示例 1：xstrdup(challenge) 可能导致缓冲区溢出
  → 原因：仅凭字符串复制函数名不能证明溢出

错误示例 2：sshbuf_free(b) 可能导致内存泄露
  → 原因：释放资源本身不是漏洞证据

错误示例 3：普通 malloc/free 配对
  → 原因：内存操作不等于漏洞

错误示例 4：仅 import dangerousLibrary 但没有实际调用
  → 原因：导入语句不构成漏洞

错误示例 5：catch (Exception e) { } 空异常处理"
  → 原因：不是安全问题，是代码质量问题

错误示例 6：字符串拼接后赋值给变量（未进入危险函数）
  → 原因：缺少危险 sink

错误示例 7：测试代码/演示代码/demo 目录中的"漏洞"
  → 原因：非生产代码

【自检要求】
报告前必须对每个发现自问：
- 如果有认证要求，攻击者需要什么权限？
- 如果没有认证要求，这个接口对外暴露了吗？
- 这个漏洞会导致的最精确用户事故是什么？
- 如果答案模糊 → 降级或标记为可疑风险
- 如果答案明确可复现 → 保持确认风险`;

/**
 * False Positive Kill Switch — 安全控制自动降级规则
 * 参考: code-security-audit 误报过滤机制
 * 指导 LLM 在发现危险模式时，先检查是否已有安全控制措施
 */
export const FALSE_POSITIVE_KILL_SWITCH = `
【误报 Kill Switch — 发现漏洞前先检查安全控制】

当你发现一个危险模式时，必须先检查是否存在以下安全控制。若控制有效，应降级而非直接丢弃：

⚠️ 重要：快速扫描标记为可疑的清单项，LLM 必须亲自审查代码后才能应用 Kill Switch。不得仅凭猜测或框架约定假设安全。

1. 强类型/枚举限制
   - 参数类型为 enum → SQL注入不可能 → 降级为 Low（不可直接删除）
   - Integer/Long/Boolean 强类型参数 → 注入降级为 Low
   - Controller 方法首行有白名单验证 → 降级为 Low

2. Bean Validation + @Valid
   - DTO + @Valid + @Pattern/@Email/@Size → 降级为 Low
   - 仅 @NotNull 不足以阻止注入 → 保持原级别

3. 全局 SecurityFilter
   - 存在 OncePerRequestFilter XssFilter + 完整实现 → XSS 降级为 Low
   - CSRF Filter + token 验证 → CSRF 降级为 Low
   - 注意：Filter 有 excludeUrlPatterns 时 → 不降级，保持原级别

4. ORM 参数绑定（非拼接）
   - MyBatis #{} 且无 \${} 拼接 → SQL注入降级为 Low（仍须报告！因为可能存在隐蔽的注入点）
   - JPA @Query with :param (非 nativeQuery) → 降级为 Low
   - Criteria API type-safe 查询 → 降级为 Low
   - MyBatis \${} 或 JPA nativeQuery + 拼接 → 保持 Critical

5. 真实权限校验（非注解摆设）
   - @PreAuthorize + @EnableGlobalMethodSecurity(prePostEnabled=true) → 降级为 Low
   - 方法内首行权限检查 (if (!hasRole()) throw) → 降级为 Low
   - 仅有注解，无 SecurityConfig 配置启用 → 保持原级别

🔴 关键规则：降级 ≠ 不报告。即使触发了 Kill Switch，仍应在 findings 中报告该发现，severity 下调一级，同时在 killSwitchInfo 中填写降级原因。`;

/**
 * 借鉴 AiCodeAudit：依赖上下文解读规则
 * 配合 buildDependencyContext 构建的上下游链路使用
 * 指导 LLM 如何正确解读调用图中的输入→传播→危险路径
 */
export const DEPENDENCY_INTERPRETATION_RULES = `
【依赖上下文分析规则 - 调用图辅助审计】

当审计文件中附带"依赖上下文分析"时，你必须按以下规则解读：

1. 优先关注"上游输入分支"中标记了 [外部输入] 的节点：它们可能是用户数据的入口
2. 优先关注"下游危险分支"中标记了 [危险操作] 的节点：它们可能是漏洞落地点
3. 当同时存在 [外部输入] 上游和 [危险操作] 下游时 — 这是最需要重点审查的组合风险路径
4. 如果提示中出现了"⚠️ 组合风险路径"标识，说明静态分析已发现潜在的完整攻击链路，请优先沿此链路组织分析
5. 不要仅因为调用链长就判定安全：需逐个节点确认是否存在防护措施
6. 如果某个中间节点明确实施了校验/鉴权/转义 → 该路径风险降低
7. 如果上游有输入但下游无危险点，或下游有危险但上游无输入源 → 不构成完整风险
8. 如果上下文中有校验/鉴权/安全信号，且源码证实这些措施有效 → 标记为审计通过
9. 不要在依赖上下文中"推测"漏洞：上下文的线索只是提示，真正的判定必须回到源码中寻找证据
10. 如果依赖上下文显示没有外部输入源也没有危险sink → 正常审计，不要受空上下文影响`;

/**
 * 攻击路径优先级 — 根据攻击者视角的实际可利用性对漏洞排序
 * 参考: code-security-audit attack_path_priority.md
 * 核心理念: 攻击者总是选择阻力最小的路径
 */
/**
 * 借鉴 AiCodeAudit：结构化输出格式增强
 * 在原有 findings JSON 基础上，增强每个 finding 的攻击向量和潜在影响描述
 */
export const AUDIT_OUTPUT_ENHANCEMENT = `
【审计输出增强要求 — 每个发现必须包含以下 8 个字段】

1. location — 文件路径、类/方法/API端点、行号（必须精确）
2. type — 漏洞类型 + 根因
3. attackVector — 攻击向量（Source → Transfer → Sink 完整证据链）
   - "确认风险"："攻击者通过[输入源]控制[参数]，经[传播路径]，到达[危险点]"
   - "可疑风险"："分析发现[危险点]，但当前上下文缺乏[缺失的证据]"
   - 禁止用"可能被攻击""可能导致安全问题"等空泛描述
4. exploitPrerequisites — 利用前提（是否需要认证、特殊权限、网络可达性）
5. impact — 潜在影响（必须是用户可感知的精确后果）
   - 正确："攻击者可读取任意用户数据包括密码哈希"；错误："可能导致数据泄露"
6. severity — 严重级别 + evidenceLabel（CONFIRMED/HIGH_CONFIDENCE/SUSPECTED/INFO）
7. remediation — 最小化修复方案（必须给出具体代码级修复，禁止"建议安全审查"等空话）
8. retestChecklist — 复测清单（列出验证修复有效的具体步骤）
   - 例如："验证 POST /api/user?id=1 OR '1'='1' 不再返回全量数据"
   - 例如："确认 PreparedStatement 已替换 Statement，占位符 ? 已绑定所有动态参数"

【Evidence Label 判定标准】
- CONFIRMED: 完整 Source→Transfer→Sink 链 + 可达输入源 + 缺失有效防护 + 可重现
- HIGH_CONFIDENCE: 完整链路但运行细节未完全验证
- SUSPECTED: 部分链路、不确定可达性或前置条件不完整
- INFO: 加固建议、设计关切、低置信度线索

注意：evidenceLabel 与 severity 独立评定。一个 High 严重的漏洞可能仅 SUSPECTED 置信度。`;

export const EVIDENCE_REQUIRED_MAP = {
  SQL_INJECTION: ['EVID_SQL_EXEC_POINT', 'EVID_SQL_STRING_CONSTRUCTION', 'EVID_SQL_USER_PARAM_MAPPING'],
  COMMAND_INJECTION: ['EVID_CMD_EXEC_POINT', 'EVID_CMD_STRING_CONSTRUCTION', 'EVID_CMD_USER_PARAM_MAPPING'],
  SSRF: ['EVID_SSRF_URL_CONSTRUCTION', 'EVID_SSRF_USER_PARAM_MAPPING', 'EVID_SSRF_DNSIP_AND_INNER_BLOCK'],
  XSS: ['EVID_XSS_OUTPUT_POINT', 'EVID_XSS_USER_INPUT_INTO_OUTPUT', 'EVID_XSS_ESCAPE_OR_RAW_CONTROL'],
  PATH_TRAVERSAL: ['EVID_FILE_READ_SINK', 'EVID_FILE_PATH_CONSTRUCTION', 'EVID_FILE_USER_PARAM_MAPPING'],
  DESERIALIZATION: ['EVID_DESER_CALLSITE', 'EVID_DESER_INPUT_SOURCE', 'EVID_DESER_OBJECT_TYPE_MAGIC_TRIGGER_CHAIN'],
  AUTH_BYPASS: ['EVID_AUTH_CHECK_BYPASS', 'EVID_AUTH_TOKEN_DECODE_JUDGMENT', 'EVID_AUTH_PERMISSION_CHECK_EXEC'],
  XXE: ['EVID_XXE_PARSER_CALL', 'EVID_XXE_INPUT_SOURCE', 'EVID_XXE_ENTITY_DOCTYPE_SAFETY_AND_ECHO'],
  FILE_OPERATION: ['EVID_FILE_READ_SINK', 'EVID_FILE_PATH_CONSTRUCTION', 'EVID_FILE_USER_PARAM_MAPPING']
};

export const JAVA_AUTH_AUDIT_FRAMEWORK = `
【Java认证鉴权审计框架 — 来自 java-auth-audit】

审计 Java Web 应用的认证鉴权必须按以下层次进行：

1. URI 解析差异检测（最常见绕过根因）：
   - 检查鉴权代码使用的 URI 获取 API：getRequestURI() → ❌ 危险 / getServletPath() → ✅ 安全
   - 如果鉴权层和路由层使用不同的 URI API，存在绕过可能
   - 关键检查：Filter/Interceptor 中是否使用 getRequestURI() 的返回值做鉴权判断

2. 分号路径参数绕过：
   - Tomcat 中 getRequestURI() 返回 /admin;.js，getServletPath() 返回 /admin
   - 静态资源后缀白名单 + getRequestURI() → 可被 /admin;.js 绕过
   - Payload: /admin;.js, /admin;.css, /admin;jsessionid=xxx, /;/admin

3. 路径穿越绕过：
   - startsWith("/admin") 可被 /public/../admin 绕过
   - contains("/api/") 可被 %61 编码绕过
   - 必须检查路径是否经过 normalize() 处理

4. 框架特定检查：
   - Shiro < 1.5.2: /xxx/..;/admin (CVE-2020-1957)
   - Shiro < 1.6.0: /admin/;page (CVE-2020-13933)
   - Spring Security antMatchers: /admin/ 尾部斜杠绕过（改用 mvcMatchers）
   - Spring < 5.3: 后缀匹配 /admin.json 可绕过

5. 数据流分析（避免误报）：
   - 发现 contains()/startsWith() 模式后，必须追踪变量在匹配后如何使用
   - 检查是否有二次校验（Interceptor/Action层）
   - 区分"绕过登录检查"和"绕过权限检查"`;

export const JAVA_SQL_AUDIT_FRAMEWORK = `
【Java SQL注入审计框架 — 来自 java-sql-audit】

审计 Java SQL 注入必须以行为驱动而非命名模式：

1. 核心原则：不是问"方法叫什么名字"，而是问"方法做了什么"
   - 错误做法：仅搜索 addOrderBy/Pagination 等方法名
   - 正确做法：搜索 "ORDER BY" + 变量拼接行为

2. 框架感知检测：
   - JDBC: Statement.execute/executeQuery/executeUpdate + 字符串拼接
   - MyBatis: \${} 不安全拼接 vs #{} 安全参数绑定
   - Hibernate: createQuery/createNativeQuery + 字符串拼接 vs setParameter 参数绑定
   - JdbcTemplate: 字符串拼接 vs ? 占位符

3. ORDER BY 注入（最常被遗漏）：
   - 搜索 .getOrderBy()/.getSortField()/.getGroupBy() 调用
   - 检查 "ORDER BY" + 变量拼接（StringBuilder.append/String.format/字符串+）
   - 白名单校验：allowedColumns.contains(orderBy) 才算安全

4. 数据库分支分析（避免误报）：
   - 检查 isOracle()/isMySQL() 条件分支
   - 在某些数据库类型下代码路径不执行 → 降低风险级别
   - 标注为"Oracle-only"/"MySQL-only"而非通用

5. 参数类型与注入风险：
   - String 类型参数 → 高危，可注入任意SQL片段
   - Integer/Long/Boolean → 低风险，但 ORDER BY 字段仍可注入列名

6. 参数实际使用检查（参数可控性）：
   - 追踪参数从HTTP入口到SQL执行点的完整路径
   - 检查参数是否被硬编码覆盖 → 排除误报
   - 区分"参数传递到DAO层"和"参数实际拼接到SQL"`;

export const JAVA_PARAM_CONTROLLABILITY = `
【Java参数可控性分析框架 — 来自 java-route-tracer】

对每个漏洞进行参数实际使用检查，避免将"参数传递但未使用"误判为漏洞：

1. 覆盖类型判定：
   - 无覆盖：参数直接到达Sink → ✅ 完全可控
   - 无条件覆盖：x = "hardcoded" 不在if内 → ❌ 不可控
   - 空值保护覆盖：if (isEmpty(x)) x = default → ⚠️ 非空时可控
   - 白名单覆盖：if (!allowed.contains(x)) x = default → ⚠️ 白名单内可控
   - 安全检查覆盖：if (!isSafe(x)) x = safe → ⚠️ 绕过检查时可控

2. 硬编码覆盖检测（排除误报的关键）：
   - SQL中已硬编码 "ORDER BY id DESC" → page.orderBy参数未使用 → ❌ 非漏洞
   - 命令中已硬编码 "ls -la" → cmd参数未使用 → ❌ 非漏洞
   - 路径中已硬编码 "/tmp/fixed.txt" → path参数未使用 → ❌ 非漏洞

3. 分支条件追踪：
   - 识别环境/平台分支（isOracle/isMySQL）
   - 识别安全检查分支（isAllowed/isSafe）
   - 识别空值/异常分支（提前return）
   - 标注敏感操作在哪些分支中执行

4. 输出格式（可控性判定表）：
   | 参数 | Sink类型 | 覆盖类型 | 覆盖条件 | 可控性结论 | 可控场景 |
   - 可控性结论：✅完全可控 / ⚠️条件可控 / ❌不可控`;

export const JAVA_FRAMEWORK_DETECTION = `
【Java Web框架自动识别 — 来自 java-route-mapper】

审计 Java 项目时先识别框架，再针对性分析：

1. 框架识别特征：
   - Spring MVC: @Controller, @RequestMapping, @RestController
   - Spring Boot: @SpringBootApplication, application.properties/yml
   - Struts2: struts.xml, ActionSupport, .action 后缀
   - Servlet: web.xml, @WebServlet, HttpServlet
   - JAX-RS: @Path, @GET, @POST, @PathParam
   - CXF WebService: jaxws:endpoint, @WebService, cxf-servlet.xml

2. 配置文件定位：
   - Spring: application.yml, application.properties, SecurityConfig.java
   - Struts2: struts.xml, struts-*.xml, struts.properties
   - Servlet: web.xml, context.xml
   - MyBatis: mybatis-config.xml, *Mapper.xml
   - Hibernate: hibernate.cfg.xml, persistence.xml

3. 通配符路由识别：
   - Struts2: name="*_*" 双通配 → 必须展开为实际URL
   - Spring: @RequestMapping 路径变量 /api/{id}/**
   - Servlet: /api/* 通配 → 内部分发方法需识别

4. WebService完整方法输出：
   - 从applicationContext.xml读取 address 属性（唯一真实路径来源）
   - 不根据类名推断：UserServiceImpl → /UserService（错误！）
   - 反编译实现类提取所有public方法签名`;

export async function loadAuditKnowledge({ languages = [], vulnerabilityTypes = [], selectedSkillIds = [] } = {}) {
  const docsDir = path.join(process.cwd(), "docs");
  const gbtAuditDir = path.join(docsDir, "gbt-audit");
  const knowledge = {};
  const isGbtAudit = selectedSkillIds.includes('gbt-code-audit');

  // GBT 映射表（仅在 GBT 审计模式下加载）
  if (isGbtAudit) {
    try {
      const skillContent = await fs.readFile(path.join(gbtAuditDir, "skill.md"), "utf8");
      const lines = skillContent.split('\n');
      let inMappingTable = false;
      let mappingLines = [];

      for (const line of lines) {
        if (line.includes('| 语言') && line.includes('GB/T')) {
          inMappingTable = true;
        }
        if (inMappingTable) {
          mappingLines.push(line);
          if (line.trim() === '|' && mappingLines.length > 5) {
            break;
          }
        }
      }

      knowledge.gbtMapping = mappingLines.join('\n');
    } catch (error) {
      knowledge.gbtMapping = '';
    }
  } else {
    knowledge.gbtMapping = '';
  }

  // 语言审计要点（始终加载，按语言过滤）
  try {
    const workflowContent = await fs.readFile(path.join(gbtAuditDir, "workflow", "audit_workflow.md"), "utf8");
    const lines = workflowContent.split('\n');
    const languageSections = [];
    let capture = false;
    let section = [];

    const targetLanguages = languages.map(l => l.toLowerCase());
    const languageKeywords = {
      'python': '### Python 审计要点',
      'java': '### Java 审计要点',
      'cpp': '### C/C++ 审计要点',
      'c': '### C/C++ 审计要点',
      'csharp': '### C# 审计要点',
      'c#': '### C# 审计要点',
      'javascript': '### JavaScript 审计要点',
      'typescript': '### TypeScript 审计要点',
      'go': '### Go 审计要点',
      'ruby': '### Ruby 审计要点',
      'rust': '### Rust 审计要点',
      'php': '### PHP 审计要点'
    };

    for (const line of lines) {
      const matchedLang = targetLanguages.find(lang => line.includes(languageKeywords[lang]));
      if (matchedLang) {
        if (section.length > 0) {
          languageSections.push(section.join('\n'));
        }
        section = [line];
        capture = true;
      } else if (capture && line.startsWith('### ')) {
        languageSections.push(section.join('\n'));
        break;
      } else if (capture) {
        section.push(line);
      }
    }
    if (section.length > 0) {
      languageSections.push(section.join('\n'));
    }

    knowledge.languageAudit = languageSections.join('\n\n');
  } catch (error) {
    knowledge.languageAudit = '';
  }

  // GB/T 国标规则全文（仅在 GBT 审计模式下加载，按语言过滤）
  if (isGbtAudit) {
    const gbtReferences = [];
    const uniqueGbtFiles = new Set();

    const baseStandard = 'GBT_39412-2020.md';
    if (!uniqueGbtFiles.has(baseStandard)) {
      uniqueGbtFiles.add(baseStandard);
      try {
        const content = await fs.readFile(path.join(gbtAuditDir, "reference", baseStandard), "utf8");
        gbtReferences.push(`\n\n=== ${baseStandard.replace('.md', '')} (通用基线) ===\n\n${content}`);
      } catch (error) {}
    }

    for (const lang of languages) {
      const gbtFile = LANGUAGE_GBT_MAP[lang.toLowerCase()];
      if (gbtFile && gbtFile !== baseStandard && !uniqueGbtFiles.has(gbtFile)) {
        uniqueGbtFiles.add(gbtFile);
        try {
          const content = await fs.readFile(path.join(gbtAuditDir, "reference", gbtFile), "utf8");
          gbtReferences.push(`\n\n=== ${gbtFile.replace('.md', '')} (${lang}) ===\n\n${content}`);
        } catch (error) {}
      }
    }
    knowledge.gbtReferences = gbtReferences.join('\n');
  } else {
    knowledge.gbtReferences = '';
  }

  const vulnReferences = [];
  const uniqueVulnFiles = new Set();
  for (const vulnType of vulnerabilityTypes) {
    const vulnFile = VULNERABILITY_FILES[vulnType.toLowerCase()];
    if (vulnFile && !uniqueVulnFiles.has(vulnFile)) {
      uniqueVulnFiles.add(vulnFile);
      try {
        const content = await fs.readFile(path.join(gbtAuditDir, "vulnerabilities", vulnFile), "utf8");
        vulnReferences.push(`\n\n=== ${vulnFile.replace('.md', '')} ===\n\n${content}`);
      } catch (error) {
      }
    }
  }
  knowledge.vulnerabilityReferences = vulnReferences.join('\n');

  try {
    const qualityContent = await fs.readFile(path.join(gbtAuditDir, "workflow", "quality_standards.md"), "utf8");
    const lines = qualityContent.split('\n');
    const prohibitedSection = [];
    const remediationExamples = [];
    let captureProhibited = false;
    let captureExamples = false;

    for (const line of lines) {
      if (line.includes('### ❌ 禁止以下敷衍内容')) {
        captureProhibited = true;
        prohibitedSection.push(line);
      } else if (captureProhibited && line.startsWith('### ')) {
        captureProhibited = false;
      } else if (captureProhibited) {
        prohibitedSection.push(line);
      }

      if (line.includes('| 漏洞类型') && line.includes('合格修复方案')) {
        captureExamples = true;
        remediationExamples.push(line);
      } else if (captureExamples && line.trim() === '|') {
        captureExamples = false;
      } else if (captureExamples) {
        remediationExamples.push(line);
      }
    }

    knowledge.qualityStandards = {
      prohibited: prohibitedSection.join('\n'),
      examples: remediationExamples.join('\n')
    };
  } catch (error) {
    knowledge.qualityStandards = { prohibited: '', examples: '' };
  }

  // 加载框架特定安全知识
  knowledge.frameworkGuides = await loadFrameworkGuides(languages);
  knowledge.securityDomainGuides = await loadSecurityDomainGuides(vulnerabilityTypes);

  return knowledge;
}

const LANGUAGE_TO_FRAMEWORKS = {
  python: ['django.md', 'flask.md', 'fastapi.md'],
  java: ['spring.md', 'java_web_framework.md', 'mybatis_security.md'],
  javascript: ['express.md', 'koa.md', 'nest_fastify.md'],
  typescript: ['express.md', 'koa.md', 'nest_fastify.md'],
  go: ['gin.md'],
  php: ['laravel.md'],
  csharp: ['dotnet.md'],
  'c#': ['dotnet.md'],
  ruby: ['rails.md'],
  rust: ['rust_web.md'],
};

const ALWAYS_LOAD_SECURITY = [
  'business_logic.md',
  'authentication_authorization.md',
  'api_security.md',
  'file_operations.md',
];

const VULN_TO_DOMAIN_MAP = {
  'command_injection': ['input_validation.md'],
  'sql_injection': ['input_validation.md'],
  'code_injection': ['input_validation.md'],
  'xss': ['input_validation.md', 'frontend_frameworks.md'],
  'xxe': ['input_validation.md'],
  'template_injection': ['input_validation.md'],
  'spel_injection': ['input_validation.md'],
  'jndi_injection': ['input_validation.md'],
  'nosql_injection': ['input_validation.md'],
  'ssrf': ['api_security.md', 'input_validation.md'],
  'csrf': ['api_security.md'],
  'auth_bypass': ['authentication_authorization.md'],
  'idor': ['authentication_authorization.md'],
  'auth_missing': ['authentication_authorization.md'],
  'path_traversal': ['file_operations.md'],
  'file_upload': ['file_operations.md'],
  'file_read': ['file_operations.md'],
  'weak_crypto': ['cryptography.md'],
  'weak_hash': ['cryptography.md'],
  'deserialization': ['input_validation.md', 'api_security.md'],
  'hard_code_password': ['cryptography.md'],
  'open_redirect': ['api_security.md'],
  'ssti': ['input_validation.md'],
  'log_injection': ['logging_security.md'],
  'race_condition': ['race_conditions.md'],
  'cors_misconfiguration': ['frontend_frameworks.md'],
  'info_leak': ['logging_security.md'],
};

async function loadFrameworkGuides(languages) {
  const securityDir = path.join(process.cwd(), 'docs', 'security', 'frameworks');
  const guides = {};
  const loadedFiles = new Set();

  for (const lang of languages || []) {
    const normalized = lang.toLowerCase();
    const frameworkFiles = LANGUAGE_TO_FRAMEWORKS[normalized] || [];

    for (const file of frameworkFiles) {
      if (loadedFiles.has(file)) continue;
      loadedFiles.add(file);
      try {
        const content = await fs.readFile(path.join(securityDir, file), 'utf8');
        guides[file.replace('.md', '')] = content;
      } catch (error) {
        // file not found, skip
      }
    }
  }

  if (Object.keys(guides).length === 0) return '';

  const sections = [];
  for (const [name, content] of Object.entries(guides)) {
    sections.push(`\n\n=== ${name} (框架安全指南) ===\n\n${content.substring(0, 1500)}`);
  }
  return sections.join('\n');
}

async function loadSecurityDomainGuides(vulnerabilityTypes = []) {
  const securityDir = path.join(process.cwd(), 'docs', 'security', 'domains');
  const sections = [];
  const loadedFiles = new Set();

  // 始终加载核心安全域
  for (const file of ALWAYS_LOAD_SECURITY) {
    loadedFiles.add(file);
    try {
      const content = await fs.readFile(path.join(securityDir, file), 'utf8');
      sections.push(`\n\n=== ${file.replace('.md', '')} (安全域指南) ===\n\n${content.substring(0, 2500)}`);
    } catch (error) {
      // file not found, skip
    }
  }

  // 按漏洞类型加载相关安全域
  if (vulnerabilityTypes && vulnerabilityTypes.length > 0) {
    for (const vt of vulnerabilityTypes) {
      const domains = VULN_TO_DOMAIN_MAP[vt.toLowerCase()] || [];
      for (const file of domains) {
        if (loadedFiles.has(file)) continue;
        loadedFiles.add(file);
        try {
          const content = await fs.readFile(path.join(securityDir, file), 'utf8');
          sections.push(`\n\n=== ${file.replace('.md', '')} (安全域指南) ===\n\n${content.substring(0, 2000)}`);
        } catch (error) {
          // file not found, skip
        }
      }
    }
  }

  return sections.join('\n');
}

export async function buildSystemPrompt(selectedSkills, auditKnowledge = {}, languages = [], modelMaxTokens = 65536) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  // 使用精简模板系统作为基础（token 节省 ~75% vs 旧版全量拼接）
  let prompt;
  try {
    const { buildSlimSystemPrompt } = await import("./prompts/index.js");
    const slimBase = await buildSlimSystemPrompt({
      languages,
      isGbtAudit,
    });
    prompt = [slimBase];
    console.log('[LLM提示词] 使用精简模板系统 (v2)');
  } catch (err) {
    // 降级到旧版拼接（兼容性保留）
    console.warn('[LLM提示词] 精简模板加载失败，降级到旧版:', err.message);
    prompt = [
      "【角色】",
      "你是一个资深代码安全审计专家。对代码进行全面的安全审计，发现漏洞并提供修复建议。",
      "",
      "【行为准则】",
      "- 只输出 JSON 对象，不要输出额外说明",
      "- 如果证据不足，就降低置信度或不要报出该问题",
      "",
      REVIEW_PRIORITY_LAYERS,
      "",
      CORE_SECURITY_PRINCIPLES,
      RUNTIME_CONTEXT_AWARENESS,
      "",
      SEVERITY_CLASSIFICATION_GUIDE,
      FALSE_POSITIVE_KILL_SWITCH,
      FILE_VALIDATION_RULES,
      DE_DUPLICATION_RULES
    ];
  }

  try {
    const knowledgeContext = await withRetryWithFallback(
      () => ragService.buildAuditContext({
        language: languages?.[0],
        fileCount: 3
      }),
      () => {
        console.warn('[LLM审计] RAG服务不可用，使用降级方案');
        return null;
      },
      { maxAttempts: 2, baseDelay: 500 }
    );
    if (knowledgeContext) {
      prompt.push("", knowledgeContext);
    }
  } catch (error) {
    console.warn('[LLM审计] 获取 RAG 知识失败:', error);
  }

  if (isGbtAudit) {
    prompt.push(
      EVIDENCE_CONTRACT_GUIDE,
      DUAL_VERDICT_SYSTEM,
      AUDIT_OUTPUT_ENHANCEMENT,
      DEPENDENCY_INTERPRETATION_RULES,
      "",
      "【审计输出要求】",
      "",
      "- 必须按证据契约要求为每个发现附带 EVID_* 证据点",
      "- 必须按双轨判定体系标注每个发现为「确认风险」或「可疑风险」",
      "- 修复建议必须给出具体代码级方案，禁止使用空话"
    );

    if (auditKnowledge.gbtMapping) {
      prompt.push(
        "",
        "【国标映射表】（必须严格遵守）：",
        "---",
        auditKnowledge.gbtMapping,
        "---"
      );
    }

    if (auditKnowledge.languageAudit) {
      prompt.push(
        "",
        "【语言特定审计要点】（必须遵循）：",
        "---",
        auditKnowledge.languageAudit,
        "---"
      );
    }

    if (languages && languages.length > 0) {
      const langToExt = {
        'python': '.py', 'javascript': '.js', 'js': '.js',
        'typescript': '.ts', 'ts': '.ts', 'java': '.java',
        'go': '.go', 'golang': '.go', 'php': '.php',
        'c': '.c', 'cpp': '.cpp', 'c++': '.cpp',
        'csharp': '.cs', 'c#': '.cs', 'cs': '.cs',
        'ruby': '.rb', 'rust': '.rs', 'swift': '.swift',
        'kotlin': '.kt', 'scala': '.scala',
      };
      const langRules = [];
      for (const lang of languages) {
        const normalized = lang.toLowerCase();
        const extKey = langToExt[normalized] || (normalized.startsWith('.') ? normalized : `.${normalized}`);
        if (LANGUAGE_AUDIT_RULES[extKey] && !langRules.includes(extKey)) {
          langRules.push(extKey);
        }
      }
      if (langRules.length > 0) {
        prompt.push(
          "",
          "【语言特定输入源/危险点/安全信号识别规则】（必须遵循）：",
          "---",
          ...langRules.map(k => LANGUAGE_AUDIT_RULES[k]),
          "---"
        );
      }
    }

    if (languages && languages.length > 0) {
      const langContexts = [];
      for (const lang of languages) {
        const ctx = buildFullLanguageContext(lang);
        if (ctx && !langContexts.includes(ctx)) {
          langContexts.push(ctx);
        }
      }
      if (langContexts.length > 0) {
        prompt.push(
          "",
          "【语言安全适配器上下文】（辅助判定，增强审查准确性）：",
          "以下包含安全控制模式、危险API、URI解析绕过、鉴权绕过技术、路由注解、框架配置等信息。",
          "安全控制模式仅用于辅助判断代码是否存在防护措施，不是漏洞的直接证据。",
          "危险API和绕过技术是重点审查目标，发现相关模式应深入分析。",
          ...langContexts
        );
      }
    }

    if (auditKnowledge.gbtReferences) {
      prompt.push(
        "",
        "【国标规则详解】（参考使用）：",
        "---",
        auditKnowledge.gbtReferences,
        "---"
      );
    }

    if (auditKnowledge.vulnerabilityReferences) {
      prompt.push(
        "",
        "【漏洞类型详解】（参考使用）：",
        "---",
        auditKnowledge.vulnerabilityReferences,
        "---"
      );
    }

    if (auditKnowledge.qualityStandards?.prohibited) {
      prompt.push(
        "",
        "【修复方案禁止内容】（出现则验证失败）：",
        "---",
        auditKnowledge.qualityStandards.prohibited,
        "---"
      );
    }

    if (auditKnowledge.qualityStandards?.examples) {
      prompt.push(
        "",
        "【修复方案示例】（合格/不合格对比）：",
        "---",
        auditKnowledge.qualityStandards.examples,
        "---"
      );
    }

    if (auditKnowledge.frameworkGuides) {
      prompt.push(
        "",
        "【框架特定安全指南】（根据项目技术栈加载）：",
        "---",
        auditKnowledge.frameworkGuides,
        "---"
      );
    }

    if (auditKnowledge.securityDomainGuides) {
      prompt.push(
        "",
        "【安全域通用指南】（业务逻辑/认证鉴权/API安全等）：",
        "---",
        auditKnowledge.securityDomainGuides,
        "---"
      );
    }

    // 添加 Java 特定审计框架（来自 java-audit-skills）
    if (languages && languages.some(l => l.toLowerCase() === 'java')) {
      prompt.push(
        "",
        "【Java认证鉴权审计框架】（来自 java-auth-audit — 必须遵循）：",
        "---",
        JAVA_AUTH_AUDIT_FRAMEWORK,
        "---",
        "",
        "【Java SQL注入审计框架】（来自 java-sql-audit — 必须遵循）：",
        "---",
        JAVA_SQL_AUDIT_FRAMEWORK,
        "---",
        "",
        "【Java参数可控性分析框架】（来自 java-route-tracer — 用于避免误报）：",
        "---",
        JAVA_PARAM_CONTROLLABILITY,
        "---",
        "",
        "【Java Web框架自动识别】（来自 java-route-mapper）：",
        "---",
        JAVA_FRAMEWORK_DETECTION,
        "---"
      );
    }
  }

  prompt.push("");
  prompt.push("关注的审计 Skill：");
  const skills = selectedSkills.map((skill) => `- ${skill.name}: ${skill.reviewPrompt}`).join("\n");
  prompt.push(skills);

  // System Prompt 总量控制：超过 30K tokens 时渐进裁剪
  const fullPrompt = prompt.join("\n");
  const { estimateTokens } = await import("../utils/contextManager.js");
  const totalTokens = estimateTokens ? estimateTokens(fullPrompt) : fullPrompt.length / 2;
  const MAX_SYSTEM_TOKENS = Math.min(80000, Math.max(30000, Math.floor(modelMaxTokens * 0.35)));

  if (totalTokens > MAX_SYSTEM_TOKENS) {
    console.warn(`[LLM提示词] System Prompt 过大 (${totalTokens} tokens)，执行渐进裁剪`);
    
    // 策略：裁剪 RAG 知识段（保留核心检测规则和 Checklist）
    let trimmed = fullPrompt;
    
    // 1. 裁剪安全域指南（保留前 40%）
    if (trimmed.includes("安全域通用指南")) {
      const parts = trimmed.split("安全域通用指南");
      if (parts.length > 1) {
        const domainContent = parts[1].split("---")[1] || "";
        if (domainContent.length > 2000) {
          const shortened = domainContent.substring(0, Math.floor(domainContent.length * 0.4));
          trimmed = parts[0] + "安全域通用指南（已裁剪至核心内容）\n---\n" + shortened + "\n---" + parts[1].substring(parts[1].indexOf("---", parts[1].indexOf("---") + 1));
        }
      }
    }
    
    // 2. 裁剪框架安全指南（保留前 30%）
    if (trimmed.includes("框架特定安全指南")) {
      const parts = trimmed.split("框架特定安全指南");
      if (parts.length > 1) {
        const frameworkContent = parts[1].split("---")[1] || "";
        if (frameworkContent.length > 1500) {
          const shortened = frameworkContent.substring(0, Math.floor(frameworkContent.length * 0.3));
          trimmed = parts[0] + "框架特定安全指南（已裁剪至核心内容）\n---\n" + shortened + "\n---" + parts[1].substring(parts[1].indexOf("---", parts[1].indexOf("---") + 1));
        }
      }
    }
    
    const newTokens = estimateTokens ? estimateTokens(trimmed) : trimmed.length / 2;
    console.log(`[LLM提示词] 裁剪后: ${newTokens} tokens (从 ${totalTokens})`);
    return trimmed;
  }

  return fullPrompt;
}

export function buildUserPrompt({ project, selectedSkills, heuristicFindings, batch, codeContext = "", incrementalPrompt = "", validationFeedback = {}, codeGraphContext = null }) {
  const gbtSkill = selectedSkills.find(skill => skill.id === "gbt-code-audit");
  const isGbtAudit = gbtSkill !== undefined;

  let prompt = [
    `项目名称：${project.name}`,
    `审计镜像路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
    `来源模式：${project.sourceType}`
  ];

  if (codeGraphContext) {
    const graphParts = ["", "【代码知识图谱分析】"];
    
    if (codeGraphContext.entryPoints && codeGraphContext.entryPoints.length > 0) {
      graphParts.push(`入口点（${codeGraphContext.entryPoints.length}个）：`);
      codeGraphContext.entryPoints.forEach((ep, i) => {
        graphParts.push(`  ${i + 1}. ${ep.name} (${ep.file})`);
      });
    }
    
    if (codeGraphContext.hubNodes && codeGraphContext.hubNodes.length > 0) {
      graphParts.push(`\n热点节点（高连接度，${codeGraphContext.hubNodes.length}个）：`);
      codeGraphContext.hubNodes.forEach((hub, i) => {
        graphParts.push(`  ${i + 1}. ${hub.name} (${hub.file}) - 连接度: ${hub.degree}`);
      });
    }
    
    if (codeGraphContext.criticalPaths && codeGraphContext.criticalPaths.length > 0) {
      graphParts.push(`\n关键执行路径（${codeGraphContext.criticalPaths.length}条）：`);
      codeGraphContext.criticalPaths.forEach((path, i) => {
        graphParts.push(`  ${i + 1}. ${path}`);
      });
    }
    
    if (codeGraphContext.architectureOverview) {
      const arch = codeGraphContext.architectureOverview;
      graphParts.push(`\n架构概览：`);
      graphParts.push(`  - 节点总数：${arch.totalNodes || 0}`);
      graphParts.push(`  - 边总数：${arch.totalEdges || 0}`);
      graphParts.push(`  - 模块社区数：${arch.communities || 0}`);
      
      if (arch.warnings && arch.warnings.length > 0) {
        graphParts.push(`\n架构警告：`);
        arch.warnings.forEach((warn, i) => {
          graphParts.push(`  ⚠️ ${warn}`);
        });
      }
    }
    
    prompt.push(graphParts.join("\n"));
  }

  if (codeContext) {
    prompt.push(codeContext);
  }

  if (incrementalPrompt) {
    prompt.push("", incrementalPrompt);
  }

  if (validationFeedback && Object.keys(validationFeedback).length > 0) {
    const feedbackParts = [];
    feedbackParts.push("【验证反馈 - 上一批次审计结果】");

    if (validationFeedback.hallucinations && validationFeedback.hallucinations.length > 0) {
      feedbackParts.push(`⚠️ 误报发现（${validationFeedback.hallucinations.length}个）：`);
      validationFeedback.hallucinations.slice(0, 3).forEach((h, i) => {
        feedbackParts.push(`  ${i + 1}. ${h.title || h.vulnId} - ${h.reason || '行号验证失败'}`);
      });
    }

    if (validationFeedback.correctedLines && validationFeedback.correctedLines.length > 0) {
      feedbackParts.push(`📝 行号修正（${validationFeedback.correctedLines.length}个）：`);
      feedbackParts.push("  请注意：之前报告的部分行号需要修正，请仔细验证");
    }

    if (validationFeedback.missingEvidence && validationFeedback.missingEvidence.length > 0) {
      feedbackParts.push(`🔍 证据缺失（${validationFeedback.missingEvidence.length}个）：`);
      validationFeedback.missingEvidence.slice(0, 3).forEach((m, i) => {
        feedbackParts.push(`  ${i + 1}. ${m.vulnId} 缺少证据点: ${m.missing.join(', ')}`);
      });
    }

    if (feedbackParts.length > 1) {
      prompt.push("", feedbackParts.join("\n"));
    }
  }

  if (isGbtAudit) {
    prompt = prompt.concat([
      "",
      "【审计任务】",
      "",
      "📋 项目信息：",
      `- 项目名称：${project.name}`,
      `- 审计路径：${project.localPath || path.join("workspace", "downloads", project.id)}`,
      `- 来源模式：${project.sourceType}`,
      "",
      "🔴 核心要求（再次强调）：",
      "- 两步审计：① 先逐条验证下方快速扫描发现（确认/降级/误报）② 再独立搜索清单外的其他安全问题",
      "- 🔴 强制覆盖：必须审计本批次每一个文件！每个文件至少输出一条 finding（即使只是 Low 级别标记为 safe）。禁止跳过任何文件",
      "- 准确行号：需要验证行号，禁止凭记忆填写",
      "",
      "📝 输出要求：",
      "🔴 只输出 JSON，不得在 JSON 代码块前后添加任何说明文字、分析摘要或问候语",
      "- 严格返回 JSON 格式，用 ```json 代码块包裹",
      "- 每个字段必须有值，禁止 null 或 undefined",
      "- evidence/impact 字数≥20，remediation 字数≥30",
      "- remediation 必须包含具体代码示例或 API 名称",
      "- score 范围 0-100，根据漏洞严重程度和数量计算",
      "- summary 提供整体评价，包括审计范围和风险等级",
      "",
      "📋 JSON 格式示例："
    ]);

    prompt.push(
      '```json',
      '{',
      '  "findings": [',
      '    {',
      '      "title": "身份认证绕过漏洞",',
      '      "severity": "high",',
      '      "confidence": 0.9,',
      '      "location": "src/controllers/AuthController.java:45",',
      '      "skillId": "gbt-code-audit",',
      '      "vulnType": "AUTH_BYPASS",',
      '      "cwe": "CWE-287",',
      '      "gbtMapping": "GB/T34944-6.3.1.2 身份鉴别被绕过；GB/T39412-6.3.1.2 身份鉴别被绕过",',
      '      "cvssScore": 8.5,',
      '      "language": "java",',
      '      "evidence": "代码中 adminCheck 方法仅验证用户名是否为 admin，未验证密码。攻击者构造用户名 admin 即可绕过认证。",',
      '      "impact": "攻击者可绕过身份认证访问管理功能，导致系统被完全控制，用户数据泄露。",',
      '      "remediation": "使用 Spring Security 的 BCryptPasswordEncoder 加密密码：BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(); boolean matches = encoder.matches(rawPassword, encodedPassword);",',
      '      "safeValidation": "验证登录接口是否正确调用 passwordEncoder.matches() 方法，检查数据库中密码是否为 BCrypt 格式（60 字符）",',
      '      "evidenceLabel": "CONFIRMED",',
      '      "type": "认证绕过",',
      '      "attackVector": "攻击者通过 /login 端点，在 username 参数中输入 admin，绕过密码校验直接获取管理员权限",',
      '      "exploitPrerequisites": "无需认证，端点对外暴露",',
      '      "attackPathPriority": "P0",',
      '      "attackPathScore": 12,',
      '      "killSwitchInfo": "未触发 Kill Switch — 无 enum 限制、无 @Valid、无全局 Filter、无参数化查询",',
      '      "retestChecklist": ["验证 POST /login 使用 BCrypt 校验密码", "确认 username=admin&password=wrong 返回 401"],',
      '      "description": "adminCheck 方法仅比较用户名，未验证密码，导致任意用户可构造用户名 admin 绕过认证",',
      '      "source": "username",',
      '      "sink": "adminCheck()",',
      '      "callChain": [{"method": "login", "file": "AuthController.java", "line": 45, "code": "if(username.equals(\\\"admin\\\")) {"}]',
      '    }',
      '  ],',
      '  "score": 75,',
      '  "summary": "本次审计共检查了 15 个源代码文件，发现 3 个安全问题（1个高危，2个中危）。整体安全状况中等，建议优先修复身份认证相关漏洞。代码质量较好，未发现严重的性能问题。"',
      '}',
      '```',
      "",
      "【Source→Sink 追踪要求】",
      "- 对于注入类漏洞（SQL注入、命令注入等），必须填写 source 和 sink 字段",
      "- source: 用户输入变量名或参数名",
      "- sink: 危险函数或方法名",
      "- callChain: 从 source 到 sink 的调用链，包含 method、file、line、code 字段",
      "- 如果无法确定完整调用链，callChain 可以为空数组",
      "",
      "【净化措施检查】",
      "- 检查是否存在 PreparedStatement、输入验证、编码等净化措施",
      "- 如果发现有效净化措施，降低漏洞严重程度或标记为误报",
      "- 在 evidence 中说明检查过程和结果"
    );

    const hasBatchHeuristics = heuristicFindings && heuristicFindings.length > 0;
    if (hasBatchHeuristics) {
      prompt.push(
        "",
        "【快速扫描发现 — 本批文件相关的启发式发现（必须逐条验证）】",
        "",
        `以下 ${heuristicFindings.length} 条由快速扫描在本批文件中发现，你必须逐条审查并给出明确判定：`,
        "",
        heuristicFindings.map((f, i) =>
          `${i + 1}. ${f.title}  @ ${f.location || 'n/a'}  [${f.vulnType || '?'}, ${f.severity || '?'}]`
        ).join('\n'),
        "",
        "对每条判定：确认（报告）| 降级（报告+降级理由）| 误报（仅 summary 中说明原因）",
        "重要：清单是审计起点。在此基础上还必须独立发现清单以外的任何安全问题。"
        );
    }
  } else {
    const skills = selectedSkills.map((skill) => `${skill.id}: ${skill.description}`).join("\n");

    const hasHeuristicContext = heuristicFindings && heuristicFindings.length > 0;

    prompt = prompt.concat([
      "",
      `已启用 Skill：\n${skills}`,
      "",
      hasHeuristicContext
        ? `【审计必审清单 — 以下快速扫描结果必须逐一审查并给出判定】

以下 ${heuristicFindings.length} 个可疑模式由快速扫描预处理发现。你必须逐条审查并给出明确判定：

${heuristicFindings.slice(0, 15).map((f, i) => `${i + 1}. ${f.title} @ ${f.location || 'n/a'} [${f.vulnType || 'unknown'}, ${f.severity || '?'}] → 判定: [ ]确认 [ ]降级 [ ]误报`).join('\n')}

${heuristicFindings.length > 15 ? `...(共 ${heuristicFindings.length} 条，以上显示前 15 条核心项)` : ''}

对每条清单项的判定要求：
- 确认：找到完整的 Source→Transfer→Sink 证据链，在 findings 中报告
- 降级：存在但不严重（如有防护、需认证等）→ 仍须在 findings 中报告！severity 下调一级 + 填写 killSwitchInfo
- 误报：不存在、不可达或不构成漏洞 → 不在 findings 中报告，但必须在 summary 中逐一列出每条误报判定及其原因

🔴 强制覆盖率：清单中的所有类型（COMMAND_INJECTION, SQL_INJECTION, SQL_INJECTION_MYBATIS, DESERIALIZATION, SSRF, XXE, PATH_TRAVERSAL, SPEL_INJECTION, LOG_INJECTION, OPEN_REDIRECT）必须全部出现在 findings 或 summary 中。不得跳过任何类型。

🔴 SQL 注入特殊要求：清单中标记了 SQL_INJECTION 和 SQL_INJECTION_MYBATIS 的项是最高风险，你必须逐条审查代码中是否真的使用了 PreparedStatement/#{} 参数化还是 \${} 拼接。如果确实是安全的参数化查询，在 findings 中以 Low 级别报告并注明 Kill Switch 原因，不得直接丢弃。

⚠️ 报告粒度要求：
- 不同端点的同类漏洞必须分别报告（如 /RCE/ProcessBuilder 和 /RCE/Runtime 的命令注入是两个独立发现）
- 不同文件的不同 sink 函数 → 分别报告
- 同一文件内多个同类模式 → 可合并，但必须在 findings 中包含所有受影响位置

重要：清单是审计起点而非终点。在此基础上还需独立发现清单以外的任何安全问题。`
        : "快速扫描未发现可疑模式，请独立进行全面审计，发现所有安全问题。",
      "",
      "【重要】LLM 自主审计要求：",
      "- 必须先逐一审查上述清单，再独立探索其他安全问题",
      "- 🔴 强制覆盖：必须审计本批次每一个文件！每个文件至少输出一条 finding。如文件无漏洞则输出一条 Low 级别 finding 标注 safe。禁止跳过任何文件",
      "- 可以发现任何类型的安全漏洞，不限于上述Skill列表",
      "- 包括但不限于：注入漏洞、XSS、CSRF、SSRF、路径遍历、敏感信息泄露、",
      "  认证绕过、访问控制、加密问题、反序列化、API安全、配置错误等",
      "- 每个漏洞都必须独立验证行号",
      "- 对清单中误判为漏洞的项，在 summary 中说明误判原因",
      "",
      "【输出方式】使用 write_finding 工具逐一报告发现，每发现一个问题立即调用。不要等到最后攒在一起输出 JSON。",
      "🔴 强制覆盖：本批次每个文件至少调用一次 write_finding。无漏洞的文件输出 severity=low，evidence 写明「本文件未发现可利用漏洞」。"
    ]);
  }

  const snippets = batch.map((file) => {
    const fileLabel = file.chunkLabel || file.relativePath;
    return `\n<!-- ⚠️ 必须审查此文件：${fileLabel} — 不可跳过，至少输出一条 finding -->\nFILE: ${fileLabel}\n\`\`\`${file.language}\n${file.content}\n\`\`\``;
  }).join("\n");
  prompt.push("");
  prompt.push(snippets);

  return prompt.join("\n\n");
}

export function buildToolEnabledUserPrompt({ project, batch, heuristicFindings, incrementalPrompt = "" }) {
  const fileList = batch.map(f => {
    const lines = (f.content || '').split('\n').length;
    const size = (f.content || '').length;
    return `  ${f.relativePath}  (${f.language || '?'}, ${lines}行, ${size}字符)`;
  }).join('\n');

  const parts = [
    `项目名称：${project.name}`,
    `审计路径：${project.localPath || ""}`,
    ``,
    `【本批审计文件清单（共 ${batch.length} 个）】`,
    `请使用 read_file 工具逐文件审计。必须对清单中的每个文件都调用 read_file 完整读取，不要跳过任何文件。可先用 search_code 搜索危险模式（exec、eval、Statement、ProcessBuilder等），再逐文件读取全文审计。`,
    ``,
    fileList,
  ];

  if (heuristicFindings && heuristicFindings.length > 0) {
    parts.push(
      ``,
      `【快速扫描发现 — 必须逐条验证（共 ${heuristicFindings.length} 条）】`,
      heuristicFindings.map((f, i) =>
        `${i + 1}. ${f.title}  @ ${f.location || '?'}  [${f.vulnType || '?'}, ${f.severity || '?'}]`
      ).join('\n'),
      ``,
      `对每条判定：确认（报告）| 降级（报告+降级理由）| 误报（仅 summary 中说明）`,
    );
  }

  if (incrementalPrompt) {
    parts.push('', incrementalPrompt);
  }

  parts.push(
    ``,
    `【审计流程】`,
    `1. 用 search_code 搜索危险模式: Runtime.getRuntime|ProcessBuilder|Statement\\.execute|createQuery|ObjectInputStream|XMLDecoder|\\$\\{|\.exec\(|\.eval\(|\.lookup\(`,
    `2. 对清单中的每个文件，用 read_file 完整读取全文（不要只读部分行号）`,
    `3. 逐条验证快速扫描发现，判断真伪`,
    `4. 完成后输出 JSON 格式 findings`,
    ``,
    `【输出格式】`,
    `严格返回 JSON，用 \`\`\`json 代码块包裹，格式：`,
    `{"findings": [{"title": "...", "severity": "critical|high|medium|low", "confidence": 0.9, "location": "path/to/File.java:42", "skillId": "gbt-code-audit", "vulnType": "SQL_INJECTION", "cwe": "CWE-89", "evidence": "代码中...", "impact": "后果...", "remediation": "修复...", "safeValidation": "验证..."}], "score": 75, "summary": "整体评价"}`,
  );

  return parts.join('\n');
}

export function getAuditToolDefinitions() {
  return [
    {
      type: "function",
      function: {
        name: "read_file",
        description: "读取项目源代码文件。传入相对路径，返回内容、行数。",
        parameters: {
          type: "object",
          properties: {
            file_path: { type: "string", description: "相对于项目根目录的路径，如 com/best/hello/controller/Login.java" }
          },
          required: ["file_path"]
        }
      }
    },
    {
      type: "function",
      function: {
        name: "search_code",
        description: "在项目源码中搜索关键词，返回匹配行及位置。搜索是大小写敏感的文本匹配，建议使用简短关键词如 'ProcessBuilder'、'Statement'、'exec'、'createQuery'。",
        parameters: {
          type: "object",
          properties: {
            query: { type: "string", description: "搜索关键词，如 'ProcessBuilder'、'Runtime.getRuntime'" },
            file_pattern: { type: "string", description: "限定文件类型，如 '*.java'，可选" }
          },
          required: ["query"]
        }
      }
    },
    {
      type: "function",
      function: {
        name: "list_files",
        description: "列出项目根目录下所有源代码文件。",
        parameters: {
          type: "object",
          properties: {}
        }
      }
    },
    {
      type: "function",
      function: {
        name: "write_finding",
        description: "记录一个安全发现。每发现一个问题就立即调用这个工具记录下来，不要把所有发现攒到最后输出。",
        parameters: {
          type: "object",
          properties: {
            title: { type: "string", description: "漏洞标题，简洁描述" },
            severity: { type: "string", description: "严重等级", enum: ["critical", "high", "medium", "low"] },
            location: { type: "string", description: "文件:行号，如 com/example/Login.java:42" },
            vulnType: { type: "string", description: "漏洞类型，如 SQL_INJECTION / COMMAND_INJECTION / SSRF / ..." },
            cwe: { type: "string", description: "CWE 编号，如 CWE-89" },
            evidence: { type: "string", description: "漏洞证据：代码上下文和漏洞分析，至少20字" },
            impact: { type: "string", description: "潜在影响" },
            remediation: { type: "string", description: "修复方案，至少15字" },
            safeValidation: { type: "string", description: "验证方法，可选" }
          },
          required: ["title", "severity", "location", "vulnType", "evidence", "remediation"]
        }
      }
    }
  ];
}

export function createEnhancedPrompt(options = {}) {
  const {
    includeContextAnalysis = true,
    includeBusinessLogic = true,
    includeAttackChain = true,
    strictMode = true
  } = options;

  const enhancements = [];

  if (includeContextAnalysis) {
    enhancements.push(`
【上下文分析要求】
- 分析数据流：从用户输入到危险函数的完整路径
- 识别安全边界：信任边界、输入验证点、输出编码
- 评估验证有效性：验证是否充分、是否存在绕过
`);
  }

  if (includeBusinessLogic) {
    enhancements.push(`
【业务逻辑漏洞检测】
- 状态机漏洞：订单状态、支付流程、权限状态
- 条件竞争：并发场景下的状态不一致
- 水平越权：用户间数据访问
- 垂直越权：普通用户访问管理功能
`);
  }

  if (includeAttackChain) {
    enhancements.push(`
【攻击链分析】
- 单一漏洞利用链：入口点 → 传播路径 → 最终影响
- 组合漏洞：多个低危漏洞组合成高危攻击
- 攻击复杂度：利用难度、所需权限、影响范围
`);
  }

  if (strictMode) {
    enhancements.push(`
【严格模式】
- 每发现必须包含具体代码行号
- evidence 必须包含问题代码片段
- remediation 必须包含可执行的修复代码
- 禁止报告未经验证的猜测
`);
  }

  return enhancements.join('\n');
}

export function createIncrementalAuditPrompt(changedFiles) {
  return `
【增量审计任务】
仅审计以下变更文件：
${changedFiles.map(f => `- ${f}`).join('\n')}

变更文件需要重点关注：
1. 新增的危险函数调用
2. 修改的认证/授权逻辑
3. 变化的数据验证流程
4. 新的外部输入处理

其他文件如有严重问题会通过上下文分析被发现。
`;
}

// ============================================================
// 对抗性验证提示词 (参考 E:\code\audit\prompts\03-validate.md)
// ============================================================

// ============================================================
// Trace 可达性追踪提示词 (参考 E:\code\audit\prompts\06-trace.md)
// ============================================================

export const TRACE_USER_PROMPT = `
【待追踪发现】
- finding_id: {finding_id}
- 文件: {file}
- 行范围: {line_start}-{line_end}
- 漏洞类型: {vuln_class}
- 严重性: {severity}
- 描述: {description}
- 证据代码片段: {evidence_snippet}

【入口点信息（来自Recon）】
{entry_points_info}

【项目路径】{repo_path}

请追踪此sink是否能从外部入口点到达。输出JSON格式的追踪结果。
`;

// ============================================================
// Gapfill 覆盖率提示词 (参考 E:\code\audit\prompts\04-gapfill.md)
// ============================================================

export const GAPFILL_COVERAGE_PROMPT = `
【覆盖率分析角色】

你是覆盖率分析员。审计员倾向于漂向他们已经发现的攻击类别——
一旦找到SQL注入，后续二十个审查都像SQL注入。你的任务是反推：
识别**没有**被检查的内容，创建将审计员引向未检查部分的新任务。

# 方法

1. 构建覆盖率矩阵：subsystem × attack_class。
   标记已完成任务覆盖的格子；其他都是候选
2. 聚合已完成任务的 gaps_observed。每个gap都是一个
   区域被打开但未完成的线索
3. 选择候选格子，当：
   - 子系统出现在 gaps_observed 中，**或**
   - 子系统尚未有发现（覆盖不足），**或**
   - 攻击类别尚未在此子系统上尝试过且有合理适用性
4. 对每个选项，构建一个精准的审查任务

# 约束
- 不要重新发出已运行过的 task_id
- 不要超过 max_new_tasks 限制
- 任务必须遵循窄域规则：一个攻击类别、具体文件、scope_hint 中的明确信任边界
- new_tasks[].task_id 以 t_gf_ 开头
`;

// ============================================================
// Feedback 同类发现提示词 (参考 E:\code\audit\prompts\07-feedback.md)
// ============================================================

// ============================================================
// 严重性保守主义护栏 (注入到现有提示词)
// ============================================================

