## 检测模式速查（Source → Sink）

对每种语言的每个漏洞类型，按 **输入源 → 危险 API → 安全信号** 三段式快速判定。
看到 Source 进入 Sink 且无 Safety 信号 → 优先确认风险。
有 Safety 信号 → 降级但必须仍报告。

### Java
| 漏洞 | Source（输入源） | Sink（危险 API） | Safety（安全信号） |
|------|-----------------|------------------|-------------------|
| 命令注入 | request.getParameter, @RequestParam, @PathVariable, @RequestBody | Runtime.exec(), ProcessBuilder | — |
| SQL 注入 | 同上 | Statement/JdbcTemplate 拼接, MyBatis `${}`, HQL 拼接 | PreparedStatement, MyBatis `#{}`, JPA `:param` |
| 路径遍历 | 同上 + MultipartFile 文件名 | FileInputStream/FileOutputStream(用户可控路径) | Paths.get(), toRealPath(), normalize() |
| SSRF | 同上 | HttpURLConnection, RestTemplate, WebClient(用户可控 URL) | 域名白名单, 内网地址过滤 |
| 反序列化 | @RequestBody | ObjectInputStream, XMLDecoder, XStream, Jackson enableDefaultTyping, Fastjson parseObject | 类型白名单, 安全配置 |
| 代码注入 | 同上 | ScriptEngine.eval(), GroovyShell.evaluate(), SpEL ExpressionParser | 表达式沙箱, 输入白名单 |
| JNDI 注入 | 同上 | InitialContext.lookup(用户输入) | 固定 JNDI 名称 |
| SSTI | @RequestParam, @PathVariable | Thymeleaf 视图名拼接, FreeMarker/Velocity 模板字符串 | 模板路径来自文件 |
| XXE | @RequestBody | XMLReader, SAXReader, SAXBuilder, DocumentBuilder(未禁用外部实体) | 禁用 DTD/外部实体 |
| XSS | @RequestParam | 用户输入直接写入响应体(`return content`) | HTML 实体编码 |
| 认证绕过 | — | 缺少 @PreAuthorize 的敏感端点, 客户端可控的头(X-Forwarded-For)做 IP 校验 | Spring Security 全局拦截器 |
| 硬编码凭据 | — | password/secret/api_key 字面量 | 环境变量/KMS 获取 |
| 文件上传 | MultipartFile, @RequestParam("file") | getOriginalFilename()拼路径, transferTo(), FileOutputStream(用户可控文件名) | UUID重命名, 白名单扩展名+MIME, 上传目录禁用脚本执行 |
| CORS | — | Access-Control-Allow-Origin 反射 Origin 头 + allowCredentials:true | 固定白名单 |

⚠️ CORS判定：Origin 反射 AND allowCredentials=true 同时满足才报；仅反射 Origin 不报。

### JavaScript / TypeScript
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | req.query, req.body, req.params | child_process.exec()/spawn()/execSync() | execFile() + args 数组 |
| SQL 注入 | 同上 | mysql.query(拼接), sequelize.query(拼接) | mysql2.execute(), sequelize bind, Prisma ORM |
| 路径遍历 | 同上 | fs.readFile/writeFile/createReadStream(用户可控路径) | path.resolve()+白名单 |
| SSRF | 同上 | fetch/axios/http.get(用户可控 URL) | URL 白名单 |
| 代码注入 | 同上 | eval(), new Function(), vm.runInNewContext | — |
| XSS | 同上 | innerHTML, dangerouslySetInnerHTML, document.write | DOMPurify, textContent, React 自动转义 |
| NoSQL 注入 | 同上 | MongoDB find/$where, mongoose 查询对象拼接 | mongoose schema 校验 |
| 原型链污染 | req.body | Object.assign, _.merge, 展开运算符 | Object.create(null), __proto__ 过滤 |

### Python
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | request.args/form/json, input() | os.system(), subprocess(shell=True) | subprocess.run(args=[]) |
| SQL 注入 | 同上 | 字符串拼接 SQL | 参数化(sqlite3 ?, psycopg2 %s, SQLAlchemy bind) |
| 代码注入 | 同上 | eval(), exec(), compile() | ast.literal_eval |
| 反序列化 | 同上 | pickle.load/loads, yaml.load(非safe_load) | yaml.safe_load, json.loads |
| 路径遍历 | 同上 | open/Path.open/read_text(用户可控) | Path.resolve() |
| SSTI | 同上 | render_template_string(用户输入) | 模板来自文件 |
| SSRF | 同上 | requests.get/httpx.get(用户可控 URL) | URL 白名单 |

### Go
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | r.URL.Query(), c.Query/PostForm(), BindJSON | exec.Command("sh","-c",用户输入) | exec.Command(args 数组) |
| SQL 注入 | 同上 | db.Query/db.Exec(拼接 SQL) | 占位符(?/$1) |
| 路径遍历 | 同上 | os.Open/Create(用户可控) | filepath.Clean/Join |
| XSS | 同上 | template.HTML(用户输入) | html/template(自动转义) |
| SSRF | 同上 | http.Get/Post(用户可控 URL) | URL 白名单 |

### PHP
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | $_GET, $_POST, $_REQUEST | system/exec/shell_exec/passthru | escapeshellcmd/arg |
| SQL 注入 | 同上 | mysqli_query(拼接), PDO::query(拼接) | PDO::prepare + bindValue |
| 文件包含 | 同上 | include/require(动态路径) | 白名单, basename |
| 反序列化 | 同上 | unserialize(用户输入) | json_decode |

### C / C++
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | argv, getenv, socket 输入 | system/popen/execl | — |
| 缓冲区溢出 | 同上 | sprintf/strcpy/strcat/gets(无边界) | snprintf/strncpy(有边界) |
| 路径遍历 | 同上 | fopen/open(用户可控路径) | realpath |

### C# (.NET)
| 漏洞 | Source | Sink | Safety |
|------|--------|------|--------|
| 命令注入 | Request.Query/Form/Body | Process.Start(用户输入) | ProcessStartInfo + args |
| SQL 注入 | 同上 | SqlCommand 拼接 | SqlParameter |
| 路径遍历 | 同上 + IFormFile | File.ReadAllText/WriteAllText(用户可控) | Path.GetFullPath/Combine |
| SSRF | 同上 | HttpClient.GetAsync(用户可控 URL) | URL 白名单 |
| 反序列化 | 同上 | BinaryFormatter, SoapFormatter | 类型白名单 |

## 通用判定规则
- Source 进入 Sink 且无 Safety → 优先确认风险
- 有 Safety 信号 → 降级为 Low/Medium（**必须仍报告**，在 killSwitchInfo 中说明原因）
- 仅 import 未调用 → 不报
- 测试代码/示例代码 → 不报
- 先 sanitize 后拼接 → sanitize 可能被绕过，仍需标记
