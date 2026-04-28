import { KnowledgeDocument, KnowledgeCategory, Severity } from './base.js';

const SQL_INJECTION = new KnowledgeDocument({
  id: 'vuln_sql_injection',
  title: 'SQL Injection',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['sql', 'injection', 'database', 'sqli', 'sql注入'],
  severity: Severity.CRITICAL,
  cweIds: ['CWE-89'],
  owaspIds: ['A03:2021'],
  gbtMapping: 'GB/T34944-6.1.1.1 未使用参数化查询;GB/T39412-6.1.1.1 SQL注入',
  content: `
SQL注入是一种代码注入技术，攻击者通过在应用程序查询中插入恶意SQL代码来操纵数据库。

## 危险模式

### Java/C#/C++
// 危险 - 字符串拼接
String query = "SELECT * FROM users WHERE id = " + userId;
String query = "SELECT * FROM users WHERE name = '" + name + "'";

// 危险 - Statement 而非 PreparedStatement
Statement stmt = conn.createStatement();
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

### Python
// 危险 - 字符串拼接
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

// 危险 - ORM原始查询
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")

### JavaScript/Node.js
// 危险
const query = \`SELECT * FROM users WHERE id = \${userId}\`;
connection.query("SELECT * FROM users WHERE name = '" + name + "'");

## 安全实践
1. 使用参数化查询/预编译语句
2. 使用ORM框架的安全API
3. 输入验证和类型检查
4. 最小权限原则
5. 使用存储过程

## 修复示例
// Java - 安全
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
pstmt.setInt(1, userId);

// Python - 安全
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

// JavaScript - 安全
const query = 'SELECT * FROM users WHERE id = ?';
connection.query(query, [userId]);

## 验证方法
1. 尝试单引号 ' 触发语法错误
2. 使用 OR 1=1 测试布尔注入
3. 使用 SLEEP() 测试时间盲注
`
});

const COMMAND_INJECTION = new KnowledgeDocument({
  id: 'vuln_command_injection',
  title: 'Command Injection',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['command', 'injection', 'rce', 'os', '命令注入', '远程代码执行'],
  severity: Severity.CRITICAL,
  cweIds: ['CWE-78'],
  owaspIds: ['A03:2021'],
  gbtMapping: 'GB/T34944-6.1.1.6 命令行注入;GB/T39412-6.1.1.6 命令行注入',
  content: `
命令注入允许攻击者在服务器上执行任意系统命令。

## 危险模式

### Java
Runtime.getRuntime().exec(command);
ProcessBuilder pb = new ProcessBuilder(command);

### C/C++
system(command);
popen(command, "r");
execve(command, args, env);

### Python
os.system(command)
os.popen(command)
subprocess.call(command, shell=True)
subprocess.run(command, shell=True)

### JavaScript/Node.js
child_process.exec(command)
child_process.execSync(command)

## 安全实践
1. 避免使用 shell=true
2. 使用数组形式传递命令参数
3. 对用户输入进行严格验证
4. 使用安全的 API 替代系统命令

## 修复示例
// Java - 安全
ProcessBuilder pb = new ProcessBuilder("ls", "-la", userDir);
pb.start();

// Python - 安全
subprocess.run(["ls", "-la", user_dir], shell=False)

// JavaScript - 安全
child_process.spawn("ls", ["-la", userDir], { shell: false });
`
});

const XSS = new KnowledgeDocument({
  id: 'vuln_xss',
  title: 'Cross-Site Scripting (XSS)',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['xss', 'javascript', 'html', 'script', '跨站脚本'],
  severity: Severity.HIGH,
  cweIds: ['CWE-79'],
  owaspIds: ['A03:2021'],
  gbtMapping: 'GB/T34944-6.1.1.3 跨站脚本;GB/T39412-6.1.1.3 跨站脚本',
  content: `
XSS 攻击允许攻击者在用户浏览器中执行恶意脚本。

## 危险模式

### Java/JSP
out.println(userInput);  // 直接输出
response.getWriter().write(userInput);

### C#/ASP.NET
Response.Write(userInput);
<%: userInput %>  // HTML编码

### Python (Flask/Jinja2)
{{ user_input|safe }}  // 禁用转义
Markup(user_input)      // 标记为安全

### JavaScript
document.write(userInput);
element.innerHTML = userInput;

## 安全实践
1. 对所有用户输入进行 HTML 转义
2. 使用 Content-Security-Policy 头
3. 设置 HttpOnly 和 Secure Cookie 标志
4. 输入验证

## 修复示例
// Java - 安全
out.println(StringEscapeUtils.escapeHtml4(userInput));

// Python Jinja2 - 安全（默认转义）
{{ user_input }}  // 自动转义

// JavaScript - 安全
element.textContent = userInput;
`
});

const PATH_TRAVERSAL = new KnowledgeDocument({
  id: 'vuln_path_traversal',
  title: 'Path Traversal',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['path', 'traversal', 'directory', 'file', '路径遍历'],
  severity: Severity.HIGH,
  cweIds: ['CWE-22'],
  owaspIds: ['A01:2021'],
  gbtMapping: 'GB/T34944-6.2.3.1 路径遍历;GB/T39412-6.2.3.1 路径遍历',
  content: `
路径遍历允许攻击者访问服务器上的任意文件。

## 危险模式

### Java
new File(userInput + filename);
FileInputStream fis = new FileInputStream(userPath);

### C/C++
fopen(filename, "r");
open(path, O_RDONLY);

### Python
open(user_path + filename, 'r')
os.path.join(user_path, filename)  // 如果 user_path 以 / 开头

### JavaScript/Node.js
fs.readFile(userPath + filename);
path.join(userPath, filename)  // 如果 userPath 是绝对路径

## 安全实践
1. 使用 realpath() 解析和验证路径
2. 使用白名单验证文件类型
3. 使用 chroot 或容器隔离
4. 避免直接拼接用户输入到文件路径

## 修复示例
// Java - 安全
Path base = Paths.get("/safe/dir").toRealPath();
Path requested = base.resolve(filename).normalize();
if (!requested.startsWith(base)) throw new SecurityException();
`
});

const WEAK_CRYPTO = new KnowledgeDocument({
  id: 'vuln_weak_crypto',
  title: 'Weak Cryptography',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['crypto', 'hash', 'encryption', 'weak', '加密', '弱加密'],
  severity: Severity.HIGH,
  cweIds: ['CWE-327', 'CWE-328', 'CWE-329'],
  owaspIds: ['A02:2021'],
  gbtMapping: 'GB/T34944-6.2.6 加密算法使用不安全;GB/T39412-6.2.6 加密算法使用不安全',
  content: `
使用不安全的加密算法或实现会导致数据泄露。

## 危险模式

### 弱哈希算法
MD5, SHA1 用于密码存储
- MessageDigest.getInstance("MD5")
- MessageDigest.getInstance("SHA1")

### 弱加密算法
DES, 3DES, RC4
- Cipher.getInstance("DES/ECB/PKCS5Padding")
- "RC4"  // 已不安全

### 不使用盐值
// 危险 - 不使用盐
BCrypt.hashpw(password, BCrypt.gensalt());  // 正确
// 危险 - 硬编码盐
BCrypt.hashpw(password, "$2a$10$fixedSalt");

## 安全实践
1. 使用 SHA-256 或更强用于数据完整性
2. 使用 Argon2, bcrypt, scrypt 用于密码哈希
3. 使用 AES-256-GCM 用于加密
4. 生成加密安全的随机盐

## 修复示例
// Java - 安全密码哈希
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);

// Java - 安全加密
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, key, iv);
`
});

const AUTH_BYPASS = new KnowledgeDocument({
  id: 'vuln_auth_bypass',
  title: 'Authentication Bypass',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['auth', 'authentication', 'bypass', 'session', '认证', '授权'],
  severity: Severity.HIGH,
  cweIds: ['CWE-287', 'CWE-306', 'CWE-384'],
  owaspIds: ['A07:2021'],
  gbtMapping: 'GB/T34944-6.3 身份鉴别;GB/T39412-6.3 身份鉴别',
  content: `
认证绕过允许攻击者绕过身份验证机制。

## 危险模式

### Java
// 只检查用户名
if (user.equals("admin")) { grantAccess(); }

// 硬编码凭证
if (username.equals("admin") && password.equals("123456"))

### C/C++
// 薄弱的认证检查
if (strcmp(password, "secret") == 0)

### Python
# Flask - 不安全的会话
session['user'] = username  # 未验证

## 安全实践
1. 使用成熟的认证框架
2. 实现强密码策略
3. 使用多因素认证
4. 安全的会话管理

## 修复示例
// Spring Security - 安全
@Autowired
private UserDetailsService userDetailsService;

protected void configure(AuthenticationManagerBuilder auth) throws Exception {
  auth.userDetailsService(userDetailsService)
      .passwordEncoder(new BCryptPasswordEncoder());
}
`
});

const INSECURE_DESERIALIZATION = new KnowledgeDocument({
  id: 'vuln_insecure_deserialization',
  title: 'Insecure Deserialization',
  category: KnowledgeCategory.VULNERABILITY,
  tags: ['deserialization', 'serialization', 'java', 'python', '反序列化'],
  severity: Severity.CRITICAL,
  cweIds: ['CWE-502'],
  owaspIds: ['A08:2021'],
  gbtMapping: 'GB/T34944-6.1.1.8 不安全反序列化;GB/T39412-6.1.1.8 不安全反序列化',
  content: `
不安全的反序列化可导致远程代码执行。

## 危险模式

### Java
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

### Python
import pickle
obj = pickle.loads(user_data)

### JavaScript
const obj = JSON.parse(user_input);  // 安全

## 安全实践
1. 避免反序列化不可信数据
2. 使用 JSON 替代二进制格式
3. 实现完整性检查
4. 在隔离环境中执行反序列化

## 修复示例
// Java - 使用 JSON
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(userJson, User.class);

// Python - 使用 JSON
import json
obj = json.loads(user_data)
`
});

export {
  SQL_INJECTION,
  COMMAND_INJECTION,
  XSS,
  PATH_TRAVERSAL,
  WEAK_CRYPTO,
  AUTH_BYPASS,
  INSECURE_DESERIALIZATION
};

export const ALL_VULNERABILITY_DOCS = [
  SQL_INJECTION,
  COMMAND_INJECTION,
  XSS,
  PATH_TRAVERSAL,
  WEAK_CRYPTO,
  AUTH_BYPASS,
  INSECURE_DESERIALIZATION
];