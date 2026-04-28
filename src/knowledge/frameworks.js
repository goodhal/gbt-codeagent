const KnowledgeCategory = {
  VULNERABILITY: "vulnerability",
  FRAMEWORK: "framework",
  BEST_PRACTICE: "best_practice",
  SECURITY_CONFIG: "security_config",
  COMPLIANCE: "compliance"
};

class KnowledgeDocument {
  constructor({
    id,
    title,
    category,
    tags = [],
    content = "",
    metadata = {}
  }) {
    this.id = id;
    this.title = title;
    this.category = category;
    this.tags = tags;
    this.content = content;
    this.metadata = metadata;
    this.createdAt = new Date().toISOString();
    this.updatedAt = new Date().toISOString();
  }

  toJSON() {
    return {
      id: this.id,
      title: this.title,
      category: this.category,
      tags: this.tags,
      content: this.content,
      metadata: this.metadata,
      createdAt: this.createdAt,
      updatedAt: this.updatedAt
    };
  }
}

const DJANGO_SECURITY = new KnowledgeDocument({
  id: "framework_django",
  title: "Django Security",
  category: KnowledgeCategory.FRAMEWORK,
  tags: ["django", "python", "web", "orm"],
  content: `
Django 内置了许多安全保护，但不当使用仍可能引入漏洞。

## 内置安全特性
1. CSRF保护
2. XSS防护（模板自动转义）
3. SQL注入防护（ORM）
4. 点击劫持防护
5. 安全的密码哈希

## 常见漏洞模式

### SQL注入 - 危险模式
\`\`\`python
# 危险 - raw()和extra()
User.objects.raw(f"SELECT * FROM users WHERE name = '{name}'")
User.objects.extra(where=[f"name = '{name}'"])

# 安全 - 使用ORM
User.objects.filter(name=name)
User.objects.raw("SELECT * FROM users WHERE name = %s", [name])
\`\`\`

### XSS - 危险模式
\`\`\`python
# 危险 - 禁用自动转义
{{ user_input|safe }}
{% autoescape off %}{{ user_input }}{% endautoescape %}

# 安全 - 默认转义
{{ user_input }}
\`\`\`

### CSRF绕过
\`\`\`python
# 危险 - 禁用CSRF
@csrf_exempt
def my_view(request):
    pass

# 安全 - 确保CSRF中间件启用
\`\`\`

### 不安全的反序列化
\`\`\`python
# 危险 - pickle
import pickle
data = pickle.loads(request.body)

# 安全 - 使用JSON
import json
data = json.loads(request.body)
\`\`\`
`
});

const EXPRESS_SECURITY = new KnowledgeDocument({
  id: "framework_express",
  title: "Express.js Security",
  category: KnowledgeCategory.FRAMEWORK,
  tags: ["express", "nodejs", "javascript", "web"],
  content: `
Express.js 框架安全最佳实践

## 内置安全特性
1. helmet 中间件
2. cors 配置
3. 速率限制
4. 输入验证

## 常见漏洞模式

### XSS - 危险模式
\`\`\`javascript
// 危险 - 直接输出用户输入
app.get('/', (req, res) => {
  res.send(\`Hello \${req.query.name}\`);
});

// 安全 - 转义或模板引擎
app.get('/', (req, res) => {
  res.render('index', { name: escape(req.query.name) });
});
\`\`\`

### SQL注入 - 危险模式
\`\`\`javascript
// 危险 - 字符串拼接
const query = \`SELECT * FROM users WHERE id = \${req.params.id}\`;

// 安全 - 参数化查询
const result = await db.query(
  'SELECT * FROM users WHERE id = ?',
  [req.params.id]
);
\`\`\`

### 命令注入 - 危险模式
\`\`\`javascript
// 危险 - exec 直接执行
app.get('/ping', (req, res) => {
  exec(\`ping -c 1 \${req.query.host}\`);
});

// 安全 - 使用 child_process.execFile 或严格验证
const host = req.query.host;
if (!/^[a-zA-Z0-9.]+$/.test(host)) {
  return res.status(400).send('Invalid host');
}
execFile('ping', ['-c', '1', host]);
\`\`\`

### 路径遍历 - 危险模式
\`\`\`javascript
// 危险 - 直接拼接路径
app.get('/files', (req, res) => {
  res.sendFile(__dirname + '/files/' + req.query.name);
});

// 安全 - 使用 path.resolve 和验证
const path = require('path');
const safePath = path.resolve(__dirname, 'files', req.query.name);
if (!safePath.startsWith(path.resolve(__dirname, 'files'))) {
  return res.status(403).send('Forbidden');
}
\`\`\`
`
});

const FASTAPI_SECURITY = new KnowledgeDocument({
  id: "framework_fastapi",
  title: "FastAPI Security",
  category: KnowledgeCategory.FRAMEWORK,
  tags: ["fastapi", "python", "web", "api"],
  content: `
FastAPI 框架安全最佳实践

## 内置安全特性
1. 自动 OpenAPI 文档
2. Pydantic 数据验证
3. OAuth2 + JWT 支持
4. 自动 CORS 配置

## 常见漏洞模式

### SQL注入 - 危险模式
\`\`\`python
# 危险 - 原始SQL字符串拼接
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    # 执行查询...

# 安全 - 使用 ORM 或参数化
from sqlalchemy import text
@app.get("/users/{user_id}")
async def get_user(user_id: int):
    result = db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
\`\`\`

### XSS - 危险模式
\`\`\`python
# 危险 - 直接返回 HTML
from fastapi.responses import HTMLResponse
@app.get("/", response_class=HTMLResponse)
async def home(name: str):
    return f"<h1>Hello {name}</h1>"

# 安全 - 使用模板引擎或转义
from fastapi.responses import HTMLResponse
from markupsafe import escape
@app.get("/", response_class=HTMLResponse)
async def home(name: str):
    return f"<h1>Hello {escape(name)}</h1>"
\`\`\`

### 认证绕过
\`\`\`python
# 危险 - 伪装饰器
@app.get("/admin")
async def admin():
    return {"secret": "data"}

# 安全 - 正确使用依赖注入
from fastapi import Depends, HTTPException, status
async def verify_token(x_token: str = Header(...)):
    if x_token != "valid-token":
        raise HTTPException(status_code=401)
    return x_token

@app.get("/admin", dependencies=[Depends(verify_token)])
async def admin():
    return {"secret": "data"}
\`\`\`
`
});

const FLASK_SECURITY = new KnowledgeDocument({
  id: "framework_flask",
  title: "Flask Security",
  category: KnowledgeCategory.FRAMEWORK,
  tags: ["flask", "python", "web", "jinja2"],
  content: `
Flask 框架安全最佳实践

## 内置安全特性
1. Jinja2 模板自动转义
2. SECURE_COOKIE 配置
3. Session 签名保护

## 常见漏洞模式

### XSS - 危险模式
\`\`\`python
# 危险 - MarkupUnsafe
from markupsafe import Markup
@app.route('/')
def home():
    return f"Hello {Markup(user_input)}"

# 安全 - 默认 Jinja2 转义
@app.route('/')
def home():
    return render_template('index.html', name=user_input)
\`\`\`

### SQL注入 - 危险模式
\`\`\`python
# 危险 - 字符串拼接
@app.route('/user/<name>')
def get_user(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"

# 安全 - 使用 ORM
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
@app.route('/user/<name>')
def get_user(name):
    user = User.query.filter_by(name=name).first()
\`\`\`

### 命令注入 - 危险模式
\`\`\`python
# 危险 - subprocess 直接执行
import subprocess
@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.check_output(f'ping -c 1 {host}', shell=True)

# 安全 - 不使用 shell=True
result = subprocess.check_output(['ping', '-c', '1', host])
\`\`\`

### 敏感信息泄露
\`\`\`python
# 危险 - DEBUG 开启
app.run(debug=True)

# 安全 - 生产环境关闭 DEBUG
if __name__ == '__main__':
    app.run(debug=False, port=5000)
\`\`\`
`
});

const REACT_SECURITY = new KnowledgeDocument({
  id: "framework_react",
  title: "React Security",
  category: KnowledgeCategory.FRAMEWORK,
  tags: ["react", "javascript", "frontend", "xss"],
  content: `
React 框架安全最佳实践

## 内置安全特性
1. JSX 自动转义
2. dangerouslySetInnerHTML 警告
3. Props 类型检查

## 常见漏洞模式

### XSS - 危险模式
\`\`\`jsx
// 危险 - dangerouslySetInnerHTML
function Component({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: content }} />;
}

// 危险 - 拼接用户输入到 HTML
function Component({ name }) {
  return <div innerHTML={"Hello " + name} />;
}

// 安全 - 使用状态和事件
function Component({ name }) {
  const [displayName, setDisplayName] = useState(name);
  return <div>Hello {escape(displayName)}</div>;
}
\`\`\`

### SQL注入 - 危险模式 (前端)
\`\`\`jsx
// 危险 - 在前端构建SQL
const query = \`SELECT * FROM users WHERE id = \${userId}\`;

// 安全 - 使用 API 调用，后端处理
const response = await fetch(\`/api/users/\${userId}\`);
\`\`\`

### 路径遍历 - 危险模式
\`\`\`jsx
// 危险 - 直接使用用户输入加载资源
function ImageComponent({ src }) {
  return <img src={src} />;
}

// 安全 - 验证和清理 URL
function ImageComponent({ src }) {
  const safeSrc = validateUrl(src);
  return safeSrc ? <img src={safeSrc} /> : null;
}
\`\`\`

### 敏感信息泄露
\`\`\`jsx
// 危险 - 在代码中存储密钥
const API_KEY = "sk-xxx-xxx";

// 安全 - 使用环境变量
const API_KEY = process.env.REACT_APP_API_KEY;
\`\`\`
`
});

const FRAMEWORK_DOCUMENTS = [
  DJANGO_SECURITY,
  EXPRESS_SECURITY,
  FASTAPI_SECURITY,
  FLASK_SECURITY,
  REACT_SECURITY
];

function getFrameworkDocument(frameworkId) {
  return FRAMEWORK_DOCUMENTS.find(doc => doc.id === `framework_${frameworkId}`) || null;
}

function getAllFrameworks() {
  return FRAMEWORK_DOCUMENTS.map(doc => ({
    id: doc.id,
    title: doc.title,
    tags: doc.tags
  }));
}

function searchFrameworks(query) {
  const lowerQuery = query.toLowerCase();
  return FRAMEWORK_DOCUMENTS.filter(doc =>
    doc.title.toLowerCase().includes(lowerQuery) ||
    doc.tags.some(tag => tag.toLowerCase().includes(lowerQuery)) ||
    doc.content.toLowerCase().includes(lowerQuery)
  );
}

export {
  KnowledgeCategory,
  KnowledgeDocument,
  FRAMEWORK_DOCUMENTS,
  DJANGO_SECURITY,
  EXPRESS_SECURITY,
  FASTAPI_SECURITY,
  FLASK_SECURITY,
  REACT_SECURITY,
  getFrameworkDocument,
  getAllFrameworks,
  searchFrameworks
};