# 硬编码密码/密钥知识库

## 漏洞概述

硬编码密码是指在源代码中直接写入明文密码、API密钥、加密密钥等敏感信息。

## 检测方法

### 1. 静态代码检测

#### 1.1 密钥/密码变量检测

```bash
# Java - password/apiKey/secret 检测
grep -rn 'password\s*=\s*"' --include='*.java'
grep -rn 'apiKey\s*=\s*"' --include='*.java'
grep -rn 'secret\s*=\s*"' --include='*.java'
grep -rn 'token\s*=\s*"' --include='*.java'
grep -rn 'PRIVATE\s+KEY' --include='*.java'

# Python - 常见密钥模式检测
grep -rn 'PASSWORD\s*=' --include='*.py'
grep -rn 'API_KEY\s*=' --include='*.py'
grep -rn 'SECRET_KEY\s*=' --include='*.py'
grep -rn 'TOKEN\s*=' --include='*.py'
grep -rn 'HARDCODED_' --include='*.py'

# C/C++ - 密码检测
grep -rn 'password\s*=\s*"' --include='*.c' --include='*.cpp'
grep -rn 'char\s+\*\s*password\s*=' --include='*.c' --include='*.cpp'
```

#### 1.2 密钥格式检测

```bash
# GitHub Token 格式
grep -rn 'ghp_[a-zA-Z0-9]\{36\}' --include='*.py' --include='*.java'
grep -rn 'github_pat_[a-zA-Z0-9_]\{22,255\}' --include='*.py'

# AWS Key 格式
grep -rn 'AKIA[0-9A-Z]\{16\}' --include='*.py'
grep -rn 'aws_access_key_id' --include='*.py'

# JWT 格式
grep -rn 'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*' --include='*.py'
```

#### 1.3 加密相关常量检测

```bash
# Java - 加密密钥检测
grep -rn 'SecretKeySpec\s*\(\s*"' --include='*.java'
grep -rn 'KeyGenerator\s*\(\s*"' --include='*.java'
grep -rn 'new\s+byte\[\s*\]\s*\{' --include='*.java' | grep -i 'key\|iv\|salt'

# Python - hashlib 检测
grep -rn 'hashlib\.md5\s*(' --include='*.py'
grep -rn 'hashlib\.sha1\s*(' --include='*.py'
```

### 2. 配置文件检测

检查配置文件中的硬编码密钥：

```bash
# 检测配置文件中的密钥
grep -rn 'password\s*=' --include='*.properties' --include='*.yml' --include='*.yaml' --include='*.json'
grep -rn 'apiKey\s*=' --include='*.properties' --include='*.yml' --include='*.yaml'
```

### 3. 危险模式

### Java
```java
// 危险
private static final String PASSWORD = "admin123";
private String apiKey = "sk-1234567890abcdef";
```

### Python
```python
# 危险
PASSWORD = "secret_password"
API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
SECRET_KEY = "my_super_secret_key"
```

### C/C++
```cpp
// 危险
const char* password = "root123";
```

## 安全实践

1. 使用环境变量存储敏感信息
2. 使用密钥管理服务（KMS）
3. 使用配置文件外部化敏感配置
4. 敏感信息加密存储

## 修复示例

### Java
```java
// 安全 - 使用环境变量
String password = System.getenv("DB_PASSWORD");
if (password == null) {
    throw new IllegalStateException("DB_PASSWORD not set");
}

// 安全 - 使用配置中心
@Value("${security.database.password}")
private String password;
```

### Python
```python
# 安全 - 使用环境变量
import os
password = os.environ.get("DB_PASSWORD")
if not password:
    raise ValueError("DB_PASSWORD not set")

# 安全 - 使用 python-dotenv
from dotenv import load_dotenv
load_dotenv()
api_key = os.getenv("API_KEY")
```

## CWE 关联

- CWE-259: Hard-coded Password
- CWE-321: Use of Hard-coded Cryptographic Key
- CWE-798: Use of Hard-coded Credentials

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.6.3 口令硬编码 |
| C/C++ | GB/T34943-6.2.7.3 口令硬编码 |
| C# | GB/T34946-6.2.6.3 口令硬编码 |
| Python | GB/T39412-6.2.1.3 使用安全相关的硬编码 |
