# 弱哈希/弱加密漏洞知识库

## 漏洞概述

使用不安全的哈希算法（如MD5、SHA1）或加密算法（如DES、RC4）会使得数据容易被破解。

## 检测方法

### 1. 静态代码检测

#### 1.1 弱哈希算法检测

```bash
# Java - MD5/SHA1 检测
grep -rn 'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']' --include='*.java'
grep -rn 'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']' --include='*.java'
grep -rn '"SHA1"' --include='*.java'

# Python - hashlib 弱算法
grep -rn 'hashlib\.md5\s*(' --include='*.py'
grep -rn 'hashlib\.sha1\s*(' --include='*.py'
grep -rn 'hashlib\.sha\s*\(' --include='*.py'

# C/C++ - OpenSSL 弱算法
grep -rn 'MD5\s*(' --include='*.c' --include='*.cpp'
grep -rn 'SHA1\s*(' --include='*.c' --include='*.cpp'
```

#### 1.2 弱加密算法检测

```bash
# Java - DES/RC4 检测
grep -rn 'Cipher\.getInstance\s*\(\s*["\']DES' --include='*.java'
grep -rn 'Cipher\.getInstance\s*\(\s*["\']RC4' --include='*.java'
grep -rn 'DES\.Create\s*\(' --include='*.java'
grep -rn 'DES\.CryptoServiceProvider\s*\(' --include='*.java'

# Python - pycrypto 弱算法
grep -rn 'Crypto\.Cipher\.DES' --include='*.py'
grep -rn 'ARC4\.new\s*(' --include='*.py'
```

#### 1.3 密钥长度检测

```bash
# Java - 短密钥检测
grep -rn 'new\s+SecretKeySpec\s*\(\s*"[^"]{1,16}"' --include='*.java'
grep -rn 'KeyGenerator\s*\(\s*["\']AES["\'].*128' --include='*.java'

# Python - 密钥长度检测
grep -rn '.Key\s*=\s*"[^"]{1,16}"' --include='*.py'
```

### 2. 随机数生成检测

```bash
# Java - Random 用于安全目的
grep -rn 'new\s+Random\s*\(\s*\)' --include='*.java'

# Python - random 用于安全目的
grep -rn 'random\.random\s*\(' --include='*.py'
grep -rn 'random\.randint\s*\(' --include='*.py'
grep -rn 'random\.choice\s*\(' --include='*.py'
```

### 3. 危险模式

### Java
```java
// 危险 - MD5
MessageDigest md = MessageDigest.getInstance("MD5");

// 危险 - SHA1
MessageDigest md = MessageDigest.getInstance("SHA1");

// 危险 - DES
Cipher cipher = Cipher.getInstance("DES");
```

### Python
```python
# 危险 - MD5
import hashlib
hashlib.md5(password.encode()).hexdigest()

# 危险 - SHA1
hashlib.sha1(password.encode()).hexdigest()
```

### C/C++
```cpp
// 危险 - 使用弱哈希
unsigned char hash[16];
MD5_CTX ctx;
MD5Init(&ctx);
MD5Update(&ctx, data, len);
MD5Final(hash, &ctx);
```

## 安全实践

1. 使用强哈希算法（SHA-256、SHA-3）
2. 使用安全的加密算法（AES-256、RSA-2048）
3. 使用密钥派生函数（PBKDF2、bcrypt、Argon2）
4. 密码存储使用专门算法（bcrypt、Argon2、scrypt）

## 修复示例

### Java
```java
// 安全 - SHA-256
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] hash = md.digest(password.getBytes());

// 安全 - 密码存储使用 BCrypt
String hashed = BCrypt.hashpw(password, BCrypt.gensalt());

// 安全 - AES加密
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey);
```

### Python
```python
# 安全 - SHA-256
import hashlib
hashlib.sha256(password.encode()).hexdigest()

# 安全 - 密码存储使用 bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# 安全 - secrets 模块生成随机数
import secrets
token = secrets.token_hex(32)
```

## CWE 关联

- CWE-327: Use of a Broken or Risky Cryptographic Algorithm
- CWE-328: Use of Weak Hash
- CWE-835: Loop with Unreachable Exit Condition (Predictable Random Number Generation)

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.6.7 使用已破解或危险的加密算法 |
| C/C++ | GB/T34943-6.2.7.5 使用已破解或危险的加密算法 |
| C# | GB/T34946-6.2.6.7 使用已破解或危险的加密算法 |
