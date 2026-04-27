# 路径遍历漏洞知识库

## 漏洞概述

路径遍历漏洞发生在应用程序使用用户可控输入访问文件时，攻击者可以通过构造特殊路径访问敏感文件。

## 检测方法

### 1. 静态代码检测

#### 1.1 文件操作函数检测

```bash
# Java - File/FileInputStream 检测
grep -rn 'new\s\+File\s*\(' --include='*.java'
grep -rn 'FileInputStream\s*\(' --include='*.java'
grep -rn 'FileReader\s*\(' --include='*.java'
grep -rn 'Paths\.get\s*\(' --include='*.java'
grep -rn 'Files\.readAllBytes\s*\(' --include='*.java'

# Python - open() 检测
grep -rn 'open\s*(' --include='*.py'

# C/C++ - fopen/sprintf 检测
grep -rn 'fopen\s*(' --include='*.c' --include='*.cpp'
grep -rn 'sprintf\s*(' --include='*.c' --include='*.cpp'
grep -rn 'strcpy\s*(' --include='*.c' --include='*.cpp'
```

#### 1.2 路径拼接模式检测

```bash
# 检测 os.path.join / File 构造
grep -rn 'os\.path\.join\s*(' --include='*.py'
grep -rn 'new\s\+File\s*\([^)]*+\s*' --include='*.java'

# 检测模板路径拼接
grep -rn 'get_template\s*(' --include='*.py'
grep -rn 'Template\s*\(' --include='*.java'
```

#### 1.3 规范化检测

```bash
# 检测是否有 normalize/realpath 校验
grep -rn '\.normalize\s*(' --include='*.java'
grep -rn 'realpath\s*(' --include='*.c'
grep -rn 'startsWith\s*(' --include='*.java'
```

### 2. 危险模式

### Java
```java
// 危险 - 路径拼接
File file = new File(baseDir, userInput);
FileInputStream fis = new FileInputStream(file);

// 危险 - 使用用户输入读取文件
Path path = Paths.get(baseDir, userInput);
byte[] data = Files.readAllBytes(path);
```

### Python
```python
# 危险
with open(os.path.join(base_dir, user_input), 'r') as f:
    content = f.read()

# 危险 - 模板引擎路径遍历
template = env.get_template(user_filename)
```

### C/C++
```cpp
// 危险
char filepath[256];
sprintf(filepath, "%s/%s", base_dir, user_input);
FILE *fp = fopen(filepath, "r");
```

## 安全实践

1. 验证和规范用户输入
2. 使用 realpath() 解析绝对路径
3. 限制访问范围（chroot/jail）
4. 使用白名单验证文件名

## 修复示例

### Java
```java
// 安全 - 验证规范路径
Path basePath = baseDir.toRealPath();
Path requestedPath = basePath.resolve(userInput).normalize();
if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Access denied");
}

// 安全 - 使用 Path API
Path safePath = baseDir.resolve(userInput).normalize();
if (!safePath.startsWith(baseDir)) {
    throw new IllegalArgumentException("Invalid path");
}
```

### Python
```python
import os

# 安全 - 验证规范路径
def safe_read(base_dir, user_filename):
    base_path = os.path.realpath(base_dir)
    requested_path = os.path.realpath(os.path.join(base_dir, user_filename))
    if not requested_path.startswith(base_path + os.sep):
        raise ValueError("Access denied")
    return open(requested_path).read()
```

## CWE 关联

- CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)
- CWE-23: Relative Path Traversal
- CWE-36: Absolute Path Traversal

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.3.1 相对路径遍历 |
| C/C++ | GB/T34943-6.2.3.1 相对路径遍历 |
| C# | GB/T34946-6.2.3.1 相对路径遍历 |
| Python | GB/T39412-6.1.1.14 边界值检查缺失 |
