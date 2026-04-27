# 命令注入漏洞知识库

## 漏洞概述

命令注入漏洞发生在应用程序执行系统命令时，将用户可控输入传递给命令解释器。

## 检测方法

### 1. 静态代码检测

#### 1.1 危险函数检测

```bash
# Java - Runtime.exec 检测
grep -rn 'Runtime\.getRuntime\(\)\.exec' --include='*.java'
grep -rn 'ProcessBuilder' --include='*.java'

# Python - subprocess/system 检测
grep -rn 'subprocess\.' --include='*.py'
grep -rn 'os\.system' --include='*.py'
grep -rn 'os\.popen' --include='*.py'

# C/C++ - system/popen 检测
grep -rn 'system\s*(' --include='*.c' --include='*.cpp'
grep -rn 'popen\s*(' --include='*.c' --include='*.cpp'
grep -rn 'exec\s*(' --include='*.c' --include='*.cpp'
```

#### 1.2 拼接模式检测

```bash
# 检测字符串拼接进入命令
grep -rn '"\s*.*".*\+.*' --include='*.java' | grep -E 'exec|system|popen'
grep -rn 'f".*".*.format' --include='*.py'
grep -rn 'String\.format.*%s' --include='*.java'
```

#### 1.3 Shell=True 检测

```bash
# Python - shell=True 危险模式
grep -rn 'shell\s*=\s*True' --include='*.py'
```

### 2. 污点分析

追踪用户输入到命令执行的数据流：

```
用户输入 (args, env, stdin)
    ↓
命令构建
    ↓
ProcessBuilder / subprocess / system
    ↓
命令执行
```

### 3. 危险模式

### Java
```java
// 危险
Runtime.getRuntime().exec("ls " + userInput);
ProcessBuilder pb = new ProcessBuilder("ls", userInput);
```

### Python
```python
# 危险
os.system("ls " + user_input)
subprocess.Popen("ls " + user_input, shell=True)
```

### C/C++
```cpp
// 危险
system(argv[1]);
execlp(argv[1], argv[2], NULL);
```

## 安全实践

1. 避免使用系统命令
2. 使用安全的API替代
3. 严格验证输入（白名单）
4. 使用参数化命令执行

## 修复示例

### Java
```java
// 安全 - 使用 ProcessBuilder 参数数组
ProcessBuilder pb = new ProcessBuilder("ls", "-la", directory);
pb.start();

// 安全 - 避免用户输入进入命令
if (!isValidDirectory(userInput)) {
    throw new IllegalArgumentException();
}
```

### Python
```python
# 安全 - 使用 subprocess 参数列表
subprocess.run(["ls", "-la", directory], shell=False)

# 安全 - 使用 Python API 替代
import glob
files = glob.glob(os.path.join(directory, "*"))
```

## CWE 关联

- CWE-78: OS Command Injection
- CWE-88: Argument Injection

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.3.3 命令注入 |
| C/C++ | GB/T34943-6.2.3.3 命令注入 |
| C# | GB/T34946-6.2.3.3 命令注入 |
| Python | GB/T39412-6.1.1.6 命令行注入 |
