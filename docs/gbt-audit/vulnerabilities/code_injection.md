# 代码注入漏洞知识库

## 漏洞概述

代码注入漏洞发生在应用程序将用户输入作为代码执行，常见于使用 eval()、exec() 等动态代码执行函数的场景。

## 检测方法

### 1. 静态代码检测

#### 1.1 Python 代码执行检测

```bash
# eval/exec 检测
grep -rn '\beval\s*\(' --include='*.py'
grep -rn '\bexec\s*\(' --include='*.py'

# compile 检测
grep -rn 'compile\s*\(' --include='*.py'

# input 传递到 eval
grep -rn 'eval\s*(.*input' --include='*.py'
```

#### 1.2 JavaScript 代码执行检测

```bash
# Node.js eval 检测
grep -rn 'eval\s*(' --include='*.js'
grep -rn 'new\s+Function\s*(' --include='*.js'
grep -rn 'vm\.runIn' --include='*.js'

# Nashorn/JavaScript Engine
grep -rn 'ScriptEngine.*eval' --include='*.java'
grep -rn 'NashornScriptEngineFactory' --include='*.java'
```

#### 1.3 Java 代码执行检测

```bash
# ScriptEngineManager 检测
grep -rn 'ScriptEngineManager\s*\(' --include='*.java'
grep -rn 'ScriptEngine.*eval\s*\(' --include='*.java'

# Runtime.exec 检测（命令注入也属于代码注入）
grep -rn 'Runtime\.getRuntime\s*\(\)\.exec\s*\(' --include='*.java'
```

#### 1.4 模板注入检测

```bash
# Jinja2/SQLAlchemy 模板注入
grep -rn 'Template\s*\(' --include='*.py'
grep -rn 'env\.get_template\s*\(' --include='*.py'

# Spring SPEL 注入
grep -rn 'SpelExpressionParser\s*\(' --include='*.java'
grep -rn '#\{.*\$' --include='*.java'
```

### 2. 数据流分析

追踪用户输入到代码执行的数据流：

```
用户输入
    ↓
字符串拼接/模板构建
    ↓
eval/exec/evaluate
    ↓
代码执行
```

### 3. 危险模式

### Java
```java
// 危险
ScriptEngineManager m = new ScriptEngineManager();
ScriptEngine engine = m.getEngineByName("JavaScript");
engine.eval("var result = " + userInput);
```

### Python
```python
# 危险
exec(user_input)
eval(user_expression)
```

### JavaScript (Node.js)
```javascript
// 危险
eval("var x = " + userInput);
new Function(userCode)();
vm.runInVM(userCode);
```

## 安全实践

1. 避免使用动态代码执行
2. 使用安全的表达式求值库
3. 输入验证和类型检查
4. 使用白名单验证

## 修复示例

### Java
```java
// 安全 - 使用预定义的命令或表达式
public enum Operation {
    ADD, SUBTRACT, MULTIPLY, DIVIDE
}

// 安全 - 使用 SpEL 表达式白名单
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext context = new StandardEvaluationContext();
context.setVariable("allowedOperations", Arrays.asList("add", "subtract"));
```

### Python
```python
# 安全 - 使用 ast 模块安全解析
import ast

def safe_eval(expr):
    try:
        ast.parse(expr)
    except SyntaxError:
        raise ValueError("Invalid expression")

# 安全 - 使用 operator 模块替代 eval
import operator
ops = {"+": operator.add, "-": operator.sub}
result = ops[op](a, b)
```

## CWE 关联

- CWE-94: Code Injection
- CWE-95: Direct Dynamic Code Evaluation (Eval Injection)

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T34944-6.2.3.5 代码注入 |
| C# | GB/T34946-6.2.3.5 代码注入 |
| Python | GB/T39412-7.3.6 暴露危险的方法或函数 |
