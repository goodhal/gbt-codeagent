# 反序列化漏洞知识库

## 漏洞概述

反序列化漏洞发生在应用程序将不可信数据反序列化为对象时，可能导致远程代码执行。

## 检测方法

### 1. 静态代码检测

#### 1.1 Java 反序列化检测

```bash
# ObjectInputStream/readObject 检测
grep -rn 'ObjectInputStream\s*\(' --include='*.java'
grep -rn 'readObject\s*\(\s*\)' --include='*.java'
grep -rn 'readUnshared\s*\(\s*\)' --include='*.java'

# XMLDecoder 检测
grep -rn 'XMLDecoder\s*\(' --include='*.java'
grep -rn 'decoder\.readObject\s*\(\s*\)' --include='*.java'

# XStream 检测
grep -rn 'XStream\s*\(' --include='*.java'
grep -rn 'fromXML\s*\(\s*' --include='*.java'

# Kryo 检测
grep -rn 'Kryo\s*\(' --include='*.java'
grep -rn 'kryo\.readObject\s*\(\s*\)' --include='*.java'
```

#### 1.2 Python 反序列化检测

```bash
# pickle 检测
grep -rn 'pickle\.load\s*\(' --include='*.py'
grep -rn 'pickle\.loads\s*\(' --include='*.py'
grep -rn 'pickle\.Unpickler\s*\(' --include='*.py'

# yaml 检测
grep -rn 'yaml\.load\s*\(' --include='*.py'
grep -rn 'yaml\.unsafe_load\s*\(' --include='*.py'

# marshal 检测
grep -rn 'marshal\.load\s*\(' --include='*.py'
grep -rn 'marshal\.loads\s*\(' --include='*.py'
```

#### 1.3 JSON 反序列化（相对安全）

```bash
# 检测是否直接使用用户输入反序列化
grep -rn 'ObjectMapper\s*\(\s*\)' --include='*.java'
grep -rn 'readValue\s*\(\s*.*request' --include='*.java'
grep -rn 'json\.loads\s*\(' --include='*.py'
```

### 2. 危险模式

### Java
```java
// 危险 - 使用 readObject
ObjectInputStream ois = new ObjectInputStream(input);
Object obj = ois.readObject();

// 危险 - XMLDecoder
XMLDecoder decoder = new XMLDecoder(input);
Object obj = decoder.readObject();
```

### Python
```python
# 危险
import pickle
data = pickle.loads(user_data)

# 危险 - yaml unsafe load
import yaml
data = yaml.unsafe_load(user_yaml)
```

## 安全实践

1. 避免反序列化不可信数据
2. 使用数字签名验证数据完整性
3. 使用安全替代方案（如JSON）
4. 启用类型检查

## 修复示例

### Java
```java
// 安全 - 使用 JSON 替代
ObjectMapper mapper = new ObjectMapper();
User user = mapper.readValue(jsonString, User.class);

// 安全 - 使用白名单
public class CustomObjectInputStream extends ObjectInputStream {
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.example.MyClass"
    );

    protected Class<?> resolveClass(ObjectStreamClass desc) {
        String name = desc.getName();
        if (!ALLOWED_CLASSES.contains(name)) {
            throw new InvalidClassException("Unauthorized: " + name);
        }
        return super.resolveClass(desc);
    }
}
```

### Python
```python
# 安全 - 使用 json 替代 pickle
import json
data = json.loads(user_data)

# 安全 - 使用 yaml safe load
import yaml
data = yaml.safe_load(user_yaml)
```

## CWE 关联

- CWE-502: Deserialization of Untrusted Data
- CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes

## 国标映射

| 语言 | 标准 |
|------|------|
| Java | GB/T39412-7.1.2 反序列化 |
| Python | GB/T39412-7.1.2 反序列化 |
