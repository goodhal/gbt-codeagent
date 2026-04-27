# 常见问题与解决方案

## 问题 1：md 文件无法解析，报告只显示 0 或 1 个发现

**症状**：
- `finalize_report` 输出 `total_findings: 0` 或 `total_findings: 1`
- 但 `findings/` 目录下有多个 md 文件

**原因**：
- md 文件使用了中文冒号 `：` (Unicode 0xff1a) 而不是英文冒号 `:` (ASCII 0x3a)
- `parse_finding_md` 函数需要正确解析键值对

**解决方案**：

**✅ 推荐格式**（英文键名 + 英文冒号，兼容性最好）：
```markdown
编号: #001
严重等级: 严重
漏洞类型: COMMAND_INJECTION
文件路径: test-samples/java/VulnerableJava.java
行号: 31
CWE: CWE-78
国标映射: GB/T34944-6.2.3.3 命令注入
来源: quick_scan
语言: java
状态: 误报
问题代码: Runtime.getRuntime().exec(command);
问题描述: 描述内容
```

**批量修复命令**（如果验证失败）：
```bash
sed -i 's/：/:/g' findings/*/*.md
```

---

## 问题 2：LLM 审计发现被过滤（幻觉检测）

**症状**：
- `finalize_report` 输出警告：`检测到 X 个幻觉问题，已过滤`
- `hallucinations` 数组显示 `reason: mismatch`

**原因**：
- LLM 编造了不存在的行号或代码片段
- `validate_code_snippet` 函数验证失败

**解决方案**：
1. 创建 md 文件前，使用 `Grep` 工具验证行号：
   ```bash
   grep -n "Runtime.getRuntime" test-samples/java/VulnerableJava.java
   ```
2. 确保行号对应实际代码行，不是注释行

---

## 问题 3：报告名称变成参数值（如 GB/T39412-2020）

**症状**：
- 报告文件名变成 `GB/T39412-2020` 而非预期的 `audit_report.md`
- 或报告生成在奇怪的目录下（如 `GB/T39412-2020/`）

**原因**：
- 参数格式错误，导致 argparse 解析失败
- 例如缺少参数名或格式不正确

**解决方案**：
```bash
# ✅ 正确：使用空格分隔多值参数
python scripts/skill.py finalize_report --standards GB/T34943 GB/T34944 GB/T39412

# ❌ 错误：缺少参数名
python scripts/skill.py finalize_report GB/T39412-2020
```

---

## 问题 4：报告生成后详细发现为空

**症状**：
- `validation.success: false`
- `detailed_count: 0` 但 `total_count: 36`
- 报告文件只有统计表，没有详细发现

**原因**：
- 输出文件名包含空格或中文字符，被错误解析为参数
- 模板占位符替换失败

**解决方案**：
```bash
# ✅ 正确：使用英文文件名
python scripts/skill.py finalize_report --output=audit_report.md --project=test-project

# ❌ 错误：空格导致参数解析错误
python scripts/skill.py finalize_report --output=审计报告_最终版.md --project=gbt-code-audit-skill 测试样例
```

---

## 问题 5：快速扫描结果为 0 或失败

**症状**：
- `quick_scan` 返回 `total_findings: 0`
- 或 `success: false, error: Java command not found`

**原因**：
- 目标目录不存在或没有源代码文件

**解决方案**：
1. 确认目标路径正确：
   ```bash
   ls test-samples/java/ test-samples/python/ test-samples/cpp/ test-samples/csharp/
   ```
2. Java 字节码扫描需要 JDK，但正则快速扫描不需要

---

## 问题 6：报告验证失败

**症状**：
- `validation.issues: ["详细条目数 (0) < 总发现数 (36)"]`
- `findings_cleaned: false`

**原因**：
- 详细发现没有被插入到报告中
- 模板占位符 `<!-- DETAILED_FINDINGS_PLACEHOLDER -->` 未被替换

**解决方案**：
1. 删除旧报告文件，重新生成：
   ```bash
   rm -f audit_report*.md 审计报告*.md
   python scripts/skill.py finalize_report --output=新报告.md
   ```
2. 检查 md 文件格式是否正确（使用英文冒号）
3. 确认 `load_all_findings()` 能正确解析 md 文件