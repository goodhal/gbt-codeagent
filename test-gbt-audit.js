import { QuickScanService } from "./src/services/quickScanService.js";
import { resolveAuditSkills } from "./src/config/auditSkills.js";
import path from "node:path";

console.log("=== GBT 代码审计功能测试 ===\n");

console.log("1. 测试 GBT 审计技能配置...");
const skills = resolveAuditSkills();
const gbtSkill = skills.find(skill => skill.id === "gbt-code-audit");

if (gbtSkill) {
  console.log("✓ GBT 审计技能配置加载成功");
  console.log(`  - 名称: ${gbtSkill.name}`);
  console.log(`  - 描述: ${gbtSkill.description}`);
  console.log(`  - 支持语言: ${gbtSkill.supportedLanguages.join(", ")}`);
  console.log(`  - 漏洞类型数量: ${gbtSkill.vulnCategories.length}`);
  console.log(`  - 国标标准: ${Object.keys(gbtSkill.gbtStandards).join(", ")}`);
} else {
  console.log("✗ GBT 审计技能配置未找到");
}

console.log("\n2. 测试快速扫描服务...");
const quickScanService = new QuickScanService();

console.log("✓ 快速扫描服务初始化成功");
console.log(`  - 支持的语言: ${Object.keys(quickScanService.patterns).join(", ")}`);

console.log("\n3. 测试语言检测...");
const testFiles = [
  "test.java",
  "test.py",
  "test.cpp",
  "test.js",
  "test.ts",
  "test.go",
  "test.php",
  "test.cs",
  "test.rb",
  "test.rs"
];

testFiles.forEach(file => {
  const language = quickScanService.detectLanguage(file);
  console.log(`  - ${file}: ${language}`);
});

console.log("\n4. 测试 CVSS 评分计算...");
const testVulns = [
  { vulnType: "SQL_INJECTION", severity: "high" },
  { vulnType: "XSS", severity: "medium" },
  { vulnType: "INFO_LEAK", severity: "low" }
];

testVulns.forEach(({ vulnType, severity }) => {
  const cvssScore = quickScanService.calculateCVSS(vulnType, severity);
  console.log(`  - ${vulnType} (${severity}): CVSS ${cvssScore}`);
});

console.log("\n5. 测试国标映射...");
const testMappings = [
  { vulnType: "SQL_INJECTION", language: "java" },
  { vulnType: "COMMAND_INJECTION", language: "python" },
  { vulnType: "AUTH_BYPASS", language: "cpp" }
];

testMappings.forEach(({ vulnType, language }) => {
  const gbtMapping = quickScanService.getGbtMapping(vulnType, language);
  console.log(`  - ${vulnType} (${language}): ${gbtMapping}`);
});

console.log("\n=== 测试完成 ===");