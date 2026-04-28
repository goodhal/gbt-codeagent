import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * 审计覆盖率检查工具
 * 用于验证审计的完整性，检查：
 * - 文件覆盖率：审计的文件数 / 总文件数
 * - 语言覆盖率：审计的语言数 / 检测到的语言数
 * - 漏洞类型覆盖率：审计的漏洞类型数 / 应审计的漏洞类型数
 */
export class AuditCoverageChecker {
  constructor(targetDir, findings) {
    this.targetDir = targetDir;
    this.findings = findings;
    this.languageExtensions = {
      "java": [".java"],
      "python": [".py", ".pyw"],
      "cpp": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
      "csharp": [".cs"],
      "go": [".go"],
      "javascript": [".js", ".jsx", ".mjs", ".cjs"],
      "typescript": [".ts", ".tsx"],
      "php": [".php", ".phtml", ".php3", ".php4", ".php5"],
      "ruby": [".rb", ".rbw"],
      "rust": [".rs"]
    };
  }

  /**
   * 获取项目中的所有源代码文件
   */
  async getSourceFiles() {
    const files = [];
    const allExtensions = new Set();
    
    for (const exts of Object.values(this.languageExtensions)) {
      exts.forEach(ext => allExtensions.add(ext));
    }

    const scanDir = async (dir) => {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          if (entry.isDirectory()) {
            if (!entry.name.startsWith(".") && entry.name !== "node_modules" && entry.name !== "target") {
              await scanDir(fullPath);
            }
          } else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (allExtensions.has(ext)) {
              files.push(fullPath);
            }
          }
        }
      } catch (error) {
        // 忽略无法访问的目录
      }
    };

    await scanDir(this.targetDir);
    return files;
  }

  /**
   * 检测项目中的编程语言
   */
  detectLanguages(sourceFiles) {
    const languages = new Set();
    
    for (const file of sourceFiles) {
      const ext = path.extname(file).toLowerCase();
      
      for (const [language, extensions] of Object.entries(this.languageExtensions)) {
        if (extensions.includes(ext)) {
          languages.add(language);
        }
      }
    }
    
    return Array.from(languages);
  }

  /**
   * 获取审计覆盖的文件
   */
  getAuditedFiles() {
    const auditedFiles = new Set();
    
    for (const finding of this.findings) {
      if (finding.file) {
        auditedFiles.add(finding.file);
      }
    }
    
    return Array.from(auditedFiles);
  }

  /**
   * 获取审计覆盖的语言
   */
  getAuditedLanguages() {
    const languages = new Set();
    
    for (const finding of this.findings) {
      if (finding.language) {
        languages.add(finding.language);
      }
    }
    
    return Array.from(languages);
  }

  /**
   * 获取审计覆盖的漏洞类型
   */
  getAuditedVulnTypes() {
    const vulnTypes = new Set();
    
    for (const finding of this.findings) {
      if (finding.vulnType) {
        vulnTypes.add(finding.vulnType);
      }
    }
    
    return Array.from(vulnTypes);
  }

  /**
   * 获取应审计的漏洞类型（基于语言）
   */
  getExpectedVulnTypes(languages) {
    // 基于语言确定应审计的漏洞类型
    const expectedTypes = new Set();
    
    // 通用漏洞类型（所有语言）
    const commonTypes = [
      "COMMAND_INJECTION", "SQL_INJECTION", "XSS", "PATH_TRAVERSAL",
      "HARD_CODED_SECRET", "WEAK_CRYPTO", "DESERIALIZATION", "SSRF",
      "AUTH_BYPASS", "MISSING_ACCESS_CONTROL", "INFO_LEAK"
    ];
    
    commonTypes.forEach(type => expectedTypes.add(type));
    
    // 语言特定漏洞类型
    if (languages.includes("java")) {
      expectedTypes.add("JAVA_SPECIFIC_VULN");
    }
    if (languages.includes("python")) {
      expectedTypes.add("PYTHON_SPECIFIC_VULN");
    }
    if (languages.includes("cpp")) {
      expectedTypes.add("BUFFER_OVERFLOW");
    }
    if (languages.includes("csharp")) {
      expectedTypes.add("CSHARP_SPECIFIC_VULN");
    }
    
    return Array.from(expectedTypes);
  }

  /**
   * 计算文件覆盖率
   */
  calculateFileCoverage(sourceFiles, auditedFiles) {
    const totalFiles = sourceFiles.length;
    const auditedCount = auditedFiles.length;
    const coverage = totalFiles > 0 ? (auditedCount / totalFiles) * 100 : 0;
    
    return {
      totalFiles,
      auditedFiles: auditedCount,
      coverage: coverage.toFixed(2) + "%"
    };
  }

  /**
   * 计算语言覆盖率
   */
  calculateLanguageCoverage(detectedLanguages, auditedLanguages) {
    const totalLanguages = detectedLanguages.length;
    const auditedCount = auditedLanguages.length;
    const coverage = totalLanguages > 0 ? (auditedCount / totalLanguages) * 100 : 0;
    
    return {
      detectedLanguages,
      auditedLanguages,
      coverage: coverage.toFixed(2) + "%"
    };
  }

  /**
   * 计算漏洞类型覆盖率
   */
  calculateVulnTypeCoverage(expectedTypes, auditedTypes) {
    const totalTypes = expectedTypes.length;
    const auditedCount = auditedTypes.length;
    const coverage = totalTypes > 0 ? (auditedCount / totalTypes) * 100 : 0;
    
    return {
      expectedTypes,
      auditedTypes,
      coverage: coverage.toFixed(2) + "%"
    };
  }

  /**
   * 执行完整的覆盖率检查
   */
  async checkCoverage() {
    // 获取源代码文件
    const sourceFiles = await this.getSourceFiles();
    
    // 检测语言
    const detectedLanguages = this.detectLanguages(sourceFiles);
    
    // 获取审计覆盖信息
    const auditedFiles = this.getAuditedFiles();
    const auditedLanguages = this.getAuditedLanguages();
    const auditedVulnTypes = this.getAuditedVulnTypes();
    const expectedVulnTypes = this.getExpectedVulnTypes(detectedLanguages);
    
    // 计算覆盖率
    const fileCoverage = this.calculateFileCoverage(sourceFiles, auditedFiles);
    const languageCoverage = this.calculateLanguageCoverage(detectedLanguages, auditedLanguages);
    const vulnTypeCoverage = this.calculateVulnTypeCoverage(expectedVulnTypes, auditedVulnTypes);
    
    return {
      targetDir: this.targetDir,
      timestamp: new Date().toISOString(),
      fileCoverage,
      languageCoverage,
      vulnTypeCoverage,
      summary: {
        totalFiles: fileCoverage.totalFiles,
        auditedFiles: fileCoverage.auditedFiles,
        fileCoveragePercent: parseFloat(fileCoverage.coverage),
        detectedLanguages: languageCoverage.detectedLanguages,
        auditedLanguages: languageCoverage.auditedLanguages,
        languageCoveragePercent: parseFloat(languageCoverage.coverage),
        expectedVulnTypes: vulnTypeCoverage.expectedTypes.length,
        auditedVulnTypes: vulnTypeCoverage.auditedTypes.length,
        vulnTypeCoveragePercent: parseFloat(vulnTypeCoverage.coverage)
      }
    };
  }

  /**
   * 生成覆盖率报告
   */
  generateReport(coverage) {
    const { fileCoverage, languageCoverage, vulnTypeCoverage, summary } = coverage;
    
    let report = `# 审计覆盖率检查报告

## 基本信息

- **项目目录**: ${coverage.targetDir}
- **检查时间**: ${coverage.timestamp}

## 文件覆盖率

| 统计项 | 数量 |
|--------|------|
| 总文件数 | ${fileCoverage.totalFiles} |
| 审计文件数 | ${fileCoverage.auditedFiles} |
| **覆盖率** | **${fileCoverage.coverage}** |

## 语言覆盖率

| 统计项 | 值 |
|--------|-----|
| 检测到的语言 | ${languageCoverage.detectedLanguages.join(", ") || "无"} |
| 审计的语言 | ${languageCoverage.auditedLanguages.join(", ") || "无"} |
| **覆盖率** | **${languageCoverage.coverage}** |

## 漏洞类型覆盖率

| 统计项 | 数量 |
|--------|------|
| 应审计的漏洞类型 | ${vulnTypeCoverage.expectedTypes.length} |
| 已审计的漏洞类型 | ${vulnTypeCoverage.auditedTypes.length} |
| **覆盖率** | **${vulnTypeCoverage.coverage}** |

## 总结

| 覆盖类型 | 覆盖率 | 状态 |
|----------|--------|------|
| 文件覆盖 | ${fileCoverage.coverage} | ${parseFloat(fileCoverage.coverage) >= 80 ? "✅ 良好" : "⚠️ 需改进"} |
| 语言覆盖 | ${languageCoverage.coverage} | ${parseFloat(languageCoverage.coverage) >= 80 ? "✅ 良好" : "⚠️ 需改进"} |
| 漏洞类型覆盖 | ${vulnTypeCoverage.coverage} | ${parseFloat(vulnTypeCoverage.coverage) >= 80 ? "✅ 良好" : "⚠️ 需改进"} |

## 建议

`;

    if (parseFloat(fileCoverage.coverage) < 80) {
      report += `- ⚠️ 文件覆盖率低于 80%，建议审计更多源代码文件\n`;
    }
    if (parseFloat(languageCoverage.coverage) < 80) {
      report += `- ⚠️ 语言覆盖率低于 80%，建议审计更多编程语言的代码\n`;
    }
    if (parseFloat(vulnTypeCoverage.coverage) < 80) {
      report += `- ⚠️ 漏洞类型覆盖率低于 80%，建议审计更多类型的漏洞\n`;
    }
    if (parseFloat(fileCoverage.coverage) >= 80 && 
        parseFloat(languageCoverage.coverage) >= 80 && 
        parseFloat(vulnTypeCoverage.coverage) >= 80) {
      report += `- ✅ 所有覆盖率指标均达到 80% 以上，审计完整性良好\n`;
    }

    return report;
  }
}

/**
 * 命令行执行入口
 */
async function main() {
  const args = process.argv.slice(2);
  let targetDir = null;
  let findingsFile = null;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--target" && i + 1 < args.length) {
      targetDir = args[i + 1];
      i++;
    } else if (args[i] === "--findings" && i + 1 < args.length) {
      findingsFile = args[i + 1];
      i++;
    }
  }

  if (!targetDir) {
    console.error("错误：请提供 --target 参数指定项目目录");
    process.exit(1);
  }

  try {
    // 读取审计结果
    let findings = [];
    if (findingsFile) {
      const content = await fs.readFile(findingsFile, "utf8");
      findings = JSON.parse(content);
    }

    const checker = new AuditCoverageChecker(targetDir, findings);
    const coverage = await checker.checkCoverage();
    const report = checker.generateReport(coverage);

    console.log(report);
    
    // 输出 JSON 格式结果
    console.log("\n--- JSON 格式 ---\n");
    console.log(JSON.stringify(coverage, null, 2));
    
  } catch (error) {
    console.error("执行失败:", error.message);
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (process.argv[1] === new URL(import.meta.url).pathname) {
  main();
}
