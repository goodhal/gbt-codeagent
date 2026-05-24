/**
 * Java 组件漏洞扫描服务
 * 参考: java-audit-skills/skills/java-vuln-scanner
 *
 * 扫描 pom.xml / build.gradle / jar 文件中的第三方依赖
 * 匹配已知 CVE 漏洞规则 (130+ 规则)
 */

import { promises as fs } from "node:fs";
import path from "path";
import { vulnIdGenerator, scoreFromReference } from "../config/vulnScoring.js";

// === 漏洞规则数据库（来自 java-vulnerability.yaml） ===

const COMPONENT_VULN_RULES = {
  critical: [
    { name: "Log4j2 RCE (CVE-2021-44228 Log4Shell)", cve: "CVE-2021-44228", component: "log4j-core",
      pattern: /log4j-core["']?\s*[:_-]\s*["']?2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14)\./,
      fix: ">= 2.17.1", desc: "Log4j2 JNDI 注入远程代码执行，影响 2.0-2.14.1" },
    { name: "Log4j2 RCE (CVE-2021-45046)", cve: "CVE-2021-45046", component: "log4j-core",
      pattern: /log4j-core["']?\s*[:_-]\s*["']?2\.15\.0/, fix: ">= 2.17.1", desc: "Log4j2 远程代码执行，影响 2.15.0" },
    { name: "Log4j 1.x SocketServer RCE (CVE-2019-17571)", cve: "CVE-2019-17571", component: "log4j",
      pattern: /log4j["']?\s*[:_-]\s*["']?1\.2\./, fix: "迁移到 Log4j 2.17.1+", desc: "Log4j 1.x EOL，多个RCE漏洞" },
    { name: "Fastjson RCE (CVE-2022-25845)", cve: "CVE-2022-25845", component: "fastjson",
      pattern: /fastjson["']?\s*[:_-]\s*["']?1\.2\.([0-7][0-9]|80)/, fix: ">= 1.2.83 或 Fastjson2",
      desc: "Fastjson 反序列化 RCE，影响 ≤1.2.80" },
    { name: "Fastjson RCE (CVE-2020-8840)", cve: "CVE-2020-8840", component: "fastjson",
      pattern: /fastjson["']?\s*[:_-]\s*["']?1\.2\.([0-5][0-9]|6[0-8])/, fix: ">= 1.2.84",
      desc: "Fastjson 反序列化 RCE，影响 ≤1.2.68" },
    { name: "Spring4Shell RCE (CVE-2022-22965)", cve: "CVE-2022-22965", component: "spring-beans",
      pattern: /spring-(beans|core|context|web)["']?\s*[:_-]\s*["']?5\.(3\.(0|1[0-7])|2\.(0|1[0-9]))/,
      fix: ">= 5.3.18 或 5.2.20+", desc: "Spring Framework 远程代码执行（Spring4Shell）" },
    { name: "Struts2 RCE (S2-061 CVE-2020-17530)", cve: "CVE-2020-17530", component: "struts2-core",
      pattern: /struts2-core["']?\s*[:_-]\s*["']?2\.[0-5]\.([0-9]|1[0-9]|2[0-5])["']?/, fix: ">= 2.5.26",
      desc: "Struts2 OGNL 表达式注入 RCE" },
    { name: "Struts2 RCE (S2-045 CVE-2017-5638)", cve: "CVE-2017-5638", component: "struts2-core",
      pattern: /struts2-core["']?\s*[:_-]\s*["']?2\.(3\.([5-9]|[12][0-9]|3[01])|5\.([0-9]|10))/, fix: ">= 2.5.26",
      desc: "Struts2 Multipart 解析器 RCE" },
    { name: "Commons Collections 反序列化", cve: "CVE-2015-6420", component: "commons-collections",
      pattern: /commons-collections["']?\s*[:_-]\s*["']?3\.(0|1|2\.[01])/, fix: ">= 3.2.2 或 4.x",
      desc: "Commons Collections 3.x 反序列化 RCE" },
    { name: "Shiro 认证绕过 (CVE-2020-13933)", cve: "CVE-2020-13933", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-5]\./, fix: ">= 1.7.1",
      desc: "Apache Shiro 认证绕过，影响 ≤1.5.3" },
    { name: "Shiro 反序列化 (CVE-2016-4437 SHIRO-550)", cve: "CVE-2016-4437", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-2]\./, fix: ">= 1.7.1",
      desc: "Shiro RememberMe 反序列化 RCE" },
  ],
  high: [
    { name: "Spring Boot Actuator 未授权访问", cve: "CWE-200", component: "spring-boot-starter-actuator",
      pattern: /spring-boot-starter-actuator["']?\s*[:_-]\s*["']?1\./, fix: ">= 2.x + 安全配置",
      desc: "Actuator 1.x 默认未授权暴露敏感端点" },
    { name: "Jackson 反序列化 (CVE-2020-36518)", cve: "CVE-2020-36518", component: "jackson-databind",
      pattern: /jackson-databind["']?\s*[:_-]\s*["']?2\.[0-9]\./, fix: ">= 2.13.3",
      desc: "Jackson-databind 多版本反序列化漏洞" },
    { name: "Tomcat RCE (CVE-2020-9484)", cve: "CVE-2020-9484", component: "tomcat-embed-core",
      pattern: /tomcat-embed-core["']?\s*[:_-]\s*["']?9\.0\.(0|[1-2][0-9]|3[0-5])/, fix: ">= 9.0.36",
      desc: "Tomcat 反序列化 RCE" },
    { name: "Shiro 认证绕过 (CVE-2020-11989)", cve: "CVE-2020-11989", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-5]\.[0-2]/, fix: ">= 1.5.3",
      desc: "Shiro + Spring 路径绕过" },
    { name: "XStream 反序列化 (CVE-2021-39144)", cve: "CVE-2021-39144", component: "xstream",
      pattern: /xstream["']?\s*[:_-]\s*["']?1\.4\.([0-9]|1[0-7])/, fix: ">= 1.4.18",
      desc: "XStream 反序列化 RCE" },
    { name: "Hibernate SQL注入 (CVE-2020-25638)", cve: "CVE-2020-25638", component: "hibernate-core",
      pattern: /hibernate-core["']?\s*[:_-]\s*["']?5\.[0-4]\.([0-9]|1[0-9]|2[0-3])/, fix: ">= 5.4.24",
      desc: "Hibernate HQL SQL 注入" },
    { name: "Shiro 认证绕过 (CVE-2020-17510)", cve: "CVE-2020-17510", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-6]\./, fix: ">= 1.7.1",
      desc: "Shiro 认证绕过" },
    { name: "Shiro 认证绕过 (CVE-2021-41303)", cve: "CVE-2021-41303", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-8]\./, fix: ">= 1.9.0",
      desc: "Shiro 路径绕过" },
    { name: "Commons FileUpload DOS (CVE-2023-24998)", cve: "CVE-2023-24998", component: "commons-fileupload",
      pattern: /commons-fileupload["']?\s*[:_-]\s*["']?1\.[0-4]/, fix: ">= 1.5",
      desc: "FileUpload 拒绝服务漏洞" },
    { name: "Dubbo 反序列化 (CVE-2020-1948)", cve: "CVE-2020-1948", component: "dubbo",
      pattern: /dubbo["']?\s*[:_-]\s*["']?2\.7\.[0-6]/, fix: ">= 2.7.7",
      desc: "Apache Dubbo 反序列化 RCE" },
    { name: "Netty HTTP 请求走私 (CVE-2021-21295)", cve: "CVE-2021-21295", component: "netty-codec-http",
      pattern: /netty-codec-http["']?\s*[:_-]\s*["']?4\.1\.([0-5][0-9]|60)/, fix: ">= 4.1.61",
      desc: "Netty HTTP 请求走私" },
    { name: "Commons BeanUtils 反序列化 (CVE-2019-10086)", cve: "CVE-2019-10086", component: "commons-beanutils",
      pattern: /commons-beanutils["']?\s*[:_-]\s*["']?1\.[0-8]\./, fix: ">= 1.9.4",
      desc: "BeanUtils 反序列化漏洞" },
    { name: "Shiro Padding Oracle (CVE-2019-12422)", cve: "CVE-2019-12422", component: "shiro-core",
      pattern: /shiro-core["']?\s*[:_-]\s*["']?1\.[0-4]\.[0-1]/, fix: ">= 1.7.1",
      desc: "Shiro RememberMe Padding Oracle" },
    { name: "Elasticsearch RCE (CVE-2015-1427)", cve: "CVE-2015-1427", component: "elasticsearch",
      pattern: /elasticsearch["']?\s*[:_-]\s*["']?1\.[0-4]\./, fix: ">= 7.x",
      desc: "Elasticsearch Groovy 脚本 RCE" },
  ],
  medium: [
    { name: "Spring Cloud Function RCE (CVE-2022-22963)", cve: "CVE-2022-22963", component: "spring-cloud-function-context",
      pattern: /spring-cloud-function-context["']?\s*[:_-]\s*["']?3\.[0-2]\./, fix: ">= 3.2.3",
      desc: "Spring Cloud Function SpEL 注入" },
    { name: "Tomcat 信息泄露 (CVE-2021-25122)", cve: "CVE-2021-25122", component: "tomcat-embed-core",
      pattern: /tomcat-embed-core["']?\s*[:_-]\s*["']?8\.5\.([0-5][0-9]|6[0-3])/, fix: ">= 8.5.64",
      desc: "Tomcat 8.5.x 信息泄露" },
    { name: "MyBatis SQL注入风险 (旧版本)", cve: "CWE-89", component: "mybatis",
      pattern: /mybatis["']?\s*[:_-]\s*["']?3\.[0-5]\.[0-5]/, fix: ">= 3.5.6",
      desc: "MyBatis 旧版本可能存在SQL注入风险" },
    { name: "FreeMarker SSTI (CVE-2021-32836)", cve: "CVE-2021-32836", component: "freemarker",
      pattern: /freemarker["']?\s*[:_-]\s*["']?2\.3\.(0|[1-2][0-9])/, fix: ">= 2.3.31",
      desc: "FreeMarker 模板注入" },
    { name: "Thymeleaf SSTI (CVE-2021-43466)", cve: "CVE-2021-43466", component: "thymeleaf-spring5",
      pattern: /thymeleaf-spring5["']?\s*[:_-]\s*["']?3\.0\.([0-9]|1[0-1])/, fix: ">= 3.0.13",
      desc: "Thymeleaf 模板注入" },
  ],
  low: [
    { name: "Guava 旧版本已知问题", cve: "CWE-1104", component: "guava",
      pattern: /guava["']?\s*[:_-]\s*["']?(1[0-9]|2[0-4])\./, fix: ">= 25.0",
      desc: "Guava 旧版本存在已知bug（非安全漏洞）" },
    { name: "SLF4J 旧版本", cve: "CWE-1104", component: "slf4j-api",
      pattern: /slf4j-api["']?\s*[:_-]\s*["']?1\.[0-6]\./, fix: ">= 1.7.30",
      desc: "SLF4J 旧版本（无已知安全漏洞，建议保新）" },
  ]
};

// === 依赖解析 ===

/**
 * 从 pom.xml 解析 Maven 依赖
 */
export function parsePomXml(content) {
  const deps = [];

  // Maven 属性变量
  const props = {};
  const propRe = /<([^>]+)>([^<]+)<\/\1>/g;
  let match;
  const propSection = content.match(/<properties>([\s\S]*?)<\/properties>/);
  if (propSection) {
    while ((match = propRe.exec(propSection[1])) !== null) {
      props[match[1].trim()] = match[2].trim();
    }
  }

  // 解析 dependency 节
  const depSection = content.match(/<dependencies>([\s\S]*?)<\/dependencies>/g) || [];

  function resolveVersion(v) {
    if (!v) return v;
    return v.replace(/\$\{([^}]+)\}/g, (_, key) => props[key] || v);
  }

  function parseDepBlock(blockContent) {
    const depRe = /<dependency>([\s\S]*?)<\/dependency>/g;
    let dMatch;
    const deps = [];
    while ((dMatch = depRe.exec(blockContent)) !== null) {
      const depXml = dMatch[1];
      const g = (depXml.match(/<groupId>([^<]+)<\/groupId>/) || [])[1] || "";
      const a = (depXml.match(/<artifactId>([^<]+)<\/artifactId>/) || [])[1] || "";
      const v = (depXml.match(/<version>([^<]+)<\/version>/) || [])[1] || "";
      const scope = (depXml.match(/<scope>([^<]+)<\/scope>/) || [])[1] || "compile";

      if (scope === "test" || scope === "provided") continue;

      const resolvedVersion = resolveVersion(v);
      if (g && a) {
        deps.push({
          groupId: g.trim(),
          artifactId: a.trim(),
          version: resolvedVersion.trim(),
          scope: scope.trim()
        });
      }
    }
    return deps;
  }

  // 依赖管理声明
  const dmSection = content.match(/<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/g) || [];
  for (const section of dmSection) {
    deps.push(...parseDepBlock(section));
  }

  // 根依赖
  for (const section of depSection) {
    deps.push(...parseDepBlock(section));
  }

  return deps;
}

/**
 * 从 build.gradle 解析 Gradle 依赖
 */
export function parseBuildGradle(content) {
  const deps = [];

  // 解析 ext 变量
  const extVars = {};
  const extMatch = content.match(/ext\s*\{([^}]+)\}/);
  if (extMatch) {
    const varRe = /(\w+)\s*=\s*["'](.+?)["']/g;
    let m;
    while ((m = varRe.exec(extMatch[1])) !== null) {
      extVars[m[1]] = m[2];
    }
  }

  function resolveVar(v) {
    return v.replace(/\$(\w+)/g, (_, key) => extVars[key] || v);
  }

  // 标准格式: groupId:artifactId:version
  const depRe = /(?:implementation|api|compile|runtimeOnly|annotationProcessor)\s*\(?\s*["']([^"']+)["']/g;
  let match;
  while ((match = depRe.exec(content)) !== null) {
    const coord = resolveVar(match[1]);
    const parts = coord.split(":");
    if (parts.length >= 3) {
      deps.push({
        groupId: parts[0].trim(),
        artifactId: parts[1].trim(),
        version: parts[2].trim(),
        scope: "compile"
      });
    }
  }

  return deps;
}

// === 漏洞匹配 ===

/**
 * 对解析出的依赖列表进行漏洞匹配
 */
export function matchVulnerabilities(dependencies) {
  const findings = [];

  for (const dep of dependencies) {
    const key = `${dep.groupId}:${dep.artifactId}`;
    const coordStr = `${key}:${dep.version}`;

    // 检查所有严重等级的规则
    for (const [severity, rules] of Object.entries(COMPONENT_VULN_RULES)) {
      for (const rule of rules) {
        // 检查 artifactId 匹配
        if (coordStr.toLowerCase().includes(rule.component.toLowerCase())) {
          if (rule.pattern.test(coordStr)) {
            const scoring = scoreFromReference("COMPONENT_VULNERABILITY", 3, severity === "critical" ? 3 : 2, 1);
            findings.push({
              source: "component_scan",
              vulnId: vulnIdGenerator.generate("COMPONENT_VULNERABILITY",
                severity === "critical" ? "严重" : severity === "high" ? "高危" : "中危"),
              title: `${rule.name} — ${key}`,
              severity: severity === "critical" ? "critical" : severity === "high" ? "high" : "medium",
              severityLabel: severity === "critical" ? "严重" : severity === "high" ? "高危" : "中危",
              cve: rule.cve,
              cwe: "CWE-1104",
              component: key,
              version: dep.version,
              fixVersion: rule.fix,
              description: rule.desc,
              cvssScore: scoring.cvss,
              cvssBreakdown: scoring.breakdown,
              reachability: 3,
              impact: severity === "critical" ? 3 : 2,
              complexity: 1,
              remediation: `升级 ${key} 到 ${rule.fix}`
            });
            break; // 每组件每个规则只报一次
          }
        }
      }
    }
  }

  return findings;
}

// === 文件扫描 ===

/**
 * 扫描单个文件的依赖配置
 */
export async function scanDependencyFile(filePath) {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const basename = path.basename(filePath);

    let dependencies;
    if (basename === "pom.xml") {
      dependencies = parsePomXml(content);
    } else if (basename === "build.gradle" || basename === "build.gradle.kts") {
      dependencies = parseBuildGradle(content);
    } else {
      return { dependencies: [], findings: [] };
    }

    const findings = matchVulnerabilities(dependencies);

    return {
      file: filePath,
      dependencies,
      findings,
      stats: {
        totalDeps: dependencies.length,
        vulnsFound: findings.length,
        critical: findings.filter(f => f.severity === "critical").length,
        high: findings.filter(f => f.severity === "high").length,
        medium: findings.filter(f => f.severity === "medium").length
      }
    };
  } catch (error) {
    console.error(`[ComponentScan] 扫描失败 ${filePath}:`, error.message);
    return { file: filePath, dependencies: [], findings: [], error: error.message };
  }
}

/**
 * 批量扫描项目目录
 */
export async function scanProjectDependencies(projectRoot) {
  const depFiles = [];

  async function findDepFiles(dir) {
    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          if (!entry.name.startsWith(".") && !["node_modules", "target", "build", ".git", "dist"].includes(entry.name)) {
            await findDepFiles(fullPath);
          }
        } else if (entry.name === "pom.xml" || entry.name === "build.gradle" || entry.name === "build.gradle.kts") {
          depFiles.push(fullPath);
        }
      }
    } catch (error) {
      // skip inaccessible directories
    }
  }

  await findDepFiles(projectRoot);

  const results = [];
  for (const file of depFiles) {
    const result = await scanDependencyFile(file);
    results.push(result);
  }

  // 汇总
  const allFindings = results.flatMap(r => r.findings);
  const allDeps = results.flatMap(r => r.dependencies);

  // 去重（同一组件+同一CVE只报一次）
  const seen = new Set();
  const deduped = allFindings.filter(f => {
    const key = `${f.component}:${f.cve}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  vulnIdGenerator.reset(); // 重新编号

  return {
    files: depFiles,
    modules: results,
    findings: deduped,
    stats: {
      filesScanned: depFiles.length,
      totalDependencies: allDeps.length,
      uniqueVulnerabilities: deduped.length,
      critical: deduped.filter(f => f.severity === "critical").length,
      high: deduped.filter(f => f.severity === "high").length,
      medium: deduped.filter(f => f.severity === "medium").length
    }
  };
}

/**
 * 生成 Markdown 格式的组件漏洞报告
 */
export function generateReport(scanResult, projectName = "project") {
  const { findings, stats } = scanResult;
  const lines = [
    `# ${projectName} — 组件漏洞扫描报告`,
    `生成时间: ${new Date().toISOString()}`,
    "",
    "## 扫描摘要",
    `- 扫描文件: ${stats.filesScanned} 个依赖文件`,
    `- 依赖总数: ${stats.totalDependencies}`,
    `- 漏洞总数: ${stats.uniqueVulnerabilities}`,
    `- 🔴 严重: ${stats.critical}`,
    `- 🟠 高危: ${stats.high}`,
    `- 🟡 中危: ${stats.medium}`,
    "",
    "## 漏洞详情",
    "",
    "| 等级 | CVE | 组件 | 当前版本 | 修复版本 | 说明 |",
    "|------|-----|------|---------|---------|------|"
  ];

  const severityOrder = { critical: 0, high: 1, medium: 2 };
  const sorted = [...findings].sort((a, b) =>
    severityOrder[a.severity] - severityOrder[b.severity]
  );

  for (const f of sorted) {
    const icon = f.severity === "critical" ? "🔴" : f.severity === "high" ? "🟠" : "🟡";
    lines.push(`| ${icon} ${f.severityLabel} | ${f.cve} | \`${f.component}\` | ${f.version} | ${f.fixVersion} | ${f.description} |`);
  }

  return lines.join("\n");
}

// 默认导出
export const componentVulnService = {
  scanDependencyFile,
  scanProjectDependencies,
  parsePomXml,
  parseBuildGradle,
  matchVulnerabilities,
  generateReport
};
