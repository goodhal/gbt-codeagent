/**
 * Java Web 路由映射分析器
 * 参考: java-audit-skills/skills/java-route-mapper
 *
 * 从 Java Web 项目源码中提取所有 HTTP 路由和参数结构
 * 支持: Spring MVC, Struts2, Servlet, JAX-RS, CXF Web Services
 */

import { promises as fs } from "node:fs";
import path from "path";

// === 框架注解/配置识别 ===

const FRAMEWORK_PATTERNS = {
  spring_mvc: {
    controllerAnnotations: [
      "@Controller", "@RestController",
      "@RequestMapping", "@GetMapping", "@PostMapping",
      "@PutMapping", "@DeleteMapping", "@PatchMapping"
    ],
    paramAnnotations: [
      "@RequestParam", "@PathVariable", "@RequestBody",
      "@RequestHeader", "@CookieValue"
    ],
    configFiles: [
      "application.yml", "application.properties",
      "spring-mvc.xml", "dispatcher-servlet.xml"
    ]
  },
  struts2: {
    controllerAnnotations: [
      "ActionSupport", "@Action", "struts.xml"
    ],
    paramDetection: ["extends ActionSupport", "implements ModelDriven"],
    configFiles: ["struts.xml", "struts-*.xml", "struts.properties"]
  },
  servlet: {
    controllerAnnotations: [
      "@WebServlet", "extends HttpServlet", "implements Servlet"
    ],
    configFiles: ["web.xml", "webdefault.xml"]
  },
  jax_rs: {
    controllerAnnotations: [
      "@Path", "@GET", "@POST", "@PUT", "@DELETE",
      "@PathParam", "@QueryParam", "@HeaderParam", "@FormParam"
    ],
    configFiles: ["web.xml (servlet-mapping)"]
  },
  cxf_ws: {
    controllerAnnotations: [
      "@WebService", "@WebMethod", "jaxws:endpoint"
    ],
    configFiles: [
      "applicationContext.xml", "cxf-servlet.xml"
    ]
  }
};

// === 路由提取正则 ===

const ROUTE_PATTERNS = {
  spring_mvc: {
    classLevel: /@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g,
    methodLevel: [
      { method: "GET",    pattern: /@GetMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
      { method: "POST",   pattern: /@PostMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
      { method: "PUT",    pattern: /@PutMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
      { method: "DELETE", pattern: /@DeleteMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
      { method: "PATCH",  pattern: /@PatchMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g },
      { method: "ANY",    pattern: /@RequestMapping\s*\(\s*(?:value\s*=\s*)?"([^"]+)"/g }
    ],
    pathVar: /@PathVariable\s*(?:\(\s*(?:value\s*=\s*)?["']?(\w+)["']?\s*\))?/g,
    requestParam: /@RequestParam\s*\(\s*(?:value\s*=\s*)?["'](\w+)["']/g,
    requestBody: /@RequestBody\s+\w+\s+(\w+)/g,
    methodSignature: /public\s+(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)/g
  },
  jax_rs: {
    classLevel: /@Path\s*\(\s*["']([^"']+)["']/g,
    methodLevel: [
      { method: "GET",    pattern: /@GET\s*$/gm },
      { method: "POST",   pattern: /@POST\s*$/gm },
      { method: "PUT",    pattern: /@PUT\s*$/gm },
      { method: "DELETE", pattern: /@DELETE\s*$/gm }
    ],
    pathVar: /@PathParam\s*\(\s*["'](\w+)["']/g,
    queryParam: /@QueryParam\s*\(\s*["'](\w+)["']/g,
    methodLevelPath: /@Path\s*\(\s*["']([^"']+)["']/g
  },
  servlet: {
    webServlet: /@WebServlet\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g,
    doMethod: /public\s+void\s+(do\w+)\s*\(\s*HttpServletRequest\s+\w+\s*,\s*HttpServletResponse\s+\w+/g
  },
  struts2: {
    actionMapping: /<action\s+name="([^"]+)"[^>]*class="([^"]+)"[^>]*/g,
    actionMethod: /<action\s+name="([^"]+)"[^>]*class="([^"]+)"[^>]*method="([^"]+)"/g,
    namespace: /<package[^>]*namespace="([^"]+)"[^>]*>/g
  }
};

// === 参数类型映射 ===

function inferJavaType(name) {
  // 从命名推断类型
  if (/^(id|num|count|size|page|index|limit|offset)$/i.test(name)) return "Integer";
  if (/^(flag|is[A-Z]|has[A-Z]|enable|disabled)$/.test(name)) return "Boolean";
  if (/^(price|amount|money|rate|score|weight)$/i.test(name)) return "Double";
  if (/^(date|time|created|updated|start[A-Z]|end[A-Z])$/i.test(name)) return "Date";
  if (/^(email|mail)$/i.test(name)) return "String (Email)";
  return "String";
}

/**
 * 检测项目使用的 Java Web 框架
 */
export function detectFrameworks(fileList, projectRoot) {
  const detected = new Set();
  const evidence = {};

  for (const file of fileList) {
    const basename = path.basename(file).toLowerCase();
    const dirname = path.dirname(file).toLowerCase();

    // 配置文件检测
    if (basename === "pom.xml" || basename === "build.gradle") {
      // 稍后通过内容检测
    }
    if (basename === "struts.xml" || basename.includes("struts-") && basename.endsWith(".xml")) {
      detected.add("struts2");
      evidence.struts2 = file;
    }
    if (basename === "web.xml") {
      detected.add("servlet");
      evidence.servlet = file;
    }
    if (basename === "application.yml" || basename === "application.properties") {
      detected.add("spring_mvc");
      evidence.spring_mvc = file;
    }
    if (basename === "applicationcontext.xml" && dirname.includes("web-inf")) {
      detected.add("cxf_ws");
      evidence.cxf_ws = file;
    }
    if (basename === "cxf-servlet.xml") {
      detected.add("cxf_ws");
      evidence.cxf_ws = file;
    }
  }

  return { frameworks: [...detected], evidence };
}

/**
 * 从 Java 源代码提取路由信息
 * @param {string} content - 源代码内容
 * @param {string} filePath - 文件路径
 * @param {string[]} frameworks - 检测到的框架
 * @returns {Object[]} 路由列表
 */
export function extractRoutes(content, filePath, frameworks = []) {
  const routes = [];
  const relativePath = filePath.replaceAll("\\", "/");

  // === Spring MVC ===
  if (frameworks.includes("spring_mvc") || frameworks.length === 0) {
    const isSpring = FRAMEWORK_PATTERNS.spring_mvc.controllerAnnotations.some(
      a => content.includes(a)
    );
    if (isSpring) {
      const classPaths = [];
      let match;
      while ((match = ROUTE_PATTERNS.spring_mvc.classLevel.exec(content)) !== null) {
        classPaths.push(match[1]);
      }
      ROUTE_PATTERNS.spring_mvc.classLevel.lastIndex = 0;

      // 方法级映射
      for (const { method, pattern } of ROUTE_PATTERNS.spring_mvc.methodLevel) {
        if (method === "ANY" && classPaths.length > 0) continue; // 跳过基类注解
        const methodPattern = new RegExp(pattern.source, "g");
        while ((match = methodPattern.exec(content)) !== null) {
          const methodPath = match[1];
          const fullPath = classPaths.length > 0
            ? (classPaths[0] + methodPath).replace("//", "/")
            : methodPath;

          // 提取参数
          const pathVars = extractParams(ROUTE_PATTERNS.spring_mvc.pathVar, content);
          const requestParams = extractParams(ROUTE_PATTERNS.spring_mvc.requestParam, content);
          const requestBody = extractRequestBody(ROUTE_PATTERNS.spring_mvc.requestBody, content);

          // 查找方法签名
          const sigMatch = findNearestMethod(content, match.index);

          routes.push({
            framework: "Spring MVC",
            httpMethod: method,
            urlPath: fullPath,
            file: relativePath,
            line: getLineNumber(content, match.index),
            className: extractClassName(content),
            methodName: sigMatch?.methodName || "unknown",
            params: {
              path: pathVars.map(p => ({ name: p, type: inferJavaType(p), in: "Path" })),
              query: requestParams.map(p => ({ name: p, type: inferJavaType(p), in: "Query" })),
              body: requestBody.length > 0 ? [{ name: requestBody[0], type: requestBody[0], in: "Body" }] : [],
              header: []
            }
          });
        }
      }

      // 重置所有正则
      for (const { pattern } of ROUTE_PATTERNS.spring_mvc.methodLevel) {
        pattern.lastIndex = 0;
      }
    }
  }

  // === JAX-RS ===
  if (frameworks.includes("jax_rs") || frameworks.length === 0) {
    if (content.includes("@Path")) {
      const classPaths = [];
      let match;
      while ((match = ROUTE_PATTERNS.jax_rs.classLevel.exec(content)) !== null) {
        classPaths.push(match[1]);
      }
      ROUTE_PATTERNS.jax_rs.classLevel.lastIndex = 0;

      for (const { method, pattern } of ROUTE_PATTERNS.jax_rs.methodLevel) {
        const methodPattern = new RegExp(pattern.source, "gm");
        while ((match = methodPattern.exec(content)) !== null) {
          const methodPath = extractMethodLevelPath(content, match.index);
          const fullPath = classPaths.length > 0
            ? (classPaths[0] + "/" + methodPath).replace("//", "/")
            : ("/" + methodPath);

          routes.push({
            framework: "JAX-RS",
            httpMethod: method,
            urlPath: fullPath,
            file: relativePath,
            line: getLineNumber(content, match.index),
            className: extractClassName(content),
            methodName: findNearestMethod(content, match.index)?.methodName || "unknown",
            params: {
              path: extractParams(ROUTE_PATTERNS.jax_rs.pathVar, content),
              query: extractParams(ROUTE_PATTERNS.jax_rs.queryParam, content),
              body: [],
              header: []
            }
          });
        }
      }
    }
  }

  // === Servlet ===
  if (frameworks.includes("servlet") || frameworks.length === 0) {
    if (content.includes("HttpServlet") || content.includes("@WebServlet")) {
      let match;
      const servletPattern = ROUTE_PATTERNS.servlet.webServlet;
      while ((match = servletPattern.exec(content)) !== null) {
        routes.push({
          framework: "Servlet",
          httpMethod: "ANY",
          urlPath: match[1],
          file: relativePath,
          line: getLineNumber(content, match.index),
          className: extractClassName(content),
          methodName: "service",
          params: {
            path: [],
            query: [],
            body: [],
            header: []
          }
        });
      }
      servletPattern.lastIndex = 0;
    }
  }

  // === Struts2 ===
  if (frameworks.includes("struts2") || frameworks.length === 0) {
    if (content.includes("<action ") || content.includes("ActionSupport")) {
      let match;
      const actionPattern = ROUTE_PATTERNS.struts2.actionMethod;
      while ((match = actionPattern.exec(content)) !== null) {
        routes.push({
          framework: "Struts2",
          httpMethod: "POST",
          urlPath: match[1].endsWith(".action") ? match[1] : match[1] + ".action",
          file: relativePath,
          line: getLineNumber(content, match.index),
          className: match[2],
          methodName: match[3],
          params: {
            path: [],
            query: [],
            body: [{ name: "formData", type: "FormBean", in: "Body" }],
            header: []
          }
        });
      }
      actionPattern.lastIndex = 0;
    }
  }

  return routes;
}

/**
 * 扫描项目目录中的 struts.xml 配置提取路由
 */
export async function extractStrutsXmlRoutes(filePath, namespace = "") {
  try {
    const content = await fs.readFile(filePath, "utf8");
    const routes = [];
    let match;

    // 提取 namespace
    const nsPattern = ROUTE_PATTERNS.struts2.namespace;
    const nsMatch = nsPattern.exec(content);
    const ns = nsMatch ? nsMatch[1] : namespace;
    nsPattern.lastIndex = 0;

    // 提取 action mappings
    const actionPattern = /<action\s+name="([^"]+)"[^>]*class="([^"]+)"(?:\s+method="([^"]+)")?[^>]*/g;
    while ((match = actionPattern.exec(content)) !== null) {
      const fullPath = `${ns}/${match[1]}.action`.replace("//", "/");
      routes.push({
        framework: "Struts2",
        httpMethod: "POST",
        urlPath: fullPath,
        file: filePath.replaceAll("\\", "/"),
        line: getLineNumber(content, match.index),
        className: match[2],
        methodName: match[3] || "execute",
        params: {
          path: [],
          query: [],
          body: [{ name: "formData", type: "ActionForm", in: "Body" }],
          header: []
        }
      });
    }

    return routes;
  } catch (error) {
    console.error(`[JavaRouteMapper] 解析 struts.xml 失败 ${filePath}:`, error.message);
    return [];
  }
}

// === 辅助函数 ===

function extractParams(regex, content) {
  const params = [];
  let match;
  const re = new RegExp(regex.source, "g");
  while ((match = re.exec(content)) !== null) {
    if (match[1] && !params.includes(match[1])) {
      params.push(match[1]);
    }
  }
  return params;
}

function extractRequestBody(regex, content) {
  const params = [];
  let match;
  const re = new RegExp(regex.source, "g");
  while ((match = re.exec(content)) !== null) {
    if (match[1]) params.push(match[1]);
  }
  return params;
}

function extractMethodLevelPath(content, annotIndex) {
  const afterAnnot = content.substring(annotIndex, Math.min(annotIndex + 200, content.length));
  const pathMatch = /@Path\s*\(\s*["']([^"']+)["']/.exec(afterAnnot);
  return pathMatch ? pathMatch[1] : "";
}

function extractClassName(content) {
  const match = /public\s+class\s+(\w+)/.exec(content);
  return match ? match[1] : "Unknown";
}

function findNearestMethod(content, beforeIndex) {
  // 从注解位置向前搜索最近的方法签名
  const after = content.substring(beforeIndex, Math.min(beforeIndex + 500, content.length));
  const lines = after.split("\n");
  for (const line of lines) {
    const match = /public\s+(?:\w+(?:<[^>]+>)?)\s+(\w+)\s*\(/.exec(line);
    if (match) return { methodName: match[1] };
  }
  return null;
}

function getLineNumber(content, index) {
  return content.substring(0, index).split("\n").length;
}

/**
 * 批量扫描 Java 项目，提取所有路由
 */
export async function scanJavaProject(projectRoot, fileList = null) {
  const routes = [];
  const errors = [];

  // 自动发现文件
  if (!fileList) {
    const files = [];
    await walkDir(projectRoot, (p) => {
      const ext = path.extname(p).toLowerCase();
      if ([".java", ".xml"].includes(ext)) files.push(p);
    });
    fileList = files;
  }

  const javaFiles = fileList.filter(f => f.endsWith(".java"));
  const xmlFiles = fileList.filter(f => f.endsWith(".xml"));

  // 检测框架
  const { frameworks } = detectFrameworks(fileList, projectRoot);
  console.log(`[JavaRouteMapper] 检测到框架: ${frameworks.join(", ") || "none"}`);

  // 处理 Java 源文件
  for (const file of javaFiles) {
    try {
      const content = await fs.readFile(file, "utf8");
      const fileRoutes = extractRoutes(content, file, frameworks);
      routes.push(...fileRoutes);
    } catch (error) {
      errors.push({ file, error: error.message });
    }
  }

  // 处理 struts.xml
  for (const file of xmlFiles) {
    const basename = path.basename(file).toLowerCase();
    if (basename === "struts.xml" || basename.startsWith("struts-")) {
      try {
        const strutsRoutes = await extractStrutsXmlRoutes(file, "");
        routes.push(...strutsRoutes);
      } catch (error) {
        errors.push({ file, error: error.message });
      }
    }
  }

  // 统计
  const frameworkCount = {};
  const methodCount = {};
  for (const r of routes) {
    frameworkCount[r.framework] = (frameworkCount[r.framework] || 0) + 1;
    methodCount[r.httpMethod] = (methodCount[r.httpMethod] || 0) + 1;
  }

  return {
    routes,
    stats: {
      totalRoutes: routes.length,
      byFramework: frameworkCount,
      byMethod: methodCount,
      filesScanned: javaFiles.length + xmlFiles.length,
      errors: errors.length
    },
    errors
  };
}

async function walkDir(root, callback) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (!entry.name.startsWith(".") && !["node_modules", "target", "build", ".git"].includes(entry.name)) {
        await walkDir(fullPath, callback);
      }
    } else if (entry.isFile()) {
      callback(fullPath);
    }
  }
}

/**
 * 格式化路由为易读的结构
 */
export function formatRoutesReport(scanResult, projectName = "project") {
  const { routes, stats } = scanResult;

  const lines = [
    `# ${projectName} — Java 路由映射报告`,
    `生成时间: ${new Date().toISOString()}`,
    "",
    "## 统计摘要",
    `- 总路由数: ${stats.totalRoutes}`,
    `- 文件扫描数: ${stats.filesScanned}`,
    "",
    "### 按框架分布",
    ...Object.entries(stats.byFramework).map(([fw, count]) => `- ${fw}: ${count}`),
    "",
    "### 按HTTP方法分布",
    ...Object.entries(stats.byMethod).map(([m, count]) => `- ${m}: ${count}`),
    "",
    "## 路由列表",
    "",
    "| # | HTTP方法 | URL路径 | 框架 | 控制器 | 方法 |",
    "|---|----------|---------|------|--------|------|"
  ];

  routes.forEach((r, i) => {
    const className = r.className.split(".").pop();
    lines.push(`| ${i + 1} | ${r.httpMethod} | \`${r.urlPath}\` | ${r.framework} | ${className} | ${r.methodName} |`);
  });

  return lines.join("\n");
}

// 导出默认的 scanner
export const javaRouteMapper = {
  scanProject: scanJavaProject,
  extractRoutes,
  detectFrameworks,
  extractStrutsXmlRoutes,
  formatRoutesReport
};
