/**
 * Java 路由调用链追踪分析器
 * 参考: java-audit-skills/skills/java-route-tracer
 *
 * 追踪从 Controller/Action → Service → DAO → Sink 的完整调用链
 * 输出每层的方法签名、参数流向、分支条件、Sink识别、可控性分析
 *
 * 支持: Spring MVC, Struts2, Servlet, JAX-RS, CXF WebService
 */

import { promises as fs } from "node:fs";
import path from "path";

// === Sink 类型定义 ===

const SINK_PATTERNS = {
  SQL: {
    methods: [
      "executeQuery", "executeUpdate", "execute",
      "createQuery", "createNativeQuery", "createSQLQuery",
      "query", "queryForObject", "queryForList", "queryForMap",
      "batchUpdate"
    ],
    keywords: [
      "Statement.", "PreparedStatement.", "JdbcTemplate",
      "NamedParameterJdbcTemplate", "SqlSession.", "sql.",
      "hibernate", "Session.", "EntityManager."
    ],
    description: "SQL 语句执行"
  },
  COMMAND: {
    methods: ["exec", "start", "run"],
    keywords: ["Runtime.getRuntime()", "ProcessBuilder", "ProcessImpl"],
    description: "系统命令执行"
  },
  HTTP: {
    methods: ["execute", "get", "post", "put", "delete", "exchange"],
    keywords: ["HttpClient", "RestTemplate", "WebClient", "HttpURLConnection", "URL.openConnection"],
    description: "HTTP 请求发起"
  },
  FILE: {
    methods: ["read", "write", "copy", "move", "delete", "transferTo", "getInputStream", "getOutputStream"],
    keywords: ["FileInputStream", "FileOutputStream", "FileReader", "BufferedReader", "Files.",
      "File(", "Path.", "Scanner."],
    description: "文件读写操作"
  },
  XML: {
    methods: ["parse", "read", "unmarshal", "transform", "evaluate"],
    keywords: ["DocumentBuilder", "SAXParser", "SAXReader", "SAXBuilder",
      "XMLReader", "XMLInputFactory", "TransformerFactory", "JAXBContext", "Unmarshaller"],
    description: "XML 解析"
  },
  DESERIALIZE: {
    methods: ["readObject", "readResolve", "fromXML", "fromJSON", "parseObject", "parse"],
    keywords: ["ObjectInputStream", "XMLDecoder", "XStream", "Yaml.load", "JSON.parseObject",
      "ObjectMapper.readValue", "Gson.fromJson"],
    description: "反序列化操作"
  },
  EXPRESSION: {
    methods: ["getValue", "parseExpression", "eval", "evaluate"],
    keywords: ["SpelExpressionParser", "StandardEvaluationContext", "ScriptEngine",
      "GroovyShell", "MVEL", "OGNL", "FreeMarker", "Velocity"],
    description: "表达式注入"
  },
  LDAP: {
    methods: ["search", "lookup", "authenticate"],
    keywords: ["DirContext", "LdapTemplate", "InitialLdapContext"],
    description: "LDAP 查询"
  },
  RESPONSE: {
    methods: ["write", "print", "flush", "append", "sendRedirect", "sendError"],
    keywords: ["response.getWriter()", "response.getOutputStream()", "HttpServletResponse"],
    description: "HTTP 响应输出"
  }
};

// === 调用关系识别 ===

const METHOD_CALL_PATTERNS = [
  // this.methodName()
  { pattern: /\bthis\.(\w+)\s*\(/g, type: "this_call" },
  // injectedField.methodName()
  { pattern: /\b(\w+)\.(\w+)\s*\(/g, type: "field_call" },
  // super.methodName()
  { pattern: /\bsuper\.(\w+)\s*\(/g, type: "super_call" },
  // ClassName.staticMethod()
  { pattern: /\b([A-Z]\w+)\.(\w+)\s*\(/g, type: "static_call" }
];

// === 依赖注入识别 ===

const DI_PATTERNS = [
  // @Autowired private SomeService someService;
  /@(?:Autowired|Inject|Resource)\s+(?:private|protected|public)?\s*\w+\s+(\w+)\s*[=;]/g,
  // Constructor injection
  /public\s+\w+\s*\(([^)]*@(?:Autowired|Qualified)[^)]*)\)/g,
  // Setter injection
  /@Autowired\s+public\s+void\s+set(\w+)\s*\(/g
];

// === 方法入口定位模式 ===

const ENTRY_PATTERNS = {
  spring: {
    annotations: ["@RequestMapping", "@GetMapping", "@PostMapping", "@PutMapping", "@DeleteMapping", "@PatchMapping"],
    signaturePattern: /public\s+(\S+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\S+)?\s*\{/g
  },
  struts2: {
    annotations: [],
    signaturePattern: /public\s+(?:String|void)\s+(\w+)\s*\(\)\s*(?:throws\s+\S+)?\s*\{/g
  },
  jaxrs: {
    annotations: ["@Path", "@GET", "@POST", "@PUT", "@DELETE"],
    signaturePattern: /public\s+(\S+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\S+)?\s*\{/g
  },
  webservice: {
    annotations: ["@WebMethod"],
    signaturePattern: /public\s+(\S+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+\S+)?\s*\{/g
  }
};

// === 核心追踪引擎 ===

/**
 * 从 Java 源代码中提取所有入口方法
 */
export function findEntryMethods(content, framework = "spring") {
  const config = ENTRY_PATTERNS[framework] || ENTRY_PATTERNS.spring;
  const methods = [];
  let match;

  const isEntry = (line) => {
    return config.annotations.some(a => line.includes(a));
  };

  const lines = content.split("\n");
  const sigRegex = new RegExp(config.signaturePattern.source, "g");

  while ((match = sigRegex.exec(content)) !== null) {
    const lineNum = content.substring(0, match.index).split("\n").length;
    // 检查前3行是否有入口注解
    const contextStart = Math.max(0, lineNum - 4);
    const contextEnd = Math.min(lines.length, lineNum);
    const context = lines.slice(contextStart, contextEnd).join("\n");

    if (framework !== "struts2" && !isEntry(context)) continue;

    methods.push({
      name: match[2],
      returnType: match[1],
      params: parseParameterList(match[3]),
      line: lineNum,
      fullSignature: match[0]
    });
  }

  return methods;
}

/**
 * 解析方法参数列表
 */
function parseParameterList(paramStr) {
  if (!paramStr || paramStr.trim() === "") return [];
  const params = [];
  // 简单分割（处理泛型）
  let depth = 0;
  let current = "";
  for (const ch of paramStr) {
    if (ch === "<") depth++;
    else if (ch === ">") depth--;
    else if (ch === "," && depth === 0) {
      params.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) params.push(current.trim());

  return params.map(p => {
    const parts = p.trim().split(/\s+/);
    const name = parts[parts.length - 1];
    const type = parts.slice(0, -1).join(" ");
    return { name, type: type || "Object" };
  });
}

/**
 * 识别方法体内的调用关系
 */
export function analyzeMethodCalls(content, methodStart, methodEnd) {
  const body = content.substring(methodStart, methodEnd);
  const calls = [];

  // this.method() 调用
  let match;
  const thisPattern = /\bthis\.(\w+)\s*\(/g;
  while ((match = thisPattern.exec(body)) !== null) {
    calls.push({ type: "this", method: match[1], position: match.index });
  }

  // super.method() 调用
  const superPattern = /\bsuper\.(\w+)\s*\(/g;
  while ((match = superPattern.exec(body)) !== null) {
    calls.push({ type: "super", method: match[1], position: match.index });
  }

  return calls.sort((a, b) => a.position - b.position);
}

/**
 * 在项目文件集合中查找类定义
 */
export function findClassInFiles(className, fileList) {
  const results = [];
  for (const file of fileList) {
    const basename = path.basename(file, path.extname(file));
    if (basename === className || basename === className + "Impl") {
      results.push(file);
    }
  }
  return results;
}

/**
 * 识别方法中的 Sink 类型
 */
export function identifySink(content, methodBody) {
  const sinks = [];

  for (const [sinkType, config] of Object.entries(SINK_PATTERNS)) {
    for (const keyword of config.keywords) {
      if (methodBody.includes(keyword)) {
        sinks.push({
          type: sinkType,
          description: config.description,
          keyword,
          methods: config.methods.filter(m => methodBody.includes(m))
        });
        break; // 每个sink类型只报一次
      }
    }
  }

  return sinks;
}

/**
 * 分析参数可控性
 */
export function analyzeControllability(paramName, callChain) {
  // 追踪参数在各层中的使用
  let overrideType = "none";
  let overrideCondition = null;
  let isUsed = false;

  for (const level of callChain) {
    if (!level.paramUsage) continue;
    const usage = level.paramUsage[paramName];
    if (!usage) continue;

    isUsed = true;

    // 检测硬编码覆盖
    if (usage.hardcodedOverride) {
      overrideType = "unconditional";
      overrideCondition = usage.hardcodedValue;
    }

    // 检测条件覆盖
    if (usage.conditionalOverride) {
      if (overrideType === "none") {
        overrideType = "conditional";
        overrideCondition = usage.condition;
      }
    }
  }

  if (!isUsed) {
    return {
      controllable: false,
      condition: "not_used",
      conclusion: "❌ 不可控",
      description: "参数被传递但未参与敏感操作"
    };
  }

  switch (overrideType) {
    case "none":
      return {
        controllable: true,
        condition: null,
        conclusion: "✅ 完全可控",
        description: "参数直接到达 Sink，无任何覆盖"
      };
    case "unconditional":
      return {
        controllable: false,
        condition: overrideCondition,
        conclusion: "❌ 不可控",
        description: `参数被无条件硬编码覆盖: ${overrideCondition}`
      };
    case "conditional":
      return {
        controllable: true,
        condition: overrideCondition,
        conclusion: "⚠️ 条件可控",
        description: `参数在特定条件下可控: ${overrideCondition}`
      };
    default:
      return { controllable: false, conclusion: "❌ 不可控", description: "未知覆盖类型" };
  }
}

/**
 * 构建完整调用链（多文件追踪）
 */
export async function traceCallChain(entryFile, entryMethod, projectFiles, projectRoot) {
  const callChain = [];
  const visited = new Set();

  try {
    const content = await fs.readFile(entryFile, "utf8");
    const lines = content.split("\n");

    // Level 1: 入口方法
    const entryBody = extractMethodBody(content, entryMethod.line);
    const entryCalls = analyzeMethodCalls(content, 0, content.length);
    const entrySinks = identifySink(content, entryBody?.body || "");
    const entryDi = extractDependencies(content);

    callChain.push({
      level: 1,
      file: path.relative(projectRoot, entryFile).replaceAll("\\", "/"),
      className: extractClassName(content),
      methodName: entryMethod.name,
      params: entryMethod.params,
      returnType: entryMethod.returnType,
      sinkTypes: entrySinks.map(s => s.type),
      sinkDetails: entrySinks,
      calls: entryCalls.map(c => ({ type: c.type, target: c.method })),
      dependencies: entryDi,
      line: entryMethod.line,
      isEntry: true
    });

    visited.add(entryFile);

    // Level 2+: 递归追踪调用链
    await traceNextLevels(entryFile, entryCalls, entryDi, callChain, projectFiles,
      projectRoot, visited, 2, 5); // max 5 levels

  } catch (error) {
    callChain.push({ error: error.message, file: entryFile });
  }

  return callChain;
}

/**
 * 递归追踪下一层调用
 */
async function traceNextLevels(fromFile, calls, dependencies, callChain, projectFiles,
  projectRoot, visited, level, maxDepth) {
  if (level > maxDepth) return;

  // 从依赖注入字段追踪
  for (const dep of dependencies) {
    const depFiles = findClassInFiles(dep.type.split(" ").pop(), projectFiles);
    for (const depFile of depFiles) {
      if (visited.has(depFile)) continue;
      visited.add(depFile);

      try {
        const content = await fs.readFile(depFile, "utf8");

        // 查找哪些方法被调用
        for (const call of calls) {
          if (call.type === "field" && dep.name === call.fieldName) continue;
          // 简化：查找被调用的方法
          const methodSig = `public.*${call.target || call.method}\\s*\\(`;
          const methodMatch = new RegExp(methodSig).exec(content);
          if (!methodMatch) continue;

          const methodBody = extractMethodBody(content,
            content.substring(0, methodMatch.index).split("\n").length);

          const depCalls = analyzeMethodCalls(content,
            methodMatch.index,
            methodMatch.index + (methodBody?.length || 0));

          const depSinks = identifySink(content, methodBody?.body || "");
          const depDi = extractDependencies(content);

          callChain.push({
            level,
            file: path.relative(projectRoot, depFile).replaceAll("\\", "/"),
            className: extractClassName(content),
            methodName: call.target || call.method,
            sinkTypes: depSinks.map(s => s.type),
            sinkDetails: depSinks,
            calls: depCalls.map(c => ({ type: c.type, target: c.method })),
            dependencies: depDi,
            line: content.substring(0, methodMatch.index).split("\n").length,
            isTerminal: depSinks.length > 0
          });

          // 继续追踪
          await traceNextLevels(depFile, depCalls, depDi, callChain, projectFiles,
            projectRoot, visited, level + 1, maxDepth);
        }
      } catch (error) {
        callChain.push({ level, file: depFile, error: error.message, className: dep.name });
      }
    }
  }

  // 从父类追踪
  for (const call of calls) {
    if (call.type !== "super") continue;
    for (const file of projectFiles) {
      if (visited.has(file)) continue;
      const basename = path.basename(file, ".java");
      // 查找包含 super.method() 方法的父类
      try {
        const content = await fs.readFile(file, "utf8");
        if (content.includes(`class ${basename}`) &&
          content.includes(`${call.method}(`)) {
          visited.add(file);

          const methodBody = extractMethodBody(content,
            content.indexOf(`${call.method}(`) > 0
              ? content.substring(0, content.indexOf(`${call.method}(`)).split("\n").length
              : 1);

          const superCalls = analyzeMethodCalls(content, 0, content.length);
          const superSinks = identifySink(content, methodBody?.body || "");

          callChain.push({
            level,
            file: path.relative(projectRoot, file).replaceAll("\\", "/"),
            className: basename,
            methodName: call.method,
            sinkTypes: superSinks.map(s => s.type),
            sinkDetails: superSinks,
            calls: superCalls.map(c => ({ type: c.type, target: c.method })),
            line: methodBody?.startLine || 0,
            isTerminal: superSinks.length > 0,
            isParent: true
          });

          await traceNextLevels(file, superCalls, [], callChain, projectFiles,
            projectRoot, visited, level + 1, maxDepth);
        }
      } catch (err) { /* skip */ }
    }
  }
}

// === 辅助函数 ===

function extractClassName(content) {
  const match = /public\s+(?:abstract\s+)?class\s+(\w+)/.exec(content);
  return match ? match[1] : "Unknown";
}

function extractDependencies(content) {
  const deps = [];
  let match;

  // 字段注入
  const fieldPattern = /@(?:Autowired|Inject|Resource)\s+(?:private|protected|public)?\s*(\w+(?:<[^>]+>)?)\s+(\w+)\s*[=;]/g;
  while ((match = fieldPattern.exec(content)) !== null) {
    deps.push({ name: match[2], type: match[1] });
  }

  // 构造器注入参数
  const ctorPattern = /public\s+\w+\s*\(([^)]*)\)\s*\{/g;
  while ((match = ctorPattern.exec(content)) !== null) {
    const paramList = match[1];
    const paramRe = /(?:@\w+\s+)?(\S+)\s+(\w+)/g;
    let pm;
    while ((pm = paramRe.exec(paramList)) !== null) {
      if (pm[1].charAt(0) === pm[1].charAt(0).toUpperCase()) {
        deps.push({ name: pm[2], type: pm[1] });
      }
    }
  }

  return deps;
}

function extractMethodBody(content, startLine) {
  const lines = content.split("\n");
  if (startLine < 1 || startLine > lines.length) return null;

  // 找到方法开始（从指定行搜索 '{'）
  let braceCount = 0;
  let inMethod = false;
  let bodyStart = 0;
  let bodyEnd = 0;

  for (let i = startLine - 1; i < lines.length; i++) {
    const line = lines[i];
    const openBraces = (line.match(/\{/g) || []).length;
    const closeBraces = (line.match(/\}/g) || []).length;

    if (!inMethod && openBraces > 0) {
      inMethod = true;
      bodyStart = i;
    }

    braceCount += openBraces - closeBraces;

    if (inMethod && braceCount === 0) {
      bodyEnd = i;
      break;
    }
  }

  if (!inMethod) return null;

  return {
    body: lines.slice(bodyStart, bodyEnd + 1).join("\n"),
    startLine: bodyStart + 1,
    endLine: bodyEnd + 1,
    length: bodyEnd - bodyStart
  };
}

/**
 * 扫描项目并按路由追踪调用链
 */
export async function traceProjectRoutes(projectRoot, routes, fileList = null) {
  if (!fileList) {
    const files = [];
    await walkJavaFiles(projectRoot, files);
    fileList = files;
  }

  const traces = [];

  for (const route of routes) {
    // 按路由找到入口文件
    const entryFiles = fileList.filter(f => {
      const basename = path.basename(f, ".java");
      return route.className && (basename === route.className || f.includes(route.className));
    });

    for (const entryFile of entryFiles) {
      try {
        const content = await fs.readFile(entryFile, "utf8");
        const framework = route.framework?.toLowerCase().includes("spring") ? "spring"
          : route.framework?.toLowerCase().includes("struts") ? "struts2"
            : route.framework?.toLowerCase().includes("jax") ? "jaxrs" : "spring";

        const methods = findEntryMethods(content, framework);

        for (const method of methods) {
          if (route.methodName && method.name !== route.methodName) continue;

          const callChain = await traceCallChain(entryFile, method, fileList, projectRoot);

          // 汇总所有层的 Sink
          const allSinks = [];
          for (const level of callChain) {
            if (level.sinkTypes) allSinks.push(...level.sinkTypes);
          }

          // 提取参数和可控性
          const paramAnalysis = [];
          for (const param of method.params) {
            const controllability = analyzeControllability(param.name, callChain);
            paramAnalysis.push({
              param: param.name,
              type: param.type,
              ...controllability
            });
          }

          traces.push({
            route: route.urlPath || route.route,
            httpMethod: route.httpMethod || "GET",
            framework: route.framework,
            entryFile: path.relative(projectRoot, entryFile).replaceAll("\\", "/"),
            entryMethod: method.name,
            params: paramAnalysis,
            sinks: [...new Set(allSinks)],
            callChain,
            summary: generateTraceSummary(callChain, paramAnalysis)
          });
        }
      } catch (error) {
        traces.push({
          route: route.urlPath,
          error: error.message,
          entryFile: path.relative(projectRoot, entryFile).replaceAll("\\", "/")
        });
      }
    }
  }

  return traces;
}

/**
 * 生成追踪摘要
 */
function generateTraceSummary(callChain, paramAnalysis) {
  const levels = callChain.filter(l => !l.error);
  const terminal = callChain.filter(l => l.isTerminal);
  const controllable = paramAnalysis.filter(p => p.controllable);
  const unconditional = paramAnalysis.filter(p => p.conclusion?.includes("❌"));

  return {
    layers: levels.length,
    terminalPoints: terminal.length,
    totalParams: paramAnalysis.length,
    controllableParams: controllable.length,
    uncontrollableParams: unconditional.length,
    chain: levels.map(l => `[L${l.level}] ${l.className}.${l.methodName}()`).join(" → ")
  };
}

async function walkJavaFiles(root, result) {
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      if (!entry.name.startsWith(".") && !["node_modules", "target", "build", ".git", "dist"].includes(entry.name)) {
        await walkJavaFiles(fullPath, result);
      }
    } else if (entry.name.endsWith(".java")) {
      result.push(fullPath);
    }
  }
}

/**
 * 格式化调用链为易读的 Markdown 报告
 */
export function formatTraceReport(trace, projectName = "project") {
  const lines = [
    `# ${projectName} — 路由调用链追踪报告`,
    `生成时间: ${new Date().toISOString()}`,
    "",
    "## 路由信息",
    `- **路由路径**: \`${trace.route}\``,
    `- **HTTP 方法**: ${trace.httpMethod}`,
    `- **框架**: ${trace.framework || "未知"}`,
    `- **入口文件**: ${trace.entryFile}`,
    `- **入口方法**: ${trace.entryMethod}()`,
    "",
    "## 参数可控性分析",
    "",
    "| 参数 | 类型 | 可控性 | 条件 | 说明 |",
    "|:-----|:-----|:-------|:-----|:-----|"
  ];

  if (trace.params) {
    for (const p of trace.params) {
      const paramName = p.param || p.name || "?";
      const paramType = p.type || "?";
      lines.push(`| ${paramName} | ${paramType} | ${p.conclusion || "未知"} | ${p.condition || "-"} | ${p.description || ""} |`);
    }
  }

  lines.push(
    "",
    "## Sink 识别",
    `- 发现 Sink 类型: ${(trace.sinks || []).join(", ") || "无"}`,
    ""
  );

  if (trace.callChain && trace.callChain.length > 0) {
    lines.push("## 调用链详情", "");

    for (const level of trace.callChain) {
      if (level.error) {
        lines.push(`### [L${level.level}] ❌ 错误`, "");
        lines.push(`- 文件: ${level.file}`);
        lines.push(`- 错误: ${level.error}`);
        lines.push("");
        continue;
      }

      const role = level.isEntry ? " (入口)" : level.isTerminal ? " (Sink)" : level.isParent ? " (父类)" : "";
      lines.push(`### [L${level.level}] ${level.className}.${level.methodName}()${role}`, "");
      lines.push(`- **文件**: ${level.file}:${level.line || "?"}`);
      if (level.params) lines.push(`- **参数**: ${level.params.map(p => `${p.name}:${p.type}`).join(", ")}`);
      if (level.sinkTypes && level.sinkTypes.length > 0) {
        lines.push(`- **Sink**: ${level.sinkTypes.join(", ")}`);
        if (level.sinkDetails) {
          for (const sd of level.sinkDetails) {
            lines.push(`  - ${sd.description}: ${sd.keyword}`);
          }
        }
      }

      if (level.calls && level.calls.length > 0) {
        lines.push(`- **调用**: ${level.calls.map(c => `${c.type} → ${c.target}`).join(", ")}`);
      }

      if (level.dependencies && level.dependencies.length > 0) {
        lines.push(`- **依赖注入**: ${level.dependencies.map(d => `${d.name}:${d.type}`).join(", ")}`);
      }

      lines.push("");
    }
  }

  // 追踪摘要
  if (trace.summary) {
    lines.push(
      "## 追踪摘要",
      `- 调用层级: ${trace.summary.layers}`,
      `- 终端 Sink 点: ${trace.summary.terminalPoints}`,
      `- 总参数数: ${trace.summary.totalParams}`,
      `- 可控参数: ${trace.summary.controllableParams}`,
      `- 不可控参数: ${trace.summary.uncontrollableParams}`,
      `- 调用链: ${trace.summary.chain}`,
      ""
    );
  }

  return lines.join("\n");
}

/**
 * 生成多方法追踪的总索引
 */
export function formatMultiTraceIndex(traces, projectName, routePath) {
  const lines = [
    `# ${projectName} — 路由 ${routePath} 多方法追踪索引`,
    `生成时间: ${new Date().toISOString()}`,
    "",
    `入口方法数: ${traces.length}`,
    "",
    "## 方法清单",
    "",
    "| # | 方法名 | Sink类型 | 可控参数 | 调用层级 |",
    "|---|--------|----------|----------|----------|"
  ];

  traces.forEach((trace, i) => {
    lines.push(`| ${i + 1} | ${trace.entryMethod} | ${(trace.sinks || []).join(", ") || "无"} | ${trace.params?.filter(p => p.controllable).length || 0}/${trace.params?.length || 0} | ${trace.summary?.layers || "?"} |`);
  });

  lines.push(
    "",
    "## 汇总统计",
    "",
    "| 统计项 | 数量 |",
    "|--------|------|",
    `| 总方法数 | ${traces.length} |`,
    `| 有 Sink 的方法 | ${traces.filter(t => t.sinks && t.sinks.length > 0).length} |`,
    `| 有可控参数的方法 | ${traces.filter(t => t.params && t.params.some(p => p.controllable)).length} |`,
    `| 终端 Sink 类型 | ${[...new Set(traces.flatMap(t => t.sinks || []))].join(", ")} |`
  );

  return lines.join("\n");
}

// 导出默认模块
export const javaRouteTracer = {
  findEntryMethods,
  analyzeMethodCalls,
  identifySink,
  analyzeControllability,
  traceCallChain,
  traceProjectRoutes,
  formatTraceReport,
  formatMultiTraceIndex,
  SINK_PATTERNS
};
