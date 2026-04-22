import { promises as fs } from "node:fs";
import path from "node:path";
import { resolveAuditSkills } from "../config/auditSkills.js";

export class AuditAnalystAgent {
  constructor({ llmReviewer }) {
    this.llmReviewer = llmReviewer;
  }

  async run({ projects, selectedSkillIds, llmConfig, onProgress }) {
    const reviewProfile = resolveAuditSkills(selectedSkillIds);
    const results = [];

    for (const [index, project] of projects.entries()) {
      onProgress?.({
        stage: "heuristic",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        label: `正在分析规则层：${project.name}`
      });

      const heuristicFindings = await buildHeuristicFindings(project, reviewProfile);
      const llmReview = this.llmReviewer
        ? await this.llmReviewer.reviewProject({
            project,
            selectedSkills: reviewProfile,
            heuristicFindings,
            llmConfig,
            onProgress: (detail) =>
              onProgress?.({
                stage: "llm-review",
                projectId: project.id,
                projectName: project.name,
                projectIndex: index + 1,
                totalProjects: projects.length,
                ...detail
              })
          })
        : {
            status: "skipped",
            called: false,
            skipReason: "reviewer-unavailable",
            summary: "未配置 LLM 复核器。",
            findings: [],
            warnings: []
          };

      const mergedFindings = prioritizeFindings([
        ...heuristicFindings,
        ...(Array.isArray(llmReview.findings) ? llmReview.findings : [])
      ]);

      results.push({
        projectId: project.id,
        projectName: project.name,
        repoUrl: project.repoUrl,
        localPath: project.localPath || "",
        reviewProfile,
        heuristicFindings,
        llmReview,
        findings: mergedFindings
      });

      onProgress?.({
        stage: "project-complete",
        projectId: project.id,
        projectName: project.name,
        projectIndex: index + 1,
        totalProjects: projects.length,
        heuristicCount: heuristicFindings.length,
        llmCount: llmReview?.findings?.length || 0,
        label: `已完成：${project.name}`
      });
    }

    return {
      reviewedAt: new Date().toISOString(),
      policy: "defensive-only",
      skillsUsed: reviewProfile.map((skill) => ({ id: skill.id, name: skill.name })),
      findingsCount: results.reduce((sum, item) => sum + item.findings.length, 0),
      heuristicFindingsCount: results.reduce((sum, item) => sum + item.heuristicFindings.length, 0),
      llmFindingsCount: results.reduce((sum, item) => sum + (item.llmReview?.findings?.length || 0), 0),
      llmCallCount: results.reduce((sum, item) => sum + (item.llmReview?.called ? 1 : 0), 0),
      llmSkippedCount: results.reduce((sum, item) => sum + (item.llmReview?.called ? 0 : 1), 0),
      projects: results
    };
  }
}

async function buildHeuristicFindings(project, reviewProfile) {
  const sourceRoot = path.join(process.cwd(), "workspace", "downloads", project.id);
  const files = await collectFiles(sourceRoot);
  const findings = [];
  const enabledSkills = new Set(reviewProfile.map((skill) => skill.id));

  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    const relative = path.relative(sourceRoot, file).replaceAll("\\", "/");
    const loweredPath = relative.toLowerCase();

    if (
      enabledSkills.has("access-control") &&
      hasObjectAccessIndicator(content) &&
      !hasAuthGuardIndicator(content) &&
      /(controller|route|resolver|service|api)/.test(loweredPath)
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "对象级访问控制边界值得重点复核",
        severity: "medium",
        confidence: 0.76,
        location: relative,
        impact: "如果控制器或服务层直接信任客户端提交的对象标识，可能导致跨用户或跨租户读取、修改内容。",
        evidence: `在 ${relative} 中发现了客户端可控对象标识的处理痕迹，但同文件附近没有明显的 ownership / policy / guard 校验线索。`,
        remediation: "在对象查询后、返回或修改前统一执行 role、tenant 与 ownership 校验，并让服务层承担二次鉴权职责。",
        safeValidation: "本地复核控制器到服务层的调用链，确认对象查找后的每条读写路径都执行了访问控制。"
      }));
    }

    if (
      enabledSkills.has("access-control") &&
      matches(content, /\b(public|anonymous|guest)\b/i, /\b(permission|permissions|role|roles|allow|grant|create|update|delete|read|find)\b/i) &&
      /(permission|policy|role|acl|rbac|config)/.test(loweredPath)
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "公共角色权限配置可能过宽",
        severity: "high",
        confidence: 0.79,
        location: relative,
        impact: "如果匿名或公共角色被默认授予内容管理能力，后台或 API 可能暴露出超出预期的读写面。",
        evidence: `在 ${relative} 中发现了 public / anonymous / guest 角色与权限授予语义同时出现。`,
        remediation: "将公共角色改为 deny-by-default，只为必要的读取接口单独放行，并把管理动作留给显式认证后的角色。",
        safeValidation: "本地检查角色初始化与权限合并逻辑，确认匿名角色不会默认获得管理或写入能力。"
      }));
    }

    if (
      enabledSkills.has("bootstrap-config") &&
      matches(content, /\b(bootstrapAdmin|seedAdmin|createFirstAdmin|registerInitialAdmin|setupAdmin|initialAdmin)\b/i, /\b(process\.env|config|if\s*\(!|allowBootstrap|enableBootstrap)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "bootstrap-config",
        title: "初始化管理员入口需要确认关闭条件",
        severity: "high",
        confidence: 0.82,
        location: relative,
        impact: "如果首次管理员创建逻辑缺少严格的单次条件或部署态关闭机制，生产环境可能暴露出高权限初始化入口。",
        evidence: `在 ${relative} 中发现了管理员初始化逻辑，并与环境配置或缺省条件绑定。`,
        remediation: "将首次管理员创建流程改为一次性、显式确认、默认关闭，并确保初始化完成后彻底失效。",
        safeValidation: "本地审查启动与迁移流程，确认生产缺省态下不存在可重复触发的管理员初始化路径。"
      }));
    }

    if (
      enabledSkills.has("access-control") &&
      (matches(content, /\b(auth\s*:\s*false|skipAuth|bypassAuth|allowUnauthenticated|publicRoute)\b/i, /\b(route|router|endpoint|admin|panel|plugin)\b/i) ||
        (/(route|router|admin|plugin)/.test(loweredPath) && /\bauth\s*:\s*false\b/i.test(content)))
    ) {
      findings.push(createFinding({
        skillId: "access-control",
        title: "部分管理或插件路由显式关闭认证",
        severity: "high",
        confidence: 0.8,
        location: relative,
        impact: "如果这些路由位于后台、插件或管理入口附近，显式关闭认证可能直接扩大高价值接口的暴露面。",
        evidence: `在 ${relative} 中发现了 auth:false 或类似绕过认证的配置语义。`,
        remediation: "对后台、插件与管理路由采用显式白名单，默认启用鉴权与权限中间件，再按需对公开只读接口单独豁免。",
        safeValidation: "本地检查路由注册代码，确认仅少量公开只读接口会关闭认证，管理与插件路由默认受保护。"
      }));
    }

    if (
      enabledSkills.has("upload-storage") &&
      matches(content, /\b(upload|multer|formidable|busboy|content-type|multipart)\b/i, /\b(path\.join|fs\.writeFile|writeFileSync|createWriteStream|public\/|static\/)\b/)
    ) {
      findings.push(createFinding({
        skillId: "upload-storage",
        title: "上传与公开文件边界值得重点审查",
        severity: "medium",
        confidence: 0.71,
        location: relative,
        impact: "如果上传内容的类型、文件名或公开访问目录没有被严格隔离，可能引发任意文件覆盖、危险内容托管或后台资源泄露。",
        evidence: `在 ${relative} 中同时出现了上传处理与文件落盘或公开目录语义。`,
        remediation: "对文件类型、扩展名、目标路径和公开目录做统一收口，公开资源目录与后台可执行路径应彻底隔离。",
        safeValidation: "本地复核上传链路，确认文件名、目标路径、MIME 与公开访问目录都经过规范化控制。"
      }));
    }

    if (
      enabledSkills.has("secret-exposure") &&
      matches(content, /\b(password|secret|token|api[_-]?key)\b/i, /\b(default|example|changeme|admin123|test|demo|sample)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "secret-exposure",
        title: "疑似存在默认凭据或占位密钥风险",
        severity: "high",
        confidence: 0.74,
        location: relative,
        impact: "如果这些默认值会进入初始化流程、后台登录或第三方集成配置，真实部署时可能留下可猜测的高风险入口。",
        evidence: `在 ${relative} 中发现了凭据命名与默认值样式同时出现。`,
        remediation: "移除可运行的默认凭据；缺失密钥时应 fail closed，而不是退回演示或占位值。",
        safeValidation: "本地检查配置装载与初始化逻辑，确认占位值不会被当作真实凭据接受。"
      }));
    }

    if (
      enabledSkills.has("secret-exposure") &&
      matches(content, /\b(NEXT_PUBLIC_|PUBLIC_|VITE_)\b/, /\b(secret|token|api[_-]?key|admin|password)\b/i)
    ) {
      findings.push(createFinding({
        skillId: "secret-exposure",
        title: "公开前端变量中疑似携带敏感配置",
        severity: "medium",
        confidence: 0.68,
        location: relative,
        impact: "如果敏感令牌或后台配置通过公开构建变量注入前端，可能导致管理能力或集成密钥暴露。",
        evidence: `在 ${relative} 中发现了公开前端环境变量前缀与敏感配置命名同时出现。`,
        remediation: "把敏感配置留在服务端，前端仅使用临时票据、代理接口或最小化公开标识。",
        safeValidation: "本地检查构建配置与运行时注入逻辑，确认公开变量中不包含后台密钥或管理接口凭据。"
      }));
    }

    if (
      enabledSkills.has("query-safety") &&
      matches(content, /\b(raw\(|sequelize\.query\(|knex\.raw\(|prisma\.[a-z]+Raw\(|SELECT\b|UPDATE\b|DELETE\b)\b/i, /(`[^`]*\$\{|\+\s*(req|params|query|body)|\b(req|params|query|body)\b)/i)
    ) {
      findings.push(createFinding({
        skillId: "query-safety",
        title: "动态查询构造路径需要重点确认",
        severity: "medium",
        confidence: 0.64,
        location: relative,
        impact: "如果这类动态查询直接拼接外部输入，内容检索、管理后台筛选或插件接口可能出现持久层注入风险。",
        evidence: `在 ${relative} 中发现了原始查询语义，并伴随模板插值或外部输入拼接痕迹。`,
        remediation: "优先改用参数化查询或 ORM 安全接口，并对动态排序、筛选字段做白名单约束。",
        safeValidation: "本地确认原始查询是否始终采用参数绑定，动态字段和值是否都经过白名单控制。"
      }));
    }
  }

  return prioritizeFindings(findings).slice(0, 8);
}

function createFinding(finding) {
  return {
    source: "rule",
    ...finding
  };
}

function prioritizeFindings(findings) {
  const deduped = [];
  const seen = new Set();
  for (const finding of findings) {
    const key = `${finding.title}::${finding.location}`;
    if (seen.has(key)) continue;
    seen.add(key);
    deduped.push(finding);
  }

  return deduped
    .filter((finding) => finding.confidence >= 0.6)
    .sort((a, b) => severityScore(b.severity) - severityScore(a.severity) || b.confidence - a.confidence);
}

function hasObjectAccessIndicator(content) {
  return /(req|request)\.(params|query)\.[a-zA-Z0-9_]+/.test(content) || /\b(ctx|event)\.(params|query)\.[a-zA-Z0-9_]+/.test(content);
}

function hasAuthGuardIndicator(content) {
  return /\b(can|authorize|authorization|permission|permissions|policy|guard|rbac|ownership|tenant)\b/i.test(content);
}

function severityScore(value) {
  return value === "high" ? 3 : value === "medium" ? 2 : 1;
}

async function collectFiles(root) {
  try {
    const entries = await fs.readdir(root, { withFileTypes: true });
    const output = [];
    for (const entry of entries) {
      const target = path.join(root, entry.name);
      if (entry.isDirectory()) output.push(...(await collectFiles(target)));
      else output.push(target);
    }
    return output;
  } catch {
    return [];
  }
}

function matches(content, requiredA, requiredB) {
  return requiredA.test(content) && requiredB.test(content);
}
