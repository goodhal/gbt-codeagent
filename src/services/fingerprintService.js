import { promises as fs } from "node:fs";
import path from "node:path";

const CMS_SIGNATURES = [
  { id: "strapi", label: "Strapi", patterns: [/strapi/i, /users-permissions/i] },
  { id: "directus", label: "Directus", patterns: [/directus/i] },
  { id: "payload", label: "Payload CMS", patterns: [/payloadcms/i, /\bpayload\b/i] },
  { id: "keystone", label: "Keystone", patterns: [/keystone/i] },
  { id: "ghost", label: "Ghost", patterns: [/\bghost\b/i] },
  { id: "wagtail", label: "Wagtail", patterns: [/wagtail/i] },
  { id: "wordpress", label: "WordPress", patterns: [/wordpress/i, /wp-content/i, /wp-admin/i] },
  { id: "joomla", label: "Joomla", patterns: [/joomla/i] },
  { id: "drupal", label: "Drupal", patterns: [/drupal/i] }
];

const TECH_SIGNATURES = [
  { id: "nextjs", label: "Next.js", patterns: [/\bnext\b/i, /next\/config/i] },
  { id: "nestjs", label: "NestJS", patterns: [/\bnestjs\b/i, /@nestjs\//i] },
  { id: "express", label: "Express", patterns: [/\bexpress\b/i] },
  { id: "koa", label: "Koa", patterns: [/\bkoa\b/i] },
  { id: "react", label: "React", patterns: [/\breact\b/i] },
  { id: "vue", label: "Vue", patterns: [/\bvue\b/i] },
  { id: "laravel", label: "Laravel", patterns: [/\blaravel\b/i] },
  { id: "django", label: "Django", patterns: [/\bdjango\b/i] },
  { id: "spring", label: "Spring", patterns: [/spring-boot/i, /\bspring\b/i] },
  { id: "graphql", label: "GraphQL", patterns: [/\bgraphql\b/i] },
  { id: "mysql", label: "MySQL", patterns: [/\bmysql\b/i] },
  { id: "postgres", label: "PostgreSQL", patterns: [/postgres/i, /\bpg\b/i] },
  { id: "redis", label: "Redis", patterns: [/\bredis\b/i] },
  { id: "s3", label: "S3/Object Storage", patterns: [/\bs3\b/i, /minio/i, /r2/i] }
];

const CMS_TYPE_MAP = {
  strapi: "headless",
  directus: "headless",
  payload: "headless",
  keystone: "headless",
  ghost: "blog",
  wagtail: "enterprise",
  wordpress: "blog",
  joomla: "enterprise",
  drupal: "enterprise"
};

const SAFE_HINTS = [
  "仅用于本地资产清单匹配，不自动发起外部检索。",
  "建议关注后台路径、登录页、公开 API 路径和常见静态资源命名。",
  "如果需要外部资产搜索，请由人工在合规边界内自行执行。"
];

export function createFingerprintService({ downloadsDir }) {
  return {
    async listProjects() {
      const projects = [];
      const entries = await safeReadDir(downloadsDir);

      for (const entry of entries) {
        if (!entry.isDirectory()) {
          continue;
        }

        const projectPath = path.join(downloadsDir, entry.name);
        const fileCount = await countFiles(projectPath);
        if (!fileCount) {
          continue;
        }

        projects.push({
          id: entry.name,
          name: entry.name,
          localPath: projectPath,
          fileCount
        });
      }

      return projects.sort((a, b) => b.fileCount - a.fileCount);
    },

    async analyzeProject(projectId) {
      const projectPath = path.join(downloadsDir, projectId);
      const files = await collectProjectFiles(projectPath);
      const combinedText = files.map((file) => `${file.relativePath}\n${file.content}`).join("\n");
      const cms = detectMatches(CMS_SIGNATURES, combinedText);
      const technologies = detectMatches(TECH_SIGNATURES, combinedText);
      const languages = collectLanguages(files);
      const adminPaths = inferAdminPaths(files);
      const apiPaths = inferApiPaths(files);
      const cmsTypes = Array.from(new Set(cms.map((item) => CMS_TYPE_MAP[item.id]).filter(Boolean)));

      return {
        projectId,
        projectPath,
        fileCount: files.length,
        cms,
        cmsTypes,
        technologies,
        languages,
        adminPaths,
        apiPaths,
        safeSearchHints: buildSafeSearchHints({ cms, technologies, adminPaths, apiPaths }),
        notice: "本页只做本地源码指纹提取与本地资产清单匹配，不自动生成外部检索语句，也不自动发起互联网搜索。"
      };
    },

    async matchAssets({ projectId, assetText }) {
      const analysis = await this.analyzeProject(projectId);
      const assets = String(assetText || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

      const tokens = [
        ...analysis.cms.map((item) => item.label),
        ...analysis.technologies.map((item) => item.label),
        ...analysis.adminPaths,
        ...analysis.apiPaths
      ]
        .map((item) => item.toLowerCase())
        .filter(Boolean);

      const matches = assets
        .map((asset) => {
          const lowered = asset.toLowerCase();
          const hitTokens = tokens.filter((token) => lowered.includes(token.toLowerCase())).slice(0, 6);
          return {
            asset,
            matched: hitTokens.length > 0,
            hitTokens
          };
        })
        .filter((item) => item.matched);

      return {
        projectId,
        totalAssets: assets.length,
        matchedAssets: matches.length,
        matches: matches.slice(0, 100),
        safeSummary: matches.length
          ? `已在导入资产清单中匹配到 ${matches.length} 条疑似同技术栈记录。`
          : "导入的资产清单里暂时没有匹配到明显同技术栈记录。"
      };
    },

    async deleteProject(projectId) {
      try {
        const projects = await this.listProjects();
        const project = projects.find(p => p.id === projectId);
        
        if (!project) {
          return { success: false, message: "Project not found" };
        }
        
        // 检查项目路径是否存在
        const projectPath = path.join(downloadsDir, project.name);
        try {
          await fs.access(projectPath);
        } catch {
          return { success: false, message: "Project directory not found" };
        }
        
        // 删除项目目录
        await fs.rm(projectPath, { recursive: true, force: true });
        
        return { 
          success: true, 
          message: "Project deleted successfully",
          projectId 
        };
      } catch (error) {
        console.error("Error deleting project:", error);
        return { 
          success: false, 
          message: error instanceof Error ? error.message : "Failed to delete project"
        };
      }
    }
  };
}

async function safeReadDir(target) {
  try {
    return await fs.readdir(target, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function countFiles(root) {
  const files = await collectProjectFiles(root, { readContent: false });
  return files.length;
}

async function collectProjectFiles(root, options = {}) {
  const output = [];
  await walk(root, root, output, options);
  return output;
}

async function walk(root, current, output, { readContent = true } = {}) {
  const entries = await safeReadDir(current);
  for (const entry of entries) {
    const target = path.join(current, entry.name);
    if (entry.isDirectory()) {
      await walk(root, target, output, { readContent });
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (entry.name === "SAFE_SAMPLE.md") {
      continue;
    }

    const relativePath = path.relative(root, target).replaceAll("\\", "/");
    const item = { fullPath: target, relativePath };
    if (readContent) {
      try {
        item.content = await fs.readFile(target, "utf8");
      } catch {
        item.content = "";
      }
    }
    output.push(item);
  }
}

function detectMatches(catalog, text) {
  return catalog.filter((item) => item.patterns.some((pattern) => pattern.test(text)));
}

function collectLanguages(files) {
  const languages = new Set();
  for (const file of files) {
    const ext = path.extname(file.relativePath).toLowerCase();
    if (ext === ".ts" || ext === ".tsx" || ext === ".js" || ext === ".jsx") languages.add("JavaScript / TypeScript");
    if (ext === ".php") languages.add("PHP");
    if (ext === ".py") languages.add("Python");
    if (ext === ".java") languages.add("Java");
    if (ext === ".cs") languages.add("C#");
    if (ext === ".rb") languages.add("Ruby");
    if (ext === ".go") languages.add("Go");
  }
  return Array.from(languages);
}

function inferAdminPaths(files) {
  const candidates = new Set();
  for (const file of files) {
    const lowered = file.relativePath.toLowerCase();
    if (/(admin|dashboard|backoffice|panel)/.test(lowered)) {
      candidates.add(relativePathToHint(file.relativePath));
    }
  }
  return Array.from(candidates).slice(0, 8);
}

function inferApiPaths(files) {
  const candidates = new Set();
  for (const file of files) {
    const lowered = file.relativePath.toLowerCase();
    if (/(api|graphql|content-api|rest)/.test(lowered)) {
      candidates.add(relativePathToHint(file.relativePath));
    }
  }
  return Array.from(candidates).slice(0, 8);
}

function relativePathToHint(relativePath) {
  const cleaned = relativePath.replace(/^packages\//, "").replace(/^src\//, "");
  const parts = cleaned.split("/");
  return `/${parts.slice(0, Math.min(parts.length, 3)).join("/")}`;
}

function buildSafeSearchHints({ cms, technologies, adminPaths, apiPaths }) {
  return [
    ...SAFE_HINTS,
    cms.length ? `识别到的 CMS 线索：${cms.map((item) => item.label).join("、")}` : "暂未识别到明显 CMS 框架名称。",
    technologies.length ? `识别到的技术栈：${technologies.map((item) => item.label).join("、")}` : "暂未识别到明显技术栈标签。",
    adminPaths.length ? `可人工关注的后台路径特征：${adminPaths.join("、")}` : "暂未提取到明显后台路径特征。",
    apiPaths.length ? `可人工关注的接口路径特征：${apiPaths.join("、")}` : "暂未提取到明显接口路径特征。"
  ];
}
