import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

const IGNORED_SEGMENTS = [
  ".git",
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  "vendor",
  "tmp",
  "temp"
];

const CODE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".php",
  ".py",
  ".go",
  ".java",
  ".rb",
  ".cs",
  ".rs"
]);

const MAX_LOCAL_FILES = 400;
const MAX_FILE_SIZE = 250_000;

export class LocalRepoScoutAgent {
  constructor({ downloadsDir }) {
    this.downloadsDir = downloadsDir;
  }

  async run({ localRepoPaths }) {
    const normalizedPaths = normalizeInputPaths(localRepoPaths);
    const projects = [];
    const skippedPaths = [];

    for (const localPath of normalizedPaths) {
      const stats = await inspectLocalPath(localPath);
      if (!stats) {
        skippedPaths.push({
          path: localPath,
          reason: "路径不存在、不可访问，或不是目录。"
        });
        continue;
      }

      projects.push({
        id: buildProjectId(localPath),
        sourceType: "local",
        name: path.basename(localPath),
        owner: "local",
        repoUrl: "",
        localPath,
        description: `本地仓库导入：${localPath}`,
        language: stats.primaryLanguage,
        defaultBranch: "local",
        updatedAt: stats.updatedAt,
        pushedAt: stats.updatedAt,
        downloadArtifact: `${buildProjectId(localPath)}.json`,
        adoptionSignals: {
          stars: 0,
          forks: 0,
          estimatedLiveUsage: 0,
          codeFiles: stats.codeFiles
        }
      });
    }

    if (!projects.length) {
      throw new Error("没有找到可导入的本地仓库，请检查路径是否存在。");
    }

    return {
      sourceMode: "local-import",
      query: "local repository import",
      discoveredAt: new Date().toISOString(),
      skippedPaths,
      summary: buildSummary(projects.length, skippedPaths),
      projects
    };
  }

  async ensureProjectMirror(project) {
    const sourceRoot = path.join(this.downloadsDir, project.id);
    const mirroredFiles = await mirrorLocalRepository(project.localPath, sourceRoot);
    const payload = {
      project,
      snapshotAt: new Date().toISOString(),
      sourceRoot,
      mirroredFiles,
      note: "This is a local defensive code mirror for static review. Dependency folders and build artifacts are excluded."
    };

    await fs.mkdir(sourceRoot, { recursive: true });
    await fs.writeFile(path.join(this.downloadsDir, project.downloadArtifact), JSON.stringify(payload, null, 2), "utf8");
    return payload;
  }
}

async function inspectLocalPath(localPath) {
  try {
    const stat = await fs.stat(localPath);
    if (!stat.isDirectory()) return null;
    const files = await collectRelevantFiles(localPath, { limit: 120 });
    return {
      updatedAt: stat.mtime.toISOString(),
      codeFiles: files.length,
      primaryLanguage: detectPrimaryLanguage(files)
    };
  } catch {
    return null;
  }
}

async function mirrorLocalRepository(localPath, destinationRoot) {
  await fs.rm(destinationRoot, { recursive: true, force: true });
  await fs.mkdir(destinationRoot, { recursive: true });

  const files = await collectRelevantFiles(localPath, { limit: MAX_LOCAL_FILES });
  const mirroredFiles = [];

  for (const sourceFile of files) {
    const relative = path.relative(localPath, sourceFile);
    const target = path.join(destinationRoot, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.copyFile(sourceFile, target);
    const stat = await fs.stat(sourceFile);
    mirroredFiles.push({ path: relative.replaceAll("\\", "/"), size: stat.size });
  }

  return mirroredFiles;
}

async function collectRelevantFiles(root, { limit }) {
  const output = [];
  await walk(root, output, limit);
  return output;
}

async function walk(currentPath, output, limit) {
  if (output.length >= limit) return;

  const entries = await fs.readdir(currentPath, { withFileTypes: true });
  for (const entry of entries) {
    if (output.length >= limit) return;
    if (IGNORED_SEGMENTS.includes(entry.name)) continue;

    const target = path.join(currentPath, entry.name);
    if (entry.isDirectory()) {
      await walk(target, output, limit);
      continue;
    }

    if (!entry.isFile()) continue;
    if (!isRelevantSourceFile(target)) continue;

    const stat = await fs.stat(target);
    if (stat.size > MAX_FILE_SIZE) continue;
    output.push(target);
  }
}

function isRelevantSourceFile(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(`\\${segment.toLowerCase()}\\`) || lowered.includes(`/${segment.toLowerCase()}/`))) {
    return false;
  }

  return CODE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function detectPrimaryLanguage(files) {
  const counts = new Map();

  for (const file of files) {
    const language = extensionToLanguage(path.extname(file).toLowerCase());
    counts.set(language, (counts.get(language) || 0) + 1);
  }

  const [topLanguage] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0] || ["Unknown"];
  return topLanguage;
}

function extensionToLanguage(ext) {
  return {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".php": "PHP",
    ".py": "Python",
    ".go": "Go",
    ".java": "Java",
    ".rb": "Ruby",
    ".cs": "C#",
    ".rs": "Rust",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML"
  }[ext] || "Unknown";
}

function normalizeInputPaths(localRepoPaths) {
  if (Array.isArray(localRepoPaths)) {
    return [...new Set(localRepoPaths.map((item) => String(item || "").trim()).filter(Boolean))];
  }

  return [...new Set(String(localRepoPaths || "")
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean))];
}

function buildProjectId(localPath) {
  const digest = crypto.createHash("sha1").update(localPath).digest("hex").slice(0, 10);
  const slug = path.basename(localPath).replace(/[^a-zA-Z0-9_-]/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "") || "local-repo";
  return `local-${slug}-${digest}`;
}

function buildSummary(importedCount, skippedPaths) {
  if (!skippedPaths.length) {
    return `已导入 ${importedCount} 个本地仓库，可继续选择目标并启动审计。`;
  }

  return `已导入 ${importedCount} 个本地仓库，跳过 ${skippedPaths.length} 个无效路径。`;
}
