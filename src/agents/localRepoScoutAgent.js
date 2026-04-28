import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { CODE_EXTENSIONS, extensionToLanguage } from "../utils/fileUtils.js";

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

const MAX_LOCAL_FILES = 400;
const MAX_FILE_SIZE = 250_000;
const MAX_PARALLEL_FILE_OPS = 10;

export class LocalRepoScoutAgent {
  constructor({ downloadsDir }) {
    this.downloadsDir = downloadsDir;
  }

  async run({ localRepoPaths }) {
    console.log(`[本地仓库扫描] 开始扫描本地仓库，路径数量：${localRepoPaths.length}`);
    const normalizedPaths = normalizeInputPaths(localRepoPaths);
    console.log(`[本地仓库扫描] 标准化后的路径：${JSON.stringify(normalizedPaths)}`);
    const projects = [];
    const skippedPaths = [];

    const pathResults = await Promise.all(
      normalizedPaths.map(async (localPath) => {
        console.log(`[本地仓库扫描] 检查路径：${localPath}`);
        const stats = await inspectLocalPath(localPath);
        if (!stats) {
          console.log(`[本地仓库扫描] 跳过路径：${localPath}，原因：路径不存在、不可访问，或不是目录。`);
          return { skipped: true, path: localPath, reason: "路径不存在、不可访问，或不是目录。" };
        }
        console.log(`[本地仓库扫描] 路径有效，代码文件数：${stats.codeFiles}，主要语言：${stats.primaryLanguage}`);
        return {
          skipped: false,
          project: {
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
          }
        };
      })
    );

    for (const result of pathResults) {
      if (result.skipped) {
        skippedPaths.push({ path: result.path, reason: result.reason });
      } else {
        projects.push(result.project);
      }
    }

    if (!projects.length) {
      console.log(`[本地仓库扫描] 没有找到可导入的本地仓库`);
      throw new Error("没有找到可导入的本地仓库，请检查路径是否存在。");
    }

    console.log(`[本地仓库扫描] 完成扫描，导入 ${projects.length} 个仓库，跳过 ${skippedPaths.length} 个路径`);
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
    console.log(`[本地仓库镜像] 开始为项目生成镜像：${project.name}`);
    const sourceRoot = path.join(this.downloadsDir, project.id);
    console.log(`[本地仓库镜像] 镜像路径：${sourceRoot}`);
    
    const mirroredFiles = await mirrorLocalRepository(project.localPath, sourceRoot);
    console.log(`[本地仓库镜像] 镜像完成，复制了 ${mirroredFiles.length} 个文件`);
    
    const payload = {
      project,
      snapshotAt: new Date().toISOString(),
      sourceRoot,
      mirroredFiles,
      note: "This is a local defensive code mirror for static review. Dependency folders and build artifacts are excluded."
    };

    await fs.mkdir(sourceRoot, { recursive: true });
    await fs.writeFile(path.join(this.downloadsDir, project.downloadArtifact), JSON.stringify(payload, null, 2), "utf8");
    console.log(`[本地仓库镜像] 镜像文件已保存：${project.downloadArtifact}`);
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

  for (let i = 0; i < files.length; i += MAX_PARALLEL_FILE_OPS) {
    const fileChunk = files.slice(i, i + MAX_PARALLEL_FILE_OPS);
    const copyPromises = fileChunk.map(async (sourceFile) => {
      const relative = path.relative(localPath, sourceFile);
      const target = path.join(destinationRoot, relative);
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.copyFile(sourceFile, target);
      const stat = await fs.stat(sourceFile);
      return { path: relative.replaceAll("\\", "/"), size: stat.size };
    });
    const chunkResults = await Promise.all(copyPromises);
    mirroredFiles.push(...chunkResults);
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
