import crypto from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  normalizeProjectInfo,
  IGNORED_SEGMENTS,
  collectRelevantFiles,
  detectPrimaryLanguageFromFiles
} from "../utils/scoutCommon.js";

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
          project: normalizeProjectInfo({
            id: buildProjectId(localPath),
            sourceType: "local",
            name: path.basename(localPath),
            owner: "local",
            html_url: "",
            localPath,
            description: `本地仓库导入：${localPath}`,
            language: stats.primaryLanguage,
            default_branch: "local",
            updated_at: stats.updatedAt,
            pushed_at: stats.updatedAt,
            downloadArtifact: `${buildProjectId(localPath)}.json`,
            stargazers_count: 0,
            forks_count: 0,
            stats: {
              codeFiles: stats.codeFiles
            }
          })
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
    
    let mirroredFiles;
    if (project.localPath === sourceRoot) {
      console.log(`[本地仓库镜像] 源路径与目标路径相同，跳过镜像复制`);
      const files = await collectRelevantFiles(project.localPath, { limit: MAX_LOCAL_FILES });
      mirroredFiles = files.map(f => ({ 
        path: path.relative(project.localPath, f).replaceAll("\\", "/"),
        size: 0 
      }));
    } else {
      mirroredFiles = await mirrorLocalRepository(project.localPath, sourceRoot);
      console.log(`[本地仓库镜像] 镜像完成，复制了 ${mirroredFiles.length} 个文件`);
    }
    
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
    const files = await collectRelevantFiles(localPath, { limit: 120, maxFileSize: MAX_FILE_SIZE });
    return {
      updatedAt: stat.mtime.toISOString(),
      codeFiles: files.length,
      primaryLanguage: detectPrimaryLanguageFromFiles(files)
    };
  } catch {
    return null;
  }
}

async function mirrorLocalRepository(localPath, destinationRoot) {
  await fs.rm(destinationRoot, { recursive: true, force: true });
  await fs.mkdir(destinationRoot, { recursive: true });

  const files = await collectRelevantFiles(localPath, { limit: MAX_LOCAL_FILES, maxFileSize: MAX_FILE_SIZE });
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
