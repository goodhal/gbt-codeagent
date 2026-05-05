import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { CODE_EXTENSIONS, extensionToLanguage } from "./fileUtils.js";

/**
 * 公共常量
 */
export const IGNORED_SEGMENTS = [
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

export const DEFAULT_EXEC_TIMEOUT_MS = 300000; // 5分钟
export const DEFAULT_MAX_BUFFER = 50 * 1024 * 1024; // 50MB

/**
 * 检测项目主要编程语言
 * @param {string} localPath - 本地路径
 * @param {Object} options - 选项
 * @param {string[]} options.ignore - 忽略的目录名称
 * @returns {Promise<string>}
 */
export async function detectLanguageByExtensions(localPath, options = {}) {
  const files = await collectRelevantFiles(localPath, { limit: Infinity, maxFileSize: Infinity });
  return detectPrimaryLanguageFromFiles(files);
}

/**
 * 检测项目主要编程语言（从文件列表）
 * @param {string[]} files - 文件路径列表
 * @returns {string}
 */
export function detectPrimaryLanguageFromFiles(files) {
  const counts = new Map();

  for (const file of files) {
    const language = extensionToLanguage(path.extname(file).toLowerCase());
    counts.set(language, (counts.get(language) || 0) + 1);
  }

  const [topLanguage] = [...counts.entries()].sort((a, b) => b[1] - a[1])[0] || ["Unknown"];
  return topLanguage;
}

/**
 * 遍历项目目录
 * @param {string} root - 根目录
 * @param {Object} options - 选项
 * @param {string[]} options.ignore - 忽略的目录名称
 * @param {Function} options.onFile - 文件回调 (filePath, stats) => void
 * @param {Function} options.onDir - 目录回调 (dirPath) => void
 * @param {number} options.maxFiles - 最大文件数
 * @returns {Promise<void>}
 */
export async function walkProjectDir(root, options = {}) {
  const ignore = options.ignore || IGNORED_SEGMENTS;
  const onFile = options.onFile || (() => {});
  const onDir = options.onDir || (() => {});
  const maxFiles = options.maxFiles || Infinity;
  let fileCount = 0;

  async function walk(dir) {
    if (fileCount >= maxFiles) return;

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      for (const entry of entries) {
        if (fileCount >= maxFiles) return;
        if (ignore.includes(entry.name) || entry.name.startsWith(".")) {
          continue;
        }

        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          onDir(fullPath);
          await walk(fullPath);
        } else if (entry.isFile()) {
          try {
            const stats = await fs.stat(fullPath);
            onFile(fullPath, stats);
            fileCount++;
          } catch {
            // 忽略无法访问的文件
          }
        }
      }
    } catch (error) {
      // 忽略无法访问的目录
    }
  }

  await walk(root);
}

/**
 * 收集相关源文件（过滤掉非代码文件、过大文件）
 * @param {string} root - 根目录
 * @param {Object} options - 选项
 * @param {number} options.limit - 最大文件数
 * @param {number} options.maxFileSize - 单个文件最大大小（字节）
 * @param {string[]} options.ignore - 忽略的目录名称
 * @returns {Promise<string[]>} 文件路径数组
 */
export async function collectRelevantFiles(root, options = {}) {
  const limit = options.limit || Infinity;
  const maxFileSize = options.maxFileSize || 250000;
  const ignore = options.ignore || IGNORED_SEGMENTS;
  const output = [];

  async function walk(currentPath) {
    if (output.length >= limit) return;

    try {
      const entries = await fs.readdir(currentPath, { withFileTypes: true });
      for (const entry of entries) {
        if (output.length >= limit) return;
        if (ignore.includes(entry.name)) continue;

        const target = path.join(currentPath, entry.name);
        if (entry.isDirectory()) {
          await walk(target);
          continue;
        }

        if (!entry.isFile()) continue;
        if (!isRelevantSourceFile(target)) continue;

        const stat = await fs.stat(target);
        if (stat.size > maxFileSize) continue;
        output.push(target);
      }
    } catch {
      // 忽略无法访问的目录
    }
  }

  await walk(root);
  return output;
}

/**
 * 判断文件是否为相关源文件
 * @param {string} filePath - 文件路径
 * @returns {boolean}
 */
export function isRelevantSourceFile(filePath) {
  const lowered = filePath.toLowerCase();
  if (IGNORED_SEGMENTS.some((segment) => lowered.includes(`\\${segment.toLowerCase()}\\`) || lowered.includes(`/${segment.toLowerCase()}/`))) {
    return false;
  }

  return CODE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

/**
 * 获取项目统计信息
 * @param {string} localPath - 本地路径
 * @param {Object} options - 选项
 * @returns {Promise<Object>}
 */
export async function getProjectStats(localPath, options = {}) {
  let fileCount = 0;
  let totalSize = 0;

  await walkProjectDir(localPath, {
    ...options,
    onFile: (filePath, stats) => {
      fileCount++;
      totalSize += stats.size;
    }
  });

  return {
    fileCount,
    totalSize,
    scannedAt: new Date().toISOString()
  };
}

/**
 * 生成唯一项目ID（基于时间戳）
 * @param {string} baseName - 基础名称
 * @returns {string}
 */
export function buildUniqueProjectId(baseName) {
  const timestamp = Date.now().toString(36);
  return `${baseName}-${timestamp}`;
}

/**
 * 执行命令（带超时和错误处理）
 * @param {string} command - 命令
 * @param {Object} options - execSync 选项
 * @returns {string} 命令输出
 */
export function execWithTimeout(command, options = {}) {
  const defaultOptions = {
    stdio: "pipe",
    timeout: DEFAULT_EXEC_TIMEOUT_MS,
    encoding: "utf-8",
    ...options
  };

  try {
    return execSync(command, defaultOptions);
  } catch (error) {
    throw new Error(`命令执行失败: ${error.message}`);
  }
}

/**
 * 批量处理项目
 * @param {Array} items - 待处理项目列表
 * @param {Function} processOne - 处理单个项目的函数 (item) => Promise<Object>
 * @param {Object} options - 选项
 * @param {string} options.stage - 阶段名称
 * @param {string} options.labelTemplate - 标签模板
 * @param {Function} options.getDetail - 获取详情的函数 (item) => string
 * @param {Function} options.onProgress - 进度回调
 * @returns {Promise<{projects: Array}>}
 */
export async function runBatch(items, processOne, options = {}) {
  const {
    stage = "processing",
    labelTemplate = "正在处理",
    getDetail = (item) => String(item),
    onProgress = () => {}
  } = options;

  const projects = [];
  const total = items.length;

  for (let i = 0; i < items.length; i++) {
    const item = items[i];
    const current = i + 1;

    try {
      onProgress({
        stage,
        label: `${labelTemplate} (${current}/${total})`,
        detail: getDetail(item),
        percent: Math.round((current / total) * 100),
        current,
        total
      });

      const project = await processOne(item);
      if (project) {
        projects.push(project);
      }
    } catch (error) {
      console.error(`[处理失败] ${getDetail(item)}:`, error.message);
      // 继续处理下一个，不中断整个流程
    }
  }

  return { projects };
}

/**
 * 标准化项目信息对象（统一数据结构）
 * 同时保留新旧字段名以保持向后兼容性
 * @param {Object} raw - 原始项目信息
 * @returns {Object} 标准化后的项目信息
 */
export function normalizeProjectInfo(raw) {
  // 统一使用 snake_case 格式（与 GitHub API 保持一致）
  // 同时保留 camelCase 别名以保持向后兼容
  const normalized = {
    // 标准字段（snake_case）
    id: raw.id,
    full_name: raw.full_name || raw.name,
    name: raw.name,
    html_url: raw.html_url || raw.repoUrl || "",
    description: raw.description || "",
    language: raw.language || "Unknown",
    stargazers_count: raw.stargazers_count ?? raw.adoptionSignals?.stars ?? 0,
    forks_count: raw.forks_count ?? raw.adoptionSignals?.forks ?? 0,
    updated_at: raw.updated_at || raw.updatedAt || new Date().toISOString(),
    pushed_at: raw.pushed_at || raw.pushedAt || new Date().toISOString(),
    default_branch: raw.default_branch || raw.defaultBranch || "main",
    topics: raw.topics || [],
    localPath: raw.localPath,
    sourceType: raw.sourceType,
    downloadArtifact: raw.downloadArtifact,
    stats: raw.stats || {},

    // 向后兼容字段（camelCase 别名）
    repoUrl: raw.html_url || raw.repoUrl || "",
    defaultBranch: raw.default_branch || raw.defaultBranch || "main",
    updatedAt: raw.updated_at || raw.updatedAt || new Date().toISOString(),
    pushedAt: raw.pushed_at || raw.pushedAt || new Date().toISOString(),

    // 保留其他可能存在的字段
    owner: raw.owner,
    cmsType: raw.cmsType,
    industries: raw.industries,
    tags: raw.tags
  };

  // 如果有 adoptionSignals，保留它（用于 FrameworkScoutAgent）
  if (raw.adoptionSignals) {
    normalized.adoptionSignals = raw.adoptionSignals;
  } else if (raw.stargazers_count !== undefined || raw.forks_count !== undefined) {
    // 如果没有 adoptionSignals 但有 stars/forks，创建一个
    normalized.adoptionSignals = {
      stars: normalized.stargazers_count,
      forks: normalized.forks_count,
      estimatedLiveUsage: raw.stats?.codeFiles || 0
    };
  }

  return normalized;
}

/**
 * 从 Git URL 提取仓库名称
 * @param {string} gitUrl - Git 仓库地址
 * @returns {string|null}
 */
export function extractRepoName(gitUrl) {
  // 支持格式：
  // https://github.com/user/repo.git
  // https://github.com/user/repo
  // git@github.com:user/repo.git
  // git@github.com:user/repo

  let match;

  // HTTPS 格式
  match = gitUrl.match(/https?:\/\/[^/]+\/([^/]+)\/([^/]+?)(\.git)?$/);
  if (match) {
    return `${match[1]}-${match[2]}`;
  }

  // SSH 格式
  match = gitUrl.match(/git@[^:]+:([^/]+)\/([^/]+?)(\.git)?$/);
  if (match) {
    return `${match[1]}-${match[2]}`;
  }

  return null;
}

/**
 * 获取 Git 仓库的默认分支
 * @param {string} localPath - 本地路径
 * @returns {Promise<string>}
 */
export async function getDefaultBranch(localPath) {
  try {
    const output = execWithTimeout("git branch --show-current", {
      cwd: localPath,
      timeout: 5000 // 5秒超时
    });
    return output.trim() || "main";
  } catch {
    return "main";
  }
}

/**
 * 获取 Git 仓库统计信息（跨平台兼容）
 * @param {string} localPath - 本地路径
 * @returns {Promise<Object>}
 */
export async function getGitRepoStats(localPath) {
  try {
    // 使用 git rev-list 代替 wc -l（跨平台兼容）
    const output = execWithTimeout("git rev-list --count HEAD", {
      cwd: localPath,
      timeout: 10000 // 10秒超时
    });
    const commitCount = parseInt(output.trim()) || 0;

    return {
      commitCount,
      clonedAt: new Date().toISOString()
    };
  } catch {
    return {
      commitCount: 0,
      clonedAt: new Date().toISOString()
    };
  }
}
