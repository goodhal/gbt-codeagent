import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

/**
 * GitUrlScoutAgent - 直接从 Git URL 克隆仓库
 */
export class GitUrlScoutAgent {
  constructor({ downloadsDir }) {
    this.downloadsDir = downloadsDir;
  }

  /**
   * 从 Git URL 列表克隆仓库
   * @param {string[]} gitUrls - Git 仓库地址列表
   * @param {Function} onProgress - 进度回调
   * @returns {Promise<{projects: Array}>}
   */
  async cloneFromUrls(gitUrls, onProgress = () => {}) {
    const projects = [];
    const total = gitUrls.length;

    for (let i = 0; i < gitUrls.length; i++) {
      const gitUrl = gitUrls[i];
      const current = i + 1;

      try {
        onProgress({
          stage: "git-clone",
          label: `正在克隆仓库 (${current}/${total})`,
          detail: gitUrl,
          percent: Math.round((current / total) * 100),
          current,
          total
        });

        const project = await this.cloneSingleRepo(gitUrl);
        if (project) {
          projects.push(project);
        }
      } catch (error) {
        console.error(`[Git克隆失败] ${gitUrl}:`, error.message);
        // 继续处理下一个，不中断整个流程
      }
    }

    return { projects };
  }

  /**
   * 克隆单个仓库
   * @param {string} gitUrl - Git 仓库地址
   * @returns {Promise<Object|null>}
   */
  async cloneSingleRepo(gitUrl) {
    // 解析仓库名称
    const repoName = this.extractRepoName(gitUrl);
    if (!repoName) {
      throw new Error(`无法解析仓库名称: ${gitUrl}`);
    }

    // 生成本地路径（添加时间戳确保唯一性）
    const timestamp = Date.now().toString(36);
    const uniqueRepoName = `${repoName}-${timestamp}`;
    const localPath = path.join(this.downloadsDir, uniqueRepoName);

    // 检查是否已存在（理论上不会发生，因为有时间戳）
    try {
      await fs.access(localPath);
      console.log(`[Git克隆] 仓库已存在，跳过: ${uniqueRepoName}`);
      return await this.buildProjectInfo(gitUrl, uniqueRepoName, localPath);
    } catch {
      // 目录不存在，继续克隆
    }

    // 执行 git clone
    console.log(`[Git克隆] 开始克隆: ${gitUrl} -> ${localPath}`);
    try {
      execSync(`git clone --depth 1 "${gitUrl}" "${localPath}"`, {
        stdio: "pipe",
        timeout: 300000, // 5分钟超时
        maxBuffer: 50 * 1024 * 1024 // 50MB buffer
      });
      console.log(`[Git克隆] 克隆成功: ${repoName}`);
    } catch (error) {
      throw new Error(`Git 克隆失败: ${error.message}`);
    }

    return await this.buildProjectInfo(gitUrl, uniqueRepoName, localPath);
  }

  /**
   * 从 Git URL 提取仓库名称
   * @param {string} gitUrl - Git 仓库地址
   * @returns {string|null}
   */
  extractRepoName(gitUrl) {
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
   * 构建项目信息对象
   * @param {string} gitUrl - Git 仓库地址
   * @param {string} repoName - 仓库名称
   * @param {string} localPath - 本地路径
   * @returns {Promise<Object>}
   */
  async buildProjectInfo(gitUrl, repoName, localPath) {
    // 检测主要编程语言
    const language = await this.detectLanguage(localPath);

    // 获取仓库统计信息
    const stats = await this.getRepoStats(localPath);

    return {
      id: repoName,
      full_name: repoName,
      name: repoName,
      html_url: gitUrl,
      description: `从 Git URL 导入: ${gitUrl}`,
      language,
      stargazers_count: 0,
      forks_count: 0,
      updated_at: new Date().toISOString(),
      pushed_at: new Date().toISOString(),
      default_branch: await this.getDefaultBranch(localPath),
      topics: [],
      localPath,
      sourceType: "git-url",
      downloadArtifact: `${repoName}.json`,
      stats
    };
  }

  /**
   * 检测仓库主要编程语言
   * @param {string} localPath - 本地路径
   * @returns {Promise<string>}
   */
  async detectLanguage(localPath) {
    const languageExtensions = {
      JavaScript: [".js", ".jsx", ".mjs"],
      TypeScript: [".ts", ".tsx"],
      Python: [".py"],
      Java: [".java"],
      PHP: [".php"],
      Ruby: [".rb"],
      Go: [".go"],
      Rust: [".rs"],
      "C++": [".cpp", ".cc", ".cxx"],
      C: [".c"],
      "C#": [".cs"]
    };

    const counts = {};

    async function scanDir(dir) {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.name.startsWith(".") || entry.name === "node_modules") {
            continue;
          }

          const fullPath = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            await scanDir(fullPath);
          } else {
            const ext = path.extname(entry.name);
            for (const [lang, exts] of Object.entries(languageExtensions)) {
              if (exts.includes(ext)) {
                counts[lang] = (counts[lang] || 0) + 1;
              }
            }
          }
        }
      } catch (error) {
        // 忽略无法访问的目录
      }
    }

    await scanDir(localPath);

    // 返回文件数最多的语言
    let maxLang = "Unknown";
    let maxCount = 0;
    for (const [lang, count] of Object.entries(counts)) {
      if (count > maxCount) {
        maxCount = count;
        maxLang = lang;
      }
    }

    return maxLang;
  }

  /**
   * 获取仓库统计信息
   * @param {string} localPath - 本地路径
   * @returns {Promise<Object>}
   */
  async getRepoStats(localPath) {
    try {
      const output = execSync("git log --oneline | wc -l", {
        cwd: localPath,
        encoding: "utf-8",
        stdio: "pipe"
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

  /**
   * 获取默认分支名称
   * @param {string} localPath - 本地路径
   * @returns {Promise<string>}
   */
  async getDefaultBranch(localPath) {
    try {
      const output = execSync("git branch --show-current", {
        cwd: localPath,
        encoding: "utf-8",
        stdio: "pipe"
      });
      return output.trim() || "main";
    } catch {
      return "main";
    }
  }
}
