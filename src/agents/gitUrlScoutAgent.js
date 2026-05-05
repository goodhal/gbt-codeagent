import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import {
  detectLanguageByExtensions,
  buildUniqueProjectId,
  extractRepoName,
  getDefaultBranch,
  getGitRepoStats,
  normalizeProjectInfo,
  runBatch,
  DEFAULT_EXEC_TIMEOUT_MS,
  DEFAULT_MAX_BUFFER
} from "../utils/scoutCommon.js";

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
    return runBatch(gitUrls, (gitUrl) => this.cloneSingleRepo(gitUrl), {
      stage: "git-clone",
      labelTemplate: "正在克隆仓库",
      getDetail: (gitUrl) => gitUrl,
      onProgress
    });
  }

  /**
   * 克隆单个仓库
   * @param {string} gitUrl - Git 仓库地址
   * @returns {Promise<Object|null>}
   */
  async cloneSingleRepo(gitUrl) {
    // 解析仓库名称
    const repoName = extractRepoName(gitUrl);
    if (!repoName) {
      throw new Error(`无法解析仓库名称: ${gitUrl}`);
    }

    // 生成本地路径（添加时间戳确保唯一性）
    const uniqueRepoName = buildUniqueProjectId(repoName);
    const localPath = path.join(this.downloadsDir, uniqueRepoName);

    // 执行 git clone
    console.log(`[Git克隆] 开始克隆: ${gitUrl} -> ${localPath}`);
    try {
      execSync(`git clone --depth 1 "${gitUrl}" "${localPath}"`, {
        stdio: "pipe",
        timeout: DEFAULT_EXEC_TIMEOUT_MS,
        maxBuffer: DEFAULT_MAX_BUFFER
      });
      console.log(`[Git克隆] 克隆成功: ${repoName}`);
    } catch (error) {
      throw new Error(`Git 克隆失败: ${error.message}`);
    }

    return await this.buildProjectInfo(gitUrl, uniqueRepoName, localPath);
  }

  /**
   * 构建项目信息对象
   * @param {string} gitUrl - Git 仓库地址
   * @param {string} repoName - 仓库名称
   * @param {string} localPath - 本地路径
   * @returns {Promise<Object>}
   */
  async buildProjectInfo(gitUrl, repoName, localPath) {
    const language = await detectLanguageByExtensions(localPath);
    const stats = await getGitRepoStats(localPath);
    const defaultBranch = await getDefaultBranch(localPath);

    return normalizeProjectInfo({
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
      default_branch: defaultBranch,
      topics: [],
      localPath,
      sourceType: "git-url",
      downloadArtifact: `${repoName}.json`,
      stats
    });
  }
}
