import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import {
  detectLanguageByExtensions,
  buildUniqueProjectId,
  getProjectStats,
  normalizeProjectInfo,
  runBatch,
  DEFAULT_EXEC_TIMEOUT_MS
} from "../utils/scoutCommon.js";

/**
 * ZipUploadScoutAgent - 处理 ZIP 代码包上传和解压
 */
export class ZipUploadScoutAgent {
  constructor({ downloadsDir }) {
    this.downloadsDir = downloadsDir;
  }

  /**
   * 处理上传的 ZIP 文件
   * @param {Array} zipFiles - 上传的文件信息数组 [{filename, filepath, size}]
   * @param {Function} onProgress - 进度回调
   * @returns {Promise<{projects: Array}>}
   */
  async processZipFiles(zipFiles, onProgress = () => {}) {
    return runBatch(zipFiles, (zipFile) => this.extractAndProcess(zipFile), {
      stage: "zip-extract",
      labelTemplate: "正在解压 ZIP 文件",
      getDetail: (zipFile) => zipFile.filename,
      onProgress
    });
  }

  /**
   * 解压并处理单个 ZIP 文件
   * @param {Object} zipFile - ZIP 文件信息 {filename, filepath, size}
   * @returns {Promise<Object|null>}
   */
  async extractAndProcess(zipFile) {
    const { filename, filepath } = zipFile;

    // 生成项目名称（去掉 .zip 后缀，添加时间戳确保唯一性）
    const baseName = filename.replace(/\.zip$/i, "");
    const projectName = buildUniqueProjectId(baseName);
    const extractPath = path.join(this.downloadsDir, projectName);

    // 创建解压目录
    await fs.mkdir(extractPath, { recursive: true });

    // 解压 ZIP 文件
    console.log(`[ZIP解压] 开始解压: ${filename} -> ${extractPath}`);
    try {
      await this.extractZip(filepath, extractPath);
      console.log(`[ZIP解压] 解压成功: ${projectName}`);
    } catch (error) {
      // 清理失败的解压目录
      await fs.rm(extractPath, { recursive: true, force: true });
      throw new Error(`ZIP 解压失败: ${error.message}`);
    }

    // 删除临时上传文件
    try {
      await fs.unlink(filepath);
    } catch {
      // 忽略删除失败
    }

    return await this.buildProjectInfo(projectName, extractPath, filename);
  }

  /**
   * 解压 ZIP 文件
   * @param {string} zipPath - ZIP 文件路径
   * @param {string} extractPath - 解压目标路径
   * @returns {Promise<void>}
   */
  async extractZip(zipPath, extractPath) {
    // 检查是否有 unzip 命令（Linux/Mac）
    try {
      execSync("which unzip", { stdio: "pipe" });
      execSync(`unzip -q "${zipPath}" -d "${extractPath}"`, {
        stdio: "pipe",
        timeout: DEFAULT_EXEC_TIMEOUT_MS
      });
      return;
    } catch {
      // unzip 不可用，尝试其他方法
    }

    // Windows 使用 PowerShell
    if (process.platform === "win32") {
      try {
        const psCommand = `Expand-Archive -Path "${zipPath}" -DestinationPath "${extractPath}" -Force`;
        execSync(`powershell -Command "${psCommand}"`, {
          stdio: "pipe",
          timeout: DEFAULT_EXEC_TIMEOUT_MS
        });
        return;
      } catch (error) {
        throw new Error(`PowerShell 解压失败: ${error.message}`);
      }
    }

    // 如果都不可用，使用 Node.js 内置方法（需要额外依赖）
    throw new Error("未找到可用的解压工具（unzip 或 PowerShell）");
  }

  /**
   * 构建项目信息对象
   * @param {string} projectName - 项目名称
   * @param {string} localPath - 本地路径
   * @param {string} originalFilename - 原始文件名
   * @returns {Promise<Object>}
   */
  async buildProjectInfo(projectName, localPath, originalFilename) {
    const language = await detectLanguageByExtensions(localPath);
    const stats = await getProjectStats(localPath);

    return normalizeProjectInfo({
      id: projectName,
      full_name: projectName,
      name: projectName,
      html_url: `file://${localPath}`,
      description: `从 ZIP 上传: ${originalFilename}`,
      language,
      stargazers_count: 0,
      forks_count: 0,
      updated_at: new Date().toISOString(),
      pushed_at: new Date().toISOString(),
      default_branch: "main",
      topics: [],
      localPath,
      sourceType: "zip-upload",
      downloadArtifact: `${projectName}.json`,
      stats
    });
  }
}
