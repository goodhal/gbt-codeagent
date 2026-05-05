import { promises as fs } from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";

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
    const projects = [];
    const total = zipFiles.length;

    for (let i = 0; i < zipFiles.length; i++) {
      const zipFile = zipFiles[i];
      const current = i + 1;

      try {
        onProgress({
          stage: "zip-extract",
          label: `正在解压 ZIP 文件 (${current}/${total})`,
          detail: zipFile.filename,
          percent: Math.round((current / total) * 100),
          current,
          total
        });

        const project = await this.extractAndProcess(zipFile);
        if (project) {
          projects.push(project);
        }
      } catch (error) {
        console.error(`[ZIP解压失败] ${zipFile.filename}:`, error.message);
        // 继续处理下一个，不中断整个流程
      }
    }

    return { projects };
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
    const timestamp = Date.now().toString(36);
    const projectName = `${baseName}-${timestamp}`;
    const extractPath = path.join(this.downloadsDir, projectName);

    // 检查是否已存在（理论上不会发生，因为有时间戳）
    try {
      await fs.access(extractPath);
      console.log(`[ZIP解压] 目录已存在，跳过: ${projectName}`);
      return await this.buildProjectInfo(projectName, extractPath, filename);
    } catch {
      // 目录不存在，继续解压
    }

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
        timeout: 300000 // 5分钟超时
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
          timeout: 300000
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
    // 检测主要编程语言
    const language = await this.detectLanguage(localPath);

    // 获取项目统计信息
    const stats = await this.getProjectStats(localPath);

    return {
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
    };
  }

  /**
   * 检测项目主要编程语言
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
   * 获取项目统计信息
   * @param {string} localPath - 本地路径
   * @returns {Promise<Object>}
   */
  async getProjectStats(localPath) {
    let fileCount = 0;
    let totalSize = 0;

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
            fileCount++;
            try {
              const stat = await fs.stat(fullPath);
              totalSize += stat.size;
            } catch {
              // 忽略无法访问的文件
            }
          }
        }
      } catch (error) {
        // 忽略无法访问的目录
      }
    }

    await scanDir(localPath);

    return {
      fileCount,
      totalSize,
      uploadedAt: new Date().toISOString()
    };
  }
}
