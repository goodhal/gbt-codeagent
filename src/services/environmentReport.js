/**
 * 环境报告模块（精简版）
 * 移除复杂依赖后保留基本功能
 */

export async function buildEnvironmentReport(options = {}) {
  const { rootDir = ".", downloadsDir = "./workspace/downloads" } = options;
  
  const report = {
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cwd: process.cwd(),
    rootDir,
    downloadsDir,
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
    cpuUsage: process.cpuUsage(),
    reportTime: new Date().toISOString()
  };

  return report;
}
